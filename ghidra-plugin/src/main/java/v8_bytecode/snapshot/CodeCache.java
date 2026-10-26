package v8_bytecode.snapshot;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Deserializer for V8 8.7 code caches (SerializedCodeData), the format bytenode
 * writes to .jsc files.
 *
 * This is a port of Deserializer::ReadObject and ReadSingleBytecodeData
 * (src/snapshot/deserializer.cc, V8 8.7.220.31) for x64 with pointer
 * compression: tagged slots are 4 bytes, external references take a full
 * system pointer. It only rebuilds the object graph; nothing is executed.
 */
public final class CodeCache {
	public static final int MAGIC_BASE = 0xC0DE0000;
	public static final int HEADER_SIZE = 32;
	public static final int TAGGED_SIZE = 4;
	public static final int SYSTEM_POINTER_SIZE = 8;

	public static final int READ_ONLY_SPACE = 0;
	public static final int OLD_SPACE = 1;
	public static final int CODE_SPACE = 2;
	public static final int MAP_SPACE = 3;
	public static final int LARGE_OBJECT_SPACE = 4;
	public static final int SPACES = 5;

	// Snapshot bytecodes (src/snapshot/serializer-deserializer.h).
	private static final int NEW_OBJECT = 0x00;
	private static final int BACKREF = 0x08;
	private static final int STARTUP_OBJECT_CACHE = 0x10;
	private static final int ROOT_ARRAY = 0x11;
	private static final int ATTACHED_REFERENCE = 0x12;
	private static final int READ_ONLY_OBJECT_CACHE = 0x13;
	private static final int NOP = 0x14;
	private static final int NEXT_CHUNK = 0x15;
	private static final int ALIGNMENT_PREFIX = 0x16;
	private static final int SYNCHRONIZE = 0x19;
	private static final int VARIABLE_REPEAT = 0x1a;
	private static final int OFF_HEAP_BACKING_STORE = 0x1b;
	private static final int VARIABLE_RAW_DATA = 0x1e;
	private static final int API_REFERENCE = 0x1f;
	private static final int EXTERNAL_REFERENCE = 0x20;
	private static final int SANDBOXED_API_REFERENCE = 0x21;
	private static final int SANDBOXED_EXTERNAL_REFERENCE = 0x22;
	private static final int CLEARED_WEAK_REFERENCE = 0x24;
	private static final int WEAK_PREFIX = 0x25;
	private static final int REGISTER_PENDING_FORWARD_REF = 0x27;
	private static final int RESOLVE_PENDING_FORWARD_REF = 0x28;
	private static final int ROOT_ARRAY_CONSTANTS = 0x40;
	private static final int FIXED_RAW_DATA = 0x60;
	private static final int FIXED_REPEAT = 0x80;
	private static final int HOT_OBJECT = 0x90;
	private static final int FIRST_ENCODABLE_REPEAT_COUNT = 2;
	private static final int FIRST_ENCODABLE_VARIABLE_REPEAT_COUNT = 18;

	public final int magic;
	public final int versionHash;
	public final int sourceHash;
	public final int flagsHash;
	public final int payloadOffset;
	public final int payloadLength;
	public final int checksum;
	/** Reserved chunk sizes, per snapshot space. */
	public final List<List<Integer>> chunkSizes = new ArrayList<>();
	/** All objects, in allocation order. */
	public final List<HeapObject> objects = new ArrayList<>();
	/** The SharedFunctionInfo of the top-level script. */
	public Object root;
	/** Objects deserialized after the root (deferred objects). */
	public int deferredObjects;

	private final byte[] blob;
	private int pos;
	private final Object[] hotObjects = new Object[8];
	private int hotIndex;
	private final int[] highWaterChunk = new int[SPACES];
	private final int[] highWaterOffset = new int[SPACES];
	private final Map<Long, HeapObject> byChunk = new HashMap<>();
	private final List<HeapObject> maps = new ArrayList<>();
	private final List<HeapObject> largeObjects = new ArrayList<>();
	private final List<HeapObject> forwardRefHolders = new ArrayList<>();
	private final List<Integer> forwardRefOffsets = new ArrayList<>();
	private int pendingAlignment;

	private CodeCache(byte[] blob) throws IOException {
		this.blob = blob;
		if (blob.length < HEADER_SIZE) {
			throw new IOException("File too small for a V8 code cache");
		}
		magic = int32(0);
		versionHash = int32(4);
		sourceHash = int32(8);
		flagsHash = int32(12);
		int reservations = int32(16);
		payloadLength = int32(20);
		checksum = int32(24);
		for (int s = 0; s < SPACES; s++) {
			chunkSizes.add(new ArrayList<>());
		}
		int space = 0;
		for (int i = 0; i < reservations; i++) {
			int r = int32(HEADER_SIZE + 4 * i);
			if (space >= SPACES) {
				throw new IOException("Reservations describe more than " + SPACES + " spaces");
			}
			chunkSizes.get(space).add(r & 0x7fffffff);
			if ((r & 0x80000000) != 0) {
				space++;
			}
		}
		// POINTER_SIZE_ALIGN(header + reservations), with the system pointer size.
		int start = HEADER_SIZE + 4 * reservations;
		payloadOffset = (start + SYSTEM_POINTER_SIZE - 1) & ~(SYSTEM_POINTER_SIZE - 1);
		if ((long) payloadOffset + payloadLength > blob.length) {
			throw new IOException("Payload extends past the end of the file");
		}
	}

	/** Reads the header only; {@link #deserialize()} rebuilds the objects. */
	public static CodeCache read(byte[] blob) throws IOException {
		return new CodeCache(blob);
	}

	/** Magic is 0xC0DE0000 ^ ExternalReferenceTable::kSize (0x3D2 in V8 8.7). */
	public static boolean isCodeCacheMagic(int magic) {
		int kSize = magic ^ MAGIC_BASE;
		return kSize >= 0x200 && kSize <= 0x800;
	}

	/**
	 * Rebuilds the object graph. Deserialization recurses once per nested
	 * object, so it runs on a thread with a large stack.
	 */
	public CodeCache deserialize() throws IOException {
		IOException[] failure = new IOException[1];
		Thread worker = new Thread(null, () -> {
			try {
				run();
			}
			catch (IOException e) {
				failure[0] = e;
			}
			catch (RuntimeException | StackOverflowError e) {
				failure[0] = new IOException(
					String.format("Deserialization failed at payload offset 0x%x: %s",
						pos - payloadOffset, e), e);
			}
		}, "v8-code-cache", 1L << 29);
		worker.start();
		try {
			worker.join();
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IOException("Interrupted while deserializing", e);
		}
		if (failure[0] != null) {
			throw failure[0];
		}
		return this;
	}

	private void run() throws IOException {
		pos = payloadOffset;
		HeapObject holder = new HeapObject(READ_ONLY_SPACE, -1, 0, SYSTEM_POINTER_SIZE, -1);
		readSingle(get(), holder, 0);
		root = holder.slot(0);
		int end = payloadOffset + payloadLength;
		while (true) {
			int code = get();
			if (code == SYNCHRONIZE) {
				break;
			}
			if (code > NEW_OBJECT + LARGE_OBJECT_SPACE) {
				throw new IOException(String.format("Unexpected deferred bytecode 0x%02x", code));
			}
			readObject(code);
			deferredObjects++;
		}
		while (pos < end) {
			if (get() != NOP) {
				throw new IOException("Trailing data after the deferred objects");
			}
		}
	}

	// ---- SnapshotByteSource ------------------------------------------------

	private int int32(int off) {
		return (blob[off] & 0xff) | ((blob[off + 1] & 0xff) << 8) | ((blob[off + 2] & 0xff) << 16) |
			((blob[off + 3] & 0xff) << 24);
	}

	private int get() {
		return blob[pos++] & 0xff;
	}

	private int peek() {
		return blob[pos] & 0xff;
	}

	/** SnapshotByteSource::GetInt: 1-4 bytes, length in the low two bits. */
	private int getInt() {
		int answer = 0;
		for (int i = 0; i < 4 && pos + i < blob.length; i++) {
			answer |= (blob[pos + i] & 0xff) << (8 * i);
		}
		int bytes = (answer & 3) + 1;
		pos += bytes;
		long mask = 0xffffffffL >>> (32 - 8 * bytes);
		return (int) ((answer & mask) >>> 2);
	}

	// ---- allocation ----------------------------------------------------------

	private HeapObject allocate(int space, int size) throws IOException {
		int sequence = objects.size();
		HeapObject obj;
		if (space == LARGE_OBJECT_SPACE) {
			obj = new HeapObject(space, largeObjects.size(), 0, size, sequence);
			largeObjects.add(obj);
		}
		else if (space == MAP_SPACE) {
			obj = new HeapObject(space, maps.size(), 0, size, sequence);
			maps.add(obj);
		}
		else {
			if (pendingAlignment != 0) {
				throw new IOException("Aligned allocations are not expected on x64");
			}
			obj = new HeapObject(space, highWaterChunk[space], highWaterOffset[space], size,
				sequence);
			byChunk.put(chunkKey(space, obj.chunk, obj.offset), obj);
			highWaterOffset[space] += size;
		}
		objects.add(obj);
		return obj;
	}

	private void moveToNextChunk(int space) throws IOException {
		int chunk = highWaterChunk[space];
		List<Integer> sizes = chunkSizes.get(space);
		if (chunk >= sizes.size() || highWaterOffset[space] != sizes.get(chunk)) {
			throw new IOException("Chunk " + chunk + " of space " + space + " not filled");
		}
		highWaterChunk[space] = chunk + 1;
		highWaterOffset[space] = 0;
	}

	private static long chunkKey(int space, int chunk, int offset) {
		return ((long) space << 56) | ((long) chunk << 32) | (offset & 0xffffffffL);
	}

	private void addHot(Object value) {
		hotObjects[hotIndex] = value;
		hotIndex = (hotIndex + 1) & 7;
	}

	// ---- deserializer ----------------------------------------------------------

	private Object backReference(int space) throws IOException {
		Object obj;
		if (space == LARGE_OBJECT_SPACE) {
			obj = largeObjects.get(getInt());
		}
		else if (space == MAP_SPACE) {
			obj = maps.get(getInt());
		}
		else if (space == READ_ONLY_SPACE) {
			int chunk = getInt();
			obj = new Ref.ReadOnlyHeap(chunk, getInt());
		}
		else {
			int chunk = getInt();
			int offset = getInt();
			obj = byChunk.get(chunkKey(space, chunk, offset));
			if (obj == null) {
				throw new IOException(String.format("Back reference to unknown object %d/%d+0x%x",
					space, chunk, offset));
			}
		}
		addHot(obj);
		return obj;
	}

	private HeapObject readObject(int space) throws IOException {
		int size = getInt() * TAGGED_SIZE;
		Object map = readDetachedReference();
		if (peek() >= ALIGNMENT_PREFIX && peek() < ALIGNMENT_PREFIX + 3) {
			pendingAlignment = get() - ALIGNMENT_PREFIX + 1;
		}
		if (peek() == NEXT_CHUNK) {
			pos++;
			if (get() != space) {
				throw new IOException("Chunk change for another space");
			}
			moveToNextChunk(space);
		}
		HeapObject obj = allocate(space, size);
		obj.setSlot(0, map);
		readData(obj, TAGGED_SIZE, size);
		return obj;
	}

	/** Deserializer::ReadObject(): fills one slot that is not part of an object. */
	private Object readDetachedReference() throws IOException {
		HeapObject holder = new HeapObject(READ_ONLY_SPACE, -1, 0, SYSTEM_POINTER_SIZE, -1);
		int cur = 0;
		while (cur == 0) {
			cur = readSingle(get(), holder, cur);
		}
		return holder.slot(0);
	}

	private void readData(HeapObject obj, int cur, int limit) throws IOException {
		while (cur < limit) {
			cur = readSingle(get(), obj, cur);
		}
		if (cur != limit) {
			throw new IOException("Object data overruns its size: " + obj);
		}
	}

	private int write(HeapObject obj, int cur, Object value) {
		obj.setSlot(cur, value);
		return cur + TAGGED_SIZE;
	}

	/** Handles one bytecode; returns the new slot offset within {@code obj}. */
	private int readSingle(int b, HeapObject obj, int cur) throws IOException {
		if (b <= NEW_OBJECT + LARGE_OBJECT_SPACE) {
			return write(obj, cur, readObject(b - NEW_OBJECT));
		}
		if (b >= BACKREF && b <= BACKREF + LARGE_OBJECT_SPACE) {
			return write(obj, cur, backReference(b - BACKREF));
		}
		if (b >= ROOT_ARRAY_CONSTANTS && b < FIXED_RAW_DATA) {
			return write(obj, cur, new Ref.Root(b - ROOT_ARRAY_CONSTANTS));
		}
		if (b >= FIXED_RAW_DATA && b < FIXED_REPEAT) {
			int n = (b - FIXED_RAW_DATA + 1) * TAGGED_SIZE;
			copyRaw(obj, cur, n);
			return cur + n;
		}
		if (b >= FIXED_REPEAT && b < HOT_OBJECT) {
			return repeat(obj, cur, b - FIXED_REPEAT + FIRST_ENCODABLE_REPEAT_COUNT);
		}
		if (b >= HOT_OBJECT && b < HOT_OBJECT + 8) {
			return write(obj, cur, hotObjects[b - HOT_OBJECT]);
		}
		if (b >= ALIGNMENT_PREFIX && b < ALIGNMENT_PREFIX + 3) {
			pendingAlignment = b - ALIGNMENT_PREFIX + 1;
			return cur;
		}
		switch (b) {
			case ROOT_ARRAY: {
				Ref root = new Ref.Root(getInt());
				addHot(root);
				return write(obj, cur, root);
			}
			case STARTUP_OBJECT_CACHE:
				return write(obj, cur, new Ref.ObjectCache(false, getInt()));
			case READ_ONLY_OBJECT_CACHE:
				return write(obj, cur, new Ref.ObjectCache(true, getInt()));
			case ATTACHED_REFERENCE:
				return write(obj, cur, new Ref.Attached(getInt()));
			case API_REFERENCE:
			case SANDBOXED_API_REFERENCE:
				obj.setSlot(cur, new Ref.External(true, getInt()));
				return cur + SYSTEM_POINTER_SIZE;
			case EXTERNAL_REFERENCE:
			case SANDBOXED_EXTERNAL_REFERENCE:
				obj.setSlot(cur, new Ref.External(false, getInt()));
				return cur + SYSTEM_POINTER_SIZE;
			case NOP:
				return cur;
			case REGISTER_PENDING_FORWARD_REF:
				forwardRefHolders.add(obj);
				forwardRefOffsets.add(cur);
				return cur + TAGGED_SIZE;
			case RESOLVE_PENDING_FORWARD_REF: {
				int index = getInt();
				forwardRefHolders.get(index).setSlot(forwardRefOffsets.get(index), obj);
				return cur;
			}
			case VARIABLE_RAW_DATA: {
				int n = getInt();
				copyRaw(obj, cur, n);
				return cur + n;
			}
			case VARIABLE_REPEAT:
				return repeat(obj, cur, getInt() + FIRST_ENCODABLE_VARIABLE_REPEAT_COUNT);
			case OFF_HEAP_BACKING_STORE:
				pos += getInt();
				return cur;
			case CLEARED_WEAK_REFERENCE:
				return write(obj, cur, new Ref.ClearedWeak());
			case WEAK_PREFIX:
				return cur;
			default:
				throw new IOException(String.format(
					"Unsupported snapshot bytecode 0x%02x at payload offset 0x%x in %s", b,
					pos - 1 - payloadOffset, obj));
		}
	}

	private void copyRaw(HeapObject obj, int cur, int n) throws IOException {
		if (cur + n > obj.size) {
			throw new IOException("Raw data overruns " + obj);
		}
		System.arraycopy(blob, pos, obj.data, cur, n);
		pos += n;
	}

	private int repeat(HeapObject obj, int cur, int count) throws IOException {
		Object value = readDetachedReference();
		for (int i = 0; i < count; i++) {
			obj.setSlot(cur, value);
			cur += TAGGED_SIZE;
		}
		return cur;
	}
}
