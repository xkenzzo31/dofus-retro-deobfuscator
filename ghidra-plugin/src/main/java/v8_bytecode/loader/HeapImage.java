package v8_bytecode.loader;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.model.V8Heap;
import v8_bytecode.snapshot.CodeCache;
import v8_bytecode.snapshot.HeapObject;
import v8_bytecode.snapshot.Ref;

/**
 * Lays the deserialized objects out as a heap in the program: every object at
 * its snapshot position (space, chunk, offset), with each tagged slot rewritten
 * to the program address of what it refers to. Read-only roots, objects of the
 * isolate's read-only heap and embedder-supplied objects, which the cache only
 * refers to, get labelled placeholder blocks; the read-only heap strings the
 * tables know (data/v8_ro_strings.json) are written there as string objects.
 */
public final class HeapImage {
	public static final long ROOTS_BASE = 0x00100000L;
	public static final long READ_ONLY_HEAP_BASE = 0x00200000L;
	public static final long READ_ONLY_PAGE_SIZE = 0x40000L;
	public static final long EMBEDDER_BASE = 0x00f00000L;
	public static final long EMBEDDER_SIZE = 0x30000L;
	public static final long STARTUP_CACHE_OFFSET = 0x10000L;
	public static final long READ_ONLY_CACHE_OFFSET = 0x20000L;
	/** js_variables block, written by FunctionImporter: one cell per variable. */
	public static final long VARIABLES_BASE = 0x01000000L;
	/** js_strings block, written by FunctionImporter: the decoded obfuscated strings. */
	public static final long STRINGS_BASE = 0x02000000L;
	public static final long HEAP_BASE = 0x10000000L;

	public static final String CATEGORY = "/V8";

	private final CodeCache cache;
	private final V8Heap heap;
	private final long[] addresses;
	private final byte[] image;
	private final TreeSet<Long> readOnlyTargets = new TreeSet<>();
	private final TreeSet<Long> embedderTargets = new TreeSet<>();

	public HeapImage(CodeCache cache, V8Heap heap) {
		this.cache = cache;
		this.heap = heap;
		this.addresses = new long[cache.objects.size()];

		// Paged spaces keep their chunk layout; map and large objects follow.
		long next = 0;
		long[][] chunkBase = new long[CodeCache.SPACES][];
		for (int space : new int[] { CodeCache.OLD_SPACE, CodeCache.CODE_SPACE }) {
			List<Integer> sizes = cache.chunkSizes.get(space);
			chunkBase[space] = new long[sizes.size()];
			for (int c = 0; c < sizes.size(); c++) {
				chunkBase[space][c] = next;
				next = align(next + sizes.get(c));
			}
		}
		for (HeapObject o : cache.objects) {
			if (o.space == CodeCache.OLD_SPACE || o.space == CodeCache.CODE_SPACE) {
				addresses[o.sequence] = HEAP_BASE + chunkBase[o.space][o.chunk] + o.offset;
			}
		}
		for (HeapObject o : cache.objects) {
			if (o.space == CodeCache.MAP_SPACE || o.space == CodeCache.LARGE_OBJECT_SPACE) {
				addresses[o.sequence] = HEAP_BASE + next;
				next = align(next + o.size);
			}
		}

		image = new byte[(int) Math.max(next, 8)];
		for (HeapObject o : cache.objects) {
			int base = (int) (addresses[o.sequence] - HEAP_BASE);
			System.arraycopy(o.data, 0, image, base, o.size);
			for (int i = 0; i < o.slotCount(); i++) {
				Object value = o.slotValue(i);
				int at = base + o.slotOffset(i);
				if (value instanceof Ref.External) {
					writeInt(at, 0);
					writeInt(at + 4, 0);
					continue;
				}
				long target = address(value);
				writeInt(at, (int) target);
				if (value instanceof Ref.ReadOnlyHeap) {
					readOnlyTargets.add(target);
				}
				else if (value instanceof Ref.Attached || value instanceof Ref.ObjectCache) {
					embedderTargets.add(target);
				}
			}
		}
	}

	private static long align(long v) {
		return (v + 7) & ~7L;
	}

	private void writeInt(int at, int v) {
		putInt(image, at, v);
	}

	public long address(HeapObject o) {
		return addresses[o.sequence];
	}

	/** Program address a slot value refers to (0 for cleared or external references). */
	public long address(Object value) {
		if (value instanceof HeapObject o) {
			return addresses[o.sequence];
		}
		if (value instanceof Ref.Root r) {
			return ROOTS_BASE + 4L * r.index();
		}
		if (value instanceof Ref.ReadOnlyHeap r) {
			return READ_ONLY_HEAP_BASE + r.chunk() * READ_ONLY_PAGE_SIZE + r.offset();
		}
		if (value instanceof Ref.Attached r) {
			return EMBEDDER_BASE + 4L * r.index();
		}
		if (value instanceof Ref.ObjectCache r) {
			return EMBEDDER_BASE + (r.readOnly() ? READ_ONLY_CACHE_OFFSET : STARTUP_CACHE_OFFSET) +
				4L * r.index();
		}
		return 0;
	}

	public byte[] bytes() {
		return image;
	}

	/** Creates the memory blocks and labels the placeholder objects. */
	public void createBlocks(Program program, TaskMonitor monitor) throws Exception {
		Memory memory = program.getMemory();
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		SymbolTable symbols = program.getSymbolTable();

		int roots = heap.tables.roots.size();
		MemoryBlock rootsBlock = memory.createInitializedBlock("v8_roots", ram.getAddress(ROOTS_BASE),
			4L * roots, (byte) 0, monitor, false);
		rootsBlock.setWrite(false);
		rootsBlock.setComment("Read-only roots of the isolate (placeholders, one slot each)");
		for (int i = 0; i < roots; i++) {
			String string = heap.tables.rootString(i);
			String name = string == null ? heap.tables.rootName(i)
					: "str_" + (string.isEmpty() ? "empty" : string);
			symbols.createLabel(ram.getAddress(ROOTS_BASE + 4L * i),
				SymbolUtilities.replaceInvalidChars(name, true), SourceType.IMPORTED);
		}

		if (!readOnlyTargets.isEmpty()) {
			long end = 0;
			for (long target : readOnlyTargets) {
				String s = readOnlyString(target);
				end = Math.max(end, target - READ_ONLY_HEAP_BASE + (s == null ? 4 : stringSize(s)));
			}
			byte[] contents = new byte[(int) align(end)];
			for (long target : readOnlyTargets) {
				String s = readOnlyString(target);
				if (s != null) {
					writeString(contents, (int) (target - READ_ONLY_HEAP_BASE), s);
				}
			}
			MemoryBlock ro = memory.createInitializedBlock("v8_ro_heap", ram.getAddress(READ_ONLY_HEAP_BASE),
				new ByteArrayInputStream(contents), contents.length, monitor, false);
			ro.setWrite(false);
			ro.setComment("Objects of the isolate's read-only heap referenced by the cache: the strings " +
				"of data/v8_ro_strings.json, other objects zero-filled");
			for (long target : readOnlyTargets) {
				String s = readOnlyString(target);
				String name = s == null ? String.format("ro_heap_%x", target - READ_ONLY_HEAP_BASE)
						: "str_" + (s.isEmpty() ? "empty" : s);
				symbols.createLabel(ram.getAddress(target), SymbolUtilities.replaceInvalidChars(name, true),
					SourceType.IMPORTED);
			}
		}

		if (!embedderTargets.isEmpty()) {
			MemoryBlock embedder = memory.createUninitializedBlock("v8_embedder",
				ram.getAddress(EMBEDDER_BASE), EMBEDDER_SIZE, false);
			embedder.setComment("Objects supplied at load time (attached objects, object caches)");
			for (long target : embedderTargets) {
				long off = target - EMBEDDER_BASE;
				String name = off >= READ_ONLY_CACHE_OFFSET
						? "read_only_object_cache_" + (off - READ_ONLY_CACHE_OFFSET) / 4
						: off >= STARTUP_CACHE_OFFSET
								? "startup_object_cache_" + (off - STARTUP_CACHE_OFFSET) / 4
								: off == 0 ? "script_source" : "attached_" + off / 4;
				symbols.createLabel(ram.getAddress(target), name, SourceType.IMPORTED);
			}
		}

		MemoryBlock heapBlock = memory.createInitializedBlock("v8_heap", ram.getAddress(HEAP_BASE),
			new ByteArrayInputStream(image), image.length, monitor, false);
		heapBlock.setExecute(true);
		heapBlock.setComment(String.format(
			"%d objects of the code cache; tagged slots hold program addresses", cache.objects.size()));
	}

	/** The string at a read-only heap address, when the tables know it. */
	private String readOnlyString(long target) {
		long off = target - READ_ONLY_HEAP_BASE;
		return heap.tables.readOnlyString((int) (off / READ_ONLY_PAGE_SIZE), (int) (off % READ_ONLY_PAGE_SIZE));
	}

	private static boolean isOneByte(String s) {
		return s.chars().allMatch(c -> c < 0x100);
	}

	private static int stringSize(String s) {
		return V8Heap.STRING_CHARS + (isOneByte(s) ? s.length() : 2 * s.length());
	}

	/** An internalized string object: map, hash field (left 0), length, characters. */
	private void writeString(byte[] to, int at, String s) {
		boolean oneByte = isOneByte(s);
		long map = ROOTS_BASE +
			4L * heap.tables.rootIndex(oneByte ? "OneByteInternalizedStringMap" : "InternalizedStringMap");
		putInt(to, at, (int) map);
		putInt(to, at + V8Heap.STRING_LENGTH, s.length());
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (oneByte) {
				to[at + V8Heap.STRING_CHARS + i] = (byte) c;
			}
			else {
				to[at + V8Heap.STRING_CHARS + 2 * i] = (byte) c;
				to[at + V8Heap.STRING_CHARS + 2 * i + 1] = (byte) (c >> 8);
			}
		}
	}

	private static void putInt(byte[] to, int at, int v) {
		to[at] = (byte) v;
		to[at + 1] = (byte) (v >> 8);
		to[at + 2] = (byte) (v >> 16);
		to[at + 3] = (byte) (v >> 24);
	}

	// ---- data types ------------------------------------------------------------

	/**
	 * Applies data types: structures for SharedFunctionInfo, BytecodeArray headers
	 * and HeapNumbers, characters for strings, and a pointer at every other tagged
	 * slot. V8_ConstantPool relies on pointers to tell references from Smis.
	 */
	public void markup(Program program, TaskMonitor monitor) throws CancelledException {
		DataTypeManager dtm = program.getDataTypeManager();
		DataType pointer = new PointerDataType(null, 4, dtm);
		DataType sfi = dtm.addDataType(sharedFunctionInfoType(pointer), null);
		DataType bytecodeArray = dtm.addDataType(bytecodeArrayType(pointer), null);
		DataType heapNumber = dtm.addDataType(heapNumberType(pointer), null);
		Listing listing = program.getListing();
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();

		for (long target : readOnlyTargets) {
			String s = readOnlyString(target);
			if (s != null && !s.isEmpty()) {
				boolean oneByte = isOneByte(s);
				try {
					listing.createData(ram.getAddress(target + V8Heap.STRING_CHARS),
						oneByte ? StringDataType.dataType : UnicodeDataType.dataType,
						oneByte ? s.length() : 2 * s.length());
				}
				catch (Exception e) {
					Msg.warn(this, "Could not type the read-only string at " + Long.toHexString(target));
				}
			}
		}

		monitor.initialize(cache.objects.size(), "Applying V8 object types");
		int failures = 0;
		for (HeapObject o : cache.objects) {
			monitor.increment();
			Address at = ram.getAddress(addresses[o.sequence]);
			String map = heap.mapName(o);
			try {
				if (heap.isSequentialString(o)) {
					int n = o.int32(V8Heap.STRING_LENGTH);
					if (n > 0) {
						boolean oneByte = heap.isOneByteString(o);
						listing.createData(at.add(V8Heap.STRING_CHARS),
							oneByte ? StringDataType.dataType : UnicodeDataType.dataType,
							oneByte ? n : 2 * n);
					}
					continue;
				}
				if ("SharedFunctionInfoMap".equals(map) && o.size >= V8Heap.SFI_SIZE) {
					listing.createData(at, sfi);
					continue;
				}
				if ("BytecodeArrayMap".equals(map)) {
					listing.createData(at, bytecodeArray);
					continue;
				}
				if ("HeapNumberMap".equals(map)) {
					listing.createData(at, heapNumber);
					continue;
				}
				for (int i = 0; i < o.slotCount(); i++) {
					if (!(o.slotValue(i) instanceof Ref.External)) {
						listing.createData(at.add(o.slotOffset(i)), pointer);
					}
				}
			}
			catch (Exception e) {
				failures++;
			}
		}
		if (failures > 0) {
			Msg.warn(this, failures + " heap objects could not be typed");
		}
	}

	private static Structure sharedFunctionInfoType(DataType pointer) {
		StructureDataType s = new StructureDataType(new CategoryPath(CATEGORY), "SharedFunctionInfo", 0);
		s.add(pointer, "map", null);
		s.add(pointer, "function_data", "BytecodeArray, or builtin / uncompiled data");
		s.add(pointer, "name_or_scope_info", "ScopeInfo or String");
		s.add(pointer, "outer_scope_info_or_feedback_metadata", null);
		s.add(pointer, "script_or_debug_info", null);
		s.add(ShortDataType.dataType, "length", "Function.length");
		s.add(UnsignedShortDataType.dataType, "formal_parameter_count", null);
		s.add(UnsignedShortDataType.dataType, "function_token_offset", null);
		s.add(ByteDataType.dataType, "expected_nof_properties", null);
		s.add(ByteDataType.dataType, "flags2", null);
		s.add(UnsignedIntegerDataType.dataType, "flags", null);
		s.add(IntegerDataType.dataType, "function_literal_id", null);
		s.add(IntegerDataType.dataType, "unique_id", null);
		return s;
	}

	private static Structure bytecodeArrayType(DataType pointer) {
		StructureDataType s = new StructureDataType(new CategoryPath(CATEGORY), "BytecodeArray", 0);
		s.add(pointer, "map", null);
		s.add(IntegerDataType.dataType, "length", "Smi: bytecode length << 1");
		s.add(pointer, "constant_pool", null);
		s.add(pointer, "handler_table", null);
		s.add(pointer, "source_position_table", null);
		s.add(IntegerDataType.dataType, "frame_size", "register count * 8");
		s.add(IntegerDataType.dataType, "parameter_size", "parameter count (with receiver) * 8");
		s.add(IntegerDataType.dataType, "incoming_new_target_or_generator_register", null);
		s.add(ByteDataType.dataType, "osr_nesting_level", null);
		s.add(ByteDataType.dataType, "bytecode_age", null);
		return s;
	}

	private static Structure heapNumberType(DataType pointer) {
		StructureDataType s = new StructureDataType(new CategoryPath(CATEGORY), "HeapNumber", 0);
		s.add(pointer, "map", null);
		s.add(Float8DataType.dataType, "value", null);
		return s;
	}
}
