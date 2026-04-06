package v8_bytecode.allocator;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.AllocSpace;
import v8_bytecode.AllocWhere;
import v8_bytecode.EnumsStorage;
import v8_bytecode.ReservObject;
import v8_bytecode.RootObject;
import v8_bytecode.RuntimeFuncArg;
import v8_bytecode.enums.AllocationAlignment;
import v8_bytecode.enums.BuiltinsEnum;
import v8_bytecode.enums.CatchPrediction;
import v8_bytecode.enums.EnumDataTypes;
import v8_bytecode.enums.RuntimesEnum;
import v8_bytecode.enums.IntrinsicsEnum;
import v8_bytecode.enums.JsRuntimesEnum;
import v8_bytecode.enums.RootsEnum;
import v8_bytecode.enums.ScriptSourceEnum;
import v8_bytecode.enums.ScriptTypeEnum;
import v8_bytecode.enums.SourcePositionTypeEnum;
import v8_bytecode.enums.TypeOfEnum;
import v8_bytecode.storage.RootsStore;
import v8_bytecode.storage.RuntimesIntrinsicsStore;
import v8_bytecode.structs.HandlerTableItemStruct;
import v8_bytecode.structs.HandlerTableStruct;
import v8_bytecode.structs.SharedFunctionInfoStruct;

public final class JscParser {
	private List<Object> attached = new ArrayList<>();
	private List<String> builtins = new ArrayList<>();
	private List<RootObject> roots = new ArrayList<>();

	private AllocationAlignment nextAlignment = AllocationAlignment.kWordAligned; 
	private long lastHotIndex = 0L;
	private Map<AllocSpace, Integer> lastChunkIndex = new HashMap<>();
	private SortedMap<Long, Object> hots = new TreeMap<>();

	private SortedMap<AllocSpace, List<ReservObject>> reserv = new TreeMap<>();
	private List<Long> codeStubs = new ArrayList<>();
	private int totalObjectCount = 0;
	
	private final BinaryReader reader;
	private final ObjectsAllocator allocator;
	private final Program program;
	private final DataTypeManager mgr;
	private final MessageLog log;
	private final TaskMonitor monitor;
	private static boolean is32Bit;
	
	private final int kPointerSizeLog2;
	public final int kPointerSize;
	
	private final long kPointerAlignment;
	private final long kPointerAlignmentMask;
	private final int kObjectAlignmentBits;
	
	public JscParser(BinaryReader reader, boolean is32Bit, Program program, TaskMonitor monitor, MessageLog log) throws Exception {
		this.reader = reader;
		this.program = program;
		this.mgr = program.getDataTypeManager();
		this.log = log;
		this.monitor = monitor;
		JscParser.is32Bit = is32Bit;
		
		kPointerSizeLog2 = is32Bit ? 2 : 3;
		kPointerSize = is32Bit ? 4 : 8;
		
		kPointerAlignment = (1 << kPointerSizeLog2);
		kPointerAlignmentMask = kPointerAlignment - 1;
		kObjectAlignmentBits = kPointerSizeLog2;
		
		attached.add("Source");
		
		RootsStore rootsEnum = loadRoots();
		BuiltinsEnum builtinsEnum = loadBuiltins();
		JsRuntimesEnum jsRuns = loadJsRuntimes();
		RuntimesIntrinsicsStore runsIntrsStore = loadIntrsAndRuntimes();
		
		Enum predict = (Enum) mgr.addDataType(new CatchPrediction(), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum srcEnum = (Enum) mgr.addDataType(new ScriptSourceEnum(), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum typeEnum = (Enum) mgr.addDataType(new ScriptTypeEnum(), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum sptEnum = (Enum) mgr.addDataType(new SourcePositionTypeEnum(), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum rootsDt = (Enum) mgr.addDataType(new RootsEnum(rootsEnum), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum runsDt = (Enum) mgr.addDataType(new RuntimesEnum(runsIntrsStore), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum intrsDt = (Enum) mgr.addDataType(new IntrinsicsEnum(runsIntrsStore), DataTypeConflictHandler.DEFAULT_HANDLER);
		
		Enum typeofDt = (Enum) mgr.addDataType(new TypeOfEnum(), DataTypeConflictHandler.DEFAULT_HANDLER);
		
		EnumDataTypes enumsDt = new EnumDataTypes(rootsDt, runsDt, intrsDt, jsRuns, builtinsEnum, sptEnum, predict, typeofDt);
		EnumsStorage enums = new EnumsStorage(rootsEnum, runsIntrsStore);
		
		allocator = new ObjectsAllocator(enums, enumsDt, program, monitor);
	}
	
	private long pointerSizeAlign(long value) {
		return ((value + kPointerAlignmentMask) & ~kPointerAlignmentMask);
	}
	
	/**
	 * Parse a V8 8.7 JSC file.
	 *
	 * Header format (V8 8.7, from code-serializer.h, 32 bytes total):
	 *   Offset 0x00: Magic           (uint32) = 0xC0DE0000 ^ ExternalReferenceTable::kSize
	 *   Offset 0x04: VersionHash     (uint32) = hash of version string "8.7.220.31"
	 *   Offset 0x08: SourceHash      (uint32) = hash of the JavaScript source
	 *   Offset 0x0C: FlagHash        (uint32) = hash of V8 flags
	 *   Offset 0x10: NumReservations  (uint32) = number of reservation entries
	 *   Offset 0x14: PayloadLength   (uint32) = size of serialized payload
	 *   Offset 0x18: Checksum        (uint32) = Adler-32 of the payload
	 *   Offset 0x1C: Padding         (4 bytes of 0)
	 *
	 * This is DIFFERENT from V8 6.x which had cpuFeatures, codeStubsCount, c1, c2 fields.
	 * V8 8.7 removed code stubs and simplified the header.
	 *
	 * After the header come NumReservations uint32 entries describing space allocations.
	 * Then the serialized payload follows (aligned to pointer size).
	 *
	 * IMPORTANT: The snapshot serializer format has changed significantly between V8 6.x
	 * and V8 8.7. The deserialization bytecodes (kNewObject, kBackref, kRootArray, etc.)
	 * use different encodings. V8 8.x introduced READ_ONLY_SPACE and changed how spaces
	 * are encoded in the bytecodes.
	 */
	public void parse() throws Exception {
		monitor.setMessage("Parsing V8 8.7 JSC binary...");

		// -- V8 8.7 header (32 bytes, no cpuFeatures/codeStubs/c1/c2) --
		reader.readNextUnsignedInt(); // skip magic dword (0xC0DE03D2)

		long versionHash = reader.readNextUnsignedInt();   // offset 0x04
		long sourceHash = reader.readNextUnsignedInt();     // offset 0x08
		long flagsHash = reader.readNextUnsignedInt();      // offset 0x0C
		// NOTE: V8 6.x had cpuFeatures between sourceHash and flagsHash.
		// V8 8.7 does NOT have cpuFeatures -- flagsHash is at offset 0x0C directly.

		long reservCount = reader.readNextUnsignedInt();    // offset 0x10
		long reservSize = reservCount * 4;
		long payloadSize = reader.readNextUnsignedInt();    // offset 0x14
		// NOTE: V8 6.x had codeStubsCount here. V8 8.7 has payloadLength instead.
		// V8 8.7 has NO code stubs -- they were removed in V8 8.x.

		long checksum = reader.readNextUnsignedInt();       // offset 0x18 (Adler-32)
		long padding = reader.readNextUnsignedInt();        // offset 0x1C (always 0)

		System.out.println(String.format("[V8 8.7] versionHash=0x%08X sourceHash=0x%08X flagsHash=0x%08X",
			versionHash, sourceHash, flagsHash));
		System.out.println(String.format("[V8 8.7] reservations=%d payloadSize=%d checksum=0x%08X",
			reservCount, payloadSize, checksum));

		// Reservations follow the header (no code stubs in V8 8.7)
		long payloadOffset = pointerSizeAlign(reader.getPointerIndex() + reservSize);

		int currSpace = 0;

		for (int i = 0; i < reservCount; ++i) {
			final AllocSpace space = AllocSpace.fromInt(currSpace);
			List<ReservObject> objects = reserv.get(space);

			if (objects == null) {
				objects = new ArrayList<>();
			}

			long size = reader.readNextUnsignedInt();

			objects.add(new ReservObject(size & 0x7FFFFFFFL, kPointerSize));
			
			reserv.put(space, objects);
			lastChunkIndex.put(space, 0);

			if ((size & 0x80000000L) >> 0x1F != 0) {
				currSpace++;
			}
		}

		// V8 8.7: no code stubs (removed in V8 8.x)

		reader.setPointerIndex(payloadOffset);

		// Initialize bump allocator offsets: each chunk starts at offset 0.
		for (Map.Entry<AllocSpace, List<ReservObject>> entry : reserv.entrySet()) {
			for (ReservObject chunk : entry.getValue()) {
				chunk.setOffset(0);
			}
		}

		// Attempt V8 snapshot deserialization.
		boolean snapshotParsed = false;
		try {
			System.out.println(String.format("[V8 8.7] Starting snapshot deserialization at offset 0x%X",
				(long) payloadOffset));

			// V8 8.7 CodeSerializer::Deserialize() calls DeserializeObject() which reads
			// the first byte to determine the space, then calls ReadObject(space).
			// ReadObject reads the object size from the stream, bump-allocates within
			// the current chunk, and calls ReadData to fill the object.
			int firstByte = reader.readNextByte() & 0xFF;
			if (firstByte >= AllocWhere.kNumberOfSpaces) {
				throw new IOException(String.format(
					"[V8 8.7] Expected kNewObject (0x00-0x04) as first byte, got 0x%02X", firstByte));
			}
			AllocSpace rootSpace = AllocSpace.fromInt(firstByte);
			System.out.println(String.format("[V8 8.7] Root object space: %s (byte=0x%02X)", rootSpace, firstByte));

			// ReadObject: read size from stream, bump-allocate, fill with ReadData.
			// The root object is stored for later retrieval by loadSpaceObjects.
			ReservObject rootObj = readObjectFromStream(rootSpace);
			System.out.println(String.format("[V8 8.7] Root object deserialized: size=%d bytes, totalObjects=%d, stream=0x%X",
				rootObj.getSize(), totalObjectCount, reader.getPointerIndex()));

			deserializeDeferredObjects();

			monitor.setMessage("Loading \"OLD_SPACE\" objects...");
			final List<ReservObject> chunks = reserv.get(AllocSpace.OLD_SPACE);
			if (chunks != null) {
				System.out.println(String.format("[V8 8.7] Loading OLD_SPACE: %d chunks", chunks.size()));
				int loadedChunks = 0;
				int failedChunks = 0;
				for (final ReservObject objs : chunks) {
					try {
						loadSpaceObjects(objs);
						loadedChunks++;
					} catch (StackOverflowError soe) {
						failedChunks++;
						if (failedChunks <= 3) {
							System.out.println("[V8 8.7] Chunk load StackOverflow (deep recursion in SFI construction)");
						}
					} catch (Exception chunkEx) {
						failedChunks++;
						if (failedChunks <= 3) {
							System.out.println("[V8 8.7] Chunk load failed: " + chunkEx.getMessage());
						}
					}
				}
				snapshotParsed = (loadedChunks > 0);
				System.out.println(String.format(
					"[V8 8.7] Snapshot deserialization: %d chunks loaded, %d failed (total objects: %d)",
					loadedChunks, failedChunks, totalObjectCount));
			}
		} catch (StackOverflowError soe) {
			System.out.println("[V8 8.7] Snapshot deserialization hit StackOverflow (deep object graph recursion).");
			System.out.println("[V8 8.7] This is expected for large JSC files. Partial results preserved.");
			snapshotParsed = true; // Preserve partial results
		} catch (Exception e) {
			System.out.println("[V8 8.7] Snapshot deserialization failed: " + e.getMessage());
			System.out.println("[V8 8.7] Stream position at failure: 0x" +
				Long.toHexString(reader.getPointerIndex()));
			e.printStackTrace(System.out);
			System.out.println("[V8 8.7] NOTE: The Dofus Retro client may use modified V8 snapshot");
			System.out.println("[V8 8.7] bytecodes. Full object graph reconstruction requires matching");
			System.out.println("[V8 8.7] the exact bytecode encoding. Falling back to raw payload import.");
		}

		if (!snapshotParsed) {
			// Load the raw payload as a memory block so SLEIGH can disassemble it.
			// Use address 0x30000000 to avoid conflicting with the allocator's
			// pre-created blocks (.text at 0x10000000, .bcods at 0x20000000, etc.).
			monitor.setMessage("Loading raw V8 8.7 payload...");
			reader.setPointerIndex(payloadOffset);
			byte[] payload = reader.readNextByteArray((int) payloadSize);

			final long RAW_PAYLOAD_BASE = 0x30000000L;
			ghidra.program.model.address.Address baseAddr =
				program.getAddressFactory().getDefaultAddressSpace().getAddress(RAW_PAYLOAD_BASE);

			ghidra.program.model.mem.Memory memory = program.getMemory();
			memory.createInitializedBlock(".v8payload", baseAddr, payload.length, (byte) 0, monitor, false);
			memory.setBytes(baseAddr, payload);

			System.out.println(String.format("[V8 8.7] Raw payload loaded: %d bytes at 0x%08X",
				payloadSize, RAW_PAYLOAD_BASE));
		}

		monitor.setMessage("Loading done.");
	}
	
	public void postAllocate() throws MemoryBlockException, LockException, NotFoundException {
		allocator.postAllocate();
	}
	
	public ObjectsAllocator getAllocator() {
		return allocator;
	}
	
	public static int smiToInt(long value, int pointerSize) {
		if (pointerSize == 4) {
			return (int)(value >> 1L);
		}
		
		return (int)(value >> 32L);
	}
	
	/**
	 * Load SharedFunctionInfo objects from an OLD_SPACE chunk.
	 *
	 * V8 8.7 approach: instead of assuming the chunk starts with an SFI and
	 * navigating Script -> shared_function_infos (fragile, fails on 99% of
	 * chunks that contain other object types), we scan all sub-objects in the
	 * chunk and identify SFIs by their map reference.
	 *
	 * A ReservObject is an SFI if its map (slot 0) is a RootObject named
	 * "SharedFunctionInfoMap". For each SFI found, we construct a
	 * SharedFunctionInfoStruct which extracts the BytecodeArray and sets up
	 * Ghidra memory blocks and functions.
	 */
	private void loadSpaceObjects(final ReservObject spaceObjs) throws Exception {
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		final List<Address> doDisasm = new ArrayList<>();
		int sfiFound = 0;
		int sfiAllocated = 0;
		int sfiErrors = 0;

		// Iterate all sub-objects stored in this chunk.
		for (Map.Entry<Long, Object> entry : spaceObjs.getObjectEntries()) {
			Object subObj = entry.getValue();

			// We only care about ReservObject sub-objects (deserialized heap objects).
			if (!(subObj instanceof ReservObject)) {
				continue;
			}

			ReservObject candidate = (ReservObject) subObj;

			// Check if this object's map (at offset 0) is the SharedFunctionInfoMap root.
			Object mapRef;
			try {
				mapRef = candidate.getAlignedObject(0);
			} catch (Exception e) {
				continue; // No map slot -> not an SFI
			}

			if (mapRef == null) {
				continue;
			}

			boolean isSfiMap = false;
			if (mapRef instanceof RootObject) {
				String mapName = ((RootObject) mapRef).getName();
				if (mapName != null && mapName.contains("SharedFunctionInfo")) {
					isSfiMap = true;
				}
			}

			if (!isSfiMap) {
				continue;
			}

			sfiFound++;

			// Validate that the SFI has enough populated fields.
			// A fully-deserialized V8 8.7 SFI (32-bit, kPointerSize=4) has:
			//   5 tagged pointer fields (offsets 0x00-0x10) + scalar fields (0x14-0x24)
			//   = at least 10 entries in the object map.
			// Partially deserialized SFIs (e.g., from cleared weak references)
			// may have only 2-3 entries and cannot be parsed.
			int entryCount = candidate.getObjectEntries().size();
			// kFunctionLiteralIdOffset for kPointerSize=4 is 0x20 = 32.
			// We need at least that offset populated. Require minimum 8 entries
			// (5 pointer fields + 3 scalar int32 words covering offsets up to 0x20).
			int kMinSfiEntries = 8;
			if (entryCount < kMinSfiEntries) {
				continue; // Incomplete SFI (weak ref or partially deserialized), skip
			}

			// Extra validation: check that function_data (offset kPointerSize) is
			// a ReservObject (BytecodeArray). If not, this SFI has no bytecode.
			Object funcData;
			try {
				funcData = candidate.getAlignedObject(kPointerSize);
			} catch (Exception e) {
				continue;
			}
			if (!(funcData instanceof ReservObject)) {
				continue; // function_data is not a heap object (builtin or root), skip
			}

			// Try to construct and allocate the SharedFunctionInfoStruct.
			try {
				// Check if this SFI was already created during deserialization
				// (e.g., via constant pool references).
				int funcIndex = SharedFunctionInfoStruct.getFunctionIndex(candidate, kPointerSize);
				SharedFunctionInfoStruct sf = SharedFunctionInfoStruct.getSharedFunctionInfo(allocator, funcIndex);

				if (sf == null) {
					sf = new SharedFunctionInfoStruct(candidate, allocator);
					Address sfiAddr = sf.allocate(allocator, monitor);
					mgr.addDataType(sf.toDataType(), DataTypeConflictHandler.DEFAULT_HANDLER);
				}

				sfiAllocated++;

				final Address bcodeAddr = sf.getAddress();
				if (bcodeAddr != null) {
					doDisasm.add(bcodeAddr);
				}

				// Handler table addresses for disassembly entry points
				final HandlerTableStruct ht = sf.getHandlerTable();
				if (ht != null && bcodeAddr != null) {
					final List<HandlerTableItemStruct> htItems = ht.getItems();
					for (int j = 0; j < htItems.size(); ++j) {
						final HandlerTableItemStruct hti = htItems.get(j);

						doDisasm.add(bcodeAddr.add(hti.getOffset()));
						doDisasm.add(bcodeAddr.add(hti.getStartAddress()));
						doDisasm.add(bcodeAddr.add(hti.getEndAddress()));

						fpa.setPreComment(bcodeAddr.add(hti.getStartAddress()),
							String.format("try { // %s_handler_%d start", sf.getName(), j));
						fpa.setPreComment(bcodeAddr.add(hti.getEndAddress()),
							String.format("} // %s_handler_%d end", sf.getName(), j));

						fpa.createLabel(bcodeAddr.add(hti.getOffset()),
							String.format("%s_handler_%d", sf.getName(), j), true,
							SourceType.USER_DEFINED);
					}
				}

				allocator.getMonitor().incrementProgress(1);
			} catch (StackOverflowError soe) {
				sfiErrors++;
				if (sfiErrors <= 3) {
					System.out.println(String.format(
						"[V8 8.7] SFI StackOverflow at chunk offset 0x%X (deep recursion)",
						entry.getKey()));
				}
			} catch (Exception e) {
				sfiErrors++;
				if (sfiErrors <= 5) {
					System.out.println(String.format(
						"[V8 8.7] SFI construction error at chunk offset 0x%X: %s",
						entry.getKey(), e.getMessage()));
				}
			}
		}

		if (sfiFound > 0) {
			System.out.println(String.format(
				"[V8 8.7] Chunk: found %d SFIs, allocated %d, errors %d",
				sfiFound, sfiAllocated, sfiErrors));
		}

		// Disassemble all collected bytecode addresses.
		for (final Address dis : doDisasm) {
			if (dis != null) {
				ObjectsAllocator.disassemble(program, monitor, dis);
			}
		}
	}
	
	private RootsStore loadRoots() {
		try {
			File file = Application.getModuleDataFile("v8_roots.json").getFile(false);
			final JsonArray rootsData = jsonArrayFromFile(file.getAbsolutePath());

			for (final var item : rootsData) {
				final JsonObject obj = item.getAsJsonObject();
				final String name = obj.get("Name").getAsString();
				final String type = obj.get("Type").getAsString();

				roots.add(new RootObject(name, type));
			}

			return new RootsStore(roots);
		} catch (IOException e) {
			e.printStackTrace();
			log.appendException(e);
			return null;
		}
		
	}
	
	public static JsonArray jsonArrayFromFile(final String file) throws IOException {
		if (file == null) {
			return null;
		}
		
		final byte[] bytes = Files.readAllBytes(Path.of(file));
		final String json = new String(bytes, "UTF8");
		
		final JsonElement tokens = JsonParser.parseString(json);
		return tokens.getAsJsonArray();
	}

	private BuiltinsEnum loadBuiltins() {
		try {
			File file = Application.getModuleDataFile("v8_builtins.json").getFile(false);
			final JsonArray rootsData = jsonArrayFromFile(file.getAbsolutePath());

			for (final var item : rootsData) {
				builtins.add(item.getAsString());
			}

			BuiltinsEnum result = new BuiltinsEnum(builtins);
			mgr.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER);
			return result;
		} catch (IOException e) {
			e.printStackTrace();
			log.appendException(e);
			return null;
		}
	}
	
	private JsRuntimesEnum loadJsRuntimes() {
		try {
			File file = Application.getModuleDataFile("v8_jsruns.json").getFile(false);
			final JsonArray jsRuns = jsonArrayFromFile(file.getAbsolutePath());
			
			final List<String> items = new ArrayList<>();
			
			for (final var item : jsRuns) {
				final JsonObject obj = item.getAsJsonObject();
				
				items.add(obj.get("Name").getAsString());
			}
			
			JsRuntimesEnum result = new JsRuntimesEnum(items);
			mgr.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER);
			return result;
		} catch (IOException e) {
			e.printStackTrace();
			log.appendException(e);
			return null;
		}
	}
	
	private RuntimesIntrinsicsStore loadIntrsAndRuntimes() {
		try {
			File file = Application.getModuleDataFile("v8_funcs.json").getFile(false);
			final JsonArray runsAndIntrs = jsonArrayFromFile(file.getAbsolutePath());
			
			final List<String> names = new ArrayList<>();
			final List<List<RuntimeFuncArg>> allArgs = new ArrayList<>();
			
			for (final var func : runsAndIntrs) {
				final JsonObject nameAndArgs = func.getAsJsonObject();

				String funcName = nameAndArgs.get("Name").getAsString();
				// Strip leading '%' (original format) or 'k' prefix (V8 8.7 enum names)
				if (funcName.startsWith("%")) {
					funcName = funcName.substring(1);
				} else if (funcName.startsWith("k")) {
					funcName = funcName.substring(1);
				}

				List<RuntimeFuncArg> funcArgs = new ArrayList<>();

				JsonElement argsElem = nameAndArgs.get("Args");
				if (argsElem != null && argsElem.isJsonArray()) {
					JsonArray args = argsElem.getAsJsonArray();
					for (final var arg : args) {
						final JsonObject argObj = arg.getAsJsonObject();
						String name = argObj.get("Name").getAsString();

						String type = null;
						if (!name.equals("...")) {
							JsonElement typeElem = argObj.get("Type");
							type = typeElem != null ? typeElem.getAsString() : "Object";
						}

						funcArgs.add(new RuntimeFuncArg(name, type));
					}
				}
				
				names.add(funcName);
				allArgs.add(funcArgs);
			}
			
			return new RuntimesIntrinsicsStore(names, allArgs);
		} catch (IOException e) {
			e.printStackTrace();
			log.appendException(e);
			return null;
		}
	}
	
	/**
	 * Deserialize deferred objects from the snapshot stream.
	 *
	 * V8 8.7 DeserializeDeferredObjects() from src/snapshot/deserializer.cc:
	 *
	 *   for (int code = source_.Get(); code != kSynchronize; code = source_.Get()) {
	 *     switch (code) {
	 *       case kAlignmentPrefix: case kAlignmentPrefix+1: case kAlignmentPrefix+2:
	 *         SetAlignment(code);
	 *         break;
	 *       default:
	 *         int space = NewObject::Decode(code);  // code IS a kNewObject byte (0x00-0x04)
	 *         ReadObject(space);  // reads size, map, allocates, then calls ReadData
	 *     }
	 *   }
	 *
	 * Bytecodes at top level:
	 *   0x00-0x04: kNewObject (space = byte)
	 *   0x16-0x18: kAlignmentPrefix
	 *   0x19:      kSynchronize (end marker)
	 */
	private void deserializeDeferredObjects() throws IOException {
		int objectCount = 0;
		while (true) {
			int b = reader.readNextByte() & 0xFF;

			// kAlignmentPrefix (0x16-0x18)
			if (b >= 0x16 && b <= 0x18) {
				nextAlignment = AllocationAlignment.fromInt(b - 0x16 + 1);
				continue;
			}

			// kSynchronize (0x19) -- end of deferred objects section
			if (b == 0x19) {
				System.out.println(String.format(
					"[V8 8.7] Deferred objects deserialized: %d objects", objectCount));
				return;
			}

			// Must be a kNewObject bytecode (0x00-0x04) identifying the target space.
			if (b > 0x04) {
				// Dump surrounding bytes for diagnosis
				long failPos = reader.getPointerIndex() - 1;
				StringBuilder hexCtx = new StringBuilder();
				long dumpStart = Math.max(0, failPos - 8);
				long savedPos = reader.getPointerIndex();
				reader.setPointerIndex(dumpStart);
				for (int i = 0; i < 24 && reader.getPointerIndex() < reader.length(); i++) {
					if (reader.getPointerIndex() == failPos) hexCtx.append("[");
					hexCtx.append(String.format("%02X", reader.readNextByte() & 0xFF));
					if (reader.getPointerIndex() == failPos + 1) hexCtx.append("]");
					hexCtx.append(" ");
				}
				reader.setPointerIndex(savedPos);

				throw new IOException(String.format(
					"[V8 8.7] Unexpected deferred bytecode: 0x%02X at offset 0x%X " +
					"(expected kNewObject 0x00-0x04, kAlignmentPrefix 0x16-0x18, or kSynchronize 0x19). " +
					"Deserialized %d deferred objects before failure. Context: %s",
					b, failPos, objectCount, hexCtx.toString().trim()));
			}

			int spaceId = b;
			AllocSpace space = AllocSpace.fromInt(spaceId);

			readObjectFromStream(space);
			objectCount++;
		}
	}

	/**
	 * Read serialized object data from the V8 8.7 snapshot stream.
	 *
	 * V8 8.7 bytecode table (serializer-deserializer.h):
	 *   0x00-0x04: kNewObject (5 spaces: RO=0, OLD=1, CODE=2, MAP=3, LO=4)
	 *   0x08-0x0C: kBackref (same 5 spaces; reads TWO GetInts: chunk_index + chunk_offset,
	 *              except MAP space = single GetInt for map_idx, LO space = single GetInt for large_idx)
	 *   0x10:      kStartupObjectCache    0x11: kRootArray
	 *   0x12:      kAttachedReference     0x13: kReadOnlyObjectCache
	 *   0x14:      kNop                   0x15: kNextChunk
	 *   0x16-0x18: kAlignmentPrefix       0x19: kSynchronize
	 *   0x1A:      kVariableRepeat        0x1B: kOffHeapBackingStore
	 *   0x1C:      kEmbedderFieldsData    0x1D: kVariableRawCode
	 *   0x1E:      kVariableRawData       0x1F: kApiReference
	 *   0x20:      kExternalReference     0x23: kInternalReference
	 *   0x24:      kClearedWeakReference  0x25: kWeakPrefix
	 *   0x26:      kOffHeapTarget         0x27: kRegisterPendingForwardRef
	 *   0x28:      kResolvePendingForwardRef  0x29: kNewMetaMap
	 *   0x40-0x5F: kRootArrayConstants (32 entries, root_index = byte - 0x40)
	 *   0x60-0x7F: kFixedRawData (32 entries, count = (byte - 0x60) + 1 tagged slots)
	 *   0x80-0x8F: kFixedRepeat (16 entries, count = (byte - 0x80) + 2 repeats)
	 *   0x90-0x97: kHotObject (8 entries, slot = byte - 0x90)
	 *
	 * ReadData fills (size) bytes starting at startInsert.
	 * Note: the MAP slot (offset 0) is read BEFORE ReadData by readObjectFromStream,
	 * so ReadData starts at kPointerSize.
	 */
	private void readData(ReservObject object, long size, AllocSpace space, long startInsert) throws IOException {
		long insertOff = startInsert;

		while (insertOff < size) {
			int b = reader.readNextByte() & 0xFF;

			// ── kNewObject 0x00-0x04 ──────────────────────────────────
			if (b >= 0x00 && b <= 0x04) {
				int spaceId = b;
				AllocSpace targetSpace = AllocSpace.fromInt(spaceId);
				readObject(object, insertOff, targetSpace);
				insertOff += kPointerSize;
			}
			// ── kBackref 0x08-0x0C ────────────────────────────────────
			else if (b >= 0x08 && b <= 0x0C) {
				int spaceId = b - 0x08;
				AllocSpace targetSpace = AllocSpace.fromInt(spaceId);
				final Object backObj = getBackReferencedObject(targetSpace, spaceId);
				object.addObject(insertOff, backObj);
				hots.put(lastHotIndex, backObj);
				lastHotIndex = (lastHotIndex + 1) & 7;
				insertOff += kPointerSize;
			}
			// ── kStartupObjectCache 0x10 ──────────────────────────────
			else if (b == 0x10) {
				long index = readInt();
				object.addObject(insertOff, new RootObject("startup_cache_" + index, "object"));
				insertOff += kPointerSize;
			}
			// ── kRootArray 0x11 ───────────────────────────────────────
			else if (b == 0x11) {
				long id = readInt();
				if (id >= 0 && id < roots.size()) {
					final RootObject rootObj = roots.get((int) id);
					hots.put(lastHotIndex, rootObj);
					lastHotIndex = (lastHotIndex + 1) & 7;
					object.addObject(insertOff, rootObj);
				}
				insertOff += kPointerSize;
			}
			// ── kAttachedReference 0x12 ───────────────────────────────
			else if (b == 0x12) {
				long index = readInt();
				if (index >= 0 && index < attached.size()) {
					object.addObject(insertOff, attached.get((int) index));
				}
				insertOff += kPointerSize;
			}
			// ── kReadOnlyObjectCache 0x13 ─────────────────────────────
			else if (b == 0x13) {
				long index = readInt();
				object.addObject(insertOff, new RootObject("readonly_cache_" + index, "object"));
				insertOff += kPointerSize;
			}
			// ── kNop 0x14 ─────────────────────────────────────────────
			else if (b == 0x14) {
				// No-op: no insert advance, no stream read
			}
			// ── kNextChunk 0x15 ───────────────────────────────────────
			else if (b == 0x15) {
				// Advance to next chunk in the given space
				int chunkSpace = reader.readNextByte() & 0xFF;
				AllocSpace chunkAllocSpace = AllocSpace.fromInt(chunkSpace);
				if (chunkAllocSpace != null) {
					int newChunkIdx = lastChunkIndex.getOrDefault(chunkAllocSpace, 0) + 1;
					lastChunkIndex.put(chunkAllocSpace, newChunkIdx);
					List<ReservObject> chunks = reserv.get(chunkAllocSpace);
					if (chunks != null && newChunkIdx < chunks.size()) {
						chunks.get(newChunkIdx).setOffset(0);
					}
				}
				// No insert advance
			}
			// ── kAlignmentPrefix 0x16-0x18 ────────────────────────────
			else if (b >= 0x16 && b <= 0x18) {
				nextAlignment = AllocationAlignment.fromInt(b - 0x16 + 1);
				// No insert advance
			}
			// ── kSynchronize 0x19 ─────────────────────────────────────
			else if (b == 0x19) {
				// Push back so the caller can see it
				reader.setPointerIndex(reader.getPointerIndex() - 1);
				return;
			}
			// ── kVariableRepeat 0x1A ──────────────────────────────────
			else if (b == 0x1A) {
				int count = (int) readInt();
				final Object lastObj = object.getLastObject();
				insertOff = repeatObject(object, insertOff, lastObj, count);
			}
			// ── kOffHeapBackingStore 0x1B ─────────────────────────────
			else if (b == 0x1B) {
				// Off-heap backing store reference; fills one tagged slot
				insertOff += kPointerSize;
			}
			// ── kEmbedderFieldsData 0x1C ──────────────────────────────
			else if (b == 0x1C) {
				long dataLen = readInt();
				byte[] rawData = reader.readNextByteArray((int) dataLen);
				object.addObject(insertOff, rawData);
				insertOff += dataLen;
			}
			// ── kVariableRawCode 0x1D ─────────────────────────────────
			else if (b == 0x1D) {
				long dataLen = readInt();
				byte[] rawData = reader.readNextByteArray((int) dataLen);
				object.addObject(insertOff, rawData);
				insertOff += dataLen;
			}
			// ── kVariableRawData 0x1E ─────────────────────────────────
			else if (b == 0x1E) {
				long dataLen = readInt();
				byte[] rawData = reader.readNextByteArray((int) dataLen);
				object.addObject(insertOff, rawData);
				insertOff += dataLen;
			}
			// ── kApiReference 0x1F ────────────────────────────────────
			else if (b == 0x1F) {
				long idx = readInt();
				object.addObject(insertOff, new RootObject("api_ref_" + idx, "object"));
				insertOff += kPointerSize;
			}
			// ── kExternalReference 0x20 ───────────────────────────────
			else if (b == 0x20) {
				long idx = readInt();
				object.addObject(insertOff, new RootObject("external_ref_" + idx, "object"));
				insertOff += kPointerSize;
			}
			// ── kInternalReference 0x23 ───────────────────────────────
			else if (b == 0x23) {
				byte[] raw = reader.readNextByteArray(kPointerSize);
				object.addObject(insertOff, raw);
				insertOff += kPointerSize;
			}
			// ── kClearedWeakReference 0x24 ────────────────────────────
			else if (b == 0x24) {
				// Cleared weak ref: fills one tagged slot with a cleared value
				insertOff += kPointerSize;
			}
			// ── kWeakPrefix 0x25 ──────────────────────────────────────
			else if (b == 0x25) {
				// Weak prefix: marks next bytecode as weak. No insert advance.
			}
			// ── kOffHeapTarget 0x26 ───────────────────────────────────
			else if (b == 0x26) {
				long idx = readInt();
				object.addObject(insertOff, new RootObject("offheap_target_" + idx, "object"));
				insertOff += kPointerSize;
			}
			// ── kRegisterPendingForwardRef 0x27 ───────────────────────
			else if (b == 0x27) {
				// Register a pending forward reference: saves the current slot for
				// later resolution by kResolvePendingForwardRef. Does NOT advance
				// the current slot (V8 src/snapshot/deserializer.cc).
				// No insertOff advance.
			}
			// ── kResolvePendingForwardRef 0x28 ────────────────────────
			else if (b == 0x28) {
				long ref = readInt();
				// Resolves a previously registered forward reference by writing the
				// last deserialized object to the saved slot. Does NOT advance the
				// current slot (V8 src/snapshot/deserializer.cc).
				// No insertOff advance.
			}
			// ── kNewMetaMap 0x29 ──────────────────────────────────────
			else if (b == 0x29) {
				// New meta map: fills one tagged slot
				insertOff += kPointerSize;
			}
			// ── kRootArrayConstants 0x40-0x5F ─────────────────────────
			else if (b >= 0x40 && b <= 0x5F) {
				int rootIndex = b - 0x40;
				if (rootIndex < roots.size()) {
					final RootObject rootObj = roots.get(rootIndex);
					hots.put(lastHotIndex, rootObj);
					lastHotIndex = (lastHotIndex + 1) & 7;
					object.addObject(insertOff, rootObj);
				}
				insertOff += kPointerSize;
			}
			// ── kFixedRawData 0x60-0x7F ───────────────────────────────
			else if (b >= 0x60 && b <= 0x7F) {
				int count = (b - 0x60) + 1;  // tagged slots
				int sizeInBytes = count * kPointerSize;
				if (sizeInBytes > 0) {
					object.addObject(insertOff, reader.readNextByteArray(sizeInBytes));
				}
				insertOff += sizeInBytes;
			}
			// ── kFixedRepeat 0x80-0x8F ────────────────────────────────
			else if (b >= 0x80 && b <= 0x8F) {
				int count = (b - 0x80) + 2;  // repeats
				final Object lastObj = object.getLastObject();
				insertOff = repeatObject(object, insertOff, lastObj, count);
			}
			// ── kHotObject 0x90-0x97 ──────────────────────────────────
			else if (b >= 0x90 && b <= 0x97) {
				long hotIndex = (long)(b - 0x90);
				Object hotObj = hots.get(hotIndex);
				if (hotObj != null) {
					object.addObject(insertOff, hotObj);
				}
				insertOff += kPointerSize;
			}
			// ── UNKNOWN ───────────────────────────────────────────────
			else {
				long failPos = reader.getPointerIndex() - 1;
				StringBuilder hexCtx = new StringBuilder();
				long dumpStart = Math.max(0, failPos - 8);
				long savedPos = reader.getPointerIndex();
				reader.setPointerIndex(dumpStart);
				for (int i = 0; i < 24 && reader.getPointerIndex() < reader.length(); i++) {
					if (reader.getPointerIndex() == failPos) hexCtx.append("[");
					hexCtx.append(String.format("%02X", reader.readNextByte() & 0xFF));
					if (reader.getPointerIndex() == failPos + 1) hexCtx.append("]");
					hexCtx.append(" ");
				}
				reader.setPointerIndex(savedPos);

				throw new IOException(String.format(
					"[V8 8.7] Unknown snapshot bytecode: 0x%02X at offset 0x%X (insertOff=%d, size=%d). Context: %s",
					b, failPos, insertOff, size, hexCtx.toString().trim()));
			}
		}
	}

	private long repeatObject(final ReservObject insert, long insertOff, final Object lastObj, int count) {
		for (int i = 0; i < count; ++i) {
			insert.addObject(insertOff, lastObj);
			insertOff += kPointerSize;
		}

		return insertOff;
	}

	/**
	 * Get a back-referenced object from a previously deserialized space.
	 *
	 * V8 8.7 back-reference encoding uses TWO separate GetInt calls for most spaces:
	 *   GetInt() -> chunk_index
	 *   GetInt() -> chunk_offset
	 *
	 * Exceptions:
	 *   - MAP_SPACE (spaceId=3): single GetInt -> map_index (sequential allocation)
	 *   - NEW_SPACE/LO (spaceId=4): single GetInt -> large_object_index
	 *
	 * @param space the allocation space enum
	 * @param spaceId the raw space ID (0-4) for determining encoding
	 */
	private Object getBackReferencedObject(AllocSpace space, int spaceId) throws IOException {
		long chunkIndex;
		long chunkOffset;

		if (spaceId == 4) {
			// kLargeObject (NEW_SPACE/LO): single GetInt = large_object_index
			long largeIdx = readInt();
			chunkIndex = 0;
			chunkOffset = largeIdx;  // Index into large object list; treat as offset
			// For large objects, the backref is an index. We look up in the space's
			// reservation list. Each large object is its own "chunk" effectively.
			List<ReservObject> spaceChunks = reserv.get(space);
			if (spaceChunks == null || (int)largeIdx >= spaceChunks.size()) {
				// Try treating as offset in chunk 0
				if (spaceChunks != null && spaceChunks.size() > 0) {
					ReservObject reservObj = spaceChunks.get(0);
					Object backObj = reservObj.getAlignedObject(largeIdx * kPointerSize);
					return backObj != null ? backObj : new RootObject("lo_backref_" + largeIdx, "object");
				}
				return new RootObject("lo_backref_" + largeIdx, "object");
			}
			ReservObject reservObj = spaceChunks.get((int) largeIdx);
			Object backObj = reservObj.getAlignedObject(0);
			return backObj != null ? backObj : reservObj;
		}

		if (spaceId == 3) {
			// MAP_SPACE: single GetInt = map_index (maps are sequentially allocated)
			long mapIdx = readInt();
			List<ReservObject> spaceChunks = reserv.get(space);
			if (spaceChunks == null || spaceChunks.isEmpty()) {
				return new RootObject("map_backref_" + mapIdx, "Map");
			}
			// Maps are allocated sequentially. map_index * kPointerSize gives the offset
			// within the first chunk, or we iterate across chunks.
			long offset = mapIdx * kPointerSize;
			for (ReservObject chunk : spaceChunks) {
				if (offset < chunk.getSize()) {
					Object backObj = chunk.getAlignedObject(offset);
					return backObj != null ? backObj : new RootObject("map_backref_" + mapIdx, "Map");
				}
				offset -= chunk.getSize();
			}
			return new RootObject("map_backref_" + mapIdx, "Map");
		}

		// Default: TWO GetInt calls = chunk_index + chunk_offset
		chunkIndex = readInt();
		chunkOffset = readInt();

		List<ReservObject> spaceChunks = reserv.get(space);
		if (spaceChunks == null || (int)chunkIndex >= spaceChunks.size()) {
			throw new IOException(String.format(
				"[V8 8.7] Back-reference out of bounds: space=%s, chunk=%d/%d, offset=0x%X",
				space, chunkIndex, spaceChunks != null ? spaceChunks.size() : 0, chunkOffset));
		}

		ReservObject reservObj = spaceChunks.get((int) chunkIndex);
		Object backObj = reservObj.getAlignedObject(chunkOffset);

		return backObj;
	}
	
	private int getMaximumFillToAlign() throws IOException {
		switch (nextAlignment) {
		case kWordAligned:
			return 0;
		case kDoubleAligned:
		case kDoubleUnaligned:
			return 8 - kPointerSize; // kDoubleSize - kPointerSize
		default:
			throw new IOException("Wrong alignment");
		}
	}
	
	private int getFillToAlign(long address) {
		if (nextAlignment.equals(AllocationAlignment.kDoubleAligned) && (address & 7L) != 0) { // kDoubleAlignmentMask
			return kPointerSize;  // kPointerSize
		}
		
		if (nextAlignment.equals(AllocationAlignment.kDoubleUnaligned) && (address & 7L) != 0) { // kDoubleAlignmentMask
			return 8 - kPointerSize; // kDoubleSize - kPointerSize
		}
		
		return 0;
	}
	
	private void createFillerObject(final ReservObject object, long address, int size) {
		if (size == 0) {
			object.addObject(address, null);
		}
		else if (size == kPointerSize) {  // kPointerSize
			object.addObject(address, roots.get(1)); // OnePointerFiller
		}
		else if (size == 2 * kPointerSize) { // 2 * kPointerSize
			object.addObject(address, roots.get(2)); // TwoPointerFiller
		}
		else {
			object.addObject(address, roots.get(0)); // FreeSpace
		}
	}
	
	private long precedeWithFiller(final ReservObject object, long address, int size) {
		createFillerObject(object, address, size);
		return address + size;
	}
	
	private void alignWithFiller(final ReservObject object, long address, long objectSize, int fillerSize) {
		int preFiller = getFillToAlign(address);
		
		if (preFiller != 0) {
			address = precedeWithFiller(object, address, preFiller);
			fillerSize -= preFiller;
		}
		
		if (fillerSize != 0) {
			createFillerObject(object, address + objectSize, fillerSize);
		}
	}

	/**
	 * Allocate an object within a space chunk, handling alignment and chunk advancement.
	 *
	 * In V8 8.7, each space has one or more reservation chunks. When a chunk is full
	 * (offset + size > chunk.getSize()), the allocator advances to the next chunk.
	 *
	 * @param space the allocation space
	 * @param size  the object size in bytes
	 * @return the newly created ReservObject, already placed in the chunk
	 */
	private ReservObject allocateInSpace(AllocSpace space, long size) throws IOException {
		int spaceChunk = lastChunkIndex.get(space);
		List<ReservObject> chunks = reserv.get(space);

		if (chunks == null || spaceChunk >= chunks.size()) {
			throw new IOException(String.format(
				"[V8 8.7] No chunks available for space %s (chunk=%d)", space, spaceChunk));
		}

		// Handle alignment
		if (!nextAlignment.equals(AllocationAlignment.kWordAligned)) {
			final ReservObject reservObject = chunks.get(spaceChunk);
			long address = reservObject.getOffset();
			int filler = getMaximumFillToAlign();
			alignWithFiller(reservObject, address, size, filler);
			reservObject.setOffset(address + filler);
			nextAlignment = AllocationAlignment.kWordAligned;
		}

		ReservObject reservObj = chunks.get(spaceChunk);

		// Check if we need to advance to the next chunk.
		// In V8, each reservation entry has a size. When the current offset plus the
		// object size exceeds the chunk capacity, we move to the next chunk.
		if (reservObj.getOffset() + size > reservObj.getSize() && spaceChunk + 1 < chunks.size()) {
			spaceChunk++;
			lastChunkIndex.put(space, spaceChunk);
			reservObj = chunks.get(spaceChunk);
			reservObj.setOffset(0);
		}

		long address = reservObj.getOffset();
		reservObj.setOffset(address + size);

		ReservObject newObj = new ReservObject(size, kPointerSize);
		reservObj.addObject(address, newObj);

		return newObj;
	}

	/**
	 * Read an object from the snapshot stream (top-level entry point).
	 *
	 * V8 8.7 ReadObject(space):
	 *   1. Read size from stream: GetInt() << kObjectAlignmentBits
	 *   2. Read the MAP as ONE bytecode (kRootArrayConstants, kHotObject, kBackref,
	 *      kNewObject for recursive map, kRootArray, kReadOnlyObjectCache, etc.)
	 *   3. Handle optional kAlignmentPrefix / kNextChunk before allocation
	 *   4. Bump-allocate `size` bytes within the current chunk for `space`
	 *   5. Store map at slot 0
	 *   6. Call ReadData for (size - kPointerSize) bytes starting at offset kPointerSize
	 *   7. Return the deserialized object
	 *
	 * This is called from parse() for the root object and from
	 * deserializeDeferredObjects() for each deferred object.
	 */
	private ReservObject readObjectFromStream(AllocSpace space) throws IOException {
		totalObjectCount++;
		long sizeInTagged = readInt();
		long size = sizeInTagged << kObjectAlignmentBits;

		// Read the MAP as one bytecode BEFORE allocating / ReadData
		Object mapRef = readMapReference();

		// Handle optional alignment prefix / next chunk BEFORE allocation
		consumePreAllocationBytecodes();

		ReservObject newObj = allocateInSpace(space, size);

		// Store map at slot 0
		if (mapRef != null) {
			newObj.addObject(0, mapRef);
		}

		// ReadData fills slots from offset kPointerSize (after map) to end of object.
		// Pass the FULL object size as the limit; startInsert = kPointerSize.
		if (size > kPointerSize) {
			readData(newObj, size, space, kPointerSize);
		}

		// Track in hot objects
		hots.put(lastHotIndex, newObj);
		lastHotIndex = (lastHotIndex + 1) & 7;

		if (totalObjectCount == 1 || totalObjectCount % 50000 == 0) {
			System.out.println(String.format(
				"[V8 8.7] Object #%d: space=%s size=%d at stream 0x%X",
				totalObjectCount, space, size, reader.getPointerIndex()));
		}

		return newObj;
	}

	/**
	 * Read a new object encountered inside readData (kNewObject bytecode).
	 *
	 * Same as readObjectFromStream but also stores the reference in the parent object.
	 */
	private void readObject(final ReservObject object, long insertOff, AllocSpace space) throws IOException {
		totalObjectCount++;
		long sizeInTagged = readInt();
		long size = sizeInTagged << kObjectAlignmentBits;

		// Read the MAP as one bytecode BEFORE allocating / ReadData
		Object mapRef = readMapReference();

		// Handle optional alignment prefix / next chunk BEFORE allocation
		consumePreAllocationBytecodes();

		ReservObject newObj = allocateInSpace(space, size);

		// Store map at slot 0
		if (mapRef != null) {
			newObj.addObject(0, mapRef);
		}

		// ReadData fills slots from offset kPointerSize (after map) to end of object.
		if (size > kPointerSize) {
			readData(newObj, size, space, kPointerSize);
		}

		// Track in hot objects
		hots.put(lastHotIndex, newObj);
		lastHotIndex = (lastHotIndex + 1) & 7;

		object.addObject(insertOff, newObj);
	}

	/**
	 * Read the MAP reference for an object being deserialized.
	 *
	 * The map is read as ONE bytecode. It can be:
	 *   - kRootArrayConstants (0x40-0x5F): direct root reference
	 *   - kHotObject (0x90-0x97): hot object slot
	 *   - kBackref (0x08-0x0C): back-reference to previously deserialized map
	 *   - kNewObject (0x00-0x04): recursively read a new map object
	 *   - kRootArray (0x11): root by index
	 *   - kReadOnlyObjectCache (0x13): read-only cache entry
	 *   - kStartupObjectCache (0x10): startup cache entry
	 *   - kNewMetaMap (0x29): new meta map
	 *   - kResolvePendingForwardRef (0x28): resolve forward ref
	 *   - kRegisterPendingForwardRef (0x27): register forward ref
	 */
	private Object readMapReference() throws IOException {
		int mapByte = reader.readNextByte() & 0xFF;

		// kRootArrayConstants 0x40-0x5F
		if (mapByte >= 0x40 && mapByte <= 0x5F) {
			int rootIndex = mapByte - 0x40;
			if (rootIndex < roots.size()) {
				RootObject rootObj = roots.get(rootIndex);
				hots.put(lastHotIndex, rootObj);
				lastHotIndex = (lastHotIndex + 1) & 7;
				return rootObj;
			}
			return null;
		}
		// kHotObject 0x90-0x97
		if (mapByte >= 0x90 && mapByte <= 0x97) {
			long hotIndex = (long)(mapByte - 0x90);
			return hots.get(hotIndex);
		}
		// kBackref 0x08-0x0C
		if (mapByte >= 0x08 && mapByte <= 0x0C) {
			int spaceId = mapByte - 0x08;
			AllocSpace targetSpace = AllocSpace.fromInt(spaceId);
			Object backObj = getBackReferencedObject(targetSpace, spaceId);
			hots.put(lastHotIndex, backObj);
			lastHotIndex = (lastHotIndex + 1) & 7;
			return backObj;
		}
		// kNewObject 0x00-0x04 (recursive map object)
		if (mapByte >= 0x00 && mapByte <= 0x04) {
			int spaceId = mapByte;
			AllocSpace targetSpace = AllocSpace.fromInt(spaceId);
			return readObjectFromStream(targetSpace);
		}
		// kRootArray 0x11
		if (mapByte == 0x11) {
			long idx = readInt();
			if (idx >= 0 && idx < roots.size()) {
				RootObject rootObj = roots.get((int) idx);
				hots.put(lastHotIndex, rootObj);
				lastHotIndex = (lastHotIndex + 1) & 7;
				return rootObj;
			}
			return null;
		}
		// kReadOnlyObjectCache 0x13
		if (mapByte == 0x13) {
			long idx = readInt();
			return new RootObject("readonly_cache_" + idx, "object");
		}
		// kStartupObjectCache 0x10
		if (mapByte == 0x10) {
			long idx = readInt();
			return new RootObject("startup_cache_" + idx, "object");
		}
		// kNewMetaMap 0x29
		if (mapByte == 0x29) {
			return new RootObject("meta_map", "Map");
		}
		// kResolvePendingForwardRef 0x28
		if (mapByte == 0x28) {
			long ref = readInt();
			return new RootObject("fwd_ref_" + ref, "object");
		}
		// kRegisterPendingForwardRef 0x27
		if (mapByte == 0x27) {
			return new RootObject("pending_fwd_ref", "object");
		}

		throw new IOException(String.format(
			"[V8 8.7] Unexpected map byte: 0x%02X at offset 0x%X",
			mapByte, reader.getPointerIndex() - 1));
	}

	/**
	 * Consume optional kAlignmentPrefix and kNextChunk bytecodes that appear
	 * between the map read and the object allocation.
	 */
	private void consumePreAllocationBytecodes() throws IOException {
		while (true) {
			long savedPos = reader.getPointerIndex();
			if (savedPos >= reader.length()) break;
			int peek = reader.readNextByte() & 0xFF;

			// kAlignmentPrefix 0x16-0x18
			if (peek >= 0x16 && peek <= 0x18) {
				nextAlignment = AllocationAlignment.fromInt(peek - 0x16 + 1);
				continue;
			}
			// kNextChunk 0x15
			if (peek == 0x15) {
				int chunkSpace = reader.readNextByte() & 0xFF;
				AllocSpace chunkAllocSpace = AllocSpace.fromInt(chunkSpace);
				if (chunkAllocSpace != null) {
					int newChunkIdx = lastChunkIndex.getOrDefault(chunkAllocSpace, 0) + 1;
					lastChunkIndex.put(chunkAllocSpace, newChunkIdx);
					List<ReservObject> chunks = reserv.get(chunkAllocSpace);
					if (chunks != null && newChunkIdx < chunks.size()) {
						chunks.get(newChunkIdx).setOffset(0);
					}
				}
				continue;
			}

			// Not alignment or next-chunk: push back and stop
			reader.setPointerIndex(savedPos);
			break;
		}
	}

	private long readInt() throws IOException {
		long answer = reader.readNextUnsignedInt();
		long bytesCount = (answer & 3L) + 1L;

		reader.setPointerIndex(reader.getPointerIndex() - 4L + bytesCount);
		long mask = 0xFFFFFFFFL;
		mask >>= 32L - (bytesCount << 3L);
		answer &= mask;
		answer >>= 2L;
		return answer;
	}

	// NOTE: The V8 6.x helper methods (allSpaces, newSpace, caseStatement, doAllSpaces,
	// doNewSpace, readSpaceData) have been removed. V8 8.7 uses a linear bytecode scheme
	// that is handled directly in readData().
}
