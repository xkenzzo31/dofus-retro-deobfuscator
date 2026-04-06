package v8_bytecode.structs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.ReservObject;
import v8_bytecode.RootObject;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.allocator.SharedFunctionsAllocator;
import v8_bytecode.storage.SharedFunctionStore;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

/**
 * V8 8.7 SharedFunctionInfo struct parser.
 *
 * Layout (from src/objects/shared-function-info.tq, branch-heads/8.7,
 *         kTaggedSize=8, 64-bit, no pointer compression):
 *
 *   SharedFunctionInfo extends HeapObject
 *   HeapObject::kHeaderSize = 8  (map: tagged)
 *
 *   Offset  Size  Field                                          Constant name
 *   0x00    8     map                 (HeapObject base)
 *   0x08    8     function_data (weak Object)                    kFunctionDataOffset
 *   0x10    8     name_or_scope_info  (String|NoSharedNameSentinel|ScopeInfo) kNameOrScopeInfoOffset
 *   0x18    8     outer_scope_info_or_feedback_metadata (HeapObject) kOuterScopeInfoOrFeedbackMetadataOffset
 *   0x20    8     script_or_debug_info (Script|DebugInfo|Undefined) kScriptOrDebugInfoOffset
 *   0x28    2     length              (int16)                    kLengthOffset
 *   0x2A    2     formal_parameter_count (uint16)                kFormalParameterCountOffset
 *   0x2C    2     function_token_offset (int16, raw)             kRawFunctionTokenOffset
 *   0x2E    1     expected_nof_properties (uint8)                kExpectedNofPropertiesOffset
 *   0x2F    1     flags2              (SharedFunctionInfoFlags2, uint8) kFlags2Offset
 *   0x30    4     flags               (SharedFunctionInfoFlags, uint32) kFlagsOffset
 *   0x34    4     function_literal_id (int32)                    kFunctionLiteralIdOffset
 *   0x38        kSize = 56, kAlignedSize = 56
 *
 * MAJOR CHANGES vs V8 6.x:
 *   Removed fields (no longer present):
 *     - kCodeOffset (was Code object; function_data is now at same offset 0x08)
 *     - kScopeInfoOffset (merged into kNameOrScopeInfoOffset)
 *     - kConstructStubOffset
 *     - kInstanceClassNameOffset
 *     - kDebugInfoOffset (merged into kScriptOrDebugInfoOffset)
 *     - kFunctionIdentifierOffset
 *     - kFeedbackMetadataOffset (merged into kOuterScopeInfoOrFeedbackMetadataOffset)
 *     - kPreParsedScopeDataOffset (now in UncompiledData pointed to by function_data)
 *     - kStartPositionAndTypeOffset (now in UncompiledData)
 *     - kEndPositionOffset (now in UncompiledData)
 *     - kCompilerHintsOffset (replaced by kFlagsOffset, same uint32 semantics)
 *
 *   Renamed / merged fields:
 *     - kCodeOffset (0x08, ptr-sized) -> kFunctionDataOffset (0x08, tagged) : same offset, different type
 *     - kNameOffset + kScopeInfoOffset -> kNameOrScopeInfoOffset (0x10)
 *     - kOuterScopeInfoOffset (0x10 in 6.x) -> kOuterScopeInfoOrFeedbackMetadataOffset (0x18)
 *     - kScriptOffset (0x28 in 6.x after 4 removed ptr fields) -> kScriptOrDebugInfoOffset (0x20)
 *     - kFunctionLiteralIdOffset (was 0x68 in 6.x) -> 0x34
 *     - kLengthOffset (was 0x6C int32) -> 0x28 int16
 *     - kFormalParameterCountOffset (was 0x70 int32) -> 0x2A uint16
 *     - kExpectedNofPropertiesOffset (was 0x74 int32) -> 0x2E uint8
 *     - kFunctionTokenPositionOffset (was 0x78 int32) -> 0x2C int16 (raw)
 *     - kCompilerHintsOffset (was 0x80 int32) -> kFlagsOffset (0x30 int32 / uint32)
 *
 * Source: chromium.googlesource.com/v8/v8 branch-heads/8.7
 *   src/objects/shared-function-info.tq  (Torque layout definition)
 *   src/objects/shared-function-info.h   (DEFINE_FIELD_OFFSET_CONSTANTS)
 *   src/objects/shared-function-info-inl.h (field accessors confirming types)
 */
public final class SharedFunctionInfoStruct implements IAllocatable {
	/** Recursion depth guard: prevents StackOverflow when SFIs reference
	 *  each other through constant pools. Max depth of 30 allows nested
	 *  closures while preventing infinite recursion. */
	private static final ThreadLocal<Integer> constructionDepth = ThreadLocal.withInitial(() -> 0);
	private static final int MAX_CONSTRUCTION_DEPTH = 30;

	private Structure s;

	private ScopeInfoStruct scopeInfos;
	private Object outerScopeOrFeedback;
	private BytecodeStruct bytecode;
	private String functionDataBuiltin;
	private Object nameOrScopeInfo;
	private int functionLiteralId;
	private int functionLength;      // int16 field, read as int
	private int formalParameterCount; // uint16 field, read as int
	private int expectedNofProperties; // uint8 field, read as int
	private int rawFunctionTokenOffset; // int16 field, read as int
	private int flags;               // uint32 / SharedFunctionInfoFlags
	private int flags2;              // uint8 / SharedFunctionInfoFlags2

	private String name = "";
	private int size;
	private SharedFunctionsAllocator sfAllocator;

	// --- Public offset constants (V8 8.7) ---

	/** kFunctionDataOffset = HeapObject::kHeaderSize = 8 (0x08).
	 *  Points to BytecodeArray (compiled), UncompiledData (lazy), or a builtin. */
	public long kFunctionDataOffset;

	/** kNameOrScopeInfoOffset = 16 (0x10).
	 *  Contains the function name (String) or ScopeInfo when compiled,
	 *  or NoSharedNameSentinel for anonymous functions. */
	public long kNameOrScopeInfoOffset;

	/** kOuterScopeInfoOrFeedbackMetadataOffset = 24 (0x18).
	 *  Contains FeedbackMetadata when compiled, outer ScopeInfo when uncompiled. */
	public long kOuterScopeInfoOrFeedbackMetadataOffset;

	/** kScriptOrDebugInfoOffset = 32 (0x20).
	 *  Contains the Script object normally, or DebugInfo when debug info is attached. */
	public long kScriptOrDebugInfoOffset;

	/** kLengthOffset = 40 (0x28). int16. Function length (number of parameters for .length). */
	public long kLengthOffset;

	/** kFormalParameterCountOffset = 42 (0x2A). uint16. Declared parameter count. */
	public long kFormalParameterCountOffset;

	/** kRawFunctionTokenOffset = 44 (0x2C). int16. Offset of function token within script. */
	public long kRawFunctionTokenOffset;

	/** kExpectedNofPropertiesOffset = 46 (0x2E). uint8. Expected number of object properties. */
	public long kExpectedNofPropertiesOffset;

	/** kFlags2Offset = 47 (0x2F). uint8. SharedFunctionInfoFlags2 bitfield. */
	public long kFlags2Offset;

	/** kFlagsOffset = 48 (0x30). uint32. SharedFunctionInfoFlags bitfield.
	 *  Replaces kCompilerHintsOffset from V8 6.x. */
	public long kFlagsOffset;

	/** kFunctionLiteralIdOffset = 52 (0x34). int32. */
	public long kFunctionLiteralIdOffset;

	// --- Static helper for JscParser and getScriptOffset ---

	/**
	 * Compute kScriptOrDebugInfoOffset statically.
	 * V8 8.7: HeapObject::kHeaderSize + 3 tagged fields = 8 + 3*8 = 32.
	 */
	public static int getScriptOffset(int pointerSize) {
		// HeapObject base: kMetaMap (0) + map (tagged) = pointerSize
		// Then: function_data(tagged) + name_or_scope_info(tagged) + outer_scope...(tagged)
		//     + script_or_debug_info(tagged)
		// kScriptOrDebugInfoOffset = 1*pointerSize + 3*pointerSize = 4*pointerSize = 32
		return 4 * pointerSize;  // = 32 for 64-bit
	}

	/**
	 * Compute kFunctionLiteralIdOffset statically (used by getFunctionIndex).
	 * V8 8.7: kScriptOrDebugInfoOffset(32) + tagged(8) = 40, then packed int16+uint16+int16+uint8+uint8+uint32 = 10 bytes
	 * kFunctionLiteralIdOffset = 32 + 8 + 2 + 2 + 2 + 1 + 1 + 4 = 52
	 */
	private static int getFunctionLiteralIdOffset(int pointerSize) {
		int base = getScriptOffset(pointerSize);          // 32 = kScriptOrDebugInfoOffset
		// After script_or_debug_info (tagged = pointerSize bytes):
		// length(2) + formal_parameter_count(2) + raw_function_token_offset(2)
		// + expected_nof_properties(1) + flags2(1) + flags(4) = 12 bytes
		// kFunctionLiteralIdOffset = 32 + 8 + 12 = 52
		return base + pointerSize + 12;
	}

	public static int getFunctionIndex(final ReservObject obj, int pointerSize) {
		return obj.getInt(getFunctionLiteralIdOffset(pointerSize));
	}

	public static SharedFunctionInfoStruct getSharedFunctionInfo(final ObjectsAllocator allocator, int funcIndex) {
		return allocator.getCreatedSharedFunc(funcIndex);
	}

	public SharedFunctionInfoStruct(final ReservObject obj, final ObjectsAllocator allocator) throws Exception {
		int depth = constructionDepth.get();
		if (depth >= MAX_CONSTRUCTION_DEPTH) {
			throw new Exception("SFI construction depth limit reached (" + MAX_CONSTRUCTION_DEPTH + ")");
		}
		constructionDepth.set(depth + 1);
		try {
			constructImpl(obj, allocator);
		} finally {
			constructionDepth.set(depth);
		}
	}

	private void constructImpl(final ReservObject obj, final ObjectsAllocator allocator) throws Exception {
		int pointerSize = allocator.getPointerSize();

		// --- Offset initialisation (V8 8.7, pointerSize=8) ---
		kFunctionDataOffset                       = ObjectsAllocator.kMetaMap + pointerSize;       // 8
		kNameOrScopeInfoOffset                    = kFunctionDataOffset + pointerSize;              // 16
		kOuterScopeInfoOrFeedbackMetadataOffset   = kNameOrScopeInfoOffset + pointerSize;           // 24
		kScriptOrDebugInfoOffset                  = kOuterScopeInfoOrFeedbackMetadataOffset + pointerSize; // 32
		// Scalar fields follow (packed, no pointer-size padding):
		kLengthOffset                             = kScriptOrDebugInfoOffset + pointerSize;         // 40
		kFormalParameterCountOffset               = kLengthOffset + 2;                              // 42
		kRawFunctionTokenOffset                   = kFormalParameterCountOffset + 2;                // 44
		kExpectedNofPropertiesOffset              = kRawFunctionTokenOffset + 2;                    // 46
		kFlags2Offset                             = kExpectedNofPropertiesOffset + 1;               // 47
		kFlagsOffset                              = kFlags2Offset + 1;                              // 48
		kFunctionLiteralIdOffset                  = kFlagsOffset + 4;                               // 52
		// --- End offset initialisation ---

		sfAllocator = new SharedFunctionsAllocator(allocator);

		functionLiteralId = obj.getInt(kFunctionLiteralIdOffset);
		allocator.addToCreatedSharedFuncs(functionLiteralId, this);

		allocator.getMonitor().setMessage(String.format("Creating function #%d", functionLiteralId));

		s = new StructureDataType(String.format("SharedFunctionInfo%d", functionLiteralId), 0);

		// --- function_data (V8 8.7: weak Object -> BytecodeArray when compiled) ---
		// In V8 8.7 the field is tagged and may be:
		//   - A BytecodeArray (normal interpreted function)
		//   - An UncompiledData HeapObject (lazy compilation)
		//   - A Smi encoding a Builtin id (built-in functions)
		//   - InterpreterData or other Code objects
		// We treat it the same as the old kFunctionDataOffset: parse as BytecodeArray.
		final Object functionDataObj = obj.getAlignedObject(kFunctionDataOffset);
		if (functionDataObj instanceof ReservObject) {
			bytecode = new BytecodeStruct((ReservObject) functionDataObj, functionLiteralId, allocator);
			functionDataBuiltin = null;
			s.add(new PointerDataType(bytecode.toDataType()), -1, "FunctionData", null);
		} else if (functionDataObj instanceof String) {
			// Builtin reference (Smi encoding)
			functionDataBuiltin = (String) functionDataObj;
			bytecode = null;
			s.add(allocator.getEnumDataTypes().getBuiltins(), -1, "FunctionData", null);
		} else {
			// RootObject or other - fallback
			functionDataBuiltin = null;
			bytecode = null;
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "FunctionData", null);
		}

		// --- name_or_scope_info ---
		// In V8 8.7: when compiled, this field holds either:
		//   - The function name (String)
		//   - NoSharedNameSentinel (a special root for anonymous functions)
		//   - ScopeInfo directly (for some cases)
		// We read ScopeInfo from here; if it's a String, it's the function name.
		nameOrScopeInfo = obj.getAlignedObject(kNameOrScopeInfoOffset);
		if (nameOrScopeInfo instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "NameOrScopeInfo", null);
		} else if (nameOrScopeInfo instanceof ReservObject) {
			// Check map type to determine if this is a ScopeInfo or a String
			String nameType = ObjectsAllocator.getObjectTypeName((ReservObject) nameOrScopeInfo);
			if (nameType != null && nameType.equals("ScopeInfo")) {
				try {
					scopeInfos = ScopeInfoStruct.fromReservObject(allocator, (ReservObject) nameOrScopeInfo);
					if (scopeInfos == null) {
						scopeInfos = new ScopeInfoStruct((ReservObject) nameOrScopeInfo, allocator);
					}
					nameOrScopeInfo = scopeInfos;
				} catch (Exception e) {
					// Failed to parse ScopeInfo, treat as opaque
					scopeInfos = null;
				}
			} else if (nameType != null && (nameType.contains("String") || nameType.contains("Internalized"))) {
				// This is a function name string, try to convert
				try {
					nameOrScopeInfo = allocator.convertReservObject((ReservObject) nameOrScopeInfo);
				} catch (Exception e) {
					// Failed to convert name, keep as-is
				}
			}
			s.add(new PointerDataType(VoidDataType.dataType), -1, "NameOrScopeInfo", null);
		} else {
			s.add(new PointerDataType(CharDataType.dataType), -1, "NameOrScopeInfo", null);
		}

		// --- outer_scope_info_or_feedback_metadata ---
		// When compiled: FeedbackMetadata (map = FeedbackMetadataArrayMap or FixedCOWArrayMap)
		// When uncompiled: outer ScopeInfo
		outerScopeOrFeedback = obj.getAlignedObject(kOuterScopeInfoOrFeedbackMetadataOffset);
		if (outerScopeOrFeedback instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "OuterScopeOrFeedback", null);
		} else if (outerScopeOrFeedback instanceof ReservObject) {
			// Check the map type to decide how to parse
			String outerType = ObjectsAllocator.getObjectTypeName((ReservObject) outerScopeOrFeedback);
			if (outerType != null && (outerType.contains("FeedbackMetadata")
					|| outerType.equals("FixedCOWArray") || outerType.equals("FixedArray"))) {
				try {
					outerScopeOrFeedback = new FeedbackMetadataStruct(
						(ReservObject) outerScopeOrFeedback, functionLiteralId, allocator);
					s.add(((FeedbackMetadataStruct) outerScopeOrFeedback).toDataType(), -1, "OuterScopeOrFeedback", null);
				} catch (Exception e) {
					// Failed to parse as FeedbackMetadata, treat as opaque pointer
					s.add(new PointerDataType(VoidDataType.dataType), -1, "OuterScopeOrFeedback", null);
				}
			} else {
				// Not a FeedbackMetadata — could be ScopeInfo or other
				s.add(new PointerDataType(VoidDataType.dataType), -1, "OuterScopeOrFeedback", null);
			}
		} else {
			s.add(new PointerDataType(VoidDataType.dataType), -1, "OuterScopeOrFeedback", null);
		}

		// --- script_or_debug_info (Script | DebugInfo | Undefined), offset 32 ---
		// The actual Script object is not parsed deeper here.
		s.add(new PointerDataType(VoidDataType.dataType), -1, "ScriptOrDebugInfo", null);

		// --- Scalar fields, offsets 40..51 ---
		// These follow the 4 tagged fields and are packed without pointer-sized padding.

		// Offset 40 (0x28): length (int16) + formal_parameter_count (uint16) packed in one int32 word.
		int scalars0 = obj.getInt(kLengthOffset);
		functionLength = (scalars0 >> 0) & 0xFFFF;        // int16 at 0x28
		formalParameterCount = (scalars0 >> 16) & 0xFFFF;  // uint16 at 0x2A
		s.add(DWordDataType.dataType, -1, "LengthAndFormalParamCount", null);

		// Offset 44 (0x2C): raw_function_token_offset (int16) + expected_nof_properties (uint8)
		//                  + flags2 (uint8) packed in one int32 word.
		int scalars1 = obj.getInt(kRawFunctionTokenOffset);
		rawFunctionTokenOffset = (scalars1 >> 0) & 0xFFFF;     // int16 at 0x2C
		expectedNofProperties = (scalars1 >> 16) & 0xFF;       // uint8 at 0x2E
		flags2 = (scalars1 >> 24) & 0xFF;                      // uint8 at 0x2F
		s.add(DWordDataType.dataType, -1, "TokenOffsetAndNofPropsAndFlags2", null);

		// Offset 48 (0x30): flags (SharedFunctionInfoFlags, uint32).
		flags = obj.getInt(kFlagsOffset);
		s.add(DWordDataType.dataType, -1, "Flags", null);

		// Offset 52 (0x34): function_literal_id (int32).
		// Already read above (before the struct was built) to identify the function early.
		s.add(DWordDataType.dataType, -1, "FunctionLiteralId", null);

		size = s.getLength();
	}

	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));

		Address result = sfAllocator.allocateNew(this, size);

		// function_data (offset 8)
		if (bytecode != null) {
			sfAllocator.allocate(bytecode);
		} else if (functionDataBuiltin != null) {
			int typeIndex = (int) allocator.getEnumDataTypes().getBuiltins().getValue(functionDataBuiltin);
			sfAllocator.allocate(typeIndex);
		} else {
			// Fallback: allocate a root/null placeholder
			sfAllocator.allocate(new v8_bytecode.RootObject("undefined", "undef"));
		}

		Address bytecodeAddr = (bytecode != null) ? bytecode.getBaseAddress() : null;

		// name_or_scope_info (offset 16)
		if (nameOrScopeInfo instanceof ScopeInfoStruct) {
			sfAllocator.allocate((ScopeInfoStruct) nameOrScopeInfo);
		} else if (nameOrScopeInfo instanceof RootObject) {
			sfAllocator.allocate(nameOrScopeInfo);
		} else {
			sfAllocator.allocate(allocator.allocateInStrings(nameOrScopeInfo));
		}

		// outer_scope_info_or_feedback_metadata (offset 24)
		if (outerScopeOrFeedback instanceof FeedbackMetadataStruct) {
			((FeedbackMetadataStruct) outerScopeOrFeedback).setAllocator(sfAllocator);
			sfAllocator.allocate((FeedbackMetadataStruct) outerScopeOrFeedback);
		} else if (outerScopeOrFeedback instanceof RootObject) {
			sfAllocator.allocate(outerScopeOrFeedback);
		} else {
			// ScopeInfo or other HeapObject
			sfAllocator.allocate(outerScopeOrFeedback);
		}

		// script_or_debug_info (offset 32) - allocate a placeholder pointer
		// The actual Script object is not parsed here; we emit a null-root reference.
		sfAllocator.allocate(new v8_bytecode.RootObject("undefined", "undef"));

		// Scalar fields packed as int32 words:
		// length(int16) + formal_parameter_count(uint16) at offset 40
		sfAllocator.allocate(functionLength | (formalParameterCount << 16));
		// raw_function_token_offset(int16) + expected_nof_properties(uint8) + flags2(uint8) at offset 44
		sfAllocator.allocate(rawFunctionTokenOffset | (expectedNofProperties << 16) | (flags2 << 24));
		// flags (uint32) at offset 48
		sfAllocator.allocate(flags);
		// function_literal_id (int32) at offset 52
		sfAllocator.allocate(functionLiteralId);

		allocator.setDataStruct(result, this);

		if (bytecodeAddr != null && scopeInfos != null) {
			initFunction(bytecodeAddr, scopeInfos, allocator);
		}

		final SharedFunctionStore sfStore = SharedFunctionStore.fromStruct(this, allocator.getProgram());
		allocator.addToSharedFunctions(sfStore);

		return result;
	}

	private void initFunction(final Address funcAddr, final ScopeInfoStruct scopeInfo, final ObjectsAllocator allocator) throws Exception {
		// Resolve function name from name_or_scope_info
		if (nameOrScopeInfo instanceof RootObject) {
			name = ((RootObject) nameOrScopeInfo).getName();
		} else if (nameOrScopeInfo instanceof ScopeInfoStruct) {
			name = "";
		} else {
			name = (String) allocator.prepareForAlloc(nameOrScopeInfo);
		}

		name = name.replace(" ", "_").replace("empty_string", "");

		if (name.isEmpty()) {
			name = String.format("func_%04d", functionLiteralId);
		}

		allocator.getFpa().createLabel(funcAddr, name, true);
		Function func = allocator.getFpa().createFunction(funcAddr, name);

		func.setReturnType(IntegerDataType.dataType, SourceType.DEFAULT);

		List<ParameterImpl> args = new ArrayList<>();

		Program program = allocator.getFpa().getCurrentProgram();

		final List<String> params = scopeInfo.getParams();
		for (int i = params.size() - 1; i >= 0; --i) {
			final String param = params.get(i).replace("empty_string", "");
			args.add(new ParameterImpl(param, IntegerDataType.dataType, program.getRegister(String.format("a%d", i)), program, SourceType.USER_DEFINED));
		}
		args.add(new ParameterImpl("this", new PointerDataType(VoidDataType.dataType), program.getRegister(String.format("a%d", params.size() + 1)), program, SourceType.USER_DEFINED));
		func.updateFunction("__stdcall", null, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.DEFAULT, args.toArray(ParameterImpl[]::new));

		final List<String> stackLocals = scopeInfo.getStackLocals();
		final List<String> addedStackLocals = new ArrayList<>();
		for (int i = 0; i < stackLocals.size(); ++i) {
			int stackOffset = scopeInfo.getStackLocalsFirstSlot() + i;
			String locName = stackLocals.get(i).replace("empty_string", "");

			if (!addedStackLocals.contains(locName)) {
				addedStackLocals.add(locName);
			} else if (!locName.isEmpty()) {
				locName = String.format("%s_%d", locName, i);
			}

			func.addLocalVariable(new LocalVariableImpl(locName, 0, IntegerDataType.dataType, program.getRegister(String.format("r%d", stackOffset)), program), SourceType.USER_DEFINED);
		}
	}

	public Object getName() {
		return name;
	}

	public Address getAddress() {
		return (bytecode != null) ? bytecode.getBaseAddress() : null;
	}

	public ScopeInfoStruct getScopeInfo() {
		return scopeInfos;
	}

	public Object getOuterScope() {
		return outerScopeOrFeedback;
	}

	public ConstantPoolStruct getConstantPool() {
		return (bytecode != null) ? bytecode.getConstantPool() : null;
	}

	public HandlerTableStruct getHandlerTable() {
		return (bytecode != null) ? bytecode.getHandlerTable() : null;
	}

	public int getSize() {
		return (bytecode != null) ? bytecode.getLength() : 0;
	}

	@Override
	public int hashCode() {
		return Objects.hash(functionLiteralId);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SharedFunctionInfoStruct other = (SharedFunctionInfoStruct) obj;
		return functionLiteralId == other.functionLiteralId;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}
}
