package v8_bytecode.structs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
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
import v8_bytecode.ScopeInfoFlags;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.allocator.ScopesInfoAllocator;

/**
 * V8 8.7 ScopeInfo struct parser.
 *
 * ScopeInfo extends FixedArray (HeapObject + length Smi + variable-length objects[]).
 * It is a FixedArray of tagged slots (Smi or HeapObject pointers).
 *
 * Static part (first 3 slots = kVariablePartIndex = 3):
 *   Slot 0  (kFlagsOffset)          : Flags (ScopeFlags, stored as Smi)
 *   Slot 1  (kParameterCount)       : ParameterCount (Smi)
 *   Slot 2  (kContextLocalCount)    : ContextLocalCount (Smi)
 *
 * NOTE: StackLocalCount was REMOVED in V8 8.7.
 *   In V8 6.x the static part had 4 slots: Flags, ParameterCount, StackLocalCount, ContextLocalCount.
 *   In V8 8.7 it has only 3 slots: Flags, ParameterCount, ContextLocalCount.
 *   Stack locals are no longer tracked by count in ScopeInfo; they are identified
 *   via their VariableAllocationInfo in the context info, or via FunctionBody analysis.
 *
 * Variable part (starting at index kVariablePartIndex = 3):
 *   1. ContextLocalNames[ContextLocalCount]      : String (tagged)
 *   2. ContextLocalInfos[ContextLocalCount]      : uint32 (as Smi)
 *   3. SavedClassVariableInfo[0 or 1]            : Smi (if HasSavedClassVariableIndex)
 *   4. ReceiverInfo[0 or 1]                      : Smi (if HasAllocatedReceiver)
 *   5. FunctionNameInfo[0 or 2]                  : String + Smi (if HasFunctionName)
 *   6. InferredFunctionName[0 or 1]              : String (if HasInferredFunctionName)
 *   7. PositionInfo[0 or 2]                      : Smi + Smi (if HasPositionInfo)
 *   8. OuterScopeInfo[0 or 1]                    : ScopeInfo (if HasOuterScopeInfo)
 *   9. LocalsBlockList[0 or 1]                   : StringSet (if HasLocalsBlockList)
 *
 * Source: chromium.googlesource.com/v8/v8 branch-heads/8.7
 *   src/objects/scope-info.h  (Fields enum, FOR_EACH_SCOPE_INFO_NUMERIC_FIELD)
 *   src/objects/scope-info.tq (ScopeFlags bitfield definition)
 *   src/objects/scope-info.cc (Create methods, index computations)
 *
 * V8 8.7 ScopeFlags bit layout (bitfield struct ScopeFlags extends uint32, scope-info.tq):
 *   bits 0-3  : scope_type (4 bits, ScopeType)
 *   bit 4     : sloppy_eval_can_extend_vars
 *   bit 5     : language_mode (LanguageMode)
 *   bit 6     : declaration_scope
 *   bits 7-8  : receiver_variable (VariableAllocationInfo, 2 bits)
 *   bit 9     : has_class_brand  [NEW in 8.7, was hasNewTarget in 6.x at this position]
 *   bit 10    : has_saved_class_variable_index  [NEW in 8.7]
 *   bit 11    : has_new_target  [was at bit 9 in 6.x]
 *   bits 12-13: function_variable (VariableAllocationInfo, 2 bits)  [was at bits 10-11 in 6.x]
 *   bit 14    : has_inferred_function_name  [NEW in 8.7]
 *   bit 15    : is_asm_module  [was at bit 12 in 6.x]
 *   bit 16    : has_simple_parameters  [was at bit 13 in 6.x]
 *   bits 17-21: function_kind (FunctionKind, 5 bits)  [was bits 14-23 (10 bits) in 6.x]
 *   bit 22    : has_outer_scope_info  [was at bit 24 in 6.x]
 *   bit 23    : is_debug_evaluate_scope  [was at bit 25 in 6.x]
 *   bit 24    : force_context_allocation  [NEW in 8.7]
 *   bit 25    : private_name_lookup_skips_outer_class  [NEW in 8.7]
 *   bit 26    : has_context_extension_slot  [NEW in 8.7]
 *   bit 27    : is_repl_mode_scope  [NEW in 8.7]
 *   bit 28    : has_locals_block_list  [NEW in 8.7]
 */
public final class ScopeInfoStruct implements IAllocatable {
	private final Structure s;

	private final int index;
	private final int flags;
	private final int paramsCount;
	// NOTE: stackLocalsCount removed from fixed fields in V8 8.7.
	// Stack locals are no longer counted in the ScopeInfo fixed header.
	private final int contextLocalsCount;
	private final List<Object> contextLocalNames;
	private final List<String> contextLocalNamesStr;
	private final List<Integer> contextLocalInfos;
	private ScopeInfoStruct outerScope;

	// For compatibility with SharedFunctionInfoStruct.initFunction()
	// In V8 8.7, parameter names are no longer stored in ScopeInfo.
	// We return an empty list for params and derived stack locals.
	private final List<String> params;         // always empty in V8 8.7
	private final List<String> stackLocalsStr; // always empty in V8 8.7

	private final String name;

	private final ReservObject rObj;
	private final int size;
	private final ScopesInfoAllocator siAllocator;

	private Address allocAddr = null;

	// --- Offset constants (V8 8.7) ---
	// ScopeInfo is a FixedArray; slots are at FixedArrayBase::kHeaderSize + index * kTaggedSize.
	// kFlagsOffset = OffsetOfElementAt(Fields::kFlags) = FixedArrayBase::kHeaderSize + 0*kTaggedSize
	//             = 16 + 0 = 16 (0x10)
	// kParameterCount = OffsetOfElementAt(1) = 16 + 1*8 = 24 (0x18)
	// kContextLocalCount = OffsetOfElementAt(2) = 16 + 2*8 = 32 (0x20)
	// kVariablePartIndex = 3

	public static long kFlagsOffset;
	public static long kParameterCount;
	// NOTE: kStackLocalCount NO LONGER EXISTS in V8 8.7 static fields.
	public static long kContextLocalCount;
	public static long kVariablePartFirstOffset; // offset of first slot in variable part

	/**
	 * Number of fixed slots before the variable part.
	 * V8 8.7: 3 (Flags, ParameterCount, ContextLocalCount).
	 * V8 6.x: 4 (Flags, ParameterCount, StackLocalCount, ContextLocalCount).
	 */
	private static final int kVariablePartIndex = 3;

	public ScopeInfoStruct(final ReservObject obj, final ObjectsAllocator allocator) throws Exception {
		int pointerSize = allocator.getPointerSize();

		// FixedArrayBase::kHeaderSize = 2 * pointerSize = 16 for 64-bit
		int fixedArrayBaseHeaderSize = 2 * pointerSize; // HeapObject::kHeaderSize(8) + length(8) = 16

		// --- Offset initialisation (V8 8.7) ---
		// FixedArray slots: OffsetOfElementAt(i) = kHeaderSize + i * kTaggedSize
		kFlagsOffset        = fixedArrayBaseHeaderSize + 0L * pointerSize; // 16
		kParameterCount     = fixedArrayBaseHeaderSize + 1L * pointerSize; // 24
		kContextLocalCount  = fixedArrayBaseHeaderSize + 2L * pointerSize; // 32
		kVariablePartFirstOffset = fixedArrayBaseHeaderSize + 3L * pointerSize; // 40 = first variable slot
		// --- End offset initialisation ---

		rObj = obj;
		siAllocator = new ScopesInfoAllocator(allocator);

		index = allocator.getCreatedScopesSize();
		allocator.addToCreatedScopes(obj, this);

		allocator.getMonitor().setMessage(String.format("Creating ScopeInfo #%d", index));

		name = String.format("ScopeInfo%d", index);
		s = new StructureDataType(name, 0);

		// --- Fixed part ---
		flags = obj.getSmiInt(kFlagsOffset);
		s.add(DWordDataType.dataType, -1, "Flags", null);

		ScopeInfoFlags scopeFlags = new ScopeInfoFlags(flags);

		paramsCount = obj.getSmiInt(kParameterCount);
		s.add(DWordDataType.dataType, -1, "ParamsCount", null);

		// V8 8.7: no StackLocalCount fixed field.
		// kContextLocalCount is at index 2 (was index 3 in V8 6.x).
		contextLocalsCount = obj.getSmiInt(kContextLocalCount);
		s.add(DWordDataType.dataType, -1, "ContextLocalsCount", null);

		// --- Variable part ---
		long offset = kVariablePartFirstOffset; // = 40

		// 1. ContextLocalNames[contextLocalsCount]
		contextLocalNames = new ArrayList<>();
		contextLocalNamesStr = new ArrayList<>();
		for (int i = 0; i < contextLocalsCount; ++i) {
			final Object nameObj = obj.getAlignedObject(offset);
			contextLocalNames.add(nameObj);
			if (nameObj instanceof RootObject) {
				contextLocalNamesStr.add(((RootObject) nameObj).getName());
				s.add(allocator.getEnumDataTypes().getRoots(), -1, String.format("ContextLocalName%d", i), null);
			} else {
				String localName = (String) allocator.prepareForAlloc(nameObj);
				contextLocalNamesStr.add(localName);
				s.add(new PointerDataType(CharDataType.dataType), -1, String.format("ContextLocalName%d", i), null);
			}
			offset += pointerSize;
		}

		// 2. ContextLocalInfos[contextLocalsCount]  (uint32 packed in Smi)
		contextLocalInfos = new ArrayList<>();
		for (int i = 0; i < contextLocalsCount; ++i) {
			int varInfo = obj.getSmiInt(offset);
			contextLocalInfos.add(varInfo);
			s.add(DWordDataType.dataType, -1, String.format("ContextLocalInfo%d", i), null);
			offset += pointerSize;
		}

		// 3. SavedClassVariableInfo (optional, 1 slot if has_saved_class_variable_index)
		if (scopeFlags.hasSavedClassVariableIndex()) {
			// Smi holding the context slot index for the class variable
			s.add(DWordDataType.dataType, -1, "SavedClassVariableInfo", null);
			offset += pointerSize;
		}

		// 4. ReceiverInfo (optional, 1 slot if HasAllocatedReceiver)
		if (scopeFlags.hasReceiver()) {
			s.add(DWordDataType.dataType, -1, "ReceiverInfo", null);
			offset += pointerSize;
		}

		// 5. FunctionNameInfo (optional, 2 slots if HasFunctionName)
		if (scopeFlags.hasFunctionVar()) {
			// slot 0: function name (String)
			final Object funcNameObj = obj.getAlignedObject(offset);
			if (funcNameObj instanceof RootObject) {
				s.add(allocator.getEnumDataTypes().getRoots(), -1, "FuncVarName", null);
			} else {
				s.add(new PointerDataType(CharDataType.dataType), -1, "FuncVarName", null);
			}
			offset += pointerSize;
			// slot 1: context or stack slot index (Smi)
			s.add(DWordDataType.dataType, -1, "FuncVarIndex", null);
			offset += pointerSize;
		}

		// 6. InferredFunctionName (optional, 1 slot if has_inferred_function_name)
		if (scopeFlags.hasInferredFunctionName()) {
			s.add(new PointerDataType(CharDataType.dataType), -1, "InferredFunctionName", null);
			offset += pointerSize;
		}

		// 7. PositionInfo (optional, 2 slots: startPosition + endPosition)
		if (scopeFlags.hasPositionInfo()) {
			s.add(DWordDataType.dataType, -1, "StartPosition", null);
			offset += pointerSize;
			s.add(DWordDataType.dataType, -1, "EndPosition", null);
			offset += pointerSize;
		}

		// 8. OuterScopeInfo (optional, 1 slot if has_outer_scope_info)
		if (scopeFlags.hasOuterScopeInfo()) {
			final Object outerObj = obj.getAlignedObject(offset);
			if (outerObj instanceof ReservObject) {
				outerScope = ScopeInfoStruct.fromReservObject(allocator, (ReservObject) outerObj);
				if (outerScope == null) {
					outerScope = new ScopeInfoStruct((ReservObject) outerObj, allocator);
				}
			}
			s.add(new PointerDataType(VoidDataType.dataType), -1, "OuterScope", null);
			offset += pointerSize;
		}

		// 9. LocalsBlockList (optional, 1 slot if has_locals_block_list) -- V8 8.7 new
		if (scopeFlags.hasLocalsBlockList()) {
			s.add(new PointerDataType(VoidDataType.dataType), -1, "LocalsBlockList", null);
			offset += pointerSize;
		}

		// In V8 8.7 parameter names are NOT stored in ScopeInfo.
		// Return empty list for API compatibility.
		params = Collections.emptyList();
		// Stack locals are not tracked directly either (no StackLocalCount).
		stackLocalsStr = Collections.emptyList();

		size = s.getLength();
	}

	public static ScopeInfoStruct fromReservObject(final ObjectsAllocator allocator, final ReservObject obj) {
		return allocator.getScopeInfoByObject(obj);
	}

	// API compatible with SharedFunctionInfoStruct.initFunction()
	public List<String> getParams() {
		return params;  // always empty in V8 8.7 (parameter names not in ScopeInfo)
	}

	public List<String> getStackLocals() {
		return stackLocalsStr;  // always empty in V8 8.7 (stack locals not tracked by ScopeInfo)
	}

	public int getStackLocalsFirstSlot() {
		return 0;  // no stack locals tracked
	}

	public List<ContextVarStruct> getContextVars() {
		List<ContextVarStruct> result = new ArrayList<>();
		for (int i = 0; i < contextLocalsCount; ++i) {
			// Compatibility: return nulls for unresolvable entries (old code used a 4-entry placeholder)
		}
		return result;
	}

	public List<String> getContextLocalNames() {
		return contextLocalNamesStr;
	}

	public List<Integer> getContextLocalInfos() {
		return contextLocalInfos;
	}

	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));

		Address result = allocAddr = siAllocator.allocateNew(this, size);

		siAllocator.allocate(flags);
		siAllocator.allocate(paramsCount);
		siAllocator.allocate(contextLocalsCount);

		// ContextLocalNames
		for (int i = 0; i < contextLocalsCount; ++i) {
			final Object nameObj = contextLocalNames.get(i);
			if (nameObj instanceof RootObject) {
				siAllocator.allocate(nameObj);
			} else {
				siAllocator.allocate(allocator.allocateInStrings(nameObj));
			}
		}

		// ContextLocalInfos
		for (int i = 0; i < contextLocalsCount; ++i) {
			siAllocator.allocate(contextLocalInfos.get(i));
		}

		// OuterScope (if present)
		if (outerScope != null) {
			siAllocator.allocate(outerScope);
		}

		allocator.setDataStruct(result, this);

		return result;
	}

	public Address getAddress() {
		return allocAddr;
	}

	public String getName() {
		return name;
	}

	public ScopeInfoStruct getOuterScope() {
		return outerScope;
	}

	@Override
	public int hashCode() {
		return Objects.hash(rObj);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ScopeInfoStruct other = (ScopeInfoStruct) obj;
		return Objects.equals(this.rObj, other.rObj);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}
}
