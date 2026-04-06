package v8_bytecode;

import v8_bytecode.enums.ScopeInfoFlagsFuncKindEnum;
import v8_bytecode.enums.ScopeInfoFlagsFuncVar;
import v8_bytecode.enums.ScopeInfoFlagsLang;
import v8_bytecode.enums.ScopeInfoFlagsReceiver;
import v8_bytecode.enums.ScopeInfoFlagsScope;

/**
 * Decoder for the ScopeInfo Flags word (V8 8.7).
 *
 * Bit layout (bitfield struct ScopeFlags extends uint32, src/objects/scope-info.tq, branch-heads/8.7):
 *
 *   bits 0-3  : scope_type                          (ScopeType, 4 bits)
 *   bit 4     : sloppy_eval_can_extend_vars
 *   bit 5     : language_mode                        (LanguageMode)
 *   bit 6     : declaration_scope
 *   bits 7-8  : receiver_variable                    (VariableAllocationInfo, 2 bits)
 *   bit 9     : has_class_brand                      [NEW in V8 8.7]
 *   bit 10    : has_saved_class_variable_index       [NEW in V8 8.7]
 *   bit 11    : has_new_target
 *   bits 12-13: function_variable                    (VariableAllocationInfo, 2 bits)
 *   bit 14    : has_inferred_function_name            [NEW in V8 8.7]
 *   bit 15    : is_asm_module
 *   bit 16    : has_simple_parameters
 *   bits 17-21: function_kind                        (FunctionKind, 5 bits; was 10 bits in V8 6.x)
 *   bit 22    : has_outer_scope_info                 [was bit 24 in V8 6.x]
 *   bit 23    : is_debug_evaluate_scope              [was bit 25 in V8 6.x]
 *   bit 24    : force_context_allocation             [NEW in V8 8.7]
 *   bit 25    : private_name_lookup_skips_outer_class [NEW in V8 8.7]
 *   bit 26    : has_context_extension_slot           [NEW in V8 8.7]
 *   bit 27    : is_repl_mode_scope                   [NEW in V8 8.7]
 *   bit 28    : has_locals_block_list                [NEW in V8 8.7]
 *
 * BREAKING CHANGES from V8 6.x:
 *   - has_new_target:    bit 9  -> bit 11  (has_class_brand + has_saved_class_variable_index inserted)
 *   - function_variable: bits 10-11 -> bits 12-13
 *   - is_asm_module:     bit 12 -> bit 15
 *   - has_simple_parameters: bit 13 -> bit 16
 *   - function_kind:     bits 14-23 (10 bits) -> bits 17-21 (5 bits)
 *   - has_outer_scope_info: bit 24 -> bit 22
 *   - is_debug_evaluate_scope: bit 25 -> bit 23
 *
 * Source: chromium.googlesource.com/v8/v8 branch-heads/8.7
 *   src/objects/scope-info.tq (bitfield struct ScopeFlags)
 */
public final class ScopeInfoFlags {

	private final ScopeInfoFlagsScope scope;
	private final boolean sloppyEvalCanExtendVars;
	private final ScopeInfoFlagsLang langMode;
	private final boolean declarationScope;
	private final ScopeInfoFlagsReceiver recv;
	private final boolean hasClassBrand;
	private final boolean hasSavedClassVariableIndex;
	private final boolean hasNewTarget;
	private final ScopeInfoFlagsFuncVar funcVar;
	private final boolean hasInferredFunctionName;
	private final boolean asmModule;
	private final boolean hasSimpleParameters;
	private final ScopeInfoFlagsFuncKindEnum.ScopeInfoFlagsFuncKind kind;
	private final boolean hasOuterScopeInfo;
	private final boolean isDebugEvaluateScope;
	private final boolean forceContextAllocation;
	private final boolean privateNameLookupSkipsOuterClass;
	private final boolean hasContextExtensionSlot;
	private final boolean isReplModeScope;
	private final boolean hasLocalsBlockList;

	public ScopeInfoFlags(int flags) {
		// bits 0-3 : scope_type (4 bits)
		scope = ScopeInfoFlagsScope.fromInt(flags & 0xF);

		// bit 4 : sloppy_eval_can_extend_vars
		sloppyEvalCanExtendVars = ((flags >> 4) & 1) != 0;

		// bit 5 : language_mode
		langMode = ScopeInfoFlagsLang.fromInt((flags >> 5) & 1);

		// bit 6 : declaration_scope
		declarationScope = ((flags >> 6) & 1) != 0;

		// bits 7-8 : receiver_variable (VariableAllocationInfo, 2 bits)
		recv = ScopeInfoFlagsReceiver.fromInt((flags >> 7) & 0x3);

		// bit 9 : has_class_brand  [NEW in V8 8.7]
		hasClassBrand = ((flags >> 9) & 1) != 0;

		// bit 10 : has_saved_class_variable_index  [NEW in V8 8.7]
		hasSavedClassVariableIndex = ((flags >> 10) & 1) != 0;

		// bit 11 : has_new_target  [was bit 9 in V8 6.x]
		hasNewTarget = ((flags >> 11) & 1) != 0;

		// bits 12-13 : function_variable (VariableAllocationInfo, 2 bits)  [was bits 10-11 in 6.x]
		funcVar = ScopeInfoFlagsFuncVar.fromInt((flags >> 12) & 0x3);

		// bit 14 : has_inferred_function_name  [NEW in V8 8.7]
		hasInferredFunctionName = ((flags >> 14) & 1) != 0;

		// bit 15 : is_asm_module  [was bit 12 in V8 6.x]
		asmModule = ((flags >> 15) & 1) != 0;

		// bit 16 : has_simple_parameters  [was bit 13 in V8 6.x]
		hasSimpleParameters = ((flags >> 16) & 1) != 0;

		// bits 17-21 : function_kind (FunctionKind, 5 bits)  [was bits 14-23 (10 bits) in V8 6.x]
		kind = ScopeInfoFlagsFuncKindEnum.ScopeInfoFlagsFuncKind.fromInt((flags >> 17) & 0x1F);

		// bit 22 : has_outer_scope_info  [was bit 24 (0x01000000) in V8 6.x]
		hasOuterScopeInfo = ((flags >> 22) & 1) != 0;

		// bit 23 : is_debug_evaluate_scope  [was bit 25 in V8 6.x]
		isDebugEvaluateScope = ((flags >> 23) & 1) != 0;

		// bit 24 : force_context_allocation  [NEW in V8 8.7]
		forceContextAllocation = ((flags >> 24) & 1) != 0;

		// bit 25 : private_name_lookup_skips_outer_class  [NEW in V8 8.7]
		privateNameLookupSkipsOuterClass = ((flags >> 25) & 1) != 0;

		// bit 26 : has_context_extension_slot  [NEW in V8 8.7]
		hasContextExtensionSlot = ((flags >> 26) & 1) != 0;

		// bit 27 : is_repl_mode_scope  [NEW in V8 8.7]
		isReplModeScope = ((flags >> 27) & 1) != 0;

		// bit 28 : has_locals_block_list  [NEW in V8 8.7]
		hasLocalsBlockList = ((flags >> 28) & 1) != 0;
	}

	public ScopeInfoFlagsScope getScope() {
		return scope;
	}

	/** @deprecated Use isSloppyEvalCanExtendVars(). Kept for source compatibility. */
	public boolean isCallsSloppyEval() {
		return sloppyEvalCanExtendVars;
	}

	public boolean isSloppyEvalCanExtendVars() {
		return sloppyEvalCanExtendVars;
	}

	public ScopeInfoFlagsLang getLangMode() {
		return langMode;
	}

	public boolean isDeclarationScope() {
		return declarationScope;
	}

	public ScopeInfoFlagsReceiver getRecv() {
		return recv;
	}

	/** True if the scope has 'has_class_brand' set (V8 8.7 new field). */
	public boolean hasClassBrand() {
		return hasClassBrand;
	}

	/** True if the scope has a saved class variable index slot (V8 8.7 new).
	 *  When true, a SavedClassVariableInfo slot is present in the variable part. */
	public boolean hasSavedClassVariableIndex() {
		return hasSavedClassVariableIndex;
	}

	public boolean hasNewTarget() {
		return hasNewTarget;
	}

	public ScopeInfoFlagsFuncVar getFuncVar() {
		return funcVar;
	}

	/** True if the scope has an inferred function name slot (V8 8.7 new).
	 *  When true, an InferredFunctionName slot is present in the variable part. */
	public boolean hasInferredFunctionName() {
		return hasInferredFunctionName;
	}

	public boolean isAsmModule() {
		return asmModule;
	}

	public boolean hasSimpleParameters() {
		return hasSimpleParameters;
	}

	public ScopeInfoFlagsFuncKindEnum.ScopeInfoFlagsFuncKind getKind() {
		return kind;
	}

	public boolean hasOuterScopeInfo() {
		return hasOuterScopeInfo;
	}

	public boolean isDebugEvaluateScope() {
		return isDebugEvaluateScope;
	}

	public boolean forceContextAllocation() {
		return forceContextAllocation;
	}

	public boolean privateNameLookupSkipsOuterClass() {
		return privateNameLookupSkipsOuterClass;
	}

	public boolean hasContextExtensionSlot() {
		return hasContextExtensionSlot;
	}

	public boolean isReplModeScope() {
		return isReplModeScope;
	}

	/** True if a LocalsBlockList slot is present in the variable part (V8 8.7 new).
	 *  Used by debug evaluate to abort variable lookup for stack-allocated locals. */
	public boolean hasLocalsBlockList() {
		return hasLocalsBlockList;
	}

	/**
	 * True if the receiver is allocated (STACK or CONTEXT), meaning a ReceiverInfo
	 * slot is present in the ScopeInfo variable part.
	 * receiver_variable == UNUSED or NONE -> no slot allocated.
	 */
	public boolean hasReceiver() {
		return !recv.equals(ScopeInfoFlagsReceiver.UNUSED) && !recv.equals(ScopeInfoFlagsReceiver.NONE);
	}

	/**
	 * True if a function name slot exists in the ScopeInfo variable part.
	 * Corresponds to function_variable != NONE.
	 */
	public boolean hasFunctionVar() {
		return !funcVar.equals(ScopeInfoFlagsFuncVar.NONE);
	}

	/**
	 * True if PositionInfo (start + end position) slots are present in the variable part.
	 * In V8 8.7, NeedsPositionInfo returns true for FUNCTION_SCOPE, MODULE_SCOPE,
	 * SCRIPT_SCOPE, EVAL_SCOPE (same as before but now via has_position_info flag
	 * baked into the flags word indirectly -- we compute it from scope_type).
	 *
	 * NOTE: In V8 8.7, there is no explicit has_position_info bit. Position info is
	 * present when NeedsPositionInfo(scope_type) is true. We reproduce that logic here.
	 */
	public boolean hasPositionInfo() {
		// Mirrors ScopeInfo::NeedsPositionInfo(scope_type) from V8 8.7:
		// returns true for FUNCTION_SCOPE, MODULE_SCOPE, SCRIPT_SCOPE, EVAL_SCOPE.
		if (scope == null) return false;
		return scope == ScopeInfoFlagsScope.EVAL_SCOPE
			|| scope == ScopeInfoFlagsScope.FUNCTION_SCOPE
			|| scope == ScopeInfoFlagsScope.MODULE_SCOPE
			|| scope == ScopeInfoFlagsScope.SCRIPT_SCOPE;
	}
}
