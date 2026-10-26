package v8_bytecode.model;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import v8_bytecode.snapshot.HeapObject;
import v8_bytecode.snapshot.Ref;

/**
 * Typed access to deserialized objects, using the V8 8.7 x64 layouts with
 * pointer compression (kTaggedSize = 4). Every offset below was checked
 * against all objects of the Dofus Retro 1.49 main.jsc.
 */
public final class V8Heap {
	// String: map, raw_hash_field, int32 length, characters.
	public static final int STRING_LENGTH = 8;
	public static final int STRING_CHARS = 12;
	public static final int THIN_STRING_ACTUAL = 12;
	public static final int CONS_STRING_FIRST = 12;
	public static final int CONS_STRING_SECOND = 16;

	// FixedArray (also ScopeInfo, boilerplate descriptions): map, Smi length, elements.
	public static final int FIXED_ARRAY_LENGTH = 4;
	public static final int FIXED_ARRAY_HEADER = 8;
	public static final int BYTE_ARRAY_LENGTH = 4;
	public static final int BYTE_ARRAY_HEADER = 8;
	public static final int HEAP_NUMBER_VALUE = 4;

	// SharedFunctionInfo (40 bytes).
	public static final int SFI_FUNCTION_DATA = 4;
	public static final int SFI_NAME_OR_SCOPE_INFO = 8;
	public static final int SFI_OUTER_SCOPE_OR_FEEDBACK_METADATA = 12;
	public static final int SFI_SCRIPT_OR_DEBUG_INFO = 16;
	public static final int SFI_LENGTH = 20;
	public static final int SFI_FORMAL_PARAMETER_COUNT = 22;
	public static final int SFI_FUNCTION_TOKEN_OFFSET = 24;
	public static final int SFI_EXPECTED_NOF_PROPERTIES = 26;
	public static final int SFI_FLAGS2 = 27;
	public static final int SFI_FLAGS = 28;
	public static final int SFI_FUNCTION_LITERAL_ID = 32;
	public static final int SFI_SIZE = 40;

	// BytecodeArray: header then the bytecodes.
	public static final int BA_LENGTH = 4;
	public static final int BA_CONSTANT_POOL = 8;
	public static final int BA_HANDLER_TABLE = 12;
	public static final int BA_SOURCE_POSITION_TABLE = 16;
	public static final int BA_FRAME_SIZE = 20;
	public static final int BA_PARAMETER_SIZE = 24;
	public static final int BA_INCOMING_NEW_TARGET_OR_GENERATOR_REGISTER = 28;
	public static final int BA_OSR_NESTING_LEVEL = 32;
	public static final int BA_BYTECODE_AGE = 33;
	public static final int BA_HEADER_SIZE = 34;

	// HandlerTable range entries (handler-table.h): int32 start, end, handler, data.
	public static final int HANDLER_ENTRY_SIZE = 16;

	// ScopeInfo flags (scope-info.tq) and its fixed slots.
	public static final String[] SCOPE_TYPES =
		{ "class", "eval", "function", "module", "script", "catch", "block", "with" };
	private static final int SCOPE_CLASS = 0;
	private static final int SCOPE_EVAL = 1;
	private static final int SCOPE_FUNCTION = 2;
	private static final int SCOPE_MODULE = 3;
	private static final int SCOPE_SCRIPT = 4;
	private static final int SCOPE_BLOCK = 6;
	private static final int SCOPE_WITH = 7;
	private static final int VARIABLE_NONE = 0;
	private static final int VARIABLE_STACK = 1;
	private static final int VARIABLE_CONTEXT = 2;
	// Context slots: scope_info, previous, [extension] (contexts.h).
	public static final int CONTEXT_HEADER = 2;
	public static final int CONTEXT_EXTENDED_HEADER = 3;
	private static final int SCOPE_FLAGS = 0;
	private static final int SCOPE_CONTEXT_LOCAL_COUNT = 2;
	private static final int SCOPE_VARIABLE_PART = 3;

	public final V8Tables tables;

	public V8Heap(V8Tables tables) {
		this.tables = tables;
	}

	public String mapName(Object value) {
		if (value instanceof HeapObject o && o.map() instanceof Ref.Root root) {
			return tables.rootName(root.index());
		}
		return null;
	}

	public boolean hasMap(Object value, String map) {
		return map.equals(mapName(value));
	}

	public boolean isString(Object value) {
		if (value instanceof Ref.Root root) {
			return tables.rootString(root.index()) != null;
		}
		if (value instanceof Ref.ReadOnlyHeap ro) {
			return tables.readOnlyString(ro.chunk(), ro.offset()) != null;
		}
		String map = mapName(value);
		return map != null && map.endsWith("StringMap") && !map.contains("Symbol");
	}

	/** Contents of a string object, string root or read-only heap string, or null for anything else. */
	public String string(Object value) {
		return string(value, 0);
	}

	private String string(Object value, int depth) {
		if (value instanceof Ref.Root root) {
			return tables.rootString(root.index());
		}
		if (value instanceof Ref.ReadOnlyHeap ro) {
			return tables.readOnlyString(ro.chunk(), ro.offset());
		}
		String map = mapName(value);
		if (map == null || depth > 64) {
			return null;
		}
		HeapObject o = (HeapObject) value;
		switch (map) {
			case "OneByteInternalizedStringMap":
			case "OneByteStringMap": {
				int n = Math.min(o.int32(STRING_LENGTH), o.size - STRING_CHARS);
				return new String(o.data, STRING_CHARS, Math.max(n, 0), StandardCharsets.ISO_8859_1);
			}
			case "InternalizedStringMap":
			case "StringMap": {
				int n = Math.min(o.int32(STRING_LENGTH) * 2, o.size - STRING_CHARS);
				return new String(o.data, STRING_CHARS, Math.max(n, 0) & ~1, StandardCharsets.UTF_16LE);
			}
			case "ThinStringMap":
			case "ThinOneByteStringMap":
				return string(o.slot(THIN_STRING_ACTUAL), depth + 1);
			case "ConsStringMap":
			case "ConsOneByteStringMap": {
				String first = string(o.slot(CONS_STRING_FIRST), depth + 1);
				String second = string(o.slot(CONS_STRING_SECOND), depth + 1);
				return first == null || second == null ? null : first + second;
			}
			default:
				return null;
		}
	}

	/** True for a sequential (flat) string whose characters are stored in the object. */
	public boolean isSequentialString(Object value) {
		String map = mapName(value);
		return map != null && (map.equals("OneByteInternalizedStringMap") ||
			map.equals("OneByteStringMap") || map.equals("InternalizedStringMap") ||
			map.equals("StringMap"));
	}

	public boolean isOneByteString(Object value) {
		String map = mapName(value);
		return map != null && map.contains("OneByte");
	}

	// ---- FixedArray --------------------------------------------------------

	public int fixedArrayLength(HeapObject o) {
		return o.smi(FIXED_ARRAY_LENGTH);
	}

	/** Element i of a FixedArray: a HeapObject/Ref, or an Integer for a Smi. */
	public Object fixedArrayElement(HeapObject o, int i) {
		int off = FIXED_ARRAY_HEADER + 4 * i;
		Object v = o.slot(off);
		return v != null ? v : Integer.valueOf(o.smi(off));
	}

	// ---- ScopeInfo -----------------------------------------------------------

	/**
	 * The parts of a ScopeInfo the loader uses. {@code contextLength} is 0 when
	 * the scope allocates no context; {@code outer} is the next outer scope that
	 * has one (the ScopeInfo chain mirrors the context chain).
	 */
	public record ScopeInfo(HeapObject object, String scopeType, List<String> contextLocals,
			int contextHeader, int contextLength, int receiverSlot, String functionName,
			int functionNameSlot, String inferredName, HeapObject outer) {

		/** Variable stored in context slot {@code slot} of this scope, or null. */
		public String slotName(int slot) {
			if (slot == receiverSlot) {
				return "this";
			}
			if (slot == functionNameSlot) {
				return functionName;
			}
			int local = slot - contextHeader;
			return local >= 0 && local < contextLocals.size() ? contextLocals.get(local) : null;
		}
	}

	public ScopeInfo scopeInfo(Object value) {
		if (!hasMap(value, "ScopeInfoMap")) {
			return null;
		}
		HeapObject o = (HeapObject) value;
		int length = fixedArrayLength(o);
		if (length < SCOPE_VARIABLE_PART) {
			return new ScopeInfo(o, "empty", List.of(), 0, 0, -1, null, -1, null, null);
		}
		int flags = smiElement(o, SCOPE_FLAGS);
		int scopeType = flags & 0xf;
		boolean sloppyEval = ((flags >> 4) & 1) != 0;
		boolean declarationScope = ((flags >> 6) & 1) != 0;
		int receiver = (flags >> 7) & 3;
		boolean savedClassVariable = ((flags >> 10) & 1) != 0;
		int functionVariable = (flags >> 12) & 3;
		boolean inferred = ((flags >> 14) & 1) != 0;
		boolean asmModule = ((flags >> 15) & 1) != 0;
		boolean outerScope = ((flags >> 22) & 1) != 0;
		boolean forceContext = ((flags >> 24) & 1) != 0;
		boolean extensionSlot = ((flags >> 26) & 1) != 0;
		int locals = smiElement(o, SCOPE_CONTEXT_LOCAL_COUNT);
		List<String> names = new ArrayList<>();
		for (int i = 0; i < locals && SCOPE_VARIABLE_PART + i < length; i++) {
			names.add(string(fixedArrayElement(o, SCOPE_VARIABLE_PART + i)));
		}
		// Variable part (scope-info.cc): ContextLocalNames, ContextLocalInfos,
		// SavedClassVariableInfo, ReceiverInfo, FunctionNameInfo (name, slot),
		// InferredFunctionName, PositionInfo (2), OuterScopeInfo, ...
		int slot = SCOPE_VARIABLE_PART + 2 * locals + (savedClassVariable ? 1 : 0);
		int receiverSlot = -1;
		if (receiver == VARIABLE_STACK || receiver == VARIABLE_CONTEXT) {
			if (receiver == VARIABLE_CONTEXT) {
				receiverSlot = smiElement(o, slot);
			}
			slot++;
		}
		String functionName = null;
		int functionNameSlot = -1;
		if (functionVariable != VARIABLE_NONE && slot + 1 < length) {
			functionName = string(fixedArrayElement(o, slot));
			if (functionVariable == VARIABLE_CONTEXT) {
				functionNameSlot = smiElement(o, slot + 1);
			}
			slot += 2;
		}
		String inferredName = null;
		if (inferred && slot < length) {
			inferredName = string(fixedArrayElement(o, slot));
			slot++;
		}
		if (scopeType == SCOPE_EVAL || scopeType == SCOPE_FUNCTION || scopeType == SCOPE_MODULE ||
			scopeType == SCOPE_SCRIPT) {
			slot += 2;
		}
		HeapObject outer = null;
		if (outerScope && slot < length && fixedArrayElement(o, slot) instanceof HeapObject h &&
			hasMap(h, "ScopeInfoMap")) {
			outer = h;
		}
		// ScopeInfo::ContextLength.
		boolean hasContext = locals > 0 || forceContext || functionVariable == VARIABLE_CONTEXT ||
			scopeType == SCOPE_WITH || scopeType == SCOPE_CLASS ||
			(scopeType == SCOPE_BLOCK && sloppyEval && declarationScope) ||
			(scopeType == SCOPE_FUNCTION && (sloppyEval || asmModule)) || scopeType == SCOPE_MODULE;
		int header = extensionSlot ? CONTEXT_EXTENDED_HEADER : CONTEXT_HEADER;
		int contextLength =
			hasContext ? header + locals + (functionVariable == VARIABLE_CONTEXT ? 1 : 0) : 0;
		return new ScopeInfo(o, SCOPE_TYPES[scopeType & 7], names, header, contextLength,
			receiverSlot, functionName, functionNameSlot, inferredName, outer);
	}

	private int smiElement(HeapObject o, int i) {
		Object v = fixedArrayElement(o, i);
		return v instanceof Integer n ? n : 0;
	}

	// ---- SharedFunctionInfo / BytecodeArray ---------------------------------

	public boolean isSharedFunctionInfo(Object value) {
		return hasMap(value, "SharedFunctionInfoMap");
	}

	/** The BytecodeArray of a SharedFunctionInfo, or null when it has none. */
	public HeapObject bytecodeArray(HeapObject sfi) {
		Object data = sfi.slot(SFI_FUNCTION_DATA);
		return hasMap(data, "BytecodeArrayMap") ? (HeapObject) data : null;
	}

	/** Name of the function: declared name, else the name V8 inferred, else null. */
	public String functionName(HeapObject sfi) {
		Object nameOrScope = sfi.slot(SFI_NAME_OR_SCOPE_INFO);
		if (isString(nameOrScope)) {
			return emptyToNull(string(nameOrScope));
		}
		ScopeInfo scope = scopeInfo(nameOrScope);
		if (scope == null) {
			return null;
		}
		String name = emptyToNull(scope.functionName());
		return name != null ? name : emptyToNull(scope.inferredName());
	}

	public String inferredName(HeapObject sfi) {
		ScopeInfo scope = scopeInfo(sfi.slot(SFI_NAME_OR_SCOPE_INFO));
		return scope == null ? null : emptyToNull(scope.inferredName());
	}

	private static String emptyToNull(String s) {
		return s == null || s.isEmpty() ? null : s;
	}
}
