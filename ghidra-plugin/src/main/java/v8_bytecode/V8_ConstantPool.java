package v8_bytecode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.StringJoiner;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import v8_bytecode.loader.HeapImage;
import v8_bytecode.model.V8Heap;
import v8_bytecode.model.V8Tables;

/**
 * Resolves the cpool operations of v8_87.slaspec for the decompiler, reading
 * the heap image the loader wrote.
 *
 * The decompiler caches records by their first two references, so
 * tools/gen_sleigh.py packs them as {@code [base, kind << 24 | index]}: base
 * is the constant pool (cpbase) for constant pool entries and names, the
 * context depth for context slots, 0 otherwise. PROPERTY, GLOBAL, CONTEXT and
 * KEY records are pointers to the variable, which the p-code loads and stores
 * through; the other kinds are values. STRING and KEY index the js_strings
 * block (4-byte units), where the loader put the strings it decoded.
 */
public class V8_ConstantPool extends ConstantPool {
	static final int ENTRY = 0;
	static final int PROPERTY = 1;
	static final int GLOBAL = 2;
	static final int CONTEXT = 3;
	static final int ROOT = 4;
	static final int RUNTIME = 5;
	static final int INTRINSIC = 6;
	static final int TYPEOF = 7;
	static final int NATIVE = 8;
	static final int STRING = 9;
	static final int KEY = 10;

	private static final String[] TYPEOF_LITERALS =
		{ "number", "string", "symbol", "boolean", "bigint", "undefined", "function", "object", "other" };
	private static final int MAX_KEYS = 6;

	private final Program program;
	private final Memory memory;
	private final AddressSpace ram;
	private final V8Tables tables;
	private final DataType value;
	private final DataType valuePointer;

	public V8_ConstantPool(Program program) throws IOException {
		this.program = program;
		this.memory = program.getMemory();
		this.ram = program.getAddressFactory().getDefaultAddressSpace();
		this.tables = V8Tables.get();
		this.value = Undefined4DataType.dataType;
		this.valuePointer = new PointerDataType(value, 4, program.getDataTypeManager());
	}

	/** The decompiler needs a record for every reference: unknown ones get a placeholder. */
	@Override
	public Record getRecord(long[] ref) {
		if (ref.length < 2) {
			return record(ConstantPool.POINTER_FIELD, "cpool_unknown", value);
		}
		long base = ref[0];
		int kind = (int) (ref[1] >>> 24);
		int index = (int) (ref[1] & 0xffffff);
		Record r = resolve(base, kind, index);
		return r != null ? r : record(ConstantPool.POINTER_FIELD, "cpool_" + kind + "_" + index,
			kind == PROPERTY || kind == GLOBAL || kind == CONTEXT || kind == KEY ? valuePointer : value);
	}

	private Record resolve(long base, int kind, int index) {
		try {
			switch (kind) {
				case ENTRY:
					return entryRecord(base, index);
				case PROPERTY:
				case GLOBAL:
					return record(ConstantPool.POINTER_FIELD, propertyName(base, index), valuePointer);
				case CONTEXT:
					// A slot ContextTracker could not attribute to a scope.
					return record(ConstantPool.POINTER_FIELD,
						base == 0 ? "slot_" + index : "up" + base + "_slot_" + index, valuePointer);
				case ROOT:
					return record(ConstantPool.POINTER_FIELD, jsRootName(tables.rootName(index)), value);
				case RUNTIME:
					return record(ConstantPool.POINTER_METHOD, "%" + listName(tables.runtimeFunctions, index),
						value);
				case INTRINSIC:
					return record(ConstantPool.POINTER_METHOD, "%_" + listName(tables.intrinsics, index),
						value);
				case TYPEOF:
					return string(index < TYPEOF_LITERALS.length ? TYPEOF_LITERALS[index] : "typeof#" + index);
				case NATIVE:
					return record(ConstantPool.POINTER_FIELD, "native_context_" + index, value);
				case STRING:
					return string(decodedString(index));
				case KEY: {
					String key = decodedString(index);
					return record(ConstantPool.POINTER_FIELD, isIdentifier(key) ? key : "[\"" + key + "\"]",
						valuePointer);
				}
				default:
					return null;
			}
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	private static String listName(List<String> names, int index) {
		return index < names.size() ? names.get(index) : Integer.toString(index);
	}

	private static Record record(int tag, String token, DataType type) {
		Record r = new Record();
		r.tag = tag;
		r.token = token;
		r.type = type;
		return r;
	}

	private Record string(String s) {
		Record r = record(ConstantPool.STRING_LITERAL, s,
			new PointerDataType(CharDataType.dataType, 4, program.getDataTypeManager()));
		r.setUTF8Data(s);
		return r;
	}

	// ---- heap reading -------------------------------------------------------------

	private int int32(long address) throws MemoryAccessException {
		return memory.getInt(ram.getAddress(address));
	}

	private String rootAt(long address) {
		long off = address - HeapImage.ROOTS_BASE;
		if (off < 0 || off % 4 != 0 || off / 4 >= tables.roots.size()) {
			return null;
		}
		return tables.rootName((int) (off / 4));
	}

	private String mapOf(long object) throws MemoryAccessException {
		return rootAt(int32(object) & 0xffffffffL);
	}

	/**
	 * Element {@code index} of the FixedArray-shaped object at {@code array}: a
	 * Long object address, an Integer for a Smi, or null when out of range.
	 */
	private Object element(long array, int index) throws MemoryAccessException {
		int length = int32(array + V8Heap.FIXED_ARRAY_LENGTH) >> 1;
		if (index < 0 || index >= length) {
			return null;
		}
		long slot = array + V8Heap.FIXED_ARRAY_HEADER + 4L * index;
		Data data = program.getListing().getDataAt(ram.getAddress(slot));
		if (data != null && data.isPointer() && data.getValue() instanceof Address target) {
			return target.getOffset();
		}
		return int32(slot) >> 1;
	}

	/** Entry {@code index} of the constant pool at {@code cpbase}. */
	private Object entry(long cpbase, int index) throws MemoryAccessException {
		return "FixedArrayMap".equals(mapOf(cpbase)) ? element(cpbase, index) : null;
	}

	/**
	 * Read-only heap and embedder objects are placeholders without contents
	 * (the cache only refers to them), except the read-only heap strings the
	 * loader knows: it wrote those, other objects there are zero-filled.
	 */
	private boolean isPlaceholder(long object) {
		MemoryBlock block = memory.getBlock(ram.getAddress(object));
		if (block == null || !block.isInitialized()) {
			return true;
		}
		try {
			return block.getName().equals("v8_ro_heap") && int32(object) == 0;
		}
		catch (MemoryAccessException e) {
			return true;
		}
	}

	private String label(long object) {
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(ram.getAddress(object));
		return symbol != null ? symbol.getName() : String.format("obj_%08x", object);
	}

	private String stringAt(long object) throws MemoryAccessException {
		long root = object - HeapImage.ROOTS_BASE;
		if (root >= 0 && root % 4 == 0 && root / 4 < tables.roots.size()) {
			return tables.rootString((int) (root / 4));
		}
		if (isPlaceholder(object)) {
			return null;
		}
		String map = mapOf(object);
		if (map == null) {
			return null;
		}
		boolean oneByte = map.equals("OneByteInternalizedStringMap") || map.equals("OneByteStringMap");
		boolean twoByte = map.equals("InternalizedStringMap") || map.equals("StringMap");
		if (!oneByte && !twoByte) {
			return null;
		}
		int length = int32(object + V8Heap.STRING_LENGTH);
		int bytes = Math.min(oneByte ? length : 2 * length, 1 << 16);
		byte[] chars = new byte[Math.max(bytes, 0)];
		memory.getBytes(ram.getAddress(object + V8Heap.STRING_CHARS), chars);
		return new String(chars, oneByte ? StandardCharsets.ISO_8859_1 : StandardCharsets.UTF_16LE);
	}

	/** Entry {@code index} of the js_strings block: an int32 byte length, then UTF-8. */
	private String decodedString(int index) throws MemoryAccessException {
		long entry = HeapImage.STRINGS_BASE + 4L * index;
		int length = int32(entry);
		if (length < 0 || length > 1 << 20) {
			throw new MemoryAccessException("bad js_strings entry");
		}
		byte[] bytes = new byte[length];
		memory.getBytes(ram.getAddress(entry + 4), bytes);
		return new String(bytes, StandardCharsets.UTF_8);
	}

	private Record entryRecord(long cpbase, int index) throws MemoryAccessException {
		Object e = entry(cpbase, index);
		if (e instanceof Integer smi) {
			Record r = record(ConstantPool.PRIMITIVE, smi.toString(), IntegerDataType.dataType);
			r.value = smi;
			return r;
		}
		if (!(e instanceof Long object)) {
			return null;
		}
		if (isPlaceholder(object)) {
			return record(ConstantPool.POINTER_FIELD, label(object), value);
		}
		String s = stringAt(object);
		if (s != null) {
			return string(s);
		}
		String root = rootAt(object);
		if (root != null) {
			return record(ConstantPool.POINTER_FIELD, jsRootName(root), value);
		}
		String map = mapOf(object);
		if ("SharedFunctionInfoMap".equals(map)) {
			long bytecode = int32(object + V8Heap.SFI_FUNCTION_DATA) & 0xffffffffL;
			Function f = program.getFunctionManager()
					.getFunctionAt(ram.getAddress(bytecode + V8Heap.BA_HEADER_SIZE));
			return record(ConstantPool.POINTER_METHOD, f != null ? f.getName() : "function", value);
		}
		if ("HeapNumberMap".equals(map)) {
			double d = Double.longBitsToDouble(memory.getLong(ram.getAddress(object + V8Heap.HEAP_NUMBER_VALUE)));
			return record(ConstantPool.POINTER_FIELD, formatNumber(d), value);
		}
		if ("ObjectBoilerplateDescriptionMap".equals(map)) {
			return record(ConstantPool.POINTER_FIELD, objectLiteral(object), value);
		}
		// Anything else by its label (scope_..., constants_...) or its map.
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(ram.getAddress(object));
		if (symbol != null && !symbol.isDynamic()) {
			return record(ConstantPool.POINTER_FIELD, symbol.getName(), value);
		}
		String name = map == null ? String.format("obj_%08x", object)
				: map.endsWith("Map") ? map.substring(0, map.length() - 3) : map;
		return record(ConstantPool.POINTER_FIELD, name, value);
	}

	/** {key, ...} of an object literal boilerplate: (key, value) pairs after a flags entry. */
	private String objectLiteral(long object) throws MemoryAccessException {
		StringJoiner keys = new StringJoiner(", ", "{", "}");
		int length = int32(object + V8Heap.FIXED_ARRAY_LENGTH) >> 1;
		for (int i = 1, shown = 0; i < length; i += 2, shown++) {
			if (shown == MAX_KEYS) {
				keys.add("...");
				break;
			}
			Object k = element(object, i);
			String key = k instanceof Integer smi ? smi.toString()
					: !(k instanceof Long o) ? "?" : isPlaceholder(o) ? label(o) : stringAt(o);
			keys.add(key != null ? key : "?");
		}
		return keys.toString();
	}

	private String propertyName(long cpbase, int index) throws MemoryAccessException {
		Object e = entry(cpbase, index);
		if (e instanceof Long object && isPlaceholder(object)) {
			return label(object);
		}
		String name = e instanceof Long object ? stringAt(object) : null;
		if (name == null) {
			return "name_" + index;
		}
		return isIdentifier(name) ? name : "[\"" + name + "\"]";
	}

	private static boolean isIdentifier(String s) {
		if (s.isEmpty() || !Character.isJavaIdentifierStart(s.charAt(0))) {
			return false;
		}
		for (int i = 1; i < s.length(); i++) {
			if (!Character.isJavaIdentifierPart(s.charAt(i))) {
				return false;
			}
		}
		return true;
	}

	static String jsRootName(String root) {
		switch (root) {
			case "UndefinedValue":
				return "undefined";
			case "NullValue":
				return "null";
			case "TrueValue":
				return "true";
			case "FalseValue":
				return "false";
			case "TheHoleValue":
				return "the_hole";
			default:
				return root;
		}
	}

	static String formatNumber(double d) {
		if (d == Math.rint(d) && !Double.isInfinite(d) && Math.abs(d) < 1e15) {
			return Long.toString((long) d);
		}
		return Double.toString(d);
	}
}
