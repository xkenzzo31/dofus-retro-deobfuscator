package v8_bytecode.loader;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.model.Ignition;
import v8_bytecode.model.Ignition.Instruction;
import v8_bytecode.model.V8Heap;
import v8_bytecode.model.V8Tables;
import v8_bytecode.snapshot.CodeCache;
import v8_bytecode.snapshot.HeapObject;
import v8_bytecode.snapshot.Ref;

/**
 * Turns every SharedFunctionInfo that has bytecode into a Ghidra function.
 *
 * The loader sets what SLEIGH cannot compute from the instruction bytes: the
 * constant pool of each function in the cpbase context field, and in aux the
 * target of each Jump*Constant or the variable cell of each global or context
 * slot access. It then disassembles from the function starts, the exception
 * handlers and the switch targets, names the functions, gives them their
 * parameters and annotates constant pool operands.
 *
 * Variables get 4-byte cells in the js_variables block, labelled with their
 * names: one per global name and one per context slot of each scope (see
 * ContextTracker). Their accesses decompile to reads and writes of the named
 * cell, and the cell's references list every reader and writer.
 *
 * Strings that obfuscator.io hid behind its string array are decoded (see
 * StringDecoder) into the js_strings block. The aux field of a decoded call,
 * of a concatenation of two known strings, or of a keyed access whose key is a
 * known string, holds the string's entry, and the decompiler shows the string
 * in place of the call or the key. A comparison of two known strings gets aux
 * 1 (false) or 2 (true), so the decompiler drops the dead branch.
 */
public final class FunctionImporter {

	/** A JavaScript function with its bytecode. */
	public static final class JsFunction {
		public final HeapObject sfi;
		public final HeapObject bytecodeArray;
		public final Address entry;
		public final int length;
		public final Object constantPool;
		public final int literalId;
		public final int parameterCount;
		public final int registerCount;
		public String name;
		public JsFunction parent;

		JsFunction(HeapObject sfi, HeapObject bytecodeArray, Address entry) {
			this.sfi = sfi;
			this.bytecodeArray = bytecodeArray;
			this.entry = entry;
			this.length = bytecodeArray.smi(V8Heap.BA_LENGTH);
			this.constantPool = bytecodeArray.slot(V8Heap.BA_CONSTANT_POOL);
			this.literalId = sfi.int32(V8Heap.SFI_FUNCTION_LITERAL_ID);
			this.parameterCount = bytecodeArray.int32(V8Heap.BA_PARAMETER_SIZE) / 8;
			this.registerCount = bytecodeArray.int32(V8Heap.BA_FRAME_SIZE) / 8;
		}

		public Address end() {
			return entry.add(Math.max(length, 1) - 1);
		}
	}

	private static final int MAX_COMMENT = 120;

	/** Accesses by name: the constant pool entry of operand 0 names the variable. */
	private static final Set<String> GLOBAL_ACCESSES = Set.of("LdaGlobal", "LdaGlobalInsideTypeof",
		"StaGlobal", "LdaLookupSlot", "LdaLookupSlotInsideTypeof", "StaLookupSlot",
		"LdaLookupContextSlot", "LdaLookupContextSlotInsideTypeof", "LdaLookupGlobalSlot",
		"LdaLookupGlobalSlotInsideTypeof");

	/** A variable cell in the js_variables block. */
	private record Cell(long address, String label, String comment) {
	}

	private final Program program;
	private final CodeCache cache;
	private final HeapImage image;
	private final V8Heap heap;
	private final V8Tables tables;
	private final AddressSpace ram;
	private final MessageLog log;
	private final List<JsFunction> functions = new ArrayList<>();
	private final Map<HeapObject, JsFunction> bySfi = new IdentityHashMap<>();
	private final Map<Address, List<Address>> switches = new HashMap<>();
	private final Map<Address, String> handlers = new TreeMap<>();
	/** Variable cell of each global or context slot access. */
	private final Map<Address, Long> cells = new HashMap<>();
	/** Variable cell of each context slot of each scope. */
	private final Map<ContextTracker.Slot, Long> slotCells = new HashMap<>();
	private int jumpConstants;
	private int globalVariables;
	private int contextVariables;
	private int unresolvedSlots;
	private String closureAgreement = "";
	private StringDecoder.Result strings;
	/** js_strings entry of each decoded call, concatenation and named keyed access. */
	private final Map<Address, Long> stringSites = new HashMap<>();
	private int distinctStrings;

	public FunctionImporter(Program program, CodeCache cache, HeapImage image, V8Heap heap,
			MessageLog log) {
		this.program = program;
		this.cache = cache;
		this.image = image;
		this.heap = heap;
		this.tables = heap.tables;
		this.ram = program.getAddressFactory().getDefaultAddressSpace();
		this.log = log;
	}

	public List<JsFunction> functions() {
		return functions;
	}

	public void run(TaskMonitor monitor) throws Exception {
		collect();
		name();
		assignVariables(monitor);
		decodeStrings(monitor);
		setContext(monitor);
		disassemble(monitor);
		createFunctions(monitor);
		annotate(monitor);
	}

	private Address addr(long offset) {
		return ram.getAddress(offset);
	}

	private byte[] code(JsFunction f) {
		return f.bytecodeArray.data;
	}

	List<Instruction> decode(JsFunction f) {
		return Ignition.decode(code(f), V8Heap.BA_HEADER_SIZE, f.length, tables);
	}

	/** Constant pool entry: HeapObject, Ref, Integer (Smi), or null when out of range. */
	public Object constantPoolEntry(JsFunction f, long index) {
		if (!(f.constantPool instanceof HeapObject cp) || !heap.hasMap(cp, "FixedArrayMap") ||
			index < 0 || index >= heap.fixedArrayLength(cp)) {
			return null;
		}
		return heap.fixedArrayElement(cp, (int) index);
	}

	/** The function of a SharedFunctionInfo, or null when it has no bytecode. */
	JsFunction function(Object sfi) {
		return sfi instanceof HeapObject o ? bySfi.get(o) : null;
	}

	/** Variable cell of the global or context slot access at {@code at}, or null. */
	Long cell(Address at) {
		return cells.get(at);
	}

	/** Variable cell of a context slot of a scope (ScopeInfo), or null. */
	Long cell(HeapObject scope, int slot) {
		return slotCells.get(new ContextTracker.Slot(scope, slot));
	}

	// ---- collection and names ----------------------------------------------

	private void collect() {
		for (HeapObject o : cache.objects) {
			if (!heap.isSharedFunctionInfo(o)) {
				continue;
			}
			HeapObject ba = heap.bytecodeArray(o);
			if (ba == null) {
				continue;
			}
			JsFunction f = new JsFunction(o, ba, addr(image.address(ba) + V8Heap.BA_HEADER_SIZE));
			functions.add(f);
			bySfi.put(o, f);
		}
		functions.sort(Comparator.comparingInt(f -> f.literalId));
		for (JsFunction f : functions) {
			if (!(f.constantPool instanceof HeapObject cp) || !heap.hasMap(cp, "FixedArrayMap")) {
				continue;
			}
			for (int i = 0; i < heap.fixedArrayLength(cp); i++) {
				if (heap.fixedArrayElement(cp, i) instanceof HeapObject child) {
					JsFunction c = bySfi.get(child);
					if (c != null && c.parent == null && c != f) {
						c.parent = f;
					}
				}
			}
		}
	}

	private void name() {
		Set<String> used = new HashSet<>();
		for (JsFunction f : functions) {
			String base = heap.functionName(f.sfi);
			if (base == null) {
				base = f.literalId == 0 ? "script" : "anonymous";
			}
			base = sanitize(base);
			String name = used.contains(base) || base.equals("anonymous") ? base + "_" + f.literalId
					: base;
			used.add(name);
			f.name = name;
		}
	}

	static String sanitize(String s) {
		String name = SymbolUtilities.replaceInvalidChars(s, true);
		return name.length() > 120 ? name.substring(0, 120) : name.isEmpty() ? "_" : name;
	}

	// ---- variables ------------------------------------------------------------------

	private void assignVariables(TaskMonitor monitor) throws Exception {
		List<Cell> variables = new ArrayList<>();
		Set<String> labels = new HashSet<>();
		Map<String, Long> globals = new HashMap<>();
		monitor.initialize(functions.size(), "Resolving global variables");
		for (JsFunction f : functions) {
			monitor.checkCancelled();
			monitor.increment();
			for (Instruction insn : decode(f)) {
				if (!GLOBAL_ACCESSES.contains(insn.name())) {
					continue;
				}
				String name = heap.string(constantPoolEntry(f, insn.operands()[0]));
				if (name == null) {
					continue;
				}
				Long cell = globals.get(name);
				if (cell == null) {
					cell = cellAddress(variables.size());
					globals.put(name, cell);
					variables.add(new Cell(cell, unique(sanitize(name), labels), "global " + clip(name)));
				}
				cells.put(f.entry.add(insn.offset()), cell);
			}
		}
		globalVariables = variables.size();

		monitor.setMessage("Resolving context variables");
		ContextTracker tracker = new ContextTracker(heap, this);
		Map<Address, ContextTracker.Variable> accesses = new TreeMap<>(tracker.run(functions));
		List<ContextTracker.Variable> declared = new ArrayList<>();
		Map<String, Integer> sameName = new HashMap<>();
		for (Map.Entry<Address, ContextTracker.Variable> e : accesses.entrySet()) {
			ContextTracker.Variable v = e.getValue();
			Long cell = slotCells.get(v.key());
			if (cell == null) {
				cell = cellAddress(variables.size() + declared.size());
				slotCells.put(v.key(), cell);
				declared.add(v);
				sameName.merge(v.name(), 1, Integer::sum);
			}
			cells.put(e.getKey(), cell);
		}
		// Minified code reuses short names in every scope: qualify those with the
		// literal id of the function the scope belongs to (as in anonymous_<id>).
		for (ContextTracker.Variable v : declared) {
			JsFunction owner = tracker.owner(v.scope());
			String label = sanitize(v.name());
			if (sameName.get(v.name()) > 1 || globals.containsKey(v.name())) {
				label += owner != null ? "_" + owner.literalId : "_s";
			}
			variables.add(new Cell(cellAddress(variables.size()), unique(label, labels),
				String.format("%s scope of %s, context slot %d", v.scope().scopeType(),
					owner != null ? owner.name : "?", v.slot())));
		}
		contextVariables = declared.size();
		unresolvedSlots = tracker.unresolvedAccesses();
		closureAgreement = tracker.closureAgreement();

		MemoryBlock block = program.getMemory()
				.createUninitializedBlock("js_variables", addr(HeapImage.VARIABLES_BASE),
					Math.max(4L * variables.size(), 4), false);
		block.setPermissions(true, true, false);
		block.setComment("One cell per global name and per context variable");
		SymbolTable symbols = program.getSymbolTable();
		Listing listing = program.getListing();
		monitor.initialize(variables.size(), "Labelling variables");
		for (Cell c : variables) {
			monitor.checkCancelled();
			monitor.increment();
			Address at = addr(c.address());
			symbols.createLabel(at, c.label(), SourceType.IMPORTED);
			listing.createData(at, Undefined4DataType.dataType);
			listing.setComment(at, CommentType.EOL, c.comment());
		}
		// Create*Context operands then show whose scope they open.
		for (Map.Entry<HeapObject, JsFunction> e : tracker.owners().entrySet()) {
			V8Heap.ScopeInfo scope = heap.scopeInfo(e.getKey());
			String type = scope == null || scope.scopeType().equals("function") ? "" : scope.scopeType() + "_";
			symbols.createLabel(addr(image.address(e.getKey())), sanitize(type + "scope_" + e.getValue().name),
				SourceType.IMPORTED);
		}
	}

	// ---- obfuscated strings ---------------------------------------------------------

	/**
	 * Decodes obfuscator.io's strings into the js_strings block: one entry per
	 * distinct string, an int32 byte length then the UTF-8 bytes and a NUL,
	 * aligned to 4 bytes (V8_ConstantPool reads them back).
	 */
	private void decodeStrings(TaskMonitor monitor) throws Exception {
		strings = new StringDecoder(this, heap).run(monitor);
		Map<Address, String> sites = new TreeMap<>(strings.calls);
		sites.putAll(strings.concatenations);
		sites.putAll(strings.keys);
		Map<String, Long> entries = new LinkedHashMap<>();
		ByteArrayOutputStream table = new ByteArrayOutputStream();
		for (Map.Entry<Address, String> e : sites.entrySet()) {
			Long entry = entries.get(e.getValue());
			if (entry == null) {
				entry = HeapImage.STRINGS_BASE + table.size();
				entries.put(e.getValue(), entry);
				byte[] utf8 = e.getValue().getBytes(StandardCharsets.UTF_8);
				for (int k = 0; k < 4; k++) {
					table.write(utf8.length >>> (8 * k));
				}
				table.writeBytes(utf8);
				do {
					table.write(0);
				}
				while (table.size() % 4 != 0);
			}
			stringSites.put(e.getKey(), entry);
		}
		distinctStrings = entries.size();
		if (entries.isEmpty()) {
			return;
		}
		byte[] bytes = table.toByteArray();
		MemoryBlock block = program.getMemory()
				.createInitializedBlock("js_strings", addr(HeapImage.STRINGS_BASE),
					new ByteArrayInputStream(bytes), bytes.length, monitor, false);
		block.setPermissions(true, false, false);
		block.setComment("Strings decoded from obfuscator.io's string array");
		Listing listing = program.getListing();
		monitor.initialize(entries.size(), "Creating decoded strings");
		for (Map.Entry<String, Long> e : entries.entrySet()) {
			monitor.checkCancelled();
			monitor.increment();
			Address at = addr(e.getValue());
			listing.createData(at, DWordDataType.dataType);
			listing.createData(at.add(4), StringUTF8DataType.dataType,
				e.getKey().getBytes(StandardCharsets.UTF_8).length + 1);
		}
	}

	private static long cellAddress(int index) {
		return HeapImage.VARIABLES_BASE + 4L * index;
	}

	private static String unique(String label, Set<String> used) {
		String name = label;
		for (int i = 2; !used.add(name); i++) {
			name = label + "_" + i;
		}
		return name;
	}

	// ---- context and disassembly ----------------------------------------------

	private void setContext(TaskMonitor monitor) throws Exception {
		ProgramContext context = program.getProgramContext();
		Register cpbase = program.getLanguage().getRegister("cpbase");
		Register aux = program.getLanguage().getRegister("aux");
		monitor.initialize(functions.size(), "Setting constant pool context");
		for (JsFunction f : functions) {
			monitor.checkCancelled();
			monitor.increment();
			long cp = image.address(f.constantPool);
			context.setValue(cpbase, f.entry, f.end(), BigInteger.valueOf(cp & 0xffffffffL));
			for (Instruction insn : decode(f)) {
				Address at = f.entry.add(insn.offset());
				Long cell = cells.get(at);
				Long string = stringSites.get(at);
				if (cell != null) {
					context.setValue(aux, at, at, BigInteger.valueOf(cell));
				}
				else if (string != null) {
					context.setValue(aux, at, at, BigInteger.valueOf(string));
				}
				else if (strings.comparisons.containsKey(at)) {
					context.setValue(aux, at, at, BigInteger.valueOf(strings.comparisons.get(at) ? 2 : 1));
				}
				else if (insn.isJumpConstant()) {
					Object entry = constantPoolEntry(f, insn.operands()[0]);
					if (entry instanceof Integer distance) {
						long rel = insn.opcodeOffset() + distance - insn.offset();
						context.setValue(aux, at, at, BigInteger.valueOf(rel));
						jumpConstants++;
					}
					else {
						log.appendMsg(String.format("No Smi jump offset for %s at %s", insn.name(), at));
					}
				}
				else if (insn.name().equals("SwitchOnSmiNoFeedback") ||
					insn.name().equals("SwitchOnGeneratorState")) {
					switches.put(at, switchTargets(f, insn));
				}
			}
			handlerTargets(f);
		}
	}

	private List<Address> switchTargets(JsFunction f, Instruction insn) {
		boolean generator = insn.name().equals("SwitchOnGeneratorState");
		long start = insn.operands()[generator ? 1 : 0];
		long count = insn.operands()[generator ? 2 : 1];
		List<Address> targets = new ArrayList<>();
		for (long i = 0; i < count; i++) {
			if (constantPoolEntry(f, start + i) instanceof Integer distance) {
				targets.add(f.entry.add(insn.opcodeOffset() + distance));
			}
		}
		if (!generator) {
			targets.add(f.entry.add(insn.offset() + insn.length()));
		}
		return targets;
	}

	/**
	 * An exception handler table entry: bytecode offsets of the try range and
	 * of the handler, and the register (index) holding the context to restore.
	 */
	record Handler(int start, int end, int handler, int contextRegister) {
	}

	/** Exception handlers of a function (HandlerTable range entries). */
	List<Handler> handlers(JsFunction f) {
		List<Handler> list = new ArrayList<>();
		if (!(f.bytecodeArray.slot(V8Heap.BA_HANDLER_TABLE) instanceof HeapObject table) ||
			!heap.hasMap(table, "ByteArrayMap")) {
			return list;
		}
		int bytes = table.smi(V8Heap.BYTE_ARRAY_LENGTH);
		for (int at = 0; at + V8Heap.HANDLER_ENTRY_SIZE <= bytes; at += V8Heap.HANDLER_ENTRY_SIZE) {
			int base = V8Heap.BYTE_ARRAY_HEADER + at;
			int handler = table.int32(base + 8) >>> 3;
			if (handler < f.length) {
				list.add(new Handler(table.int32(base), table.int32(base + 4), handler,
					table.int32(base + 12)));
			}
		}
		return list;
	}

	private void handlerTargets(JsFunction f) {
		for (Handler h : handlers(f)) {
			handlers.merge(f.entry.add(h.handler()),
				String.format("catch for [%s, %s), context in r%d", f.entry.add(h.start()),
					f.entry.add(h.end()), h.contextRegister()),
				(a, b) -> a + "\n" + b);
		}
	}

	private void disassemble(TaskMonitor monitor) throws CancelledException {
		AddressSet starts = new AddressSet();
		AddressSet code = new AddressSet();
		for (JsFunction f : functions) {
			if (f.length > 0) {
				starts.add(f.entry);
				code.add(f.entry, f.end());
			}
		}
		handlers.keySet().forEach(starts::add);
		switches.values().forEach(targets -> targets.forEach(starts::add));
		monitor.setMessage("Disassembling bytecode");
		new DisassembleCommand(starts, code, true).applyTo(program, monitor);

		// Code that no flow reaches (dead code V8 kept) is still valid bytecode.
		AddressSet unreached = new AddressSet();
		Listing listing = program.getListing();
		for (JsFunction f : functions) {
			monitor.checkCancelled();
			for (Instruction insn : decode(f)) {
				Address at = f.entry.add(insn.offset());
				if (listing.getInstructionContaining(at) == null) {
					unreached.add(at);
				}
			}
		}
		if (!unreached.isEmpty()) {
			new DisassembleCommand(unreached, code, true).applyTo(program, monitor);
		}
	}

	// ---- functions ---------------------------------------------------------------

	private void createFunctions(TaskMonitor monitor) throws Exception {
		FunctionManager manager = program.getFunctionManager();
		Language language = program.getLanguage();
		String convention = program.getCompilerSpec().getDefaultCallingConvention().getName();
		DataType value = Undefined4DataType.dataType;
		monitor.initialize(functions.size(), "Creating JavaScript functions");
		for (JsFunction f : functions) {
			monitor.checkCancelled();
			monitor.increment();
			if (f.length == 0) {
				continue;
			}
			Function function = manager.createFunction(f.name, f.entry,
				new AddressSet(f.entry, f.end()), SourceType.IMPORTED);
			List<Variable> params = new ArrayList<>();
			for (int i = 0; i < f.parameterCount; i++) {
				String reg = i == 0 ? "receiver" : "a" + (i - 1);
				params.add(new ParameterImpl(reg, value, language.getRegister(reg), program));
			}
			function.updateFunction(convention,
				new ReturnParameterImpl(value, language.getRegister("acc"), program), params,
				FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.IMPORTED);
			program.getListing()
					.setComment(f.entry, CommentType.PLATE, plateComment(f));
			SymbolTable symbols = program.getSymbolTable();
			symbols.createLabel(addr(image.address(f.sfi)), "sfi_" + f.name, SourceType.IMPORTED);
			symbols.createLabel(addr(image.address(f.bytecodeArray)), "bytecode_" + f.name,
				SourceType.IMPORTED);
			if (f.constantPool instanceof HeapObject cp) {
				symbols.createLabel(addr(image.address(cp)), "constants_" + f.name,
					SourceType.IMPORTED);
			}
		}

		for (Map.Entry<Address, List<Address>> e : switches.entrySet()) {
			Function function = manager.getFunctionContaining(e.getKey());
			if (function != null && !e.getValue().isEmpty()) {
				ReferenceManager refs = program.getReferenceManager();
				for (Address target : e.getValue()) {
					refs.addMemoryReference(e.getKey(), target, RefType.COMPUTED_JUMP,
						SourceType.IMPORTED, Reference.MNEMONIC);
				}
				jumpTable(e.getKey(), e.getValue()).writeOverride(function);
			}
		}

		SymbolTable symbols = program.getSymbolTable();
		Listing listing = program.getListing();
		int n = 0;
		for (Map.Entry<Address, String> e : handlers.entrySet()) {
			symbols.createLabel(e.getKey(), "catch_" + n++, SourceType.IMPORTED);
			listing.setComment(e.getKey(), CommentType.PRE, e.getValue());
		}
	}

	/** A jump table override; the constructor gained a parameter in Ghidra 12.1. */
	private static JumpTable jumpTable(Address at, List<Address> targets) throws ReflectiveOperationException {
		ArrayList<Address> list = new ArrayList<>(targets);
		try {
			return JumpTable.class.getConstructor(Address.class, ArrayList.class, boolean.class, int.class)
					.newInstance(at, list, true, 0);
		}
		catch (NoSuchMethodException e) {
			return JumpTable.class.getConstructor(Address.class, ArrayList.class, boolean.class)
					.newInstance(at, list, true);
		}
	}

	private String plateComment(JsFunction f) {
		StringBuilder b = new StringBuilder();
		b.append("JavaScript function ").append(f.name);
		b.append("\nfunction_literal_id ").append(f.literalId);
		b.append(", parameters: receiver + ").append(Math.max(f.parameterCount - 1, 0));
		b.append(", registers: ").append(f.registerCount);
		String inferred = heap.inferredName(f.sfi);
		if (inferred != null && !inferred.equals(f.name)) {
			b.append("\ninferred name: ").append(inferred);
		}
		if (f.parent != null) {
			b.append("\nclosure created in: ").append(f.parent.name);
		}
		Integer array = strings.arrays.get(f);
		if (array != null) {
			b.append(String.format("\nobfuscator.io string array: %d strings, rotated %d times at start-up", array,
				strings.rotations));
		}
		if (strings.decoders.contains(f)) {
			b.append("\nobfuscator.io string decoder: reads the string array");
		}
		return b.toString();
	}

	// ---- operand annotations ---------------------------------------------------------

	private void annotate(TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		ReferenceManager refs = program.getReferenceManager();
		monitor.initialize(functions.size(), "Annotating constant pool operands");
		for (JsFunction f : functions) {
			monitor.checkCancelled();
			monitor.increment();
			for (Instruction insn : decode(f)) {
				Address at = f.entry.add(insn.offset());
				Long string = stringSites.get(at);
				if (string != null) {
					refs.addMemoryReference(at, addr(string + 4), RefType.DATA, SourceType.IMPORTED,
						Reference.MNEMONIC);
					String key = strings.keys.get(at);
					listing.setComment(at, CommentType.EOL, key != null ? propertyComment(key)
							: quote(strings.calls.getOrDefault(at, strings.concatenations.get(at))));
					continue;
				}
				Boolean truth = strings.comparisons.get(at);
				if (truth != null) {
					listing.setComment(at, CommentType.EOL, truth ? "always true" : "always false");
					continue;
				}
				int operand = insn.constantPoolOperand();
				if (operand < 0) {
					continue;
				}
				Object entry = constantPoolEntry(f, insn.operands()[operand]);
				if (entry == null) {
					continue;
				}
				Address target = referenceTarget(entry);
				if (target != null) {
					refs.addMemoryReference(at, target, RefType.DATA, SourceType.IMPORTED, operand);
				}
				String text = cells.containsKey(at) ? null : describe(entry, insn.name());
				if (text != null) {
					listing.setComment(at, CommentType.EOL, text);
				}
			}
		}
	}

	private Address referenceTarget(Object entry) {
		if (entry instanceof HeapObject o) {
			JsFunction f = bySfi.get(o);
			if (f != null) {
				return f.entry;
			}
			long a = image.address(o);
			return addr(heap.isSequentialString(o) ? a + V8Heap.STRING_CHARS : a);
		}
		if (entry instanceof Ref) {
			long a = image.address(entry);
			if (entry instanceof Ref.ReadOnlyHeap && heap.isString(entry)) {
				a += V8Heap.STRING_CHARS;
			}
			return a != 0 ? addr(a) : null;
		}
		return null;
	}

	/** Short JavaScript-like rendering of a constant pool entry. */
	public String describe(Object entry, String bytecode) {
		if (entry instanceof Integer smi) {
			return smi.toString();
		}
		if (entry instanceof Ref.Root root && tables.rootString(root.index()) == null) {
			return jsRootName(tables.rootName(root.index()));
		}
		String s = heap.string(entry);
		if (s != null) {
			if (bytecode.contains("NamedProperty")) {
				return "." + clip(s);
			}
			if (bytecode.contains("Global") || bytecode.contains("Lookup") ||
				bytecode.equals("ThrowReferenceErrorIfHole")) {
				return clip(s);
			}
			return quote(s);
		}
		if (!(entry instanceof HeapObject o)) {
			return null;
		}
		JsFunction f = bySfi.get(o);
		if (f != null) {
			return "function " + f.name;
		}
		String map = heap.mapName(o);
		if (map == null) {
			return null;
		}
		switch (map) {
			case "HeapNumberMap":
				return formatNumber(o.float64(V8Heap.HEAP_NUMBER_VALUE));
			case "ObjectBoilerplateDescriptionMap":
				return objectLiteral(o);
			case "ArrayBoilerplateDescriptionMap":
				return "[array literal]";
			case "ScopeInfoMap": {
				V8Heap.ScopeInfo scope = heap.scopeInfo(o);
				return scope == null ? "ScopeInfo" : scope.scopeType() + " scope " + scope.contextLocals();
			}
			default:
				return map.endsWith("Map") ? map.substring(0, map.length() - 3) : map;
		}
	}

	private String objectLiteral(HeapObject o) {
		StringJoiner keys = new StringJoiner(", ", "{", "}");
		int length = heap.fixedArrayLength(o);
		int shown = 0;
		for (int i = 1; i < length; i += 2) {
			String key = heap.string(heap.fixedArrayElement(o, i));
			if (key == null) {
				Object k = heap.fixedArrayElement(o, i);
				if (!(k instanceof Integer)) {
					continue;
				}
				key = k.toString();
			}
			if (shown++ == 6) {
				keys.add("...");
				break;
			}
			keys.add(key);
		}
		return keys.toString();
	}

	/** .name, or ["name"] when the name is not an identifier. */
	static String propertyComment(String name) {
		return isIdentifier(name) ? "." + name : "[" + quote(name) + "]";
	}

	static boolean isIdentifier(String s) {
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
			case "EmptyString":
			case "empty_string":
				return "\"\"";
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

	static String clip(String s) {
		return s.length() > MAX_COMMENT ? s.substring(0, MAX_COMMENT) + "..." : s;
	}

	static String quote(String s) {
		StringBuilder b = new StringBuilder("\"");
		for (int i = 0; i < s.length() && i < MAX_COMMENT; i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"':
					b.append("\\\"");
					break;
				case '\\':
					b.append("\\\\");
					break;
				case '\n':
					b.append("\\n");
					break;
				case '\r':
					b.append("\\r");
					break;
				case '\t':
					b.append("\\t");
					break;
				default:
					if (c < 0x20 || (c >= 0x7f && c < 0xa0)) {
						b.append(String.format("\\x%02x", (int) c));
					}
					else {
						b.append(c);
					}
			}
		}
		if (s.length() > MAX_COMMENT) {
			b.append("...");
		}
		return b.append('"').toString();
	}

	public int jumpConstantCount() {
		return jumpConstants;
	}

	public int globalVariableCount() {
		return globalVariables;
	}

	public int contextVariableCount() {
		return contextVariables;
	}

	/** Context slot accesses no scope was found for (they decompile to cpool reads). */
	public int unresolvedSlotCount() {
		return unresolvedSlots;
	}

	/** Closures whose context at creation matched their ScopeInfo chain, as "n/total". */
	public String closureAgreement() {
		return closureAgreement;
	}

	public int variableAccessCount() {
		return cells.size();
	}

	/** What the string decoder found, for the import log. */
	public String stringSummary() {
		String arrays = strings.arrays.isEmpty() ? "none"
				: strings.arrays.entrySet()
						.stream()
						.map(e -> e.getKey().name + " (" + e.getValue() + " strings)")
						.collect(Collectors.joining(", "));
		return String.format("Strings: %d calls decoded, %d keyed accesses named, %d concatenations and %d " +
			"comparisons folded, %d distinct strings; " +
			"string array: %s, rotated %d times%s; start-up run: %s (%d steps); %d rounds (known variables/" +
			"changing literals: %s), %d variables with a known value, %d calls evaluated (%d steps)%s",
			strings.calls.size(), strings.keys.size(), strings.concatenations.size(), strings.comparisons.size(),
			distinctStrings, arrays, strings.rotations,
			strings.rotated ? "" : " (the rotation loop did not finish)", strings.initStop, strings.initSteps,
			strings.rounds, String.join(" ", strings.roundLog), strings.knownVariables, strings.evaluations,
			strings.evaluationSteps,
			strings.firstError == null ? "" : "; first interpreter error: " + strings.firstError);
	}

	public int handlerCount() {
		return handlers.size();
	}

	public int switchCount() {
		return switches.size();
	}
}
