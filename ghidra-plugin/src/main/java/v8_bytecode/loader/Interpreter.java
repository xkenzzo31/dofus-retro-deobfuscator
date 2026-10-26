package v8_bytecode.loader;

import java.util.*;

import ghidra.program.model.address.Address;
import v8_bytecode.loader.FunctionImporter.Handler;
import v8_bytecode.loader.FunctionImporter.JsFunction;
import v8_bytecode.loader.Js.*;
import v8_bytecode.model.Ignition.Instruction;
import v8_bytecode.model.V8Heap;
import v8_bytecode.snapshot.HeapObject;
import v8_bytecode.snapshot.Ref;

/**
 * Runs Ignition bytecode on Js values: the start of a script, to replay what
 * obfuscator.io's set-up does, and single calls to string wrappers. Anything
 * it does not model (the host's globals, generators, most built-ins...)
 * throws Js.Unsupported, which ends the run.
 *
 * Contexts the interpreter did not create are the static context: a variable
 * read through it takes the value of the cell the loader resolved for that
 * instruction (cellValues). In a sandboxed evaluation, nothing that existed
 * before it can change: stores to older objects and contexts are Unsupported.
 */
final class Interpreter {
	static final int NO_EPOCH = -1;
	private static final int MAX_DEPTH = 64;
	private static final int MIN_STRING_ARRAY = 16;

	/** Instructions of a function, with the instruction index of each bytecode offset. */
	private static final class Code {
		final List<Instruction> insns;
		final int[] index;
		final List<Handler> handlers;

		Code(List<Instruction> insns, int length, List<Handler> handlers) {
			this.insns = insns;
			this.index = new int[length + 1];
			Arrays.fill(index, -1);
			for (int i = 0; i < insns.size(); i++) {
				index[insns.get(i).offset()] = i;
			}
			this.handlers = handlers;
		}
	}

	/** One activation. */
	private static final class Frame {
		final Closure closure;
		final JsFunction function;
		final Code code;
		final Object[] params;
		final Object[] registers;
		final Object[] args;
		Context context;
		Object acc = Js.UNDEFINED;
		int offset;

		Frame(Closure closure, Code code, Object[] params, Object[] registers, Object[] args) {
			this.closure = closure;
			this.function = closure.function();
			this.code = code;
			this.params = params;
			this.registers = registers;
			this.args = args;
			this.context = closure.context();
		}
	}

	private final FunctionImporter importer;
	private final V8Heap heap;
	private final Map<JsFunction, Code> codes = new IdentityHashMap<>();
	final JsObject global = Js.globals();
	/** Values of the variables read through the static context, by cell address. */
	final Map<Long, Object> cellValues = new HashMap<>();

	private long steps;
	private long budget;
	private int epoch;
	private boolean sandbox;
	private int depth;
	private Object pendingMessage = Js.UNDEFINED;

	/** While true, the run records contexts, stores and string arrays (script start). */
	boolean recording;
	/** Contexts created by the outermost function of a recorded run. */
	final List<Context> contexts = new ArrayList<>();
	final Set<Address> executedStores = new HashSet<>();
	/** obfuscator.io string arrays: large array literals of strings, with their function. */
	final Map<JsArray, JsFunction> stringArrays = new IdentityHashMap<>();
	/** shift() calls on a string array, and the functions that made them. */
	int rotations;
	final Set<JsFunction> rotators = Collections.newSetFromMap(new IdentityHashMap<>());
	/** Functions that returned during a recorded run. */
	final Set<JsFunction> returned = Collections.newSetFromMap(new IdentityHashMap<>());
	/** Functions that read an element of a string array. */
	final Set<JsFunction> arrayReaders = Collections.newSetFromMap(new IdentityHashMap<>());
	/** Set when an evaluation reads an element of a string array. */
	boolean readStringArray;
	/** Functions the last run entered. */
	final Set<JsFunction> entered = Collections.newSetFromMap(new IdentityHashMap<>());
	/** Where and why the last run stopped. */
	String stopped;

	Interpreter(FunctionImporter importer, V8Heap heap) {
		this.importer = importer;
		this.heap = heap;
	}

	/** Runs a call with its effects until it returns or needs what is not modelled (then Unsupported). */
	Object execute(Object callee, Object receiver, Object[] args, long maxSteps) throws Throw {
		begin(maxSteps, false);
		return call(callee, receiver, args);
	}

	/** Evaluates a call without changing any existing state; null when it cannot be evaluated. */
	Object evaluate(Object callee, Object receiver, Object[] args, long maxSteps) {
		begin(maxSteps, true);
		try {
			return call(callee, receiver, args);
		}
		catch (Throw | Unsupported | StackOverflowError e) {
			return null;
		}
		finally {
			sandbox = false;
		}
	}

	private void begin(long maxSteps, boolean sandboxed) {
		epoch++;
		sandbox = sandboxed;
		steps = 0;
		budget = maxSteps;
		depth = 0;
		readStringArray = false;
		entered.clear();
		stopped = null;
	}

	long steps() {
		return steps;
	}

	/** The current (or last) run: objects and contexts it created carry it. */
	int epoch() {
		return epoch;
	}

	Object call(Object callee, Object receiver, Object[] args) throws Throw {
		if (callee instanceof Native n) {
			if (sandbox && !n.pure && !(receiver instanceof JsObject o && o.epoch == epoch)) {
				throw new Unsupported(n.name + " on an older object");
			}
			return n.body.call(receiver, args);
		}
		if (callee instanceof Closure c) {
			return run(c, receiver, args);
		}
		if (callee instanceof Opaque o) {
			throw new Unsupported("call to " + o);
		}
		throw new Throw(Js.error("TypeError", Js.describe(callee) + " is not a function"));
	}

	/** A call made by bytecode: records the rotations of string arrays. */
	private Object invoke(Frame fr, Object callee, Object receiver, Object[] args) throws Throw {
		if (recording && callee instanceof Native n && n.name.equals("shift") && receiver instanceof JsArray a &&
			stringArrays.containsKey(a)) {
			rotations++;
			rotators.add(fr.function);
		}
		return call(callee, receiver, args);
	}

	private Code code(JsFunction f) {
		return codes.computeIfAbsent(f, g -> new Code(importer.decode(g), g.length, importer.handlers(g)));
	}

	private Object run(Closure c, Object receiver, Object[] args) throws Throw {
		JsFunction f = c.function();
		if (f == null) {
			throw new Unsupported("function without bytecode");
		}
		if (depth >= MAX_DEPTH) {
			throw new Unsupported("call depth");
		}
		depth++;
		entered.add(f);
		Object[] params = new Object[Math.max(f.parameterCount, 1)];
		params[0] = receiver;
		for (int i = 1; i < params.length; i++) {
			params[i] = i - 1 < args.length ? args[i - 1] : Js.UNDEFINED;
		}
		Object[] registers = new Object[f.registerCount];
		Arrays.fill(registers, Js.UNDEFINED);
		Frame fr = new Frame(c, code(f), params, registers, args);
		try {
			Object result = loop(fr);
			if (recording) {
				returned.add(f);
			}
			return result;
		}
		catch (Unsupported u) {
			if (stopped == null) {
				stopped = String.format("%s+%d: %s", f.name, fr.offset, u.getMessage());
			}
			throw u;
		}
		finally {
			depth--;
		}
	}

	// ---- registers and constants -------------------------------------------------------

	private static Object get(Frame fr, long r) {
		if (r == -1) {
			return fr.context;
		}
		if (r == -2) {
			return fr.closure;
		}
		if (r >= 2) {
			int i = (int) (r - 2);
			if (i < fr.params.length) {
				return fr.params[i];
			}
		}
		else {
			int i = (int) (-6 - r);
			if (i >= 0 && i < fr.registers.length) {
				return fr.registers[i];
			}
		}
		throw new Unsupported("register " + r);
	}

	private static void set(Frame fr, long r, Object v) {
		if (r == -1 && v instanceof Context c) {
			fr.context = c;
			return;
		}
		if (r >= 2) {
			int i = (int) (r - 2);
			if (i < fr.params.length) {
				fr.params[i] = v;
				return;
			}
		}
		else {
			int i = (int) (-6 - r);
			if (i >= 0 && i < fr.registers.length) {
				fr.registers[i] = v;
				return;
			}
		}
		throw new Unsupported("register " + r);
	}

	/** Registers first, first-1, ... (consecutive registers have decreasing operands). */
	private static Object[] list(Frame fr, long first, long count) {
		Object[] values = new Object[(int) count];
		for (int k = 0; k < count; k++) {
			values[k] = get(fr, first - k);
		}
		return values;
	}

	private Object entry(Frame fr, long index) {
		return importer.constantPoolEntry(fr.function, index);
	}

	/** A constant pool entry or boilerplate element as a value. */
	Object value(Object entry) {
		if (entry instanceof Integer smi) {
			return (double) smi;
		}
		String s = heap.string(entry);
		if (s != null) {
			return s;
		}
		if (entry instanceof Ref.Root root) {
			switch (heap.tables.rootName(root.index())) {
				case "UndefinedValue":
					return Js.UNDEFINED;
				case "NullValue":
					return Js.NULL;
				case "TheHoleValue":
					return Js.HOLE;
				case "TrueValue":
					return Boolean.TRUE;
				case "FalseValue":
					return Boolean.FALSE;
				case "UninitializedValue":
					return Oddball.UNINITIALIZED;
				case "NanValue":
					return Double.NaN;
				case "InfinityValue":
					return Double.POSITIVE_INFINITY;
				case "MinusInfinityValue":
					return Double.NEGATIVE_INFINITY;
				case "MinusZeroValue":
					return -0.0;
				default:
					throw new Unsupported("root " + heap.tables.rootName(root.index()));
			}
		}
		if (entry instanceof HeapObject o && heap.hasMap(o, "HeapNumberMap")) {
			return o.float64(V8Heap.HEAP_NUMBER_VALUE);
		}
		throw new Unsupported("constant " + entry);
	}

	/** A fresh object or array from a literal boilerplate. */
	JsObject literal(Object description, int creator) {
		String map = heap.mapName(description);
		if ("ObjectBoilerplateDescriptionMap".equals(map)) {
			HeapObject d = (HeapObject) description;
			JsObject o = new JsObject(creator);
			int pairs = (heap.fixedArrayLength(d) - 1) / 2;
			for (int i = 0; i < pairs; i++) {
				String key = Js.toKey(value(heap.fixedArrayElement(d, 1 + 2 * i)));
				o.properties.put(key, element(heap.fixedArrayElement(d, 2 + 2 * i), creator));
			}
			return o;
		}
		if ("ArrayBoilerplateDescriptionMap".equals(map)) {
			Object elements = ((HeapObject) description).slot(8);
			List<Object> list = new ArrayList<>();
			String kind = heap.mapName(elements);
			if ("FixedDoubleArrayMap".equals(kind)) {
				HeapObject e = (HeapObject) elements;
				for (int i = 0, n = e.smi(V8Heap.FIXED_ARRAY_LENGTH); i < n; i++) {
					double d = e.float64(V8Heap.FIXED_ARRAY_HEADER + 8 * i);
					boolean hole = Double.doubleToRawLongBits(d) == 0xfff7fffffff7ffffL;
					list.add(hole ? Js.HOLE : d);
				}
			}
			else if ("FixedArrayMap".equals(kind) || "FixedCOWArrayMap".equals(kind)) {
				HeapObject e = (HeapObject) elements;
				for (int i = 0, n = heap.fixedArrayLength(e); i < n; i++) {
					list.add(element(heap.fixedArrayElement(e, i), creator));
				}
			}
			else if (!(elements instanceof Ref.Root)) {
				throw new Unsupported("array boilerplate elements " + kind);
			}
			return new JsArray(creator, list);
		}
		throw new Unsupported("boilerplate " + map);
	}

	private Object element(Object v, int creator) {
		String map = heap.mapName(v);
		if ("ObjectBoilerplateDescriptionMap".equals(map) || "ArrayBoilerplateDescriptionMap".equals(map)) {
			return literal(v, creator);
		}
		return value(v);
	}

	// ---- contexts ---------------------------------------------------------------------

	private Context newContext(Frame fr, long scopeIndex, long slots) {
		Object scope = entry(fr, scopeIndex);
		V8Heap.ScopeInfo info = heap.scopeInfo(scope);
		if (info == null) {
			throw new Unsupported("scope");
		}
		Object[] values = new Object[Math.max(info.contextLength(), V8Heap.CONTEXT_EXTENDED_HEADER + (int) slots)];
		Arrays.fill(values, Js.UNDEFINED);
		Context c = new Context(scope, values, fr.context, epoch);
		if (recording && depth == 1) {
			contexts.add(c);
		}
		return c;
	}

	private Context target(Object start, long depthValue) {
		if (!(start instanceof Context c)) {
			throw new Unsupported("context register");
		}
		for (long i = 0; i < depthValue && !c.isStatic(); i++) {
			c = c.previous;
			if (c == null) {
				throw new Unsupported("context chain");
			}
		}
		return c;
	}

	private Object loadSlot(Frame fr, Instruction insn, Object start, long slot, long depthValue) {
		Context c = target(start, depthValue);
		if (c.isStatic()) {
			Long cell = importer.cell(fr.function.entry.add(insn.offset()));
			Object v = cell == null ? null : cellValues.get(cell);
			if (v == null || v == Js.UNKNOWN) {
				throw new Unsupported("variable outside the run");
			}
			return v;
		}
		if (slot >= c.slots.length) {
			throw new Unsupported("context slot");
		}
		return c.slots[(int) slot];
	}

	private void storeSlot(Frame fr, Instruction insn, Object start, long slot, long depthValue, Object v) {
		Context c = target(start, depthValue);
		if (c.isStatic() || (sandbox && c.epoch != epoch) || slot >= c.slots.length) {
			throw new Unsupported("store to an outer variable");
		}
		c.slots[(int) slot] = v;
		if (recording) {
			executedStores.add(fr.function.entry.add(insn.offset()));
		}
	}

	private void writable(Object target) {
		if (sandbox && !(target instanceof JsObject o && o.epoch == epoch)) {
			throw new Unsupported("store to an older object");
		}
	}

	/** A property read; literals from the static analysis are read only while nothing changes them. */
	private Object read(Object target, Object key) throws Throw {
		if (sandbox && target instanceof JsObject o && o.epoch == NO_EPOCH && !o.constant) {
			throw new Unsupported("object that changes");
		}
		return Js.getProperty(target, key);
	}

	// ---- the loop ---------------------------------------------------------------------

	private int jump(Frame fr, Instruction insn) {
		int target;
		if (insn.isJumpConstant()) {
			if (!(entry(fr, insn.operands()[0]) instanceof Integer distance)) {
				throw new Unsupported("jump offset");
			}
			target = insn.opcodeOffset() + distance;
		}
		else {
			target = insn.immediateJumpTarget();
		}
		int i = target >= 0 && target < fr.code.index.length ? fr.code.index[target] : -1;
		if (i < 0) {
			throw new Unsupported("jump target");
		}
		return i;
	}

	private Handler handler(Frame fr) {
		Handler innermost = null;
		for (Handler h : fr.code.handlers) {
			if (fr.offset >= h.start() && fr.offset < h.end()) {
				innermost = h;
			}
		}
		return innermost;
	}

	private Object loop(Frame fr) throws Throw {
		List<Instruction> insns = fr.code.insns;
		int pc = 0;
		while (true) {
			if (++steps > budget) {
				throw new Unsupported("step budget");
			}
			if (pc < 0 || pc >= insns.size()) {
				throw new Unsupported("fell off the code");
			}
			Instruction insn = insns.get(pc);
			fr.offset = insn.offset();
			int next = pc + 1;
			try {
				Object result = step(fr, insn);
				if (result == RETURN) {
					return fr.acc;
				}
				if (result instanceof Integer target) {
					next = target;
				}
			}
			catch (Throw t) {
				Handler h = handler(fr);
				if (h == null) {
					throw t;
				}
				Object saved = get(fr, -6 - h.contextRegister());
				if (!(saved instanceof Context c)) {
					throw new Unsupported("handler context");
				}
				fr.context = c;
				fr.acc = t.value;
				next = fr.code.index[h.handler()];
			}
			pc = next;
		}
	}

	private static final Object RETURN = new Object();

	/** Executes one instruction; returns RETURN, a jump target index, or null to fall through. */
	private Object step(Frame fr, Instruction insn) throws Throw {
		long[] op = insn.operands();
		String name = insn.name();
		switch (name) {
			// Loads and moves.
			case "LdaZero":
				fr.acc = 0.0;
				return null;
			case "LdaSmi":
				fr.acc = (double) op[0];
				return null;
			case "LdaUndefined":
				fr.acc = Js.UNDEFINED;
				return null;
			case "LdaNull":
				fr.acc = Js.NULL;
				return null;
			case "LdaTheHole":
				fr.acc = Js.HOLE;
				return null;
			case "LdaTrue":
				fr.acc = Boolean.TRUE;
				return null;
			case "LdaFalse":
				fr.acc = Boolean.FALSE;
				return null;
			case "LdaConstant":
				fr.acc = value(entry(fr, op[0]));
				return null;
			case "Ldar":
				fr.acc = get(fr, op[0]);
				return null;
			case "Star":
				set(fr, op[0], fr.acc);
				return null;
			case "Mov":
				set(fr, op[1], get(fr, op[0]));
				return null;

			// Globals.
			case "LdaGlobal":
			case "LdaGlobalInsideTypeof": {
				String global = Js.toKey(value(entry(fr, op[0])));
				Object v = this.global.properties.get(global);
				if (v == null) {
					Long cell = importer.cell(fr.function.entry.add(insn.offset()));
					v = cell == null ? null : cellValues.get(cell);
				}
				if (v == null || v == Js.UNKNOWN) {
					throw new Unsupported("global " + global);
				}
				fr.acc = v;
				return null;
			}
			case "StaGlobal":
				if (sandbox) {
					throw new Unsupported("global store");
				}
				global.properties.put(Js.toKey(value(entry(fr, op[0]))), fr.acc);
				return null;

			// Contexts.
			case "CreateFunctionContext":
			case "CreateEvalContext":
				fr.acc = newContext(fr, op[0], op[1]);
				return null;
			case "CreateBlockContext":
				fr.acc = newContext(fr, op[0], 0);
				return null;
			case "CreateCatchContext": {
				Context c = newContext(fr, op[1], 1);
				c.slots[V8Heap.CONTEXT_HEADER] = get(fr, op[0]);
				fr.acc = c;
				return null;
			}
			case "PushContext":
				if (!(fr.acc instanceof Context pushed)) {
					throw new Unsupported("PushContext");
				}
				set(fr, op[0], fr.context);
				fr.context = pushed;
				return null;
			case "PopContext":
				if (!(get(fr, op[0]) instanceof Context popped)) {
					throw new Unsupported("PopContext");
				}
				fr.context = popped;
				return null;
			case "LdaContextSlot":
			case "LdaImmutableContextSlot":
				fr.acc = loadSlot(fr, insn, get(fr, op[0]), op[1], op[2]);
				return null;
			case "LdaCurrentContextSlot":
			case "LdaImmutableCurrentContextSlot":
				fr.acc = loadSlot(fr, insn, fr.context, op[0], 0);
				return null;
			case "StaContextSlot":
				storeSlot(fr, insn, get(fr, op[0]), op[1], op[2], fr.acc);
				return null;
			case "StaCurrentContextSlot":
				storeSlot(fr, insn, fr.context, op[0], 0, fr.acc);
				return null;

			// Properties.
			case "LdaNamedProperty":
			case "LdaNamedPropertyNoFeedback":
				fr.acc = read(get(fr, op[0]), value(entry(fr, op[1])));
				return null;
			case "LdaKeyedProperty": {
				Object target = get(fr, op[0]);
				if (target instanceof JsArray a && stringArrays.containsKey(a)) {
					readStringArray = true;
					arrayReaders.add(fr.function);
				}
				fr.acc = read(target, fr.acc);
				return null;
			}
			case "StaNamedProperty":
			case "StaNamedPropertyNoFeedback":
			case "StaNamedOwnProperty": {
				Object target = get(fr, op[0]);
				writable(target);
				Js.setProperty(target, value(entry(fr, op[1])), fr.acc);
				return null;
			}
			case "StaKeyedProperty":
			case "StaInArrayLiteral":
			case "StaDataPropertyInLiteral": {
				Object target = get(fr, op[0]);
				writable(target);
				Js.setProperty(target, get(fr, op[1]), fr.acc);
				return null;
			}

			// Operators.
			case "Add":
			case "Sub":
			case "Mul":
			case "Div":
			case "Mod":
			case "Exp":
			case "BitwiseOr":
			case "BitwiseXor":
			case "BitwiseAnd":
			case "ShiftLeft":
			case "ShiftRight":
			case "ShiftRightLogical":
				fr.acc = Js.binary(name, get(fr, op[0]), fr.acc);
				return null;
			case "AddSmi":
			case "SubSmi":
			case "MulSmi":
			case "DivSmi":
			case "ModSmi":
			case "ExpSmi":
			case "BitwiseOrSmi":
			case "BitwiseXorSmi":
			case "BitwiseAndSmi":
			case "ShiftLeftSmi":
			case "ShiftRightSmi":
			case "ShiftRightLogicalSmi":
				fr.acc = Js.binary(name.substring(0, name.length() - 3), fr.acc, (double) op[0]);
				return null;
			case "Inc":
				fr.acc = Js.toNumber(fr.acc) + 1;
				return null;
			case "Dec":
				fr.acc = Js.toNumber(fr.acc) - 1;
				return null;
			case "Negate":
				fr.acc = -Js.toNumber(fr.acc);
				return null;
			case "BitwiseNot":
				fr.acc = (double) ~Js.toInt32(Js.toNumber(fr.acc));
				return null;
			case "ToNumber":
			case "ToNumeric":
				fr.acc = Js.toNumber(fr.acc);
				return null;
			case "ToString":
				fr.acc = Js.toStr(fr.acc);
				return null;
			case "ToName":
				set(fr, op[0], Js.toKey(fr.acc));
				return null;
			case "ToObject":
				if (!(fr.acc instanceof JsObject)) {
					throw new Unsupported("ToObject");
				}
				set(fr, op[0], fr.acc);
				return null;
			case "LogicalNot":
				if (!(fr.acc instanceof Boolean b)) {
					throw new Unsupported("LogicalNot");
				}
				fr.acc = !b;
				return null;
			case "ToBooleanLogicalNot":
				fr.acc = !Js.toBoolean(fr.acc);
				return null;
			case "TypeOf":
				fr.acc = Js.typeOf(fr.acc);
				return null;
			case "TestEqual":
				fr.acc = Js.looseEquals(get(fr, op[0]), fr.acc);
				return null;
			case "TestEqualStrict":
			case "TestReferenceEqual":
				fr.acc = Js.strictEquals(get(fr, op[0]), fr.acc);
				return null;
			case "TestLessThan":
			case "TestGreaterThan":
			case "TestLessThanOrEqual":
			case "TestGreaterThanOrEqual":
				fr.acc = Js.compare(name, get(fr, op[0]), fr.acc);
				return null;
			case "TestNull":
				fr.acc = fr.acc == Js.NULL;
				return null;
			case "TestUndefined":
				fr.acc = fr.acc == Js.UNDEFINED;
				return null;
			case "TestUndetectable":
				fr.acc = fr.acc == Js.NULL || fr.acc == Js.UNDEFINED;
				return null;
			case "TestTypeOf": {
				fr.acc = Js.typeOf(fr.acc).equals(Js.typeofLiteral(op[0]));
				return null;
			}
			case "TestIn": {
				String key = Js.toKey(get(fr, op[0]));
				if (fr.acc instanceof JsArray a) {
					int i = Js.arrayIndex(key);
					fr.acc = key.equals("length") || (i >= 0 && i < a.elements.size()) ||
						a.properties.containsKey(key);
				}
				else if (fr.acc instanceof JsObject o) {
					fr.acc = o.properties.containsKey(key);
				}
				else {
					throw new Unsupported("in");
				}
				return null;
			}

			// Control flow.
			case "Jump":
			case "JumpConstant":
			case "JumpLoop":
				return jump(fr, insn);
			case "JumpIfTrue":
			case "JumpIfTrueConstant":
				return Boolean.TRUE.equals(fr.acc) ? jump(fr, insn) : null;
			case "JumpIfFalse":
			case "JumpIfFalseConstant":
				return Boolean.FALSE.equals(fr.acc) ? jump(fr, insn) : null;
			case "JumpIfToBooleanTrue":
			case "JumpIfToBooleanTrueConstant":
				return Js.toBoolean(fr.acc) ? jump(fr, insn) : null;
			case "JumpIfToBooleanFalse":
			case "JumpIfToBooleanFalseConstant":
				return !Js.toBoolean(fr.acc) ? jump(fr, insn) : null;
			case "JumpIfNull":
			case "JumpIfNullConstant":
				return fr.acc == Js.NULL ? jump(fr, insn) : null;
			case "JumpIfNotNull":
			case "JumpIfNotNullConstant":
				return fr.acc != Js.NULL ? jump(fr, insn) : null;
			case "JumpIfUndefined":
			case "JumpIfUndefinedConstant":
				return fr.acc == Js.UNDEFINED ? jump(fr, insn) : null;
			case "JumpIfNotUndefined":
			case "JumpIfNotUndefinedConstant":
				return fr.acc != Js.UNDEFINED ? jump(fr, insn) : null;
			case "JumpIfUndefinedOrNull":
			case "JumpIfUndefinedOrNullConstant":
				return fr.acc == Js.UNDEFINED || fr.acc == Js.NULL ? jump(fr, insn) : null;
			case "JumpIfJSReceiver":
			case "JumpIfJSReceiverConstant":
				return fr.acc instanceof JsObject || fr.acc instanceof Closure || fr.acc instanceof Native
						? jump(fr, insn)
						: null;
			case "SwitchOnSmiNoFeedback": {
				if (!(fr.acc instanceof Double d) || d != Math.rint(d)) {
					throw new Unsupported("switch value");
				}
				long i = (long) (double) d - op[2];
				if (i < 0 || i >= op[1]) {
					return null;
				}
				if (!(entry(fr, op[0] + i) instanceof Integer distance)) {
					throw new Unsupported("switch table");
				}
				int target = insn.opcodeOffset() + distance;
				return fr.code.index[target];
			}
			case "Return":
				return RETURN;
			case "Throw":
			case "ReThrow":
				throw new Throw(fr.acc);
			case "ThrowReferenceErrorIfHole":
				if (fr.acc == Js.HOLE) {
					throw new Throw(Js.error("ReferenceError", "not initialized"));
				}
				return null;
			case "SetPendingMessage": {
				Object previous = pendingMessage;
				pendingMessage = fr.acc;
				fr.acc = previous;
				return null;
			}
			case "SwitchOnGeneratorState":
				if (get(fr, op[0]) != Js.UNDEFINED) {
					throw new Unsupported("generator resume");
				}
				return null;
			case "Debugger":
			case "IncBlockCounter":
			case "CollectTypeProfile":
				return null;

			// Calls.
			case "CallUndefinedReceiver":
				fr.acc = invoke(fr, get(fr, op[0]), Js.UNDEFINED, list(fr, op[1], op[2]));
				return null;
			case "CallUndefinedReceiver0":
				fr.acc = invoke(fr, get(fr, op[0]), Js.UNDEFINED, new Object[0]);
				return null;
			case "CallUndefinedReceiver1":
				fr.acc = invoke(fr, get(fr, op[0]), Js.UNDEFINED, new Object[] { get(fr, op[1]) });
				return null;
			case "CallUndefinedReceiver2":
				fr.acc = invoke(fr, get(fr, op[0]), Js.UNDEFINED, new Object[] { get(fr, op[1]), get(fr, op[2]) });
				return null;
			case "CallProperty":
			case "CallAnyReceiver":
			case "CallNoFeedback": {
				Object[] all = list(fr, op[1], op[2]);
				if (all.length == 0) {
					throw new Unsupported("call without receiver");
				}
				fr.acc = invoke(fr, get(fr, op[0]), all[0], Arrays.copyOfRange(all, 1, all.length));
				return null;
			}
			case "CallProperty0":
				fr.acc = invoke(fr, get(fr, op[0]), get(fr, op[1]), new Object[0]);
				return null;
			case "CallProperty1":
				fr.acc = invoke(fr, get(fr, op[0]), get(fr, op[1]), new Object[] { get(fr, op[2]) });
				return null;
			case "CallProperty2":
				fr.acc = invoke(fr, get(fr, op[0]), get(fr, op[1]), new Object[] { get(fr, op[2]), get(fr, op[3]) });
				return null;

			// Literals and closures.
			case "CreateObjectLiteral":
				fr.acc = literal(entry(fr, op[0]), epoch);
				return null;
			case "CreateArrayLiteral": {
				JsObject a = literal(entry(fr, op[0]), epoch);
				if (recording && a instanceof JsArray array && array.elements.size() >= MIN_STRING_ARRAY &&
					array.elements.stream().allMatch(e -> e instanceof String)) {
					stringArrays.put(array, fr.function);
				}
				fr.acc = a;
				return null;
			}
			case "CreateEmptyObjectLiteral":
				fr.acc = new JsObject(epoch);
				return null;
			case "CreateEmptyArrayLiteral":
				fr.acc = new JsArray(epoch, new ArrayList<>());
				return null;
			case "CreateClosure":
				fr.acc = new Closure(importer.function(entry(fr, op[0])), fr.context);
				return null;
			case "CreateMappedArguments":
			case "CreateUnmappedArguments":
				fr.acc = new JsArray(epoch, new ArrayList<>(Arrays.asList(fr.args)));
				return null;
			case "CreateRestParameter": {
				int formal = Math.max(fr.function.parameterCount - 1, 0);
				List<Object> rest = new ArrayList<>();
				for (int i = formal; i < fr.args.length; i++) {
					rest.add(fr.args[i]);
				}
				fr.acc = new JsArray(epoch, rest);
				return null;
			}
			default:
				if (name.startsWith("DebugBreak")) {
					return null;
				}
				throw new Unsupported(name);
		}
	}
}
