package v8_bytecode.loader;

import java.util.*;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.Supplier;

import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.loader.FunctionImporter.Handler;
import v8_bytecode.loader.FunctionImporter.JsFunction;
import v8_bytecode.loader.Js.*;
import v8_bytecode.model.Ignition.Instruction;
import v8_bytecode.model.V8Heap;
import v8_bytecode.snapshot.HeapObject;

/**
 * Decodes the strings obfuscator.io moved out of the code, without running
 * the application.
 *
 * obfuscator.io puts the string literals in one array, returned by a function
 * that redefines itself. At start-up a loop rotates the array until a
 * checksum of decoded strings matches. Every literal became a call to the
 * decoder (here an index lookup) through wrapper functions, whose arguments
 * are offsets, some of them read from constant object literals.
 *
 * 1. The interpreter runs the start of the script as Node would, which builds
 *    and rotates the array, until the code needs something it does not model
 *    (require, Function.prototype.toString...).
 * 2. A variable of the module scope takes its value from that run when every
 *    store to it ran. Any other variable has a value when every store of the
 *    program stores the same known value.
 * 3. Values flow through the registers of every function. A call whose callee
 *    is known is evaluated in the interpreter's sandbox, which cannot change
 *    anything that already exists. A call that read the string array and
 *    returned a string is a decoded string; a keyed load or store whose key is
 *    a known string gets that property name.
 *
 * Steps 2 and 3 repeat until the variables' values no longer change. The
 * last pass also folds what obfuscator.io built from strings: concatenations
 * of two known strings (split strings) and comparisons of two known strings
 * (the opaque predicates guarding injected dead code).
 */
final class StringDecoder {
	private static final long INIT_STEPS = 50_000_000L;
	private static final long CALL_STEPS = 20_000L;
	/** Larger functions are not evaluated at call sites (wrappers are a few dozen bytes). */
	private static final int MAX_CALLEE_LENGTH = 2048;
	private static final int MAX_ROUNDS = 8;
	private static final Object UNKNOWN = Js.UNKNOWN;

	/** Calls v8_87.slaspec can show as the string they return. */
	static final Set<String> CALLS = Set.of("CallAnyReceiver", "CallProperty", "CallProperty0", "CallProperty1",
		"CallProperty2", "CallUndefinedReceiver", "CallUndefinedReceiver0", "CallUndefinedReceiver1",
		"CallUndefinedReceiver2", "CallNoFeedback");

	private static final Set<String> TERMINATORS = Set.of("Return", "Throw", "ReThrow", "Abort", "Illegal");
	private static final Set<String> UNCONDITIONAL = Set.of("Jump", "JumpConstant", "JumpLoop");
	private static final Set<String> STORES = Set.of("StaContextSlot", "StaCurrentContextSlot", "StaGlobal");

	/** What the decoder found. */
	static final class Result {
		/** Decoded string each call returns, by instruction address. */
		final Map<Address, String> calls = new HashMap<>();
		/** Known string key of keyed loads and stores, by instruction address. */
		final Map<Address, String> keys = new HashMap<>();
		/** Concatenations (Add) of two known strings, with the result. */
		final Map<Address, String> concatenations = new HashMap<>();
		/** Comparisons of two known strings, with the result. */
		final Map<Address, Boolean> comparisons = new HashMap<>();
		/** String arrays: the function creating each one, with its length. */
		final Map<JsFunction, Integer> arrays = new LinkedHashMap<>();
		/** Functions that read an element of a string array. */
		final Set<JsFunction> decoders = new LinkedHashSet<>();
		int rotations;
		/** The rotation loop ran to its end (its checksum matched). */
		boolean rotated;
		String initStop = "not run";
		long initSteps;
		int rounds;
		int knownVariables;
		/** Known variables and changing literals after each round. */
		final List<String> roundLog = new ArrayList<>();
		int evaluations;
		long evaluationSteps;
		String firstError;
	}

	/** Outcome of one evaluated call: its value (UNKNOWN when not a plain value), null when it failed. */
	private record Evaluation(Object value, boolean readArray) {
	}

	private final FunctionImporter importer;
	private final V8Heap heap;
	private final Interpreter in;
	private final Result result = new Result();
	/** Store sites of each variable cell. */
	private final Map<Long, List<Address>> storeSites = new HashMap<>();
	/** Values of module scope variables after the start-up run. */
	private final Map<Long, Object> stable = new HashMap<>();
	/** The object every run of an object or array literal creates, as long as nothing changes it. */
	private final Map<Address, Object> literals = new HashMap<>();
	private final Map<List<Object>, Evaluation> evaluations = new HashMap<>();
	/** Values the current round stored to each cell (UNKNOWN when they differ). */
	private final Map<Long, Object> stores = new HashMap<>();
	/** Literal objects found to change or escape; they no longer give values. */
	private int changing;
	private boolean last;

	StringDecoder(FunctionImporter importer, V8Heap heap) {
		this.importer = importer;
		this.heap = heap;
		this.in = new Interpreter(importer, heap);
	}

	Result run(TaskMonitor monitor) throws CancelledException {
		List<JsFunction> functions = importer.functions();
		if (functions.isEmpty() || functions.get(0).literalId != 0) {
			return result;
		}
		monitor.setMessage("Running the start of the script");
		start(functions.get(0));
		findStores(functions, monitor);
		stableVariables();
		in.cellValues.putAll(stable);
		Map<Long, Object> used = Map.of();
		boolean converged = false;
		for (int round = 1; round <= MAX_ROUNDS && !converged; round++) {
			result.rounds = round;
			int changed = changing;
			sweep(functions, false, monitor);
			Map<Long, Object> next = new HashMap<>(stable);
			stores.forEach((cell, v) -> {
				if (v != UNKNOWN) {
					next.putIfAbsent(cell, v);
				}
			});
			converged = next.equals(in.cellValues) && changing == changed;
			result.roundLog.add(next.size() + "/" + changing);
			used = new HashMap<>(in.cellValues);
			in.cellValues.clear();
			in.cellValues.putAll(next);
		}
		if (!converged) {
			// Pruned branches can make a few variables alternate: they keep no value.
			Map<Long, Object> previous = used;
			in.cellValues.entrySet().removeIf(e -> !Objects.equals(previous.get(e.getKey()), e.getValue()));
		}
		result.knownVariables = in.cellValues.size();
		sweep(functions, true, monitor);
		result.decoders.addAll(in.arrayReaders);
		return result;
	}

	// ---- start-up run and variables -------------------------------------------------

	/** Runs the script, then the module function it returns, as Node does. */
	private void start(JsFunction script) {
		in.recording = true;
		try {
			Object module = in.execute(new Closure(script, Context.STATIC), Js.UNDEFINED, new Object[0], INIT_STEPS);
			if (module instanceof Closure) {
				Object[] args = { new Opaque("exports"), new Opaque("require"), new Opaque("module"),
					new Opaque("__filename"), new Opaque("__dirname") };
				in.execute(module, new Opaque("module.exports"), args, INIT_STEPS);
			}
			result.initStop = "end of the script";
		}
		catch (Throw t) {
			result.initStop = "uncaught exception " + Js.describe(t.value);
		}
		catch (Unsupported e) {
			result.initStop = in.stopped != null ? in.stopped : e.getMessage();
		}
		catch (StackOverflowError e) {
			result.initStop = "stack overflow";
		}
		finally {
			result.initSteps = in.steps();
			in.recording = false;
		}
		in.stringArrays.forEach((array, f) -> result.arrays.put(f, array.elements.size()));
		result.rotations = in.rotations;
		result.rotated = !in.rotators.isEmpty() && in.returned.containsAll(in.rotators);
	}

	private void findStores(List<JsFunction> functions, TaskMonitor monitor) throws CancelledException {
		for (JsFunction f : functions) {
			monitor.checkCancelled();
			for (Instruction insn : importer.decode(f)) {
				if (STORES.contains(insn.name())) {
					Address at = f.entry.add(insn.offset());
					Long cell = importer.cell(at);
					if (cell != null) {
						storeSites.computeIfAbsent(cell, k -> new ArrayList<>()).add(at);
					}
				}
			}
		}
	}

	/**
	 * Variables of the scopes the module function opened once, whose every
	 * store ran: the run gave their final value (the decoder after it
	 * redefined itself, for instance).
	 */
	private void stableVariables() {
		Map<Object, List<Context>> instances = new IdentityHashMap<>();
		for (Context c : in.contexts) {
			instances.computeIfAbsent(c.scope, k -> new ArrayList<>()).add(c);
		}
		for (Map.Entry<Object, List<Context>> e : instances.entrySet()) {
			if (e.getValue().size() != 1 || !(e.getKey() instanceof HeapObject scope)) {
				continue;
			}
			Object[] slots = e.getValue().get(0).slots;
			for (int slot = 0; slot < slots.length; slot++) {
				Long cell = importer.cell(scope, slot);
				List<Address> sites = cell == null ? null : storeSites.get(cell);
				if (sites != null && in.executedStores.containsAll(sites) && isValue(slots[slot]) &&
					slots[slot] != Js.HOLE) {
					stable.put(cell, slots[slot]);
				}
			}
		}
	}

	// ---- values -------------------------------------------------------------------

	/** A value the analysis can hold: anything but contexts, host objects and placeholders. */
	private static boolean isValue(Object v) {
		return v instanceof Double || v instanceof String || v instanceof Boolean || v == Js.UNDEFINED ||
			v == Js.NULL || v == Js.HOLE || v instanceof JsObject || v instanceof Closure || v instanceof Native;
	}

	private static boolean isPrimitive(Object v) {
		return v instanceof Double || v instanceof String || v instanceof Boolean || v == Js.UNDEFINED ||
			v == Js.NULL;
	}

	/** A value an evaluation may return: objects it created are not followed. */
	private static boolean isResult(Object v) {
		return isPrimitive(v) || v instanceof Closure || v instanceof Native;
	}

	/** A literal object stops giving values once it may change. */
	private void changes(Object v) {
		if (v instanceof JsObject o && o.constant && o.epoch == Interpreter.NO_EPOCH) {
			o.constant = false;
			changing++;
			for (Object p : o.properties.values()) {
				changes(p);
			}
			if (o instanceof JsArray a) {
				for (Object e : a.elements) {
					changes(e);
				}
			}
		}
	}

	private Evaluation evaluate(Object callee, Object receiver, Object[] args) {
		if (callee instanceof Native n) {
			if (!n.pure) {
				return null;
			}
		}
		else if (!(callee instanceof Closure c) || c.function() == null ||
			c.function().length > MAX_CALLEE_LENGTH) {
			return null;
		}
		List<Object> key = new ArrayList<>(args.length + 2);
		key.add(callee);
		key.add(receiver);
		Collections.addAll(key, args);
		Evaluation cached = evaluations.get(key);
		if (cached == null) {
			Object v;
			try {
				v = in.evaluate(callee, receiver, args, CALL_STEPS);
			}
			catch (RuntimeException e) {
				// A gap in the interpreter: the call stays undecoded.
				v = null;
				if (result.firstError == null) {
					result.firstError = e.toString();
				}
			}
			result.evaluations++;
			result.evaluationSteps += in.steps();
			// A closure over a context the evaluation created differs at every evaluation.
			if (v instanceof Closure c && !c.context().isStatic() && c.context().epoch == in.epoch()) {
				v = UNKNOWN;
			}
			cached = new Evaluation(v == null ? null : isResult(v) ? v : UNKNOWN, in.readStringArray);
			evaluations.put(key, cached);
		}
		return cached.value() == null ? null : cached;
	}

	private void sweep(List<JsFunction> functions, boolean last, TaskMonitor monitor) throws CancelledException {
		this.last = last;
		stores.clear();
		evaluations.clear();
		monitor.initialize(functions.size(),
			last ? "Decoding strings" : "Propagating values, round " + result.rounds);
		for (JsFunction f : functions) {
			monitor.checkCancelled();
			monitor.increment();
			if (f.length > 0) {
				new Flow(f).run();
			}
		}
	}

	// ---- value flow -----------------------------------------------------------------

	/**
	 * Forward value flow through one function, by basic blocks. A state holds
	 * the accumulator, the parameters (receiver first) and the registers, each
	 * a known value or UNKNOWN. Exception handlers start from what any
	 * instruction of their try range saw.
	 */
	private final class Flow {
		private final JsFunction f;
		private final List<Instruction> code;
		/** Instruction at each bytecode offset, -1 elsewhere. */
		private final int[] index;
		private final int params;
		private final int size;
		private final int[] blockStart;
		private final int[] blockOf;
		/** Handler blocks whose try range covers each instruction (null when none). */
		private final int[][] handlersAt;

		Flow(JsFunction f) {
			this.f = f;
			this.code = importer.decode(f);
			this.index = new int[f.length + 1];
			Arrays.fill(index, -1);
			for (int i = 0; i < code.size(); i++) {
				index[code.get(i).offset()] = i;
			}
			this.params = Math.max(f.parameterCount, 1);
			this.size = 1 + params + f.registerCount;
			int n = code.size();
			List<Handler> handlers = importer.handlers(f);
			boolean[] leader = new boolean[n + 1];
			leader[0] = true;
			for (Handler h : handlers) {
				int t = at(h.handler());
				if (t >= 0) {
					leader[t] = true;
				}
			}
			for (int i = 0; i < n; i++) {
				Instruction insn = code.get(i);
				List<Integer> targets = targets(insn);
				for (int t : targets) {
					leader[t] = true;
				}
				if (!targets.isEmpty() || insn.isJumpImmediate() || insn.isJumpConstant() ||
					TERMINATORS.contains(insn.name())) {
					leader[i + 1] = true;
				}
			}
			int blocks = 0;
			for (int i = 0; i < n; i++) {
				if (leader[i]) {
					blocks++;
				}
			}
			blockStart = new int[blocks + 1];
			blockOf = new int[n];
			for (int i = 0, b = -1; i < n; i++) {
				if (leader[i]) {
					blockStart[++b] = i;
				}
				blockOf[i] = b;
			}
			blockStart[blocks] = n;
			handlersAt = new int[n][];
			for (Handler h : handlers) {
				int t = at(h.handler());
				if (t < 0) {
					continue;
				}
				for (int i = 0; i < n; i++) {
					int offset = code.get(i).offset();
					if (offset >= h.start() && offset < h.end()) {
						int[] old = handlersAt[i];
						handlersAt[i] = old == null ? new int[] { blockOf[t] } : append(old, blockOf[t]);
					}
				}
			}
		}

		private int at(int offset) {
			return offset >= 0 && offset < index.length ? index[offset] : -1;
		}

		private static int[] append(int[] a, int v) {
			int[] b = Arrays.copyOf(a, a.length + 1);
			b[a.length] = v;
			return b;
		}

		/** Instructions a jump or a Smi switch can go to (generator resumes fall through). */
		private List<Integer> targets(Instruction insn) {
			List<Integer> out = new ArrayList<>(1);
			if (insn.isJumpImmediate()) {
				add(out, at(insn.immediateJumpTarget()));
			}
			else if (insn.isJumpConstant()) {
				if (importer.constantPoolEntry(f, insn.operands()[0]) instanceof Integer distance) {
					add(out, at(insn.opcodeOffset() + distance));
				}
			}
			else if (insn.name().equals("SwitchOnSmiNoFeedback")) {
				long start = insn.operands()[0];
				for (long k = 0; k < insn.operands()[1]; k++) {
					if (importer.constantPoolEntry(f, start + k) instanceof Integer distance) {
						add(out, at(insn.opcodeOffset() + distance));
					}
				}
			}
			return out;
		}

		private static void add(List<Integer> list, int v) {
			if (v >= 0 && !list.contains(v)) {
				list.add(v);
			}
		}

		void run() {
			int blocks = blockStart.length - 1;
			Object[][] entry = new Object[blocks][];
			boolean[] queued = new boolean[blocks];
			ArrayDeque<Integer> work = new ArrayDeque<>();
			// Ignition fills the register file with undefined.
			Object[] initial = new Object[size];
			Arrays.fill(initial, Js.UNDEFINED);
			Arrays.fill(initial, 0, 1 + params, UNKNOWN);
			entry[0] = initial;
			work.add(0);
			queued[0] = true;
			while (!work.isEmpty()) {
				int b = work.poll();
				queued[b] = false;
				Object[] s = entry[b].clone();
				int end = blockStart[b + 1];
				for (int i = blockStart[b]; i < end; i++) {
					if (handlersAt[i] != null) {
						Object[] caught = s.clone();
						caught[0] = UNKNOWN;
						for (int h : handlersAt[i]) {
							merge(h, caught, entry, work, queued);
						}
					}
					step(code.get(i), s, false);
				}
				for (int t : successors(end - 1, s)) {
					merge(t, s, entry, work, queued);
				}
			}
			// Effects and results come from the stable states only.
			for (int b = 0; b < blocks; b++) {
				if (entry[b] != null) {
					Object[] s = entry[b].clone();
					for (int i = blockStart[b]; i < blockStart[b + 1]; i++) {
						step(code.get(i), s, true);
					}
				}
			}
		}

		private void merge(int b, Object[] s, Object[][] entry, ArrayDeque<Integer> work, boolean[] queued) {
			Object[] old = entry[b];
			boolean changed = false;
			if (old == null) {
				entry[b] = s.clone();
				changed = true;
			}
			else {
				for (int k = 0; k < size; k++) {
					if (old[k] != UNKNOWN && !Objects.equals(old[k], s[k])) {
						old[k] = UNKNOWN;
						changed = true;
					}
				}
			}
			if (changed && !queued[b]) {
				queued[b] = true;
				work.add(b);
			}
		}

		/** Blocks control can reach after instruction i; a known accumulator decides branches. */
		private List<Integer> successors(int i, Object[] s) {
			Instruction insn = code.get(i);
			String name = insn.name();
			List<Integer> out = new ArrayList<>(2);
			if (TERMINATORS.contains(name)) {
				return out;
			}
			int fall = i + 1 < code.size() ? blockOf[i + 1] : -1;
			if (name.equals("SwitchOnSmiNoFeedback")) {
				long[] op = insn.operands();
				if (s[0] instanceof Double d && d == Math.rint(d)) {
					long k = (long) (double) d - op[2];
					if (k < 0 || k >= op[1]) {
						add(out, fall);
						return out;
					}
					if (importer.constantPoolEntry(f, op[0] + k) instanceof Integer distance) {
						int t = at(insn.opcodeOffset() + distance);
						if (t >= 0) {
							add(out, blockOf[t]);
							return out;
						}
					}
				}
				for (int t : targets(insn)) {
					add(out, blockOf[t]);
				}
				add(out, fall);
				return out;
			}
			if (insn.isJumpImmediate() || insn.isJumpConstant()) {
				boolean always = UNCONDITIONAL.contains(name);
				Boolean taken = always ? Boolean.TRUE : condition(name, s[0]);
				if (taken == null || taken) {
					for (int t : targets(insn)) {
						add(out, blockOf[t]);
					}
				}
				if (!always && (taken == null || !taken)) {
					add(out, fall);
				}
				return out;
			}
			add(out, fall);
			return out;
		}

		private Boolean condition(String name, Object acc) {
			if (acc == UNKNOWN) {
				return null;
			}
			String test = name.endsWith("Constant") ? name.substring(0, name.length() - 8) : name;
			try {
				switch (test) {
					case "JumpIfTrue":
						return acc instanceof Boolean b ? b : null;
					case "JumpIfFalse":
						return acc instanceof Boolean b ? !b : null;
					case "JumpIfToBooleanTrue":
						return Js.toBoolean(acc);
					case "JumpIfToBooleanFalse":
						return !Js.toBoolean(acc);
					case "JumpIfNull":
						return acc == Js.NULL;
					case "JumpIfNotNull":
						return acc != Js.NULL;
					case "JumpIfUndefined":
						return acc == Js.UNDEFINED;
					case "JumpIfNotUndefined":
						return acc != Js.UNDEFINED;
					case "JumpIfUndefinedOrNull":
						return acc == Js.UNDEFINED || acc == Js.NULL;
					case "JumpIfJSReceiver":
						return acc instanceof JsObject || acc instanceof Closure || acc instanceof Native;
					default:
						return null;
				}
			}
			catch (RuntimeException e) {
				return null;
			}
		}

		// ---- one instruction ----------------------------------------------------------

		/** State slot of a register operand, or -1 (context, closure, out of range). */
		private int slot(long r) {
			if (r >= 2) {
				long i = r - 2;
				return i < params ? (int) (1 + i) : -1;
			}
			if (r <= -6) {
				long i = -6 - r;
				return i < f.registerCount ? (int) (1 + params + i) : -1;
			}
			return -1;
		}

		private Object get(Object[] s, long r) {
			int k = slot(r);
			return k < 0 ? UNKNOWN : s[k];
		}

		private void set(Object[] s, long r, Object v) {
			int k = slot(r);
			if (k >= 0) {
				s[k] = v;
			}
		}

		private Object[] list(Object[] s, long first, long count) {
			Object[] values = new Object[(int) Math.max(count, 0)];
			for (int k = 0; k < values.length; k++) {
				values[k] = get(s, first - k);
			}
			return values;
		}

		private Address address(Instruction insn) {
			return f.entry.add(insn.offset());
		}

		/**
		 * Applies one instruction. The final pass ({@code effects}) also records
		 * stores to variables, objects that may change, and the results.
		 */
		private void step(Instruction insn, Object[] s, boolean effects) {
			long[] op = insn.operands();
			String name = insn.name();
			switch (name) {
				case "LdaZero":
					s[0] = 0.0;
					return;
				case "LdaSmi":
					s[0] = (double) op[0];
					return;
				case "LdaUndefined":
					s[0] = Js.UNDEFINED;
					return;
				case "LdaNull":
					s[0] = Js.NULL;
					return;
				case "LdaTheHole":
					s[0] = Js.HOLE;
					return;
				case "LdaTrue":
					s[0] = Boolean.TRUE;
					return;
				case "LdaFalse":
					s[0] = Boolean.FALSE;
					return;
				case "LdaConstant":
					s[0] = constant(op[0]);
					return;
				case "Ldar":
					s[0] = get(s, op[0]);
					return;
				case "Star":
					set(s, op[0], s[0]);
					return;
				case "Mov":
					set(s, op[1], get(s, op[0]));
					return;

				case "LdaGlobal":
				case "LdaGlobalInsideTypeof":
					s[0] = global(insn);
					return;
				case "StaGlobal":
					if (effects) {
						store(insn, s[0]);
						changes(s[0]);
					}
					return;
				case "LdaContextSlot":
				case "LdaImmutableContextSlot":
				case "LdaCurrentContextSlot":
				case "LdaImmutableCurrentContextSlot": {
					Long cell = importer.cell(address(insn));
					Object v = cell == null ? null : in.cellValues.get(cell);
					s[0] = v == null ? UNKNOWN : v;
					return;
				}
				case "StaContextSlot":
				case "StaCurrentContextSlot":
					if (effects) {
						store(insn, s[0]);
					}
					return;

				case "LdaNamedProperty":
				case "LdaNamedPropertyNoFeedback":
					s[0] = property(get(s, op[0]), constant(op[1]));
					return;
				case "LdaKeyedProperty":
					if (effects) {
						key(insn, s[0]);
					}
					s[0] = property(get(s, op[0]), s[0]);
					return;
				case "StaKeyedProperty":
					if (effects) {
						key(insn, get(s, op[1]));
						changes(get(s, op[0]));
						changes(s[0]);
					}
					return;
				case "StaNamedProperty":
				case "StaNamedPropertyNoFeedback":
				case "StaNamedOwnProperty":
				case "StaInArrayLiteral":
				case "StaDataPropertyInLiteral":
					if (effects) {
						changes(get(s, op[0]));
						changes(s[0]);
					}
					return;

				case "Add":
					if (effects && last && get(s, op[0]) instanceof String a && s[0] instanceof String b) {
						result.concatenations.put(address(insn), a + b);
					}
					s[0] = binary(name, get(s, op[0]), s[0]);
					return;
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
					s[0] = binary(name, get(s, op[0]), s[0]);
					return;
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
					s[0] = binary(name.substring(0, name.length() - 3), s[0], (double) op[0]);
					return;
				case "Inc":
					s[0] = unary(s[0], v -> Js.toNumber(v) + 1);
					return;
				case "Dec":
					s[0] = unary(s[0], v -> Js.toNumber(v) - 1);
					return;
				case "Negate":
					s[0] = unary(s[0], v -> -Js.toNumber(v));
					return;
				case "BitwiseNot":
					s[0] = unary(s[0], v -> (double) ~Js.toInt32(Js.toNumber(v)));
					return;
				case "ToNumber":
				case "ToNumeric":
					s[0] = unary(s[0], Js::toNumber);
					return;
				case "ToString":
					s[0] = unary(s[0], Js::toStr);
					return;
				case "ToName":
					set(s, op[0], unary(s[0], Js::toKey));
					return;
				case "LogicalNot":
					s[0] = s[0] instanceof Boolean b ? !b : UNKNOWN;
					return;
				case "ToBooleanLogicalNot":
					s[0] = unary(s[0], v -> !Js.toBoolean(v));
					return;
				case "TypeOf":
					s[0] = s[0] == UNKNOWN ? UNKNOWN : attempt(() -> Js.typeOf(s[0]));
					return;
				case "TestTypeOf": {
					String literal = Js.typeofLiteral(op[0]);
					s[0] = s[0] == UNKNOWN ? UNKNOWN : attempt(() -> Js.typeOf(s[0]).equals(literal));
					return;
				}
				case "TestEqual":
				case "TestEqualStrict":
					if (effects && last && get(s, op[0]) instanceof String a && s[0] instanceof String b) {
						result.comparisons.put(address(insn), a.equals(b));
					}
					s[0] = test(get(s, op[0]), s[0], name.equals("TestEqual") ? Js::looseEquals : Js::strictEquals);
					return;
				case "TestReferenceEqual":
					s[0] = test(get(s, op[0]), s[0], Js::strictEquals);
					return;
				case "TestLessThan":
				case "TestGreaterThan":
				case "TestLessThanOrEqual":
				case "TestGreaterThanOrEqual":
					s[0] = test(get(s, op[0]), s[0], (a, b) -> Js.compare(name, a, b));
					return;
				case "TestNull":
					s[0] = s[0] == UNKNOWN ? UNKNOWN : (Object) (s[0] == Js.NULL);
					return;
				case "TestUndefined":
					s[0] = s[0] == UNKNOWN ? UNKNOWN : (Object) (s[0] == Js.UNDEFINED);
					return;
				case "TestUndetectable":
					s[0] = s[0] == UNKNOWN ? UNKNOWN : (Object) (s[0] == Js.NULL || s[0] == Js.UNDEFINED);
					return;

				case "CallUndefinedReceiver":
					s[0] = call(insn, get(s, op[0]), Js.UNDEFINED, list(s, op[1], op[2]), effects);
					return;
				case "CallUndefinedReceiver0":
					s[0] = call(insn, get(s, op[0]), Js.UNDEFINED, new Object[0], effects);
					return;
				case "CallUndefinedReceiver1":
					s[0] = call(insn, get(s, op[0]), Js.UNDEFINED, new Object[] { get(s, op[1]) }, effects);
					return;
				case "CallUndefinedReceiver2":
					s[0] = call(insn, get(s, op[0]), Js.UNDEFINED, new Object[] { get(s, op[1]), get(s, op[2]) },
						effects);
					return;
				case "CallProperty":
				case "CallAnyReceiver":
				case "CallNoFeedback": {
					Object[] all = list(s, op[1], op[2]);
					s[0] = all.length == 0 ? UNKNOWN
							: call(insn, get(s, op[0]), all[0], Arrays.copyOfRange(all, 1, all.length), effects);
					return;
				}
				case "CallProperty0":
					s[0] = call(insn, get(s, op[0]), get(s, op[1]), new Object[0], effects);
					return;
				case "CallProperty1":
					s[0] = call(insn, get(s, op[0]), get(s, op[1]), new Object[] { get(s, op[2]) }, effects);
					return;
				case "CallProperty2":
					s[0] = call(insn, get(s, op[0]), get(s, op[1]), new Object[] { get(s, op[2]), get(s, op[3]) },
						effects);
					return;

				case "CreateClosure": {
					JsFunction g = importer.function(importer.constantPoolEntry(f, op[0]));
					s[0] = g == null ? UNKNOWN : new Closure(g, Context.STATIC);
					return;
				}
				case "CreateObjectLiteral":
				case "CreateArrayLiteral":
					s[0] = literal(insn, op[0]);
					return;
				case "ResumeGenerator":
					// The saved registers come back as they were.
					s[0] = UNKNOWN;
					return;
				case "Return":
				case "Throw":
				case "ReThrow":
				case "SuspendGenerator":
					if (effects) {
						changes(s[0]);
					}
					return;
				case "SwitchOnGeneratorState":
				case "SwitchOnSmiNoFeedback":
				case "ThrowReferenceErrorIfHole":
				case "ThrowSuperNotCalledIfHole":
				case "ThrowSuperAlreadyCalledIfNotHole":
				case "Debugger":
				case "IncBlockCounter":
				case "CollectTypeProfile":
					return;
				default:
					if (name.startsWith("Jump")) {
						return;
					}
					unmodelled(insn, s, effects);
			}
		}

		/** Anything else: its outputs are unknown, and objects it is given may change. */
		private void unmodelled(Instruction insn, Object[] s, boolean effects) {
			List<String> kinds = insn.bytecode().operands();
			long[] op = insn.operands();
			String use = insn.bytecode().accumulator();
			if (effects) {
				if (use.equals("Read") || use.equals("ReadWrite")) {
					changes(s[0]);
				}
				for (int i = 0; i < kinds.size() && i < op.length; i++) {
					int count = switch (kinds.get(i)) {
						case "Reg" -> 1;
						case "RegPair" -> 2;
						case "RegList" -> i + 1 < op.length ? (int) op[i + 1] : 0;
						default -> 0;
					};
					for (int k = 0; k < count; k++) {
						changes(get(s, op[i] - k));
					}
				}
			}
			for (int i = 0; i < kinds.size() && i < op.length; i++) {
				int count = switch (kinds.get(i)) {
					case "RegOut" -> 1;
					case "RegOutPair" -> 2;
					case "RegOutTriple" -> 3;
					case "RegOutList" -> i + 1 < op.length ? (int) op[i + 1] : 0;
					default -> 0;
				};
				for (int k = 0; k < count; k++) {
					set(s, op[i] - k, UNKNOWN);
				}
			}
			if (use.equals("Write") || use.equals("ReadWrite")) {
				s[0] = UNKNOWN;
			}
		}

		private Object constant(long index) {
			Object e = importer.constantPoolEntry(f, index);
			if (e == null) {
				return UNKNOWN;
			}
			try {
				Object v = in.value(e);
				return isValue(v) ? v : UNKNOWN;
			}
			catch (RuntimeException ex) {
				return UNKNOWN;
			}
		}

		/** A global: its single known value, else the built-in when the program never assigns it. */
		private Object global(Instruction insn) {
			Long cell = importer.cell(address(insn));
			Object v = cell == null ? null : in.cellValues.get(cell);
			if (v == null && (cell == null || !storeSites.containsKey(cell))) {
				String name = heap.string(importer.constantPoolEntry(f, insn.operands()[0]));
				v = name == null ? null : in.global.properties.get(name);
			}
			return v == null ? UNKNOWN : v;
		}

		private void store(Instruction insn, Object v) {
			Long cell = importer.cell(address(insn));
			if (cell != null && v != Js.HOLE) {
				stores.merge(cell, v, (a, b) -> Objects.equals(a, b) ? a : UNKNOWN);
			}
		}

		private void key(Instruction insn, Object key) {
			if (last && key instanceof String k) {
				result.keys.put(address(insn), k);
			}
		}

		/** Properties of strings, built-ins, and literal objects nothing changes. */
		private Object property(Object target, Object key) {
			if (target == UNKNOWN || key == UNKNOWN) {
				return UNKNOWN;
			}
			if (target instanceof JsObject o ? o.epoch != Interpreter.NO_EPOCH || !o.constant
					: !(target instanceof String || target instanceof Native)) {
				return UNKNOWN;
			}
			try {
				Object v = Js.getProperty(target, key);
				return isValue(v) ? v : UNKNOWN;
			}
			catch (Throw | RuntimeException e) {
				return UNKNOWN;
			}
		}

		private Object binary(String op, Object a, Object b) {
			if (!isPrimitive(a) || !isPrimitive(b)) {
				return UNKNOWN;
			}
			return attempt(() -> Js.binary(op, a, b));
		}

		private Object unary(Object v, Function<Object, Object> op) {
			return isPrimitive(v) ? attempt(() -> op.apply(v)) : UNKNOWN;
		}

		/** Comparisons of primitives only: a literal object stands for every object its site creates. */
		private Object test(Object a, Object b, BiPredicate<Object, Object> p) {
			if (!isPrimitive(a) || !isPrimitive(b)) {
				return UNKNOWN;
			}
			return attempt(() -> p.test(a, b));
		}

		private Object attempt(Supplier<Object> operation) {
			try {
				Object v = operation.get();
				return isValue(v) ? v : UNKNOWN;
			}
			catch (RuntimeException e) {
				return UNKNOWN;
			}
		}

		private Object call(Instruction insn, Object callee, Object receiver, Object[] args, boolean effects) {
			Evaluation e = evaluate(callee, receiver, args);
			if (e == null) {
				if (effects) {
					changes(receiver);
					for (Object a : args) {
						changes(a);
					}
				}
				return UNKNOWN;
			}
			if (effects && last && e.readArray() && e.value() instanceof String s && CALLS.contains(insn.name())) {
				result.calls.put(address(insn), s);
			}
			return e.value();
		}

		private Object literal(Instruction insn, long index) {
			Address at = address(insn);
			Object o = literals.get(at);
			if (o == null) {
				try {
					o = in.literal(importer.constantPoolEntry(f, index), Interpreter.NO_EPOCH);
				}
				catch (RuntimeException e) {
					o = UNKNOWN;
				}
				literals.put(at, o);
			}
			return o;
		}
	}
}
