package v8_bytecode.loader;

import java.util.*;

import ghidra.program.model.address.Address;
import v8_bytecode.loader.FunctionImporter.Handler;
import v8_bytecode.loader.FunctionImporter.JsFunction;
import v8_bytecode.model.Ignition.Instruction;
import v8_bytecode.model.V8Heap;
import v8_bytecode.model.V8Heap.ScopeInfo;
import v8_bytecode.snapshot.HeapObject;

/**
 * Finds which variable each context slot access refers to.
 *
 * A context belongs to the scope whose ScopeInfo created it, and the
 * ScopeInfo of a function links to the scopes of the contexts it is closed
 * over (the chain mirrors the context chain). From there, the tracker follows
 * the current context and the registers holding contexts through
 * Create*Context, PushContext, PopContext, Star, Ldar and Mov, along the
 * control flow: V8 pops contexts before a break or return leaves a block, so
 * the code after such a jump is still inside the block. Every point has a
 * single context chain, so the first state reaching an instruction is kept.
 */
final class ContextTracker {
	/** The register operand of the current context (frame slot -1). */
	private static final long CONTEXT_REGISTER = -1;
	/** Operand of register r0 (kRegisterFileStartOffset); r<i> is this minus i. */
	private static final long REGISTER_FILE_START = -6;

	private static final Set<String> TERMINATORS = Set.of("Return", "Throw", "ReThrow", "Abort", "Illegal");
	private static final Set<String> UNCONDITIONAL = Set.of("Jump", "JumpConstant", "JumpLoop");

	/** A variable living in a context slot. */
	record Variable(ScopeInfo scope, int slot, String name) {
		/** The variable's identity: its scope (by object) and slot. */
		Slot key() {
			return new Slot(scope.object(), slot);
		}
	}

	/** HeapObject compares by identity, so this identifies one slot of one scope. */
	record Slot(HeapObject scope, int slot) {
	}

	/** Immutable chain of contexts, innermost first. */
	private record Chain(ScopeInfo scope, Chain outer) {
		ScopeInfo at(long depth) {
			Chain c = this;
			for (long i = 0; i < depth && c != null; i++) {
				c = c.outer;
			}
			return c == null ? null : c.scope;
		}
	}

	/** Contexts known at one program point: the current one, the accumulator, registers. */
	private static final class State {
		Chain current;
		Chain acc;
		final Map<Long, Chain> registers;

		State(Chain current, Chain acc, Map<Long, Chain> registers) {
			this.current = current;
			this.acc = acc;
			this.registers = registers;
		}

		State copy() {
			return new State(current, acc, new HashMap<>(registers));
		}

		Chain get(long register) {
			return register == CONTEXT_REGISTER ? current : registers.get(register);
		}

		void put(long register, Chain chain) {
			if (chain != null) {
				registers.put(register, chain);
			}
			else {
				registers.remove(register);
			}
		}
	}

	private final V8Heap heap;
	private final FunctionImporter importer;
	private final Map<HeapObject, Chain> closureChains = new IdentityHashMap<>();
	private final Map<HeapObject, JsFunction> owners = new IdentityHashMap<>();
	private final Map<Address, Variable> variables = new HashMap<>();
	private int checkedClosures;
	private int matchingClosures;
	private int unresolved;

	ContextTracker(V8Heap heap, FunctionImporter importer) {
		this.heap = heap;
		this.importer = importer;
	}

	/** Variables of the context slot accesses, by instruction address. */
	Map<Address, Variable> run(List<JsFunction> functions) {
		for (JsFunction f : functions) {
			ScopeInfo own = ownScope(f);
			if (own != null) {
				owners.putIfAbsent(own.object(), f);
			}
		}
		// Literal ids follow source order: a closure's creator comes first, which
		// functions without a ScopeInfo of their own rely on.
		for (JsFunction f : functions) {
			walk(f);
		}
		// Check the walk against the declared chains of the closures it created.
		for (JsFunction f : functions) {
			ScopeInfo own = ownScope(f);
			if (own != null && closureChains.containsKey(f.sfi)) {
				checkedClosures++;
				if (sameScopes(closureChains.get(f.sfi), outerChain(own))) {
					matchingClosures++;
				}
			}
		}
		return variables;
	}

	/** The function a scope belongs to: its own function, or the one creating its context. */
	JsFunction owner(ScopeInfo scope) {
		return owners.get(scope.object());
	}

	/** Every scope seen (ScopeInfo object) with the function it belongs to. */
	Map<HeapObject, JsFunction> owners() {
		return owners;
	}

	int unresolvedAccesses() {
		return unresolved;
	}

	/** Closures whose context at creation matches their ScopeInfo chain. */
	String closureAgreement() {
		return matchingClosures + "/" + checkedClosures;
	}

	private ScopeInfo ownScope(JsFunction f) {
		return heap.scopeInfo(f.sfi.slot(V8Heap.SFI_NAME_OR_SCOPE_INFO));
	}

	/** Contexts around a scope: its ScopeInfo's outer chain (null when there are none). */
	private Chain outerChain(ScopeInfo own) {
		List<ScopeInfo> scopes = new ArrayList<>();
		HeapObject outer = own.outer();
		while (outer != null && scopes.size() < 256) {
			ScopeInfo s = heap.scopeInfo(outer);
			if (s == null) {
				break;
			}
			scopes.add(s);
			outer = s.outer();
		}
		Chain chain = null;
		for (int i = scopes.size() - 1; i >= 0; i--) {
			chain = new Chain(scopes.get(i), chain);
		}
		return chain;
	}

	private static boolean sameScopes(Chain a, Chain b) {
		while (a != null && b != null) {
			if (a.scope.object() != b.scope.object()) {
				return false;
			}
			a = a.outer;
			b = b.outer;
		}
		return a == null && b == null;
	}

	private void walk(JsFunction f) {
		List<Instruction> code = importer.decode(f);
		if (code.isEmpty()) {
			return;
		}
		ScopeInfo own = ownScope(f);
		Chain entry = own != null ? outerChain(own) : closureChains.get(f.sfi);
		if (own != null && own.scopeType().equals("script")) {
			// The script context exists before the script's code runs.
			entry = new Chain(own, entry);
		}
		Map<Integer, Integer> index = new HashMap<>();
		for (int i = 0; i < code.size(); i++) {
			index.put(code.get(i).offset(), i);
		}
		Map<Integer, List<Handler>> tries = new HashMap<>();
		for (Handler h : importer.handlers(f)) {
			tries.computeIfAbsent(h.start(), k -> new ArrayList<>()).add(h);
		}

		State[] before = new State[code.size()];
		State[] after = new State[code.size()];
		Deque<Integer> work = new ArrayDeque<>();
		before[0] = new State(entry, null, new HashMap<>());
		work.push(0);
		int unvisited = 0;
		while (true) {
			while (!work.isEmpty()) {
				int i = work.pop();
				if (after[i] != null) {
					continue;
				}
				Instruction insn = code.get(i);
				State in = before[i];
				for (Handler h : tries.getOrDefault(insn.offset(), List.of())) {
					// The handler runs in the context saved in its register at try entry.
					State caught = in.copy();
					caught.acc = null;
					Chain saved = in.registers.get(REGISTER_FILE_START - h.contextRegister());
					caught.current = saved != null ? saved : in.current;
					enqueue(index.get(h.handler()), caught, before, work);
				}
				State out = in.copy();
				step(f, insn, out);
				after[i] = out;
				List<Integer> next = successors(f, code, i, index);
				// Push the fall-through last so the walk follows the code layout first.
				for (int k = next.size() - 1; k >= 0; k--) {
					enqueue(next.get(k), k == 0 ? out : out.copy(), before, work);
				}
			}
			// Dead code, and resume points only reached from SwitchOnGeneratorState,
			// continue from the instruction before them.
			while (unvisited < code.size() && after[unvisited] != null) {
				unvisited++;
			}
			if (unvisited == code.size()) {
				break;
			}
			if (before[unvisited] == null) {
				before[unvisited] = unvisited > 0 && after[unvisited - 1] != null
						? after[unvisited - 1].copy()
						: new State(entry, null, new HashMap<>());
			}
			work.push(unvisited);
		}
	}

	private static void enqueue(Integer i, State state, State[] before, Deque<Integer> work) {
		if (i != null && before[i] == null) {
			before[i] = state;
			work.push(i);
		}
	}

	/** Instructions control can reach next, the fall-through first. */
	private List<Integer> successors(JsFunction f, List<Instruction> code, int i,
			Map<Integer, Integer> index) {
		Instruction insn = code.get(i);
		String name = insn.name();
		List<Integer> next = new ArrayList<>();
		if (TERMINATORS.contains(name)) {
			return next;
		}
		if (!UNCONDITIONAL.contains(name) && i + 1 < code.size()) {
			next.add(i + 1);
		}
		if (insn.isJumpImmediate()) {
			next.add(index.get(insn.immediateJumpTarget()));
		}
		else if (insn.isJumpConstant()) {
			if (importer.constantPoolEntry(f, insn.operands()[0]) instanceof Integer distance) {
				next.add(index.get(insn.opcodeOffset() + distance));
			}
		}
		else if (name.equals("SwitchOnSmiNoFeedback")) {
			long start = insn.operands()[0];
			for (long k = 0; k < insn.operands()[1]; k++) {
				if (importer.constantPoolEntry(f, start + k) instanceof Integer distance) {
					next.add(index.get(insn.opcodeOffset() + distance));
				}
			}
		}
		// SwitchOnGeneratorState targets are resume points: the context there is
		// the one saved by SuspendGenerator, which falls through to them.
		next.removeIf(Objects::isNull);
		return next;
	}

	/** Applies one instruction to the state, recording the context slot it accesses. */
	private void step(JsFunction f, Instruction insn, State s) {
		long[] op = insn.operands();
		Address at = f.entry.add(insn.offset());
		Chain created = null;
		switch (insn.name()) {
			case "CreateFunctionContext":
			case "CreateEvalContext":
			case "CreateBlockContext":
				created = push(f, op[0], s.current);
				break;
			case "CreateCatchContext":
			case "CreateWithContext":
				created = push(f, op[1], s.current);
				break;
			case "PushContext":
				s.put(op[0], s.current);
				s.current = s.acc;
				return;
			case "PopContext":
				s.current = s.registers.get(op[0]);
				return;
			case "Star":
				s.put(op[0], s.acc);
				return;
			case "Ldar":
				s.acc = s.get(op[0]);
				return;
			case "Mov":
				s.put(op[1], s.get(op[0]));
				return;
			case "LdaCurrentContextSlot":
			case "LdaImmutableCurrentContextSlot":
			case "StaCurrentContextSlot":
				resolve(at, s.current, op[0], 0);
				break;
			case "LdaContextSlot":
			case "LdaImmutableContextSlot":
			case "StaContextSlot":
				resolve(at, s.get(op[0]), op[1], op[2]);
				break;
			case "CreateClosure":
				if (importer.constantPoolEntry(f, op[0]) instanceof HeapObject sfi &&
					heap.isSharedFunctionInfo(sfi)) {
					closureChains.putIfAbsent(sfi, s.current);
				}
				break;
			case "ResumeGenerator":
				// Restores the registers saved by SuspendGenerator: contexts kept in
				// registers are the same objects again.
				return;
			default:
				break;
		}
		if (writesAccumulator(insn)) {
			s.acc = created;
		}
		clobberOutputs(insn, s.registers);
	}

	private Chain push(JsFunction f, long index, Chain current) {
		ScopeInfo scope = heap.scopeInfo(importer.constantPoolEntry(f, index));
		if (scope == null) {
			return null;
		}
		owners.putIfAbsent(scope.object(), f);
		return new Chain(scope, current);
	}

	private void resolve(Address at, Chain chain, long slot, long depth) {
		ScopeInfo scope = chain == null ? null : chain.at(depth);
		String name = scope == null ? null : scope.slotName((int) slot);
		if (name == null || name.isEmpty()) {
			unresolved++;
			return;
		}
		variables.put(at, new Variable(scope, (int) slot, name));
	}

	private static boolean writesAccumulator(Instruction insn) {
		String use = insn.bytecode().accumulator();
		return use.equals("Write") || use.equals("ReadWrite");
	}

	/** Forgets contexts held in registers the instruction overwrites. */
	private static void clobberOutputs(Instruction insn, Map<Long, Chain> registers) {
		List<String> kinds = insn.bytecode().operands();
		long[] op = insn.operands();
		for (int i = 0; i < kinds.size(); i++) {
			int count;
			switch (kinds.get(i)) {
				case "RegOut":
					count = 1;
					break;
				case "RegOutPair":
					count = 2;
					break;
				case "RegOutTriple":
					count = 3;
					break;
				case "RegOutList":
					count = i + 1 < op.length ? (int) op[i + 1] : 0;
					break;
				default:
					continue;
			}
			// Consecutive registers have decreasing operands (Ignition.java).
			for (int k = 0; k < count; k++) {
				registers.remove(op[i] - k);
			}
		}
	}
}
