package v8_bytecode.storage;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import v8_bytecode.RuntimeFuncArg;

/**
 * V8 8.7 runtime and intrinsic function store.
 *
 * In V8 8.7, runtime functions and inline intrinsics are both in the same
 * list (loaded from v8_funcs.json). Intrinsics have names starting with
 * "Inline" (after stripping the "k" prefix). They appear at the end of the list.
 */
public final class RuntimesIntrinsicsStore implements Serializable {
	private final List<List<RuntimeFuncArg>> allArgs;
	private final List<String> names;

	// Indices of intrinsic functions within the names list
	private final List<Integer> intrinsicIndices;

	public RuntimesIntrinsicsStore(final List<String> names, final List<List<RuntimeFuncArg>> allArgs) {
		this.allArgs = allArgs;
		this.names = names;

		// Detect intrinsics: names starting with "Inline" (after k prefix was stripped)
		this.intrinsicIndices = new ArrayList<>();
		for (int i = 0; i < names.size(); i++) {
			if (names.get(i).startsWith("Inline")) {
				intrinsicIndices.add(i);
			}
		}
	}

	public List<RuntimeFuncArg> getArgs(int index) {
		if (index >= 0 && index < allArgs.size()) {
			return allArgs.get(index);
		}
		return List.of();
	}

	public List<String> getNames() {
		return names;
	}

	public int getNamesCount() {
		return names.size();
	}

	public String getRuntimeName(int index) {
		if (index >= 0 && index < names.size()) {
			return names.get(index);
		}
		return "Runtime_" + index;
	}

	public int getIntrinsicsCount() {
		return intrinsicIndices.size();
	}

	public String getIntrinsicName(int index) {
		if (index >= 0 && index < intrinsicIndices.size()) {
			return String.format("_%s", names.get(intrinsicIndices.get(index)));
		}
		return "_Intrinsic_" + index;
	}
}
