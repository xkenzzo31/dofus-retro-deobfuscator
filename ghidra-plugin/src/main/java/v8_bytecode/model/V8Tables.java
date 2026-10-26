package v8_bytecode.model;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import generic.jar.ResourceFile;
import ghidra.framework.Application;

/**
 * Tables of V8 8.7.220.31: Ignition bytecodes, runtime functions and intrinsics
 * (data/v8_87_bytecodes.json, written by tools/extract_v8_tables.py), the
 * read-only roots (data/v8_roots.json), and the strings of the read-only heap
 * that are not roots (data/v8_ro_strings.json, written by
 * tools/extract_ro_strings.py from Electron's snapshot).
 */
public final class V8Tables {

	/**
	 * One Ignition bytecode: opcode, name, accumulator use (None, Read, Write,
	 * ReadWrite) and operand types (OperandType::k*).
	 */
	public record Bytecode(int opcode, String name, String accumulator, List<String> operands) {
	}

	public final List<Bytecode> bytecodes = new ArrayList<>();
	public final List<String> runtimeFunctions = new ArrayList<>();
	public final List<String> intrinsics = new ArrayList<>();
	public final List<String> roots = new ArrayList<>();
	/** Value of each root that is an internalized string (null for other roots). */
	public final List<String> rootStrings = new ArrayList<>();
	private final Map<String, Integer> rootIndex = new HashMap<>();
	/** Strings of the read-only heap by page << 32 | offset in the page. */
	private final Map<Long, String> readOnlyStrings = new HashMap<>();
	private final Map<String, Bytecode> byName = new HashMap<>();

	private static V8Tables instance;

	/** Tables shipped in the extension's data directory. */
	public static synchronized V8Tables get() throws IOException {
		if (instance == null) {
			ResourceFile bytecodes = Application.getModuleDataFile("v8_87_bytecodes.json");
			ResourceFile roots = Application.getModuleDataFile("v8_roots.json");
			ResourceFile readOnly = Application.getModuleDataFile("v8_ro_strings.json");
			instance = new V8Tables(bytecodes.getFile(false), roots.getFile(false), readOnly.getFile(false));
		}
		return instance;
	}

	public V8Tables(File bytecodesJson, File rootsJson, File readOnlyStringsJson) throws IOException {
		JsonObject tables = parse(bytecodesJson).getAsJsonObject();
		int opcode = 0;
		for (JsonElement e : tables.getAsJsonArray("bytecodes")) {
			JsonObject b = e.getAsJsonObject();
			List<String> operands = new ArrayList<>();
			for (JsonElement o : b.getAsJsonArray("operands")) {
				operands.add(o.getAsString());
			}
			Bytecode bytecode = new Bytecode(opcode++, b.get("name").getAsString(),
				b.get("accumulator").getAsString(), List.copyOf(operands));
			bytecodes.add(bytecode);
			byName.put(bytecode.name(), bytecode);
		}
		for (JsonElement e : tables.getAsJsonArray("runtime_functions")) {
			runtimeFunctions.add(e.getAsJsonObject().get("name").getAsString());
		}
		for (JsonElement e : tables.getAsJsonArray("intrinsics")) {
			intrinsics.add(e.getAsJsonObject().get("name").getAsString());
		}
		// Names of string roots are their values (v8_roots.json "Type": "str"),
		// except the empty string's.
		for (JsonElement e : parse(rootsJson).getAsJsonArray()) {
			JsonObject root = e.getAsJsonObject();
			String name = root.get("Name").getAsString();
			boolean string = root.has("Type") && root.get("Type").getAsString().equals("str");
			if (!string) {
				rootIndex.putIfAbsent(name, roots.size());
			}
			roots.add(name);
			rootStrings.add(!string ? null : name.equals("empty_string") ? "" : name);
		}
		for (JsonElement e : parse(readOnlyStringsJson).getAsJsonObject().getAsJsonArray("strings")) {
			JsonObject s = e.getAsJsonObject();
			readOnlyStrings.put((s.get("page").getAsLong() << 32) | s.get("offset").getAsLong(),
				s.get("value").getAsString());
		}
	}

	private static JsonElement parse(File file) throws IOException {
		try (Reader reader = new FileReader(file)) {
			return JsonParser.parseReader(reader);
		}
	}

	public Bytecode bytecode(String name) {
		return byName.get(name);
	}

	public String rootName(int index) {
		return index >= 0 && index < roots.size() ? roots.get(index) : "Root" + index;
	}

	/** The string a root holds, or null when the root is not a string. */
	public String rootString(int index) {
		return index >= 0 && index < rootStrings.size() ? rootStrings.get(index) : null;
	}

	/** The string at an offset of a read-only heap page, or null when unknown. */
	public String readOnlyString(int page, int offset) {
		return readOnlyStrings.get(((long) page << 32) | offset);
	}

	/** Index of a read-only root by name (e.g. "UndefinedValue"), or -1. */
	public int rootIndex(String name) {
		return rootIndex.getOrDefault(name, -1);
	}
}
