/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package v8_bytecode;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.storage.FuncsStorage;

/**
 * Post-analysis enrichment pass that injects decoded strings and function names
 * from the jsc-deobfuscator pipeline into the Ghidra listing.
 *
 * Data source: data/v8_ghidra_strings.json (main.ghidra.json from jsc-deobfuscator)
 *
 * This analyzer:
 *   1. Renames functions using deobfuscated names from the pipeline
 *   2. Adds plate comments to functions with metadata
 *   3. Annotates constant-pool-referencing instructions with resolved string values
 *      as EOL comments, resolving obfuscated _0x... references to readable strings
 *
 * Matching strategy:
 *   - Ghidra SFI loader names functions "func_NNNN" (decimal functionLiteralId)
 *   - Pipeline functions have an "index" field (sequential) and a "name" field
 *   - We match by name first, then by "func_NNNN" -> pipeline index mapping
 *   - For CP string annotation, we use the FuncsStorage (internal Ghidra data)
 *     when available, with pipeline data as a supplementary source
 *
 * Runs AFTER V8RefsAnalyzer (which resolves CP references and creates equates).
 */
public class V8_StringResolverAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "V8StringResolver";
	private static final String DESCRIPTION =
		"Enriches V8 bytecode with decoded strings and function names from the deobfuscation pipeline";

	// CP-referencing opcodes and their operand indices (mirrors V8_bytecodeAnalyzer)
	private static final Map<String, Integer> CP_OPERAND_INDEX = Map.ofEntries(
		Map.entry("LdaNamedProperty", 1),
		Map.entry("LdaNamedPropertyFromSuper", 1),
		Map.entry("StaNamedProperty", 1),
		Map.entry("StaNamedOwnProperty", 1),
		Map.entry("CreateObjectLiteral", 0),
		Map.entry("CreateClosure", 0),
		Map.entry("LdaConstant", 0),
		Map.entry("LdaGlobal", 0),
		Map.entry("LdaGlobalInsideTypeof", 0),
		Map.entry("StaGlobal", 0),
		Map.entry("CreateBlockContext", 0),
		Map.entry("CreateCatchContext", 1),
		Map.entry("ThrowReferenceErrorIfHole", 0)
	);

	public V8_StringResolverAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(V8_bytecodeLoader.LDR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(V8_bytecodeLoader.LDR_NAME);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		monitor.setMessage("[V8StringResolver] Loading decoded strings data...");

		// Load the enrichment data from the plugin's data directory
		JsonObject ghidraData;
		try {
			File dataFile = Application.getModuleDataFile("v8_ghidra_strings.json").getFile(false);
			String jsonContent = new String(Files.readAllBytes(dataFile.toPath()), "UTF-8");
			ghidraData = JsonParser.parseString(jsonContent).getAsJsonObject();
		} catch (IOException e) {
			System.out.println("[V8StringResolver] WARNING: v8_ghidra_strings.json not found: " + e.getMessage());
			return true;
		}

		// Parse function descriptors from the pipeline
		JsonArray functionsArray = ghidraData.getAsJsonArray("functions");
		List<FunctionInfo> functionInfos = new ArrayList<>();
		Map<String, FunctionInfo> infoByName = new HashMap<>();

		if (functionsArray != null) {
			for (int i = 0; i < functionsArray.size(); i++) {
				JsonObject funcObj = functionsArray.get(i).getAsJsonObject();
				FunctionInfo info = new FunctionInfo();
				info.index = funcObj.get("index").getAsInt();
				info.name = funcObj.get("name").getAsString();
				info.bytecodeLength = funcObj.get("bytecodeLength").getAsInt();
				info.parameterCount = funcObj.get("parameterCount").getAsInt();
				info.registerCount = funcObj.get("registerCount").getAsInt();
				info.instructionCount = funcObj.get("instructionCount").getAsInt();

				JsonArray cpArray = funcObj.getAsJsonArray("constantPool");
				if (cpArray != null) {
					info.constantPool = new String[cpArray.size()];
					for (int j = 0; j < cpArray.size(); j++) {
						info.constantPool[j] = cpArray.get(j).getAsString();
					}
				} else {
					info.constantPool = new String[0];
				}

				functionInfos.add(info);
				if (info.name != null && !info.name.isEmpty()) {
					infoByName.put(info.name, info);
				}
			}
		}
		System.out.println(String.format("[V8StringResolver] Loaded %d function descriptors from pipeline",
			functionInfos.size()));

		// Build an index -> FunctionInfo map (index = sequential position in pipeline)
		Map<Integer, FunctionInfo> infoByIndex = new HashMap<>();
		for (FunctionInfo info : functionInfos) {
			infoByIndex.put(info.index, info);
		}

		// Phase 1: Match and annotate Ghidra functions
		monitor.setMessage("[V8StringResolver] Matching functions...");
		final FunctionManager funcMgr = program.getFunctionManager();
		final Listing listing = program.getListing();
		int functionsMatched = 0;
		int functionsAnnotated = 0;
		int stringsResolved = 0;

		Map<Function, FunctionInfo> matchedFunctions = new HashMap<>();

		FunctionIterator funcIter = funcMgr.getFunctions(true);
		while (funcIter.hasNext()) {
			if (monitor.isCancelled()) break;
			Function func = funcIter.next();
			String funcName = func.getName();

			FunctionInfo info = null;

			// Strategy 1: exact name match
			info = infoByName.get(funcName);

			// Strategy 2: match "func_NNNN" (decimal) to pipeline by index
			// The SFI loader uses: String.format("func_%04d", functionLiteralId)
			if (info == null && funcName.startsWith("func_")) {
				try {
					int funcId = Integer.parseInt(funcName.substring(5));
					info = infoByIndex.get(funcId);
				} catch (NumberFormatException e) {
					// Try hex: maybe some IDs are in hex
					try {
						int funcId = Integer.parseInt(funcName.substring(5), 16);
						info = infoByIndex.get(funcId);
					} catch (NumberFormatException e2) {
						// Give up on this function
					}
				}
			}

			if (info != null) {
				matchedFunctions.put(func, info);

				// Add plate comment with function metadata
				String plateComment = String.format(
					"[Deob] %s | params=%d regs=%d bytecode=%dB instrs=%d cp_entries=%d",
					info.name, info.parameterCount, info.registerCount,
					info.bytecodeLength, info.instructionCount,
					info.constantPool.length);
				listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, plateComment);
				functionsAnnotated++;

				// Rename function if the pipeline name is more descriptive
				if (!info.name.startsWith("func_") && !info.name.matches("[a-zA-Z]{5}")
						&& !info.name.startsWith("_0x") && !info.name.startsWith("a0_0x")) {
					try {
						func.setName(info.name, SourceType.ANALYSIS);
						functionsMatched++;
					} catch (Exception e) {
						// Name collision or invalid name; keep the existing name
					}
				}
			}
		}

		System.out.println(String.format(
			"[V8StringResolver] Matched %d functions, renamed %d, annotated %d",
			matchedFunctions.size(), functionsMatched, functionsAnnotated));

		// Phase 2: Annotate CP-referencing instructions with resolved strings
		// Walk ALL instructions in matched functions and annotate using pipeline CP data
		monitor.setMessage("[V8StringResolver] Resolving constant pool strings...");

		for (Map.Entry<Function, FunctionInfo> entry : matchedFunctions.entrySet()) {
			if (monitor.isCancelled()) break;

			Function func = entry.getKey();
			FunctionInfo info = entry.getValue();

			Instruction instr = listing.getInstructionAt(func.getEntryPoint());
			Address funcEnd = func.getBody().getMaxAddress();

			while (instr != null && instr.getAddress().compareTo(funcEnd) <= 0) {
				String mnemonic = trimMnemonic(instr.getMnemonicString());
				Integer cpOpIdx = CP_OPERAND_INDEX.get(mnemonic);

				if (cpOpIdx != null) {
					try {
						int cpIndex = (int) (instr.getScalar(cpOpIdx).getValue() & 0xFFFFFFFF);
						if (cpIndex >= 0 && cpIndex < info.constantPool.length) {
							String cpValue = info.constantPool[cpIndex];
							String comment = formatCpComment(cpValue);
							if (comment != null) {
								appendEolComment(listing, instr.getAddress(), comment);
								stringsResolved++;
							}
						}
					} catch (Exception e) {
						// Skip: scalar access failure or out-of-bounds
					}
				}

				instr = instr.getNext();
			}
		}

		// Phase 3: Also try to annotate unmatched functions using the internal
		// FuncsStorage constant pool data (already resolved during SFI allocation).
		// This works for ALL functions that have FuncsStorage entries, regardless
		// of pipeline matching.
		monitor.setMessage("[V8StringResolver] Annotating via internal CP data...");
		int internalResolved = 0;

		try {
			FuncsStorage funcsStorage = FuncsStorage.load(program);
			if (funcsStorage != null) {
				FunctionIterator allFuncs = funcMgr.getFunctions(true);
				while (allFuncs.hasNext()) {
					if (monitor.isCancelled()) break;
					Function func = allFuncs.next();

					// Skip already-matched functions
					if (matchedFunctions.containsKey(func)) continue;

					Instruction instr = listing.getInstructionAt(func.getEntryPoint());
					Address funcEnd = func.getBody().getMaxAddress();

					while (instr != null && instr.getAddress().compareTo(funcEnd) <= 0) {
						String mnemonic = trimMnemonic(instr.getMnemonicString());
						Integer cpOpIdx = CP_OPERAND_INDEX.get(mnemonic);

						if (cpOpIdx != null) {
							try {
								int cpIndex = (int) (instr.getScalar(cpOpIdx).getValue() & 0xFFFFFFFF);
								Object cpItem = funcsStorage.getConstItem(instr.getAddress(), cpIndex);
								if (cpItem instanceof String) {
									String cpValue = (String) cpItem;
									String comment = formatCpComment(cpValue);
									if (comment != null) {
										appendEolComment(listing, instr.getAddress(), comment);
										internalResolved++;
									}
								}
							} catch (Exception e) {
								// Skip
							}
						}

						instr = instr.getNext();
					}
				}
			}
		} catch (Exception e) {
			System.out.println("[V8StringResolver] Internal CP resolution skipped: " + e.getMessage());
		}

		System.out.println(String.format(
			"[V8StringResolver] REPORT: %d functions annotated, %d pipeline strings, %d internal CP strings resolved",
			functionsAnnotated, stringsResolved, internalResolved));

		return true;
	}

	/**
	 * Format a constant pool value as a comment string.
	 * Returns null if the value is not interesting enough to annotate.
	 */
	private static String formatCpComment(String cpValue) {
		if (cpValue == null || cpValue.isEmpty() || cpValue.length() <= 2) {
			return null;
		}

		if (isObfuscatedRef(cpValue)) {
			return "[deob:ref] " + cpValue;
		}

		// Readable string value
		String display = cpValue.length() > 60 ? cpValue.substring(0, 57) + "..." : cpValue;
		return "\"" + escapeString(display) + "\"";
	}

	/**
	 * Append text to an existing EOL comment, or create a new one.
	 * Avoids duplicating the same annotation.
	 */
	private static void appendEolComment(Listing listing, Address addr, String newText) {
		String existing = listing.getComment(CodeUnit.EOL_COMMENT, addr);
		if (existing != null) {
			if (existing.contains(newText)) return; // Already present
			listing.setComment(addr, CodeUnit.EOL_COMMENT, existing + " | " + newText);
		} else {
			listing.setComment(addr, CodeUnit.EOL_COMMENT, newText);
		}
	}

	/**
	 * Check if a string looks like an obfuscated reference.
	 */
	private static boolean isObfuscatedRef(String value) {
		if (value == null || value.isEmpty()) return false;
		return value.matches("_0x[0-9a-fA-F]+")
			|| value.matches("a\\d+_0x[0-9a-fA-F]+");
	}

	private static String trimMnemonic(String mnemonic) {
		int dotPos = mnemonic.indexOf(".");
		return (dotPos != -1) ? mnemonic.substring(0, dotPos) : mnemonic;
	}

	private static String escapeString(String s) {
		return s.replace("\\", "\\\\")
				.replace("\"", "\\\"")
				.replace("\n", "\\n")
				.replace("\r", "\\r")
				.replace("\t", "\\t");
	}

	private static class FunctionInfo {
		int index;
		String name;
		int bytecodeLength;
		int parameterCount;
		int registerCount;
		int instructionCount;
		String[] constantPool;
	}
}
