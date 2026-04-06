// Resolve obfuscator.io string wrappers in V8 8.7 bytecode.
//
// This script enriches the Ghidra listing with deobfuscation data from the
// jsc-deobfuscator pipeline. It operates on functions already created by
// CreateV8Functions.java.
//
// What it does:
//   Phase 1: Tags ~5,043 wrapper functions (namespace + plate comments)
//     - Moves wrappers into "StringWrappers" namespace
//     - Each wrapper is a short function that computes an index from caller args,
//       passes it to a closure-bound decoder, which returns a decoded string.
//     - The resolved string depends on what arguments each CALLER passes,
//       so wrappers can't be statically resolved to a single string.
//
//   Phase 2: Annotates ~500 call sites with runtime-captured resolved strings
//     - Uses payload-offset-to-string mappings from the deob pipeline
//     - These are bytecode locations where the decoder was observed returning
//       a specific string at runtime.
//
//   Phase 3: Propagates runtime wrapper strings to xref call sites (when available)
//
//   Phase 4: Scans CP references for wrapper CreateClosure annotations
//
//   Phase 5: Static formula-based string resolution
//     - Loads wrapper formulas extracted from decompiled JavaScript
//     - For each call to a simple wrapper (236 wrappers with literal offsets),
//       finds nearby LdaSmi instructions and applies the formula:
//       string_index = smi_value OP offset
//     - Looks up the string in the decoded string array
//     - Annotates call sites with resolved strings
//
// Data sources:
//   data/v8_string_resolution.json (combined pipeline data)
//   data/v8_wrapper_formulas.json  (wrapper formulas + decoded strings)
//
// @author LuskaBot
// @category V8

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.ArrayList;
import com.google.gson.*;

public class ResolveWrappers extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== ResolveWrappers: Static string wrapper resolution ===");

        // Find the .v8payload block
        MemoryBlock payloadBlock = currentProgram.getMemory().getBlock(".v8payload");
        if (payloadBlock == null) {
            println("ERROR: No .v8payload block found.");
            return;
        }
        long baseAddr = payloadBlock.getStart().getOffset();
        println("Payload base: 0x" + Long.toHexString(baseAddr));

        // ── Load resolution data ────────────────────────────────────────────
        JsonObject resolution = loadJson("v8_string_resolution.json");
        if (resolution == null) {
            println("ERROR: v8_string_resolution.json not found.");
            return;
        }

        // Parse wrapper names set
        Set<String> wrapperNames = new HashSet<>();
        JsonArray wrapperArr = resolution.getAsJsonArray("wrapperNames");
        if (wrapperArr != null) {
            for (int i = 0; i < wrapperArr.size(); i++) {
                wrapperNames.add(wrapperArr.get(i).getAsString());
            }
        }
        println("Loaded " + wrapperNames.size() + " wrapper function names");

        // Parse callsite strings: payload_offset -> string
        Map<Long, String> callsiteStrings = new HashMap<>();
        JsonObject csObj = resolution.getAsJsonObject("callsiteStrings");
        if (csObj != null) {
            for (Map.Entry<String, JsonElement> entry : csObj.entrySet()) {
                try {
                    long offset = Long.parseLong(entry.getKey());
                    callsiteStrings.put(offset, entry.getValue().getAsString());
                } catch (NumberFormatException e) {
                    // skip
                }
            }
        }
        println("Loaded " + callsiteStrings.size() + " callsite string resolutions");

        // Parse runtime wrapper -> string mappings (runtime-observed, not bytecode-level names)
        Map<String, String> wrapperPrimaryString = new HashMap<>();
        JsonObject wrtObj = resolution.getAsJsonObject("wrapperRuntimeStrings");
        if (wrtObj != null) {
            for (Map.Entry<String, JsonElement> entry : wrtObj.entrySet()) {
                String wrapperName = entry.getKey();
                JsonArray resolutions = entry.getValue().getAsJsonArray();
                if (resolutions != null && resolutions.size() > 0) {
                    String bestString = null;
                    int bestCount = 0;
                    for (int i = 0; i < resolutions.size(); i++) {
                        JsonObject r = resolutions.get(i).getAsJsonObject();
                        int count = r.get("count").getAsInt();
                        if (count > bestCount) {
                            bestCount = count;
                            bestString = r.get("string").getAsString();
                        }
                    }
                    if (bestString != null) {
                        wrapperPrimaryString.put(wrapperName, bestString);
                    }
                }
            }
        }
        println("Loaded " + wrapperPrimaryString.size() + " runtime-resolved wrapper strings");

        // Parse good/trap string classification
        Set<String> trapStringValues = new HashSet<>();
        JsonObject trapsObj = resolution.getAsJsonObject("trapStrings");
        if (trapsObj != null) {
            for (Map.Entry<String, JsonElement> entry : trapsObj.entrySet()) {
                trapStringValues.add(entry.getValue().getAsString());
            }
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        // ── Phase 1: Tag wrapper functions ───────────────────────────────────
        monitor.setMessage("Phase 1: Tagging wrapper functions...");

        Namespace wrapperNs = getOrCreateNamespace(symbolTable, "StringWrappers");

        int wrappersTagged = 0;
        int wrappersWithString = 0;
        Map<Address, String> wrapperAddrToString = new HashMap<>();

        FunctionIterator funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) break;
            Function func = funcIter.next();
            String name = func.getName();

            if (!wrapperNames.contains(name)) continue;

            // Move to StringWrappers namespace
            if (wrapperNs != null) {
                try {
                    func.setParentNamespace(wrapperNs);
                } catch (Exception e) { /* skip - name collision in namespace */ }
            }

            // Build plate comment
            String runtimeStr = wrapperPrimaryString.get(name);
            StringBuilder plate = new StringBuilder();
            plate.append("[STRING WRAPPER] ").append(name);

            if (runtimeStr != null) {
                boolean isTrap = trapStringValues.contains(runtimeStr);
                if (!isTrap) {
                    plate.append("\nRuntime resolves to: \"")
                         .append(sanitize(runtimeStr, 80)).append("\"");
                    wrapperAddrToString.put(func.getEntryPoint(), runtimeStr);
                    wrappersWithString++;
                } else {
                    plate.append("\nRuntime: [trap/dead-code string]");
                }
            } else {
                plate.append("\nCall-site dependent (computed index from caller args)");
            }
            plate.append("\nPattern: loads decoder from closure ctx, applies Smi offsets to args, calls decoder");

            // Preserve existing plate comment
            String existing = listing.getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint());
            if (existing != null && !existing.contains("[STRING WRAPPER]")) {
                plate.insert(0, existing + "\n");
            }
            listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, plate.toString());

            wrappersTagged++;
        }

        println("REPORT Phase 1: " + wrappersTagged + " wrappers tagged" +
                " (" + wrappersWithString + " with runtime string)");

        // ── Phase 2: Annotate callsite offsets with resolved strings ─────────
        monitor.setMessage("Phase 2: Annotating callsite strings...");

        int callsitesAnnotated = 0;
        int callsitesInRange = 0;
        int callsitesNearby = 0;

        for (Map.Entry<Long, String> entry : callsiteStrings.entrySet()) {
            if (monitor.isCancelled()) break;

            long payloadOffset = entry.getKey();
            String resolvedString = entry.getValue();
            Address addr = space.getAddress(baseAddr + payloadOffset);

            if (!payloadBlock.contains(addr)) continue;
            callsitesInRange++;

            // Find the instruction at or near this address
            Instruction instr = listing.getInstructionContaining(addr);
            if (instr == null) {
                instr = listing.getInstructionAt(addr);
            }
            if (instr == null) {
                // Search nearby addresses (+/- 3 bytes) for instruction alignment
                for (int delta = 1; delta <= 3 && instr == null; delta++) {
                    Address tryAddr = addr.add(delta);
                    if (payloadBlock.contains(tryAddr)) {
                        instr = listing.getInstructionAt(tryAddr);
                        if (instr != null) callsitesNearby++;
                    }
                    if (instr == null) {
                        tryAddr = addr.subtract(delta);
                        if (payloadBlock.contains(tryAddr)) {
                            instr = listing.getInstructionAt(tryAddr);
                            if (instr != null) callsitesNearby++;
                        }
                    }
                }
            }
            if (instr == null) continue;

            boolean isTrap = trapStringValues.contains(resolvedString);
            String comment;
            if (isTrap) {
                comment = "[deob:trap] \"" + sanitize(resolvedString, 40) + "\"";
            } else {
                comment = "[deob] -> \"" + sanitize(resolvedString, 60) + "\"";
            }

            appendEolComment(listing, instr.getMinAddress(), comment);
            callsitesAnnotated++;
        }

        println("REPORT Phase 2: " + callsitesAnnotated + " callsite strings annotated" +
                " (" + callsitesInRange + " in range, " + callsitesNearby + " via nearby search)");

        // ── Phase 3: Propagate resolved strings to xrefs into wrappers ──────
        monitor.setMessage("Phase 3: Propagating strings to wrapper call sites...");

        int xrefsAnnotated = 0;
        int xrefsTotal = 0;

        for (Map.Entry<Address, String> entry : wrapperAddrToString.entrySet()) {
            if (monitor.isCancelled()) break;

            Address wrapperEntry = entry.getKey();
            String resolvedString = entry.getValue();

            ReferenceIterator refIter = refMgr.getReferencesTo(wrapperEntry);
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                xrefsTotal++;
                Address fromAddr = ref.getFromAddress();

                Instruction callerInstr = listing.getInstructionAt(fromAddr);
                if (callerInstr == null) continue;

                String comment = "[deob:wrapper] -> \"" + sanitize(resolvedString, 60) + "\"";
                appendEolComment(listing, fromAddr, comment);
                xrefsAnnotated++;
            }
        }

        println("REPORT Phase 3: " + xrefsAnnotated + " xref propagations" +
                " (" + xrefsTotal + " total xrefs)");

        // ── Phase 4: Annotate CP references to wrappers in real functions ────
        // Wrappers are loaded via closure context (LdaContextSlot), not via
        // constant pool CreateClosure. So direct CP->wrapper references are rare.
        // But we still check for any CP string values that match wrapper names.
        monitor.setMessage("Phase 4: Scanning CP references...");

        int cpRefsAnnotated = 0;

        JsonObject allFuncsRoot = loadJson("v8_all_functions.json");
        if (allFuncsRoot != null) {
            JsonArray allFuncs = allFuncsRoot.getAsJsonArray("functions");

            for (int i = 0; i < allFuncs.size(); i++) {
                if (monitor.isCancelled()) break;

                JsonObject fn = allFuncs.get(i).getAsJsonObject();
                String funcName = fn.has("name") ? fn.get("name").getAsString() : "";

                if (wrapperNames.contains(funcName)) continue;

                JsonArray cp = fn.has("constantPool") ? fn.getAsJsonArray("constantPool") : null;
                if (cp == null || cp.size() == 0) continue;

                // Check if any CP entry references a wrapper with a known string
                Map<Integer, String> cpIdxToString = new HashMap<>();
                for (int j = 0; j < cp.size(); j++) {
                    String cpVal = cp.get(j).getAsString();
                    if (wrapperPrimaryString.containsKey(cpVal)) {
                        String resolved = wrapperPrimaryString.get(cpVal);
                        if (!trapStringValues.contains(resolved)) {
                            cpIdxToString.put(j, resolved);
                        }
                    }
                }
                if (cpIdxToString.isEmpty()) continue;

                long payloadOffset = fn.get("payloadOffset").getAsLong();
                int bcLen = fn.get("bytecodeLength").getAsInt();
                if (payloadOffset < 0 || bcLen <= 0) continue;

                Address funcAddr = space.getAddress(baseAddr + payloadOffset);
                Address funcEnd = space.getAddress(baseAddr + payloadOffset + bcLen - 1);

                if (!payloadBlock.contains(funcAddr)) continue;

                InstructionIterator instrIter = listing.getInstructions(funcAddr, true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (instr.getMinAddress().compareTo(funcEnd) > 0) break;

                    try {
                        String mnemonic = instr.getMnemonicString();
                        int dotPos = mnemonic.indexOf('.');
                        if (dotPos >= 0) mnemonic = mnemonic.substring(0, dotPos);

                        if (mnemonic.equals("CreateClosure")) {
                            int cpIdx = extractScalarOperand(instr, 0);
                            if (cpIdx >= 0 && cpIdxToString.containsKey(cpIdx)) {
                                String resolved = cpIdxToString.get(cpIdx);
                                String comment = "[deob:cp-ref] wrapper -> \"" +
                                    sanitize(resolved, 50) + "\"";
                                appendEolComment(listing, instr.getMinAddress(), comment);
                                cpRefsAnnotated++;
                            }
                        }
                    } catch (Exception e) {
                        // Skip
                    }
                }
            }
        }

        println("REPORT Phase 4: " + cpRefsAnnotated + " CP reference annotations");

        // ── Phase 5: Static formula-based string resolution ─────────────────
        // Uses wrapper formulas extracted from decompiled JS:
        //   Each simple wrapper calls the decoder as: ctx_6(paramN OP offset, keyParam)
        //   At call sites, paramN is loaded via LdaSmi before the call.
        //   Formula: string_index = smi_value OP offset
        monitor.setMessage("Phase 5: Formula-based string resolution...");

        int formulaResolved = 0;
        int formulaSkippedExisting = 0;
        int formulaAmbiguous = 0;

        JsonObject formulasRoot = loadJson("v8_wrapper_formulas.json");
        if (formulasRoot != null) {
            // Parse decoded string array
            Map<Integer, String> decodedStrings = new HashMap<>();
            JsonObject dsObj = formulasRoot.getAsJsonObject("decodedStrings");
            if (dsObj != null) {
                for (Map.Entry<String, JsonElement> entry : dsObj.entrySet()) {
                    try {
                        decodedStrings.put(Integer.parseInt(entry.getKey()),
                                           entry.getValue().getAsString());
                    } catch (NumberFormatException e) { /* skip */ }
                }
            }
            println("Loaded " + decodedStrings.size() + " decoded strings for formula resolution");

            // Parse wrapper formulas: name -> {paramIndex, operation, offset}
            Map<String, int[]> wrapperFormulas = new HashMap<>();  // name -> [paramIndex, opSign, offset]
            JsonArray wrapperArr2 = formulasRoot.getAsJsonArray("wrappers");
            if (wrapperArr2 != null) {
                for (int i = 0; i < wrapperArr2.size(); i++) {
                    JsonObject w = wrapperArr2.get(i).getAsJsonObject();
                    String name = w.get("name").getAsString();
                    int paramIdx = w.get("paramIndex").getAsInt();
                    String op = w.get("operation").getAsString();
                    int offset = w.get("offset").getAsInt();
                    int opSign = op.equals("+") ? 1 : -1;
                    wrapperFormulas.put(name, new int[]{paramIdx, opSign, offset});
                }
            }
            println("Loaded " + wrapperFormulas.size() + " wrapper formulas");

            int minIdx = formulasRoot.getAsJsonArray("indexRange").get(0).getAsInt();
            int maxIdx = formulasRoot.getAsJsonArray("indexRange").get(1).getAsInt();

            // Build wrapper name -> Ghidra function entry point map
            Map<String, Address> wrapperEntryPoints = new HashMap<>();
            FunctionIterator funcIter5 = fm.getFunctions(true);
            while (funcIter5.hasNext()) {
                Function func = funcIter5.next();
                String name = func.getName();
                if (wrapperFormulas.containsKey(name)) {
                    wrapperEntryPoints.put(name, func.getEntryPoint());
                }
            }
            println("Found " + wrapperEntryPoints.size() + " simple wrapper functions in Ghidra");

            // For each simple wrapper, find all xrefs (call sites) and try to resolve
            for (Map.Entry<String, Address> wEntry : wrapperEntryPoints.entrySet()) {
                if (monitor.isCancelled()) break;

                String wrapperName = wEntry.getKey();
                Address wrapperAddr = wEntry.getValue();
                int[] formula = wrapperFormulas.get(wrapperName);
                // formula[0] = paramIndex (0-4 for arg1-arg5, 5 for this/receiver)
                // formula[1] = opSign (+1 or -1)
                // formula[2] = offset

                ReferenceIterator refIter5 = refMgr.getReferencesTo(wrapperAddr);
                while (refIter5.hasNext()) {
                    if (monitor.isCancelled()) break;
                    Reference ref = refIter5.next();
                    Address callAddr = ref.getFromAddress();

                    // Skip if already annotated with a deob comment
                    String existingComment = listing.getComment(CodeUnit.EOL_COMMENT, callAddr);
                    if (existingComment != null && existingComment.contains("[deob")) {
                        formulaSkippedExisting++;
                        continue;
                    }

                    // Walk backward from the call to find LdaSmi instructions
                    // Collect all Smi values found within 30 instructions before the call
                    List<Integer> smiValues = new ArrayList<>();
                    Instruction scan = listing.getInstructionBefore(callAddr);
                    int maxScanBack = 30;
                    int scanned = 0;

                    while (scan != null && scanned < maxScanBack) {
                        String mnemonic = scan.getMnemonicString();
                        // Strip width prefix for matching
                        String baseMnemonic = mnemonic;
                        if (baseMnemonic.startsWith("Wide.")) {
                            baseMnemonic = baseMnemonic.substring(5);
                        } else if (baseMnemonic.startsWith("ExtraWide.")) {
                            baseMnemonic = baseMnemonic.substring(10);
                        }

                        if (baseMnemonic.equals("LdaSmi")) {
                            int smiVal = extractSignedScalarOperand(scan, 0);
                            if (smiVal != Integer.MIN_VALUE) {
                                smiValues.add(smiVal);
                            }
                        }

                        // Stop scanning at another call instruction or function boundary
                        if (baseMnemonic.startsWith("Call") ||
                            baseMnemonic.equals("Return") ||
                            baseMnemonic.equals("JumpLoop")) {
                            break;
                        }

                        scan = listing.getInstructionBefore(scan.getMinAddress());
                        scanned++;
                    }

                    if (smiValues.isEmpty()) continue;

                    // Try each Smi value with the formula
                    List<String> validResults = new ArrayList<>();
                    for (int smi : smiValues) {
                        int stringIndex;
                        if (formula[1] == 1) {  // operation is '+'
                            stringIndex = smi + formula[2];
                        } else {  // operation is '-'
                            stringIndex = smi - formula[2];
                        }

                        if (stringIndex >= minIdx && stringIndex <= maxIdx) {
                            String resolved = decodedStrings.get(stringIndex);
                            if (resolved != null) {
                                // Filter out trap/junk strings (5-char random-looking)
                                if (!trapStringValues.contains(resolved)) {
                                    validResults.add(resolved);
                                }
                            }
                        }
                    }

                    if (validResults.size() == 1) {
                        // Unique resolution - annotate
                        String resolved = validResults.get(0);
                        String comment = "[deob:formula] -> \"" + sanitize(resolved, 60) + "\"";
                        appendEolComment(listing, callAddr, comment);
                        formulaResolved++;
                    } else if (validResults.size() > 1) {
                        // Multiple valid results - annotate with candidates
                        StringBuilder comment = new StringBuilder("[deob:formula?] ");
                        for (int k = 0; k < Math.min(validResults.size(), 3); k++) {
                            if (k > 0) comment.append(" | ");
                            comment.append("\"").append(sanitize(validResults.get(k), 25)).append("\"");
                        }
                        appendEolComment(listing, callAddr, comment.toString());
                        formulaAmbiguous++;
                    }
                }
            }
        } else {
            println("Warning: v8_wrapper_formulas.json not found, skipping Phase 5");
        }

        println("REPORT Phase 5: " + formulaResolved + " formula-resolved strings" +
                " (" + formulaSkippedExisting + " skipped existing, " +
                formulaAmbiguous + " ambiguous)");

        // ── Summary ─────────────────────────────────────────────────────────
        int totalAnnotations = callsitesAnnotated + xrefsAnnotated + cpRefsAnnotated + formulaResolved;
        println("REPORT === RESOLVE WRAPPERS SUMMARY ===");
        println("REPORT   Wrapper functions tagged: " + wrappersTagged + " / " + wrapperNames.size());
        println("REPORT   Wrappers with runtime string: " + wrappersWithString);
        println("REPORT   Callsite strings annotated: " + callsitesAnnotated);
        println("REPORT   Xref propagations: " + xrefsAnnotated);
        println("REPORT   CP reference annotations: " + cpRefsAnnotated);
        println("REPORT   Formula-resolved strings: " + formulaResolved +
                " (ambiguous: " + formulaAmbiguous + ")");
        println("REPORT   Total string annotations: " + totalAnnotations);
        println("REPORT   Non-wrapper functions in Ghidra: " +
                (fm.getFunctionCount() - wrappersTagged));
    }

    // ── Helper methods ──────────────────────────────────────────────────────

    private JsonObject loadJson(String filename) {
        String[] paths = {
            System.getProperty("user.dir") + "/data/" + filename,
            "/Users/kenzzo/PRO/04_PROJETS/luskabot/tools/ghidra_v8_87/data/" + filename
        };
        for (String p : paths) {
            File f = new File(p);
            if (f.exists()) {
                try {
                    String json = new String(Files.readAllBytes(f.toPath()));
                    println("Loaded: " + p);
                    return JsonParser.parseString(json).getAsJsonObject();
                } catch (Exception e) {
                    println("Error loading " + p + ": " + e.getMessage());
                }
            }
        }
        return null;
    }

    private Namespace getOrCreateNamespace(SymbolTable st, String name) {
        try {
            Namespace ns = st.getNamespace(name, null);
            if (ns == null) {
                ns = st.createNameSpace(null, name, SourceType.IMPORTED);
            }
            return ns;
        } catch (Exception e) {
            println("Warning: Could not create namespace " + name + ": " + e.getMessage());
            return null;
        }
    }

    private int extractScalarOperand(Instruction instr, int operandIndex) {
        try {
            return (int) (instr.getScalar(operandIndex).getValue() & 0xFFFFFFFF);
        } catch (Exception e) {
            try {
                byte[] bytes = instr.getBytes();
                if (bytes == null || bytes.length < 2) return -1;
                int opcode = bytes[0] & 0xFF;
                int start = 1;
                if (opcode == 0x01) { // Wide prefix
                    if (bytes.length < 4) return -1;
                    start = 2;
                    return (bytes[start] & 0xFF) | ((bytes[start + 1] & 0xFF) << 8);
                } else if (opcode == 0x02) { // ExtraWide prefix
                    if (bytes.length < 6) return -1;
                    start = 2;
                    return (bytes[start] & 0xFF) | ((bytes[start + 1] & 0xFF) << 8) |
                           ((bytes[start + 2] & 0xFF) << 16) | ((bytes[start + 3] & 0xFF) << 24);
                }
                return bytes[start] & 0xFF;
            } catch (Exception e2) {
                return -1;
            }
        }
    }

    private void appendEolComment(Listing listing, Address addr, String newText) {
        String existing = listing.getComment(CodeUnit.EOL_COMMENT, addr);
        if (existing != null) {
            if (existing.contains(newText)) return;
            if (existing.split("\\|").length >= 3) return;
            listing.setComment(addr, CodeUnit.EOL_COMMENT, existing + " | " + newText);
        } else {
            listing.setComment(addr, CodeUnit.EOL_COMMENT, newText);
        }
    }

    private int extractSignedScalarOperand(Instruction instr, int operandIndex) {
        try {
            long val = instr.getScalar(operandIndex).getSignedValue();
            return (int) val;
        } catch (Exception e) {
            try {
                byte[] bytes = instr.getBytes();
                if (bytes == null || bytes.length < 2) return Integer.MIN_VALUE;
                int opcode = bytes[0] & 0xFF;
                int start = 1;
                if (opcode == 0x01) { // Wide prefix
                    if (bytes.length < 4) return Integer.MIN_VALUE;
                    start = 2;
                    // 16-bit signed
                    int val = (bytes[start] & 0xFF) | ((bytes[start + 1]) << 8);
                    return (short) val;
                } else if (opcode == 0x02) { // ExtraWide prefix
                    if (bytes.length < 6) return Integer.MIN_VALUE;
                    start = 2;
                    return (bytes[start] & 0xFF) | ((bytes[start + 1] & 0xFF) << 8) |
                           ((bytes[start + 2] & 0xFF) << 16) | ((bytes[start + 3]) << 24);
                }
                // 8-bit signed
                return bytes[start];
            } catch (Exception e2) {
                return Integer.MIN_VALUE;
            }
        }
    }

    private String sanitize(String s, int maxLen) {
        if (s == null) return "";
        s = s.replace("\"", "'").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
        if (s.length() > maxLen) {
            return s.substring(0, maxLen - 3) + "...";
        }
        return s;
    }
}
