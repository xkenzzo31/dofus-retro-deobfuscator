//Export wrapper formulas from V8 8.7 bytecode analysis.
//
//Runs as a Ghidra headless postScript after V8_bytecodeAnalyzer.
//Iterates all functions, identifies obfuscator.io wrapper patterns,
//extracts the formula (paramIndex, operation, offset), and exports as JSON.
//
//Usage (headless):
//  analyzeHeadless <project> <name> -import main.jsc -processor "V8:LE:32:8.7" \
//    -postScript ExportWrapperFormulas.java /output/data
//
//@author Luska
//@category V8

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.util.*;

public class ExportWrapperFormulas extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        String outputDir = args.length > 0 ? args[0] : "/tmp";

        println("ExportWrapperFormulas: Starting formula extraction...");

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcIter = funcMgr.getFunctions(true);

        List<Map<String, Object>> wrappers = new ArrayList<>();
        int totalFunctions = 0;
        int wrapperCount = 0;

        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            totalFunctions++;

            String name = func.getName();
            if (!name.startsWith("_0x") && !name.startsWith("a0_0x")) {
                continue;
            }

            // Check if this looks like a wrapper (short function)
            AddressSetView body = func.getBody();
            long bodySize = body.getNumAddresses();
            if (bodySize > 100) continue; // Wrappers are short

            // Get parameter count
            int paramCount = func.getParameterCount();

            // Analyze the bytecode instructions in this function
            // Look for: LdaSmi (literal offset), Add/Sub (operation), Call (decoder invocation)
            InstructionIterator instrIter = currentProgram.getListing().getInstructions(body, true);

            int ldaSmiValue = Integer.MIN_VALUE;
            int activeParam = -1;
            String operation = "+";
            boolean hasCall = false;
            boolean hasContextSlot = false;

            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                String mnemonic = instr.getMnemonicString();

                // Detect LdaSmi (loads a literal small integer)
                if (mnemonic.startsWith("LdaSmi")) {
                    try {
                        // The operand is the Smi value
                        Object[] opObjs = instr.getOpObjects(0);
                        if (opObjs.length > 0) {
                            ldaSmiValue = ((Number) opObjs[0]).intValue();
                        }
                    } catch (Exception e) {
                        // Try parsing from instruction representation
                        String repr = instr.toString();
                        try {
                            String numStr = repr.replaceAll(".*\\[", "").replaceAll("\\].*", "").trim();
                            ldaSmiValue = Integer.parseInt(numStr);
                        } catch (Exception e2) { /* skip */ }
                    }
                }

                // Detect Add/Sub operations
                if (mnemonic.equals("Add")) {
                    operation = "+";
                    // The register operand tells us which parameter
                    try {
                        String repr = instr.toString();
                        if (repr.contains("a0")) activeParam = 0;
                        else if (repr.contains("a1")) activeParam = 1;
                        else if (repr.contains("a2")) activeParam = 2;
                        else if (repr.contains("a3")) activeParam = 3;
                        else if (repr.contains("a4")) activeParam = 4;
                    } catch (Exception e) { /* skip */ }
                }
                if (mnemonic.equals("Sub")) {
                    operation = "-";
                    try {
                        String repr = instr.toString();
                        if (repr.contains("a0")) activeParam = 0;
                        else if (repr.contains("a1")) activeParam = 1;
                        else if (repr.contains("a2")) activeParam = 2;
                        else if (repr.contains("a3")) activeParam = 3;
                        else if (repr.contains("a4")) activeParam = 4;
                    } catch (Exception e) { /* skip */ }
                }

                // Detect context slot loading (decoder reference)
                if (mnemonic.contains("ContextSlot") || mnemonic.contains("CurrentContextSlot")) {
                    hasContextSlot = true;
                }

                // Detect call instruction
                if (mnemonic.startsWith("Call")) {
                    hasCall = true;
                }
            }

            // A wrapper must: have a call, load a context slot (decoder), and have a literal offset
            if (hasCall && hasContextSlot && ldaSmiValue != Integer.MIN_VALUE && activeParam >= 0) {
                Map<String, Object> wrapper = new LinkedHashMap<>();
                wrapper.put("name", name);
                wrapper.put("paramIndex", activeParam);
                wrapper.put("operation", operation);
                wrapper.put("offset", Math.abs(ldaSmiValue));
                wrapper.put("description", String.format("wrapper: ctx(%s %s %d)",
                    "arg" + (activeParam + 1), operation, Math.abs(ldaSmiValue)));
                wrappers.add(wrapper);
                wrapperCount++;
            }
        }

        println(String.format("ExportWrapperFormulas: %d functions analyzed, %d wrappers found",
            totalFunctions, wrapperCount));

        // Write output JSON
        String outputPath = outputDir + "/ghidra_wrapper_formulas.json";
        try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
            pw.println("{");
            pw.println("  \"source\": \"ghidra_headless\",");
            pw.println("  \"total_functions\": " + totalFunctions + ",");
            pw.println("  \"wrappers\": [");

            for (int i = 0; i < wrappers.size(); i++) {
                Map<String, Object> w = wrappers.get(i);
                pw.print("    {");
                pw.print("\"name\": \"" + w.get("name") + "\", ");
                pw.print("\"paramIndex\": " + w.get("paramIndex") + ", ");
                pw.print("\"operation\": \"" + w.get("operation") + "\", ");
                pw.print("\"offset\": " + w.get("offset") + ", ");
                pw.print("\"description\": \"" + w.get("description") + "\"");
                pw.print("}");
                if (i < wrappers.size() - 1) pw.print(",");
                pw.println();
            }

            pw.println("  ]");
            pw.println("}");
        }

        println("ExportWrapperFormulas: Exported to " + outputPath);
    }
}
