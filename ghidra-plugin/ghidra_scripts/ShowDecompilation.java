// Show listing + decompiler output for sample functions
// @author LuskaBot
// @category V8
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

public class ShowDecompilation extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        // Find interesting functions (not wrappers, not too short)
        String[] targets = {"execute", "replace", "containers", "ate", "encrypt", "decrypt",
            "getHash", "init", "connect", "parse", "send", "receive", "check"};

        // Also find some Shield_Crypto functions
        SymbolTable st = currentProgram.getSymbolTable();
        Namespace cryptoNs = st.getNamespace("Shield_Crypto", null);

        // Setup decompiler
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        int shown = 0;
        for (Function func : fm.getFunctions(true)) {
            if (shown >= 8) break;

            String name = func.getName();
            boolean isTarget = false;

            // Check if it's a target name
            for (String t : targets) {
                if (name.equalsIgnoreCase(t)) { isTarget = true; break; }
            }

            // Check if in Shield_Crypto namespace
            if (!isTarget && cryptoNs != null && func.getParentNamespace().equals(cryptoNs)) {
                isTarget = true;
            }

            // Skip tiny functions and wrappers
            long size = func.getBody().getNumAddresses();
            if (size < 10) continue;
            if (name.startsWith("v8_anon_") || name.startsWith("_0x")) continue;

            if (!isTarget) continue;

            println("╔══════════════════════════════════════════════════════════════");
            println("║ FUNCTION: " + name + " @ " + func.getEntryPoint());
            println("║ Size: " + size + " bytes | Namespace: " + func.getParentNamespace().getName());
            println("╠══ LISTING (first 20 instructions) ══════════════════════════");

            // Show listing with comments
            InstructionIterator it = listing.getInstructions(func.getBody(), true);
            int instrCount = 0;
            while (it.hasNext() && instrCount < 20) {
                Instruction inst = it.next();
                String eol = listing.getComment(CodeUnit.EOL_COMMENT, inst.getAddress());
                String pre = listing.getComment(CodeUnit.PRE_COMMENT, inst.getAddress());
                if (pre != null) println("║   " + pre);
                String line = String.format("║   %s: %s", inst.getAddress(), inst);
                if (eol != null) line += "  // " + eol;
                println(line);
                instrCount++;
            }
            if (it.hasNext()) println("║   ... (more instructions)");

            // Show plate comment (metadata)
            String plate = listing.getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint());
            if (plate != null) {
                println("╠══ METADATA ══════════════════════════════════════════════════");
                for (String line : plate.split("\n")) {
                    println("║   " + line);
                }
            }

            // Show decompiler output
            println("╠══ DECOMPILER OUTPUT ═════════════════════════════════════════");
            try {
                DecompileResults res = decomp.decompileFunction(func, 10, monitor);
                if (res.decompileCompleted()) {
                    String decompiledCode = res.getDecompiledFunction().getC();
                    String[] lines = decompiledCode.split("\n");
                    for (int i = 0; i < Math.min(30, lines.length); i++) {
                        println("║   " + lines[i]);
                    }
                    if (lines.length > 30) println("║   ... (" + (lines.length - 30) + " more lines)");
                } else {
                    println("║   (decompilation failed: " + res.getErrorMessage() + ")");
                }
            } catch (Exception e) {
                println("║   (decompiler error: " + e.getMessage() + ")");
            }

            println("╚══════════════════════════════════════════════════════════════");
            println("");
            shown++;
        }

        // Also show a random Shield_Crypto function
        if (cryptoNs != null && shown < 10) {
            for (Function func : fm.getFunctions(true)) {
                if (!func.getParentNamespace().equals(cryptoNs)) continue;
                if (func.getBody().getNumAddresses() < 20) continue;

                println("╔══════════════════════════════════════════════════════════════");
                println("║ SHIELD_CRYPTO: " + func.getName() + " @ " + func.getEntryPoint());
                println("║ Size: " + func.getBody().getNumAddresses() + " bytes");
                println("╠══ LISTING (first 15 instructions) ══════════════════════════");

                InstructionIterator it = listing.getInstructions(func.getBody(), true);
                int instrCount = 0;
                while (it.hasNext() && instrCount < 15) {
                    Instruction inst = it.next();
                    String eol = listing.getComment(CodeUnit.EOL_COMMENT, inst.getAddress());
                    String line = String.format("║   %s: %s", inst.getAddress(), inst);
                    if (eol != null) line += "  // " + eol;
                    println(line);
                    instrCount++;
                }

                println("╠══ DECOMPILER ════════════════════════════════════════════════");
                try {
                    DecompileResults res = decomp.decompileFunction(func, 10, monitor);
                    if (res.decompileCompleted()) {
                        String[] lines = res.getDecompiledFunction().getC().split("\n");
                        for (int i = 0; i < Math.min(25, lines.length); i++) {
                            println("║   " + lines[i]);
                        }
                    }
                } catch (Exception e) {
                    println("║   (error: " + e.getMessage() + ")");
                }
                println("╚══════════════════════════════════════════════════════════════");
                break;
            }
        }

        decomp.dispose();
        println("=== Done: " + shown + " functions shown ===");
    }
}
