import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class DumpProjectInfo extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Memory blocks
        println("REPORT === MEMORY BLOCKS ===");
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            println(String.format("REPORT   %s: %s - %s (%d bytes, %s%s%s)",
                block.getName(),
                block.getStart(), block.getEnd(),
                block.getSize(),
                block.isRead() ? "R" : "-",
                block.isWrite() ? "W" : "-",
                block.isExecute() ? "X" : "-"));
        }

        // Functions
        FunctionManager fm = currentProgram.getFunctionManager();
        int total = fm.getFunctionCount();
        println("REPORT === FUNCTIONS: " + total + " total ===");
        int shown = 0;
        for (Function f : fm.getFunctions(true)) {
            if (shown < 20) {
                println(String.format("REPORT   %s @ %s (%d bytes, %d params)",
                    f.getName(), f.getEntryPoint(),
                    f.getBody().getNumAddresses(),
                    f.getParameterCount()));
                shown++;
            }
        }
        if (total > 20) println("REPORT   ... (" + (total - 20) + " more)");

        // Symbols
        SymbolTable st = currentProgram.getSymbolTable();
        println("REPORT === SYMBOLS: " + st.getNumSymbols() + " ===");

        // Count all instructions (up to 500K)
        Listing listing = currentProgram.getListing();
        int instrCount = 0;
        var instIter = listing.getInstructions(true);
        while (instIter.hasNext() && instrCount < 2000000) {
            instIter.next();
            instrCount++;
        }
        boolean truncated = instIter.hasNext();
        println("REPORT === INSTRUCTIONS: " + instrCount + (truncated ? "+" : "") + " ===");

        // Count defined data
        int dataCount = 0;
        var dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && dataCount < 100000) {
            dataIter.next();
            dataCount++;
        }
        println("REPORT === DEFINED DATA: " + dataCount + (dataCount >= 100000 ? "+" : "") + " ===");
    }
}
