// Annotate try/catch handler tables from v8_handler_tables.json
// For each function with handlers:
//   - PRE_COMMENT "// try {" at the try-start offset
//   - PRE_COMMENT "// } catch {" at the try-end / handler offset
//   - Label "catch_handler_N" at handler offset
//   - Bookmark at each catch handler
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
import com.google.gson.*;

public class AnnotateHandlers extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Find the .v8payload block
        MemoryBlock payloadBlock = currentProgram.getMemory().getBlock(".v8payload");
        if (payloadBlock == null) {
            println("ERROR: No .v8payload block found. Import main.jsc first.");
            return;
        }
        long baseAddr = payloadBlock.getStart().getOffset();
        println("handler Payload base: 0x" + Long.toHexString(baseAddr));

        // Load function list (for payloadOffset per function index)
        String funcJsonStr = loadFile(new String[]{
            "/Users/kenzzo/PRO/04_PROJETS/luskabot/tools/ghidra_v8_87/data/v8_all_functions.json",
            System.getProperty("user.dir") + "/data/v8_all_functions.json"
        });
        if (funcJsonStr == null) {
            println("ERROR: Cannot find v8_all_functions.json");
            return;
        }

        JsonObject funcRoot = JsonParser.parseString(funcJsonStr).getAsJsonObject();
        JsonArray funcs = funcRoot.getAsJsonArray("functions");
        println("handler Loaded " + funcs.size() + " functions from v8_all_functions.json");

        // Load handler tables
        String handlerJsonStr = loadFile(new String[]{
            "/Users/kenzzo/PRO/04_PROJETS/luskabot/tools/ghidra_v8_87/data/v8_handler_tables.json",
            System.getProperty("user.dir") + "/data/v8_handler_tables.json"
        });
        if (handlerJsonStr == null) {
            println("ERROR: Cannot find v8_handler_tables.json");
            return;
        }

        JsonObject handlerRoot = JsonParser.parseString(handlerJsonStr).getAsJsonObject();
        JsonObject handlers = handlerRoot.getAsJsonObject("handlers");
        int totalWithHandlers = handlerRoot.get("functionsWithHandlers").getAsInt();
        int totalEntries = handlerRoot.get("totalHandlerEntries").getAsInt();
        println("handler Functions with handlers: " + totalWithHandlers + ", total entries: " + totalEntries);

        Listing listing = currentProgram.getListing();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        BookmarkManager bookmarkMgr = currentProgram.getBookmarkManager();

        int annotated = 0;
        int bookmarked = 0;
        int labeled = 0;
        int errors = 0;
        int catchHandlerIdx = 0;

        for (Map.Entry<String, JsonElement> entry : handlers.entrySet()) {
            int funcIdx = Integer.parseInt(entry.getKey());
            JsonObject handlerInfo = entry.getValue().getAsJsonObject();
            String funcName = handlerInfo.get("name").getAsString();
            JsonArray entries = handlerInfo.getAsJsonArray("entries");

            // Get the payloadOffset for this function from the function list
            if (funcIdx >= funcs.size()) {
                println("  Warning: func index " + funcIdx + " out of range");
                errors++;
                continue;
            }

            JsonObject fn = funcs.get(funcIdx).getAsJsonObject();
            long payloadOff = fn.get("payloadOffset").getAsLong();
            int bcLen = fn.get("bytecodeLength").getAsInt();
            String fnName = fn.has("name") ? fn.get("name").getAsString() : "anon_" + funcIdx;

            if (payloadOff < 0 || bcLen <= 0) {
                errors++;
                continue;
            }

            long funcBaseAddr = baseAddr + payloadOff;

            for (int i = 0; i < entries.size(); i++) {
                JsonObject he = entries.get(i).getAsJsonObject();
                int tryStart = he.get("tryStart").getAsInt();
                int tryEnd = he.get("tryEnd").getAsInt();
                int handlerOff = he.get("handlerOffset").getAsInt();
                int prediction = he.get("prediction").getAsInt();

                // Prediction values: 0=CAUGHT, 1=UNCAUGHT, 2=PROMISE, 4=DESUGARING, 5=ASYNC_AWAIT
                String predStr;
                switch (prediction) {
                    case 0: predStr = "CAUGHT"; break;
                    case 1: predStr = "UNCAUGHT"; break;
                    case 2: predStr = "PROMISE"; break;
                    case 4: predStr = "DESUGARING"; break;
                    case 5: predStr = "ASYNC_AWAIT"; break;
                    default: predStr = "type=" + prediction; break;
                }

                try {
                    // --- try-start comment ---
                    Address tryStartAddr = space.getAddress(funcBaseAddr + tryStart);
                    if (payloadBlock.contains(tryStartAddr)) {
                        setPreComment(listing, tryStartAddr,
                            "// try { [" + predStr + "] handler->" + handlerOff);
                        annotated++;
                    }

                    // --- try-end / catch comment ---
                    Address tryEndAddr = space.getAddress(funcBaseAddr + tryEnd);
                    if (payloadBlock.contains(tryEndAddr)) {
                        String catchComment;
                        if (tryEnd == handlerOff) {
                            catchComment = "// } catch { [" + predStr + "]";
                        } else {
                            catchComment = "// } // end try [" + predStr + "] -> catch at +" + handlerOff;
                        }
                        setPreComment(listing, tryEndAddr, catchComment);
                        annotated++;
                    }

                    // --- handler label and comment (if different from tryEnd) ---
                    Address handlerAddr = space.getAddress(funcBaseAddr + handlerOff);
                    if (payloadBlock.contains(handlerAddr)) {
                        if (tryEnd != handlerOff) {
                            setPreComment(listing, handlerAddr,
                                "// catch handler [" + predStr + "] for try@+" + tryStart);
                            annotated++;
                        }

                        // Create label
                        String labelName = "catch_handler_" + catchHandlerIdx;
                        try {
                            symbolTable.createLabel(handlerAddr, labelName, SourceType.IMPORTED);
                            labeled++;
                        } catch (Exception e) {
                            // Label may already exist
                        }

                        // Create bookmark
                        String bookmarkCategory = "V8_TryCatch";
                        String bookmarkComment = fnName + ": try[" + tryStart + "," + tryEnd + ")->" + handlerOff + " " + predStr;
                        bookmarkMgr.setBookmark(handlerAddr, BookmarkType.ANALYSIS, bookmarkCategory, bookmarkComment);
                        bookmarked++;

                        catchHandlerIdx++;
                    }

                } catch (Exception e) {
                    errors++;
                    if (errors <= 10) {
                        println("  handler Error at func " + funcIdx + " (" + fnName + ") entry " + i + ": " + e.getMessage());
                    }
                }
            }
        }

        println("REPORT === HANDLER ANNOTATION DONE ===");
        println("REPORT   Functions with handlers: " + totalWithHandlers);
        println("REPORT   try/catch comments added: " + annotated);
        println("REPORT   catch handler labels: " + labeled);
        println("REPORT   catch handler bookmarks: " + bookmarked);
        println("REPORT   Errors: " + errors);

        // Print summary of prediction types
        Map<Integer, Integer> predCounts = new HashMap<>();
        for (Map.Entry<String, JsonElement> entry : handlers.entrySet()) {
            JsonArray ents = entry.getValue().getAsJsonObject().getAsJsonArray("entries");
            for (int i = 0; i < ents.size(); i++) {
                int p = ents.get(i).getAsJsonObject().get("prediction").getAsInt();
                predCounts.merge(p, 1, Integer::sum);
            }
        }
        println("REPORT   Handler prediction breakdown:");
        for (Map.Entry<Integer, Integer> pc : predCounts.entrySet()) {
            String name;
            switch (pc.getKey()) {
                case 0: name = "CAUGHT"; break;
                case 1: name = "UNCAUGHT"; break;
                case 2: name = "PROMISE"; break;
                case 4: name = "DESUGARING"; break;
                case 5: name = "ASYNC_AWAIT"; break;
                default: name = "UNKNOWN(" + pc.getKey() + ")"; break;
            }
            println("REPORT     " + name + ": " + pc.getValue());
        }
    }

    /**
     * Set a PRE_COMMENT on an address, appending to existing comment if present.
     * Uses CodeUnit API to avoid Listing.getComment signature issues across Ghidra versions.
     */
    private void setPreComment(Listing listing, Address addr, String comment) {
        CodeUnit cu = listing.getCodeUnitAt(addr);
        if (cu == null) {
            // No code unit at this exact address, try containing
            cu = listing.getCodeUnitContaining(addr);
        }
        if (cu != null) {
            String existing = cu.getComment(CodeUnit.PRE_COMMENT);
            if (existing != null && !existing.isEmpty()) {
                comment = existing + "\n" + comment;
            }
            cu.setComment(CodeUnit.PRE_COMMENT, comment);
        }
    }

    private String loadFile(String[] paths) {
        for (String p : paths) {
            File f = new File(p);
            if (f.exists()) {
                try {
                    println("handler Loaded: " + p);
                    return new String(Files.readAllBytes(f.toPath()));
                } catch (Exception e) {
                    println("handler Warning: failed to read " + p + ": " + e.getMessage());
                }
            }
        }
        return null;
    }
}
