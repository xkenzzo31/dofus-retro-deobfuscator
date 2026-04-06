// Create V8 functions from v8_all_functions.json (8611 functions)
// Falls back to v8_ghidra_strings.json (2296 functions) if the full file isn't found.
// Also: marks inter-function gaps as data, resolves constant pool values inline,
// categorises functions into Ghidra Namespaces, and creates cross-references.
// @author LuskaBot
// @category V8
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import com.google.gson.*;

public class CreateV8Functions extends GhidraScript {

    // Category classification for function namespaces
    private static final String[][] CATEGORY_KEYWORDS = {
        {"Shield_Crypto", "crypto", "aes", "encrypt", "decrypt", "cryptojs", "hash", "cipher", "hmac", "sha", "md5", "pbkdf"},
        {"Electron",      "electron", "ipc", "browserwindow", "remote", "nativeimage", "webcontents", "tray", "dialog"},
        {"Network",       "thrift", "http", "connect", "socket", "fetch", "xhr", "websocket", "tcp", "udp", "request"},
        {"Auth",          "oauth", "token", "session", "auth", "login", "credential", "apikey"},
        {"Zaap",          "zaap", "initconnect", "launcher"},
        {"Game",          "map", "combat", "inventory", "spell", "pathfind", "dofus", "ankama"},
    };

    @Override
    public void run() throws Exception {
        // Find the .v8payload block
        var payloadBlock = currentProgram.getMemory().getBlock(".v8payload");
        if (payloadBlock == null) {
            println("ERROR: No .v8payload block found. Import main.jsc first.");
            return;
        }
        long baseAddr = payloadBlock.getStart().getOffset();
        long payloadSize = payloadBlock.getSize();
        println("Payload base: 0x" + Long.toHexString(baseAddr) + ", size: " + payloadSize);

        // Try to load v8_all_functions.json first (8611 functions), then fall back
        String[] allPaths = {
            System.getProperty("user.dir") + "/data/v8_all_functions.json",
            "/Users/kenzzo/PRO/04_PROJETS/luskabot/tools/ghidra_v8_87/data/v8_all_functions.json"
        };
        String[] fallbackPaths = {
            System.getProperty("user.dir") + "/data/v8_ghidra_strings.json",
            "/Users/kenzzo/PRO/04_PROJETS/luskabot/tools/ghidra_v8_87/data/v8_ghidra_strings.json"
        };

        String jsonStr = null;
        boolean isFullFile = false;
        for (String p : allPaths) {
            File f = new File(p);
            if (f.exists()) {
                jsonStr = new String(Files.readAllBytes(f.toPath()));
                println("Loaded FULL function list: " + p);
                isFullFile = true;
                break;
            }
        }
        if (jsonStr == null) {
            for (String p : fallbackPaths) {
                File f = new File(p);
                if (f.exists()) {
                    jsonStr = new String(Files.readAllBytes(f.toPath()));
                    println("Loaded FALLBACK function list: " + p);
                    break;
                }
            }
        }
        if (jsonStr == null) {
            println("ERROR: No function list JSON found.");
            return;
        }

        JsonObject root = JsonParser.parseString(jsonStr).getAsJsonObject();
        JsonArray funcs = root.getAsJsonArray("functions");
        println("REPORT Functions in JSON: " + funcs.size());

        // Load category index if available
        Map<Integer, List<String>> idToCategories = loadCategoryIndex();
        if (!idToCategories.isEmpty()) {
            println("REPORT Category index loaded: " + idToCategories.size() + " functions with categories");
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        int created = 0;
        int skipped = 0;
        int errors = 0;

        // Collect function boundaries for gap analysis
        List<long[]> funcBounds = new ArrayList<>();

        // Build a map of function names for cross-reference
        Map<String, Address> nameToAddr = new HashMap<>();

        // Map of namespace name -> Namespace object
        Map<String, Namespace> namespaceCache = new HashMap<>();

        // Store function data for post-processing (CP inline + xrefs)
        List<FuncRecord> funcRecords = new ArrayList<>();

        for (int i = 0; i < funcs.size(); i++) {
            JsonObject fn = funcs.get(i).getAsJsonObject();
            long payloadOff = fn.get("payloadOffset").getAsLong();
            int bcLen = fn.get("bytecodeLength").getAsInt();
            String name = fn.has("name") ? fn.get("name").getAsString() : "";
            int params = fn.has("parameterCount") ? fn.get("parameterCount").getAsInt() : 0;

            if (bcLen <= 0 || payloadOff < 0) {
                skipped++;
                continue;
            }

            Address funcAddr = space.getAddress(baseAddr + payloadOff);
            Address funcEnd = space.getAddress(baseAddr + payloadOff + bcLen - 1);

            // Check if address is within the payload block
            if (!payloadBlock.contains(funcAddr)) {
                skipped++;
                continue;
            }
            if (!payloadBlock.contains(funcEnd)) {
                // Clamp to payload end
                funcEnd = payloadBlock.getEnd();
                bcLen = (int)(funcEnd.getOffset() - funcAddr.getOffset() + 1);
            }

            try {
                // Clean function name
                if (name == null || name.isEmpty()) name = "v8_anon_" + i;
                name = name.replaceAll("[^a-zA-Z0-9_]", "_");
                if (name.length() > 0 && Character.isDigit(name.charAt(0))) name = "fn_" + name;

                // Check for existing function
                Function existing = fm.getFunctionAt(funcAddr);
                if (existing != null) {
                    skipped++;
                    continue;
                }

                // Clear any existing code/data at this address range
                listing.clearCodeUnits(funcAddr, funcEnd, false);

                // Disassemble the full function body using DisassembleCommand
                AddressSet disasmSet = new AddressSet(funcAddr, funcEnd);
                DisassembleCommand cmd = new DisassembleCommand(disasmSet, null, true);
                cmd.applyTo(currentProgram, monitor);

                // Create the function
                AddressSet body = new AddressSet(funcAddr, funcEnd);
                Function func = fm.createFunction(name, funcAddr, body, SourceType.IMPORTED);

                // === Assign namespace (Part 3) ===
                String nsName = determineNamespace(i, fn, idToCategories);
                if (nsName != null && !nsName.equals("Uncategorized")) {
                    Namespace ns = namespaceCache.get(nsName);
                    if (ns == null) {
                        try {
                            ns = symbolTable.getNamespace(nsName, null);
                            if (ns == null) {
                                ns = symbolTable.createNameSpace(null, nsName, SourceType.IMPORTED);
                            }
                            namespaceCache.put(nsName, ns);
                        } catch (Exception e) {
                            // Namespace creation can fail for reserved names
                        }
                    }
                    if (ns != null) {
                        try { func.setParentNamespace(ns); } catch (Exception e) { /* skip */ }
                    }
                }

                // Store in name map for cross-references
                nameToAddr.put(name, funcAddr);
                funcBounds.add(new long[]{payloadOff, payloadOff + bcLen});

                // Add metadata as plate comment
                StringBuilder comment = new StringBuilder();
                comment.append("V8 Function #").append(i).append(": ").append(name).append("\n");
                comment.append("Params: ").append(params);
                int regs = fn.has("registerCount") ? fn.get("registerCount").getAsInt() : 0;
                int frame = fn.has("frameSize") ? fn.get("frameSize").getAsInt() : 0;
                comment.append(" | Registers: ").append(regs);
                comment.append(" | Frame: ").append(frame);
                comment.append(" | BytecodeLen: ").append(bcLen).append("\n");

                // Add constant pool strings
                JsonArray cp = fn.has("constantPool") ? fn.getAsJsonArray("constantPool") : null;
                if (cp != null && cp.size() > 0) {
                    comment.append("Constants: ");
                    for (int j = 0; j < Math.min(10, cp.size()); j++) {
                        if (j > 0) comment.append(", ");
                        String val = cp.get(j).getAsString();
                        if (val.length() > 40) val = val.substring(0, 40) + "...";
                        comment.append("[").append(j).append("]=").append(val);
                    }
                    if (cp.size() > 10) comment.append(" (+" + (cp.size() - 10) + " more)");
                }

                listing.setComment(funcAddr, CodeUnit.PLATE_COMMENT, comment.toString());

                // Save record for post-processing
                funcRecords.add(new FuncRecord(i, funcAddr, funcEnd, fn));

                created++;

            } catch (Exception e) {
                errors++;
                if (errors <= 10) {
                    println("  Error at func " + i + " (" + name + "): " + e.getMessage());
                }
            }

            if (created % 1000 == 0 && created > 0) {
                println("  Progress: " + created + " functions created...");
            }
        }

        println("REPORT === FUNCTION CREATION DONE ===");
        println("REPORT   Created: " + created);
        println("REPORT   Skipped: " + skipped);
        println("REPORT   Errors: " + errors);
        println("REPORT   Total functions in Ghidra: " + fm.getFunctionCount());

        // Count namespaces created
        println("REPORT   Namespaces created: " + namespaceCache.size());
        for (var entry : namespaceCache.entrySet()) {
            println("REPORT     " + entry.getKey());
        }

        // === Phase 2: Mark inter-function gaps as data ===
        println("Phase 2: Marking inter-function gaps as data...");
        markGapsAsData(payloadBlock, baseAddr, payloadSize, funcBounds, listing, space);

        // === Phase 3: Resolve constant pool values inline (Part 2) ===
        println("Phase 3: Resolving constant pool values inline...");
        int cpComments = resolveConstantPoolInline(funcRecords, listing, space, baseAddr);
        println("REPORT   CP inline comments: " + cpComments);

        // === Phase 4: Create cross-references from constant pool (Part 4) ===
        println("Phase 4: Creating cross-references...");
        int xrefs = createCrossReferences(funcs, nameToAddr, baseAddr, space, listing);
        println("REPORT   Cross-references created: " + xrefs);
    }

    // ── Category determination ─────────��────────────────────────────────────
    private Map<Integer, List<String>> loadCategoryIndex() {
        Map<Integer, List<String>> result = new HashMap<>();
        String[] indexPaths = {
            "/Users/kenzzo/PRO/04_PROJETS/luskabot/deobfuscated/jsc_decompiled/v2/index.json",
            "/Users/kenzzo/PRO/04_PROJETS/luskabot/deobfuscated/jsc_decompiled/v3/index.json"
        };
        for (String path : indexPaths) {
            File f = new File(path);
            if (f.exists()) {
                try {
                    String json = new String(Files.readAllBytes(f.toPath()));
                    JsonArray arr = JsonParser.parseString(json).getAsJsonArray();
                    for (int i = 0; i < arr.size(); i++) {
                        JsonObject entry = arr.get(i).getAsJsonObject();
                        int id = entry.has("id") ? entry.get("id").getAsInt() : -1;
                        JsonArray cats = entry.has("categories") ? entry.getAsJsonArray("categories") : null;
                        if (id >= 0 && cats != null && cats.size() > 0) {
                            List<String> catList = new ArrayList<>();
                            for (int j = 0; j < cats.size(); j++) {
                                catList.add(cats.get(j).getAsString());
                            }
                            result.put(id, catList);
                        }
                    }
                    println("Loaded category index from: " + path);
                    break;
                } catch (Exception e) {
                    println("Warning: Failed to load category index: " + e.getMessage());
                }
            }
        }
        return result;
    }

    private String determineNamespace(int funcId, JsonObject fn, Map<Integer, List<String>> idToCategories) {
        // First, try the index.json categories
        List<String> cats = idToCategories.get(funcId);
        if (cats != null && !cats.isEmpty()) {
            String cat = cats.get(0);
            // Map index.json category names to Ghidra namespace names
            switch (cat) {
                case "crypto": return "Shield_Crypto";
                case "electron": return "Electron";
                case "network": return "Network";
                case "auth": return "Auth";
                case "zaap": return "Zaap";
                case "game": return "Game";
                default: return cat.substring(0, 1).toUpperCase() + cat.substring(1);
            }
        }

        // Fallback: keyword-based categorization from constant pool strings + name
        String name = fn.has("name") ? fn.get("name").getAsString().toLowerCase() : "";
        StringBuilder haystack = new StringBuilder(name);
        haystack.append(" ");
        JsonArray cp = fn.has("constantPool") ? fn.getAsJsonArray("constantPool") : null;
        if (cp != null) {
            for (int j = 0; j < cp.size(); j++) {
                haystack.append(cp.get(j).getAsString().toLowerCase()).append(" ");
            }
        }
        String searchText = haystack.toString();

        for (String[] cat : CATEGORY_KEYWORDS) {
            String nsName = cat[0];
            for (int k = 1; k < cat.length; k++) {
                if (searchText.contains(cat[k])) {
                    return nsName;
                }
            }
        }

        return null;  // Don't put everything in Uncategorized — leave unnamespaced
    }

    // ── Constant pool inline resolution (Part 2) ───────────────────────────
    private int resolveConstantPoolInline(List<FuncRecord> funcRecords, Listing listing,
                                           AddressSpace space, long baseAddr) {
        int comments = 0;

        // Set of call-like opcode bytes (CallProperty, CallUndefinedReceiver, etc.)
        // These opcodes have constant pool index operands
        Set<Integer> cpRefOpcodes = new HashSet<>(Arrays.asList(
            0x0a, // LdaConstant
            0x0b, // LdaGlobal
            0x0c, // LdaGlobalInsideTypeof
            0x0d, // StaGlobal
            0x30, // LdaNamedProperty
            0x31, // LdaNamedPropertyFromSuper
            0x35, // StaNamedProperty
            0x36, // StaNamedOwnProperty
            0x85, // CreateClosure
            0x7e, // CreateRegExpLiteral
            0x7f, // CreateArrayLiteral
            0x80, // CreateEmptyArrayLiteral
            0x81, // CreateObjectLiteral
            0xb0  // ThrowReferenceErrorIfHole
        ));

        for (FuncRecord rec : funcRecords) {
            JsonArray cp = rec.fn.has("constantPool") ? rec.fn.getAsJsonArray("constantPool") : null;
            if (cp == null || cp.size() == 0) continue;

            // Walk all instructions in this function
            InstructionIterator instrIter = listing.getInstructions(rec.start, true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                if (instr.getMinAddress().compareTo(rec.end) > 0) break;

                try {
                    String mnemonic = instr.getMnemonicString();
                    // Check instruction bytes for the opcode
                    byte[] bytes = instr.getBytes();
                    if (bytes == null || bytes.length < 2) continue;

                    int opcode = bytes[0] & 0xFF;
                    int operandStart = 1;
                    // Handle Wide/ExtraWide prefixes
                    if (opcode == 0x01 || opcode == 0x02) {
                        if (bytes.length < 3) continue;
                        opcode = bytes[1] & 0xFF;
                        operandStart = 2;
                    }

                    // For opcodes that reference constant pool, extract the index
                    // The CP index position varies by opcode, but for most it's
                    // the first or second operand byte
                    int cpIdx = -1;
                    if (cpRefOpcodes.contains(opcode)) {
                        if (operandStart < bytes.length) {
                            // For LdaNamedProperty (0x30), CP index is 2nd operand
                            if (opcode == 0x30 || opcode == 0x31 || opcode == 0x35 || opcode == 0x36) {
                                if (operandStart + 1 < bytes.length) {
                                    cpIdx = bytes[operandStart + 1] & 0xFF;
                                }
                            } else {
                                cpIdx = bytes[operandStart] & 0xFF;
                            }
                        }
                    }

                    if (cpIdx >= 0 && cpIdx < cp.size()) {
                        String val = cp.get(cpIdx).getAsString();
                        if (val != null && !val.isEmpty()) {
                            String display = val.length() > 60 ? val.substring(0, 60) + "..." : val;
                            // Check if it looks like a SFI reference
                            if (display.startsWith("<SFI") || display.matches("^\\d+$")) {
                                display = "<SFI: " + display + ">";
                            }
                            listing.setComment(instr.getMinAddress(), CodeUnit.EOL_COMMENT,
                                "// CP[" + cpIdx + "] = \"" + display.replace("\"", "'") + "\"");
                            comments++;
                        }
                    }
                } catch (Exception e) {
                    // Skip problematic instructions
                }
            }
        }
        return comments;
    }

    // ── Gap marking ───────────────────────────���─────────────────────────────
    private void markGapsAsData(MemoryBlock payloadBlock, long baseAddr, long payloadSize,
                                 List<long[]> funcBounds, Listing listing, AddressSpace space) {
        // Sort function boundaries by start offset
        funcBounds.sort((a, b) -> Long.compare(a[0], b[0]));

        int gapsMarked = 0;
        long bytesMarked = 0;

        // Walk through the payload, marking gaps between functions
        long prevEnd = 0;
        for (long[] bounds : funcBounds) {
            long gapStart = prevEnd;
            long gapEnd = bounds[0];

            if (gapEnd > gapStart && (gapEnd - gapStart) >= 4) {
                // Mark this gap as undefined data
                try {
                    Address start = space.getAddress(baseAddr + gapStart);
                    Address end = space.getAddress(baseAddr + gapEnd - 1);
                    if (payloadBlock.contains(start) && payloadBlock.contains(end)) {
                        listing.clearCodeUnits(start, end, false);
                        gapsMarked++;
                        bytesMarked += (gapEnd - gapStart);
                    }
                } catch (Exception e) {
                    // Skip problematic gaps
                }
            }

            prevEnd = Math.max(prevEnd, bounds[1]);
        }

        // Mark trailing gap
        if (payloadSize > prevEnd) {
            try {
                Address start = space.getAddress(baseAddr + prevEnd);
                Address end = space.getAddress(baseAddr + payloadSize - 1);
                if (payloadBlock.contains(start)) {
                    listing.clearCodeUnits(start, end, false);
                    gapsMarked++;
                    bytesMarked += (payloadSize - prevEnd);
                }
            } catch (Exception e) {
                // ignore
            }
        }

        println("REPORT   Gaps cleared: " + gapsMarked + " (" + bytesMarked + " bytes)");
    }

    // ── Cross-references (Part 4) ───────────────────────────────────────────
    private int createCrossReferences(JsonArray funcs, Map<String, Address> nameToAddr,
                                       long baseAddr, AddressSpace space, Listing listing) {
        int xrefs = 0;
        var refMgr = currentProgram.getReferenceManager();

        // Call-like opcodes where we should create CALL xrefs instead of DATA
        Set<Integer> callOpcodes = new HashSet<>(Arrays.asList(
            0x5d, 0x5e, 0x5f, 0x60, 0x61, // CallAnyReceiver, CallProperty, CallProperty0/1/2
            0x62, 0x63, 0x64, 0x65,         // CallUndefinedReceiver, 0/1/2
            0x66,                             // CallWithSpread
            0x6b, 0x6c                        // Construct, ConstructWithSpread
        ));

        for (int i = 0; i < funcs.size(); i++) {
            JsonObject fn = funcs.get(i).getAsJsonObject();
            long payloadOff = fn.get("payloadOffset").getAsLong();
            int bcLen = fn.has("bytecodeLength") ? fn.get("bytecodeLength").getAsInt() : 0;
            if (payloadOff < 0 || bcLen <= 0) continue;

            Address funcStart = space.getAddress(baseAddr + payloadOff);
            Address funcEnd = space.getAddress(baseAddr + payloadOff + bcLen - 1);
            JsonArray cp = fn.has("constantPool") ? fn.getAsJsonArray("constantPool") : null;
            if (cp == null) continue;

            // Build a set of CP indices that resolve to known function names
            Map<Integer, Address> cpToTarget = new HashMap<>();
            for (int j = 0; j < cp.size(); j++) {
                String constName = cp.get(j).getAsString();
                String cleanName = constName.replaceAll("[^a-zA-Z0-9_]", "_");
                if (cleanName.length() > 0 && Character.isDigit(cleanName.charAt(0))) {
                    cleanName = "fn_" + cleanName;
                }

                Address targetAddr = nameToAddr.get(cleanName);
                if (targetAddr == null) {
                    targetAddr = nameToAddr.get(constName);
                }
                if (targetAddr != null && !targetAddr.equals(funcStart)) {
                    cpToTarget.put(j, targetAddr);
                }
            }

            if (cpToTarget.isEmpty()) continue;

            // Walk instructions and create references from specific call sites
            InstructionIterator instrIter = listing.getInstructions(funcStart, true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                if (instr.getMinAddress().compareTo(funcEnd) > 0) break;

                try {
                    byte[] bytes = instr.getBytes();
                    if (bytes == null || bytes.length < 2) continue;

                    int opcode = bytes[0] & 0xFF;
                    int operandStart = 1;
                    if (opcode == 0x01 || opcode == 0x02) {
                        if (bytes.length < 3) continue;
                        opcode = bytes[1] & 0xFF;
                        operandStart = 2;
                    }

                    // For any instruction, check if any of its operand bytes match a CP index
                    // that resolves to a known function
                    for (int b = operandStart; b < bytes.length; b++) {
                        int val = bytes[b] & 0xFF;
                        Address target = cpToTarget.get(val);
                        if (target != null) {
                            ghidra.program.model.symbol.RefType refType;
                            if (callOpcodes.contains(opcode)) {
                                refType = ghidra.program.model.symbol.RefType.UNCONDITIONAL_CALL;
                            } else {
                                refType = ghidra.program.model.symbol.RefType.DATA;
                            }
                            refMgr.addMemoryReference(instr.getMinAddress(), target,
                                refType, SourceType.IMPORTED, 0);
                            xrefs++;
                            break;  // One xref per instruction
                        }
                    }
                } catch (Exception e) {
                    // skip
                }
            }
        }
        return xrefs;
    }

    // Helper record to store function data for post-processing
    static class FuncRecord {
        int index;
        Address start;
        Address end;
        JsonObject fn;
        FuncRecord(int index, Address start, Address end, JsonObject fn) {
            this.index = index;
            this.start = start;
            this.end = end;
            this.fn = fn;
        }
    }
}
