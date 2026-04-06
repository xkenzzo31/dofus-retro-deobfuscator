// Export V8 function signatures for version diffing
// For each function: name, address, bytecodeLength, sha256(first 32 bytes)
// Output: /tmp/v8_signatures.json
// @author LuskaBot
// @category V8

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class ExportV8Signatures extends GhidraScript {

    private static final int SIGNATURE_BYTES = 32;
    private static final String OUTPUT_PATH = "/tmp/v8_signatures.json";

    @Override
    public void run() throws Exception {
        MemoryBlock payloadBlock = currentProgram.getMemory().getBlock(".v8payload");
        if (payloadBlock == null) {
            println("ERROR: No .v8payload block found.");
            return;
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Memory mem = currentProgram.getMemory();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        int total = fm.getFunctionCount();
        println("signature Exporting signatures for " + total + " functions...");

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"exportDate\": \"").append(new java.util.Date().toString()).append("\",\n");
        json.append("  \"program\": \"").append(escapeJson(currentProgram.getName())).append("\",\n");
        json.append("  \"totalFunctions\": ").append(total).append(",\n");
        json.append("  \"signatureBytes\": ").append(SIGNATURE_BYTES).append(",\n");
        json.append("  \"functions\": [\n");

        int count = 0;
        int exported = 0;
        int errors = 0;

        FunctionIterator funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            count++;

            try {
                Address entry = func.getEntryPoint();
                long bodySize = func.getBody().getNumAddresses();
                String name = func.getName();

                // Read first N bytes for signature
                int readLen = (int) Math.min(SIGNATURE_BYTES, bodySize);
                byte[] bytes = new byte[readLen];
                int bytesRead = mem.getBytes(entry, bytes);

                // Compute SHA-256
                sha256.reset();
                sha256.update(bytes, 0, bytesRead);
                byte[] hash = sha256.digest();
                String hexHash = bytesToHex(hash);

                // Also compute a full-body hash for exact match detection
                String fullHash = "";
                if (bodySize <= 65536) {
                    byte[] fullBytes = new byte[(int) bodySize];
                    int fullRead = mem.getBytes(entry, fullBytes);
                    sha256.reset();
                    sha256.update(fullBytes, 0, fullRead);
                    fullHash = bytesToHex(sha256.digest());
                }

                // Get namespace
                String ns = "";
                try {
                    if (func.getParentNamespace() != null &&
                        !func.getParentNamespace().isGlobal()) {
                        ns = func.getParentNamespace().getName();
                    }
                } catch (Exception e) { /* skip */ }

                // Check for handler bookmarks anywhere in the function body
                boolean hasTryCatch = false;
                AddressSetView body = func.getBody();
                var bmIter = currentProgram.getBookmarkManager().getBookmarksIterator(
                    body.getMinAddress(), true);
                while (bmIter.hasNext()) {
                    Bookmark bm = bmIter.next();
                    if (bm.getAddress().compareTo(body.getMaxAddress()) > 0) break;
                    if ("V8_TryCatch".equals(bm.getCategory())) {
                        hasTryCatch = true;
                        break;
                    }
                }

                // Count instructions
                int instrCount = 0;
                InstructionIterator instrIter = currentProgram.getListing().getInstructions(
                    func.getBody(), true);
                while (instrIter.hasNext()) {
                    instrIter.next();
                    instrCount++;
                }

                if (exported > 0) json.append(",\n");
                json.append("    {");
                json.append("\"name\": \"").append(escapeJson(name)).append("\", ");
                json.append("\"address\": \"").append(entry.toString()).append("\", ");
                json.append("\"bytecodeLength\": ").append(bodySize).append(", ");
                json.append("\"instructionCount\": ").append(instrCount).append(", ");
                json.append("\"headSignature\": \"").append(hexHash).append("\", ");
                json.append("\"fullSignature\": \"").append(fullHash).append("\", ");
                json.append("\"namespace\": \"").append(escapeJson(ns)).append("\", ");
                json.append("\"hasTryCatch\": ").append(hasTryCatch);
                json.append("}");

                exported++;

            } catch (Exception e) {
                errors++;
                if (errors <= 5) {
                    println("signature Error at func " + func.getName() + ": " + e.getMessage());
                }
            }

            if (count % 2000 == 0) {
                println("  signature Progress: " + count + "/" + total);
            }
        }

        json.append("\n  ]\n}\n");

        // Write output
        Files.write(Paths.get(OUTPUT_PATH), json.toString().getBytes());

        println("REPORT === SIGNATURE EXPORT DONE ===");
        println("REPORT   export Exported: " + exported + " functions");
        println("REPORT   export Errors: " + errors);
        println("REPORT   export Output: " + OUTPUT_PATH);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
