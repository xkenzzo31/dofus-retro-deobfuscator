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

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.options.Options;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.allocator.JscParser;
import v8_bytecode.allocator.ObjectsAllocator;

/**
 * Ghidra Loader for V8 8.7 JSC (bytenode) files.
 *
 * Detects .jsc files by checking the magic number which is constructed as:
 *   0xC0DE0000 ^ ExternalReferenceTable::kSize
 *
 * For V8 8.7.220.31 (Electron 11.5.0, bytenode 1.3.7):
 *   INSTANCE_SIZE = 0x3D2, so magic = 0xC0DE03D2
 *
 * Header format (V8 8.7, 32 bytes total):
 *   Offset 0x00: Magic         (uint32) = 0xC0DE0000 ^ kSize
 *   Offset 0x04: VersionHash   (uint32)
 *   Offset 0x08: SourceHash    (uint32)
 *   Offset 0x0C: FlagHash      (uint32)
 *   Offset 0x10: NumReservations (uint32)
 *   Offset 0x14: PayloadLength (uint32)
 *   Offset 0x18: Checksum      (uint32) = Adler-32
 *   Offset 0x1C: padding       (4 bytes)
 */
public class V8_bytecodeLoader extends AbstractLibrarySupportLoader {

	// V8 8.7.220.31-electron.0: ExternalReferenceTable::kSize = 978 = 0x3D2
	// Magic = 0xC0DE0000 ^ 0x3D2 = 0xC0DE03D2
	// The isV8JscMagic() method checks for any kSize in the plausible range [0x200, 0x800].
	static final String LDR_NAME = "Jsc V8 8.7 (Bytenode) Loader";

	private JscParser parser = null;
	private V8_VersionDetector verDetector = null;

	@Override
	public String getName() {
		return LDR_NAME;
	}

	/**
	 * Check if the magic word matches a known V8 JSC magic.
	 * The magic is 0xC0DE0000 ^ ExternalReferenceTable::kSize.
	 */
	private static boolean isV8JscMagic(long magic) {
		long base = magic ^ 0xC0DE0000L;
		// kSize is typically in range [0x200, 0x800] for known V8 versions
		return (base >= 0x200L && base <= 0x800L);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);

		long magic = reader.readNextUnsignedInt();

		if (isV8JscMagic(magic)) {
			verDetector = new V8_VersionDetector();

			final long versionHash = reader.readNextUnsignedInt();

			String detectedVersion = verDetector.detectVersion(versionHash);
			System.out.println("[V8Loader] Detected version: " + detectedVersion +
				" (hash: 0x" + Long.toHexString(versionHash) + ")");

			// V8 8.7 uses 32-bit pointers for bytecode (Ignition VM is 32-bit addressed)
			// The ldefs defines V8:LE:32:8.7 as the language ID
			loadSpecs.add(new LoadSpec(this, ObjectsAllocator.CODE_BASE,
				new LanguageCompilerSpecPair("V8:LE:32:8.7", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(Program program, Loader.ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();

		Options aOpts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		aOpts.setBoolean("Decompiler Switch Analysis", false);

		BinaryReader reader = new BinaryReader(provider, true);

		boolean sfiLoaded = false;
		try {
			// V8 8.7 (Electron 13+) uses pointer compression: tagged pointers are 32-bit
			// even on 64-bit platforms. The snapshot format uses kTaggedSize=4 throughout,
			// so we parse as 32-bit.
			parser = new JscParser(reader, true, program, monitor, log);
			parser.parse();
			parser.postAllocate();
			sfiLoaded = program.getMemory().getBlocks().length > 0;
			System.out.println(String.format(
				"[V8 8.7 Loader] Snapshot parsed: %d memory blocks created.",
				program.getMemory().getBlocks().length));
		} catch (Exception e) {
			System.out.println("[V8 8.7 Loader] Snapshot parse error: " + e.getMessage());
		}

		// ALWAYS load the raw payload for SLEIGH disassembly.
		// The structured blocks (.bcods, .cpool, .sfunc, .str, .scope) contain metadata,
		// but .text is often nearly empty because SFI bytecode allocation fails.
		// The raw payload at 0x30000000 gives the SLEIGH disassembler full access
		// to all 12.7 MB of V8 bytecodes.
		{
			System.out.println("[V8 8.7 Loader] Loading raw payload for SLEIGH disassembly...");
			try {
				reader.setPointerIndex(0x00);
				reader.readNextUnsignedInt(); // magic
				reader.readNextUnsignedInt(); // versionHash
				reader.readNextUnsignedInt(); // sourceHash
				reader.readNextUnsignedInt(); // flagsHash
				long numReserv = reader.readNextUnsignedInt();
				long payloadLen = reader.readNextUnsignedInt();
				reader.readNextUnsignedInt(); // checksum
				reader.readNextUnsignedInt(); // padding
				// Skip reservations
				for (int i = 0; i < numReserv; i++) {
					reader.readNextUnsignedInt();
				}
				// Align to 8 bytes
				long pos = reader.getPointerIndex();
				long aligned = (pos + 7) & ~7L;
				reader.setPointerIndex(aligned);

				byte[] payload = reader.readNextByteArray((int) payloadLen);

				long rawBase = 0x30000000L;
				ghidra.program.model.address.Address baseAddr =
					program.getAddressFactory().getDefaultAddressSpace().getAddress(rawBase);

				// Remove existing block if any
				ghidra.program.model.mem.MemoryBlock existing = program.getMemory().getBlock(baseAddr);
				if (existing != null) {
					program.getMemory().removeBlock(existing, monitor);
				}

				ghidra.program.model.mem.MemoryBlock block = program.getMemory().createInitializedBlock(
					".v8payload", baseAddr, payload.length, (byte) 0, monitor, false);
				block.setRead(true);
				block.setExecute(true);
				program.getMemory().setBytes(baseAddr, payload);

				System.out.println(String.format("[V8 8.7 Loader] Raw payload: %d bytes at 0x%08X", payloadLen, rawBase));
			} catch (Exception e2) {
				e2.printStackTrace();
				log.appendException(e2);
			}
		}
	}
}
