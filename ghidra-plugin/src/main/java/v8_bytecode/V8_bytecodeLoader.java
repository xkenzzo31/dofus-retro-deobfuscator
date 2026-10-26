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

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.program.database.ProgramCompilerSpec;
import ghidra.program.model.lang.DecompilerLanguage;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.loader.FunctionImporter;
import v8_bytecode.loader.HeapImage;
import v8_bytecode.model.V8Heap;
import v8_bytecode.model.V8Tables;
import v8_bytecode.snapshot.CodeCache;

/**
 * Loader for V8 8.7 code caches: the .jsc files bytenode writes, e.g. the
 * main process of Electron 11 applications (V8 8.7.220.31).
 *
 * Header (SerializedCodeData, 32 bytes): magic (0xC0DE0000 ^
 * ExternalReferenceTable::kSize), version hash, source hash, flags hash,
 * number of reservations, payload length, checksum, padding; then the
 * reservations and the payload, aligned to 8 bytes.
 *
 * The payload is deserialized into a heap image (see HeapImage) and every
 * function with bytecode becomes a Ghidra function (see FunctionImporter).
 */
public class V8_bytecodeLoader extends AbstractLibrarySupportLoader {

	static final String LDR_NAME = "V8 8.7 code cache (bytenode .jsc)";
	static final String LANGUAGE_ID = "V8:LE:32:8.7";
	static final String SUPPORTED_VERSION = "8.7.220.31";

	@Override
	public String getName() {
		return LDR_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (provider.length() < CodeCache.HEADER_SIZE) {
			return loadSpecs;
		}
		byte[] magic = provider.readBytes(0, 4);
		if (CodeCache.isCodeCacheMagic((magic[0] & 0xff) | (magic[1] & 0xff) << 8 |
			(magic[2] & 0xff) << 16 | (magic[3] & 0xff) << 24)) {
			loadSpecs.add(new LoadSpec(this, HeapImage.HEAP_BASE,
				new LanguageCompilerSpecPair(LANGUAGE_ID, "default"), true));
		}
		return loadSpecs;
	}

	@Override
	protected void load(Program program, Loader.ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();

		CodeCache cache = CodeCache.read(provider.readBytes(0, provider.length()));
		String version = new V8_VersionDetector().detectVersion(cache.versionHash & 0xffffffffL);
		if (!version.equals(SUPPORTED_VERSION)) {
			log.appendMsg(String.format("Version hash %08x is V8 %s; the tables of this loader are " +
				"for V8 %s, results may be wrong", cache.versionHash, version, SUPPORTED_VERSION));
		}

		monitor.setMessage("Deserializing V8 code cache");
		cache.deserialize();
		V8Heap heap = new V8Heap(V8Tables.get());
		HeapImage image = new HeapImage(cache, heap);
		try {
			image.createBlocks(program, monitor);
			FunctionImporter importer = new FunctionImporter(program, cache, image, heap, log);
			importer.run(monitor);
			image.markup(program, monitor);
			// JavaScript reads closer to Java than to C: obj.name, no '*' on
			// property loads and stores (see V8_ConstantPool).
			program.getOptions(ProgramCompilerSpec.DECOMPILER_PROPERTY_LIST_NAME)
					.setEnum(ProgramCompilerSpec.DECOMPILER_OUTPUT_LANGUAGE, DecompilerLanguage.JAVA_LANGUAGE);
			log.appendMsg(String.format(
				"V8 %s code cache: %d objects (%d deferred), %d functions, %d constant-pool jumps, " +
					"%d switches, %d exception handlers",
				version, cache.objects.size(), cache.deferredObjects, importer.functions().size(),
				importer.jumpConstantCount(), importer.switchCount(), importer.handlerCount()));
			log.appendMsg(String.format(
				"Variables: %d globals, %d context variables, %d accesses resolved, %d context slot " +
					"accesses unresolved; closures matching their scope chain: %s",
				importer.globalVariableCount(), importer.contextVariableCount(),
				importer.variableAccessCount(), importer.unresolvedSlotCount(), importer.closureAgreement()));
			log.appendMsg(importer.stringSummary());
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException("Failed to load V8 code cache: " + e.getMessage(), e);
		}
	}
}
