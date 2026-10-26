package v8_bytecode;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Program;

/**
 * Gives the decompiler the V8 constant pool (see V8_ConstantPool). Registered
 * through the pcodeInjectLibraryClass property of v8_87.pspec.
 */
public class V8_PcodeInjectLibrary extends PcodeInjectLibrary {

	public V8_PcodeInjectLibrary(SleighLanguage language) {
		super(language);
	}

	public V8_PcodeInjectLibrary(V8_PcodeInjectLibrary other) {
		super(other);
	}

	@Override
	public PcodeInjectLibrary clone() {
		return new V8_PcodeInjectLibrary(this);
	}

	@Override
	public ConstantPool getConstantPool(Program program) throws IOException {
		return new V8_ConstantPool(program);
	}
}
