package v8_bytecode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;


public class V8_InjectConstruct extends V8_InjectPayload {

	public V8_InjectConstruct(String sourceName, SleighLanguage language, long uniqBase) {
		super(sourceName, language, uniqBase);
	}

	@Override
	public String getName() {
		return "ConstructCallOther";
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		V8_PcodeOpEmitter pCode = new V8_PcodeOpEmitter(language, context.baseAddr, uniqueBase);
		// V8 8.7: pcodeop is V8_Construct (op=0x6b, operands: callee, first_arg, arg_count, feedback_idx).
		// We emit V8_Construct(callee, first_arg, arg_count, feedback_idx).
		Address opAddr = context.baseAddr;
		Instruction instruction = program.getListing().getInstructionAt(opAddr);
		// opIndex=2 is the reglist (first register of argument list) in V8 8.7.
		Integer opIndex = 2;
		Object[] opObjects = instruction.getOpObjects(opIndex);
		String[] args = new String[opObjects.length + 1];
		// args[0] = callee (register operand 0)
		args[0] = instruction.getRegister(0).toString();
		for(int i=0; i < opObjects.length; i++) {
			args[i+1] = ((Register)opObjects[i]).toString();
		}
		// V8 8.7 SLEIGH defines pcodeop V8_Construct (not "Construct")
		pCode.emitAssignVarnodeFromPcodeOpCall("acc", 4, "V8_Construct", args);
		return pCode.getPcodeOps();
	}

}
