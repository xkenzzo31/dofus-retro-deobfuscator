package v8_bytecode;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Program;

public class V8_PcodeInjectLibrary extends PcodeInjectLibrary {
	private Set<String> implementedOps;
	private SleighLanguage language;

	public V8_PcodeInjectLibrary(SleighLanguage l) {
		super(l);
		language = l;
		implementedOps = new HashSet<>();
		// Names must match "define pcodeop <name>" in v8_87.slaspec + "CallOther" suffix.
		// The SLEIGH defines: V8_InvokeIntrinsic, V8_CallRuntime, V8_CallProperty,
		// V8_CallFunction, V8_Construct, V8_Throw, V8_SetKeyedProperty, etc.
		// Ghidra forms callother fixup names as "<pcodeop_name>CallOther".
		implementedOps.add("V8_InvokeIntrinsicCallOther");
		implementedOps.add("V8_CallRuntimeCallOther");
		implementedOps.add("V8_CallPropertyCallOther");
		implementedOps.add("V8_CallFunctionCallOther");
		implementedOps.add("V8_ConstructCallOther");
		implementedOps.add("V8_CallJSRuntimeCallOther");
		implementedOps.add("V8_ThrowCallOther");
		implementedOps.add("V8_ThrowReferenceErrorCallOther");
		implementedOps.add("V8_SetKeyedPropertyCallOther");
	}
	
	@Override
	public ConstantPool getConstantPool(Program program) throws IOException {
		return new V8_ConstantPool(program);
	}
	
	@Override
	/**
	* This method is called by DecompileCallback.getPcodeInject.
	* In Ghidra 12.x, getPayload takes only (int type, String name).
	*/
	public InjectPayload getPayload(int type, String name) {
		if (type == InjectPayload.CALLMECHANISM_TYPE) {
			return null;
		}

		if (!implementedOps.contains(name)) {
			return super.getPayload(type, name);
		}

		V8_InjectPayload payload = null;
		switch (name) {
		case ("V8_InvokeIntrinsicCallOther"):
		case ("V8_CallPropertyCallOther"):
		case ("V8_CallRuntimeCallOther"):
			payload = new V8_InjectCallVariadic("", language, 0);
			break;
		case ("V8_ConstructCallOther"):
			payload = new V8_InjectConstruct("", language, 0);
			break;
		case ("V8_CallFunctionCallOther"):
			payload = new V8_InjectJSCallN("", language, 0);
			break;
		case ("V8_CallJSRuntimeCallOther"):
			payload = new V8_InjectCallJSRuntime("", language, 0);
			break;
		case ("V8_ThrowCallOther"):
		case ("V8_ThrowReferenceErrorCallOther"):
			payload = new V8_InjectThrow("", language, 0);
			break;
		case ("V8_SetKeyedPropertyCallOther"):
			payload = new V8_InjectStaDataPropertyInLiteral("", language, 0);
			break;
		default:
			return super.getPayload(type, name);
		}

		return payload;
	}

}
