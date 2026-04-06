package v8_bytecode;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.exception.NotFoundException;
import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;

public abstract class V8_InjectPayload implements InjectPayload {
	protected SleighLanguage language;
	protected long uniqueBase;
	private String sourceName;

	public V8_InjectPayload(String sourceName, SleighLanguage language, long uniqBase) {
		this.language = language;
		this.sourceName = sourceName;
		this.uniqueBase = uniqBase;
	}

	@Override
	public int getType() {
		return InjectPayload.CALLOTHERFIXUP_TYPE;
	}

	@Override
	public String getSource() {
		return sourceName;
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit)
			throws UnknownInstructionException, MemoryAccessException, IOException, NotFoundException {
		// Not used - getPcode is used instead
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

	@Override
	public boolean isIncidentalCopy() {
		return false;
	}

	@Override
	public boolean isErrorPlaceholder() {
		return false;
	}

	@Override
	public InjectParameter[] getInput() {
		return null;
	}

	@Override
	public InjectParameter[] getOutput() {
		return null;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		// Dynamic inject payloads do not need to encode to XML/stream
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang) throws XmlParseException {
		// Dynamic inject payloads do not restore from XML
	}

	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		V8_InjectPayload other = (V8_InjectPayload) obj;
		if (getType() != other.getType()) {
			return false;
		}
		String name = getName();
		String otherName = other.getName();
		if (name == null) {
			return otherName == null;
		}
		return name.equals(otherName);
	}

}
