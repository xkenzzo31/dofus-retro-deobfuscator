package v8_bytecode.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Decoder for Ignition bytecode arrays (src/interpreter/bytecodes.h and
 * bytecode-operands.h, V8 8.7). The loader uses it to find what SLEIGH cannot
 * compute on its own: Jump*Constant and switch targets, exception handlers and
 * the constant pool operands that deserve references.
 */
public final class Ignition {
	public static final int WIDE = 0x00;
	public static final int EXTRA_WIDE = 0x01;

	/** Operand index of the constant pool entry used by each bytecode. */
	private static final Map<String, Integer> CONSTANT_POOL_OPERAND = Map.ofEntries(
		Map.entry("LdaConstant", 0), Map.entry("LdaGlobal", 0),
		Map.entry("LdaGlobalInsideTypeof", 0), Map.entry("StaGlobal", 0),
		Map.entry("LdaLookupSlot", 0), Map.entry("LdaLookupContextSlot", 0),
		Map.entry("LdaLookupGlobalSlot", 0),
		Map.entry("LdaLookupSlotInsideTypeof", 0),
		Map.entry("LdaLookupContextSlotInsideTypeof", 0),
		Map.entry("LdaLookupGlobalSlotInsideTypeof", 0),
		Map.entry("StaLookupSlot", 0), Map.entry("LdaNamedProperty", 1),
		Map.entry("LdaNamedPropertyNoFeedback", 1),
		Map.entry("LdaNamedPropertyFromSuper", 1),
		Map.entry("StaNamedProperty", 1),
		Map.entry("StaNamedPropertyNoFeedback", 1),
		Map.entry("StaNamedOwnProperty", 1), Map.entry("CreateRegExpLiteral", 0),
		Map.entry("CreateArrayLiteral", 0), Map.entry("CreateObjectLiteral", 0),
		Map.entry("GetTemplateObject", 0), Map.entry("CreateClosure", 0),
		Map.entry("CreateBlockContext", 0), Map.entry("CreateCatchContext", 1),
		Map.entry("CreateFunctionContext", 0), Map.entry("CreateEvalContext", 0),
		Map.entry("CreateWithContext", 1),
		Map.entry("ThrowReferenceErrorIfHole", 0));

	private static final Set<String> FIXED_ONE_BYTE =
		Set.of("Flag8", "IntrinsicId", "NativeContextIndex");
	private static final Set<String> SIGNED =
		Set.of("Reg", "RegOut", "RegList", "RegOutList", "RegPair", "RegOutPair", "RegOutTriple", "Imm");

	/** One decoded bytecode; {@code offset} is the start of its prefix, if any. */
	public record Instruction(int offset, int length, int scale, V8Tables.Bytecode bytecode,
			long[] operands) {

		public String name() {
			return bytecode.name();
		}

		/** Offset of the opcode byte, which relative jumps are based on. */
		public int opcodeOffset() {
			return scale > 1 ? offset + 1 : offset;
		}

		/** Operand index of the constant pool entry this bytecode uses, or -1. */
		public int constantPoolOperand() {
			return CONSTANT_POOL_OPERAND.getOrDefault(bytecode.name(), -1);
		}

		public boolean isJumpConstant() {
			return name().startsWith("Jump") && name().endsWith("Constant");
		}

		public boolean isJumpImmediate() {
			return name().startsWith("Jump") && !name().endsWith("Constant");
		}

		/** Target of an immediate jump (JumpLoop jumps backwards). */
		public int immediateJumpTarget() {
			int distance = (int) operands[0];
			return name().equals("JumpLoop") ? opcodeOffset() - distance : opcodeOffset() + distance;
		}
	}

	private Ignition() {
	}

	public static int operandSize(String kind, int scale) {
		if (FIXED_ONE_BYTE.contains(kind)) {
			return 1;
		}
		return kind.equals("RuntimeId") ? 2 : scale;
	}

	/**
	 * Decodes a whole bytecode array. Decoding stops at the first byte that is
	 * not a valid bytecode or whose operands run past the end.
	 */
	public static List<Instruction> decode(byte[] code, int start, int length, V8Tables tables) {
		List<Instruction> out = new ArrayList<>();
		int pos = 0;
		while (pos < length) {
			int begin = pos;
			int scale = 1;
			int op = code[start + pos] & 0xff;
			if (op == WIDE || op == EXTRA_WIDE) {
				scale = op == WIDE ? 2 : 4;
				if (++pos >= length) {
					break;
				}
				op = code[start + pos] & 0xff;
			}
			if (op >= tables.bytecodes.size()) {
				break;
			}
			V8Tables.Bytecode bytecode = tables.bytecodes.get(op);
			pos++;
			long[] operands = new long[bytecode.operands().size()];
			boolean truncated = false;
			for (int i = 0; i < operands.length; i++) {
				String kind = bytecode.operands().get(i);
				int n = operandSize(kind, scale);
				if (pos + n > length) {
					truncated = true;
					break;
				}
				long v = 0;
				for (int k = 0; k < n; k++) {
					v |= (long) (code[start + pos + k] & 0xff) << (8 * k);
				}
				if (SIGNED.contains(kind)) {
					v = (v << (64 - 8 * n)) >> (64 - 8 * n);
				}
				operands[i] = v;
				pos += n;
			}
			if (truncated) {
				break;
			}
			out.add(new Instruction(begin, pos - begin, scale, bytecode, operands));
		}
		return out;
	}
}
