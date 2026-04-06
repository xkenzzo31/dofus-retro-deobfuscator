package v8_bytecode.structs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.ReservObject;
import v8_bytecode.RootObject;
import v8_bytecode.allocator.BytecodesAllocator;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;

/**
 * V8 8.7 BytecodeArray struct parser.
 *
 * Layout (from src/objects/code.tq, branch-heads/8.7, kTaggedSize=8, 64-bit):
 *
 *   BytecodeArray extends FixedArrayBase extends HeapObject
 *
 *   HeapObject::kHeaderSize      = 8  (map: tagged)
 *   FixedArrayBase::kHeaderSize  = 16 (map + length: Smi = tagged)
 *
 *   Offset  Size  Field
 *   0x00    8     map                (HeapObject)
 *   0x08    8     length             (FixedArrayBase, Smi)
 *   0x10    8     constant_pool      (FixedArray)          kConstantPoolOffset
 *   0x18    8     handler_table      (ByteArray)           kHandlerTableOffset
 *   0x20    8     source_position_table (Undefined|ByteArray|Exception) kSourcePositionTableOffset
 *   0x28    4     frame_size         (int32)               kFrameSizeOffset
 *   0x2C    4     parameter_size     (int32)               kParameterSizeOffset
 *   0x30    4     incoming_new_target_or_generator_register (int32) kIncomingNewTargetOrGeneratorRegisterOffset
 *   0x34    1     osr_nesting_level  (int8)                kOsrNestingLevelOffset
 *   0x35    1     bytecode_age       (int8)                kBytecodeAgeOffset
 *   0x36    2     padding            (to align kHeaderSize to 8 bytes)
 *   0x38    ...   bytecodes                               kHeaderSize
 *
 * CHANGES vs V8 6.x:
 *   - kInterruptBudgetOffset REMOVED (int32 field that was between kIncoming... and kOSR)
 *   - kOsrNestingLevelOffset: was 56 (0x38), now 52 (0x34)
 *   - kBytecodeAgeOffset:     was 57 (0x39), now 53 (0x35)
 *   - kHeaderSize:            was 60 (0x3C), now 56 (0x38)
 *
 * Source: chromium.googlesource.com/v8/v8 branch-heads/8.7
 *   src/objects/code.tq (BytecodeArray Torque definition)
 *   src/objects/code.h  (STATIC_ASSERT verifying kBytecodeAgeOffset == kOsrNestingLevelOffset + kCharSize)
 */
public final class BytecodeStruct implements IAllocatable {
	private final int length;
	private Object cp;
	private Object ht;
	private final SourcePositionsStruct spt;

	private final int funcIndex;
	private final int frameSize;
	private final int parameterSize;
	private final int incoming;
	private final byte osrNestingLevel;
	private final byte bytecodeAge;
	// NOTE: interruptBudget was removed from BytecodeArray in V8 8.x.
	// It is now managed elsewhere (FeedbackVector).

	private final byte[] bytecode;
	private final Structure s;

	private final int size;
	private final BytecodesAllocator bcAllocator;

	private Address baseAddr = null;

	// --- Offsets (V8 8.7, kTaggedSize=8, 64-bit, no pointer compression) ---

	/** kConstantPoolOffset = FixedArrayBase::kHeaderSize = 16 (0x10) */
	public final int kConstantPoolOffset;

	/** kHandlerTableOffset = kConstantPoolOffset + kTaggedSize = 24 (0x18) */
	public final int kHandlerTableOffset;

	/** kSourcePositionTableOffset = kHandlerTableOffset + kTaggedSize = 32 (0x20) */
	public final int kSourcePositionTableOffset;

	/** kFrameSizeOffset = kSourcePositionTableOffset + kTaggedSize = 40 (0x28) */
	public final int kFrameSizeOffset;

	/** kParameterSizeOffset = kFrameSizeOffset + 4 = 44 (0x2C) */
	public final int kParameterSizeOffset;

	/**
	 * kIncomingNewTargetOrGeneratorRegisterOffset = kParameterSizeOffset + 4 = 48 (0x30)
	 */
	public final int kIncomingNewTargetOrGeneratorRegisterOffset;

	/**
	 * kOsrNestingLevelOffset = kIncomingNewTargetOrGeneratorRegisterOffset + 4 = 52 (0x34)
	 * NOTE: in V8 6.x this was 56 (0x38) because kInterruptBudgetOffset occupied [52..55].
	 *       kInterruptBudgetOffset has been REMOVED in V8 8.x.
	 */
	public final int kOsrNestingLevelOffset;

	/**
	 * kBytecodeAgeOffset = kOsrNestingLevelOffset + 1 = 53 (0x35)
	 * STATIC_ASSERT from code.h: kBytecodeAgeOffset == kOsrNestingLevelOffset + kCharSize
	 */
	public final int kBytecodeAgeOffset;

	/**
	 * kHeaderSize = OBJECT_POINTER_ALIGN(kBytecodeAgeOffset + 1)
	 *             = OBJECT_POINTER_ALIGN(54) = 56 (0x38)
	 * Bytecodes start immediately after kHeaderSize.
	 * In V8 6.x this was 60 (0x3C).
	 */
	public final int kHeaderSize;

	public BytecodeStruct(final ReservObject obj, int funcIndex, final ObjectsAllocator allocator) throws Exception {
		int pointerSize = allocator.getPointerSize();

		// --- Offset initialisation (V8 8.7) ---
		// FixedArrayBase::kHeaderSize = HeapObject::kHeaderSize + kTaggedSize
		//                             = kTaggedSize + kTaggedSize = 2 * pointerSize
		kConstantPoolOffset = ArrayStruct.getArrayHeaderSize(pointerSize);  // 16
		kHandlerTableOffset = kConstantPoolOffset + pointerSize;             // 24
		kSourcePositionTableOffset = kHandlerTableOffset + pointerSize;      // 32
		kFrameSizeOffset = kSourcePositionTableOffset + pointerSize;         // 40
		kParameterSizeOffset = kFrameSizeOffset + 4;                         // 44
		kIncomingNewTargetOrGeneratorRegisterOffset = kParameterSizeOffset + 4; // 48
		// V8 8.7: no kInterruptBudgetOffset here (removed from BytecodeArray)
		kOsrNestingLevelOffset = kIncomingNewTargetOrGeneratorRegisterOffset + 4; // 52
		kBytecodeAgeOffset = kOsrNestingLevelOffset + 1;                     // 53
		// kHeaderSize = OBJECT_POINTER_ALIGN(54) = 56
		// The +2 accounts for the 2 padding bytes that bring 54 up to 56.
		kHeaderSize = kBytecodeAgeOffset + 1 + 2;                            // 56
		// --- End offset initialisation ---

		bcAllocator = new BytecodesAllocator(allocator);

		this.funcIndex = funcIndex;

		allocator.getMonitor().setMessage(String.format("Creating bytecode for function #%d", funcIndex));

		s = new StructureDataType(String.format("Bytecode%d", funcIndex), 0);

		// Length (Smi stored at FixedArrayBase offset = kMetaMap + pointerSize)
		length = obj.getSmiInt(ArrayStruct.getArrayLengthOffset(pointerSize));
		s.add(DWordDataType.dataType, -1, "Length", null);

		// constant_pool: FixedArray | RootObject
		cp = obj.getAlignedObject(kConstantPoolOffset);
		if (cp instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "ConstantPool", null);
		} else {
			cp = new ConstantPoolStruct((ReservObject) cp, funcIndex, allocator);
			s.add(new PointerDataType(VoidDataType.dataType), -1, "ConstantPool", null);
		}

		// handler_table: ByteArray | RootObject
		ht = obj.getAlignedObject(kHandlerTableOffset);
		if (ht instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "HandlerTable", null);
		} else {
			ht = new HandlerTableStruct((ReservObject) ht, funcIndex, allocator);
			s.add(((HandlerTableStruct) ht).toDataType(), -1, "HandlerTable", null);
		}

		// source_position_table: Undefined | ByteArray | Exception
		final Object sptObj = obj.getAlignedObject(kSourcePositionTableOffset);
		spt = new SourcePositionsStruct((ReservObject) sptObj, funcIndex, allocator);
		s.add(spt.toDataType(), -1, "SourcePositions", null);

		// frame_size: int32
		frameSize = obj.getInt(kFrameSizeOffset);
		s.add(DWordDataType.dataType, -1, "FrameSize", null);

		// parameter_size: int32
		parameterSize = obj.getInt(kParameterSizeOffset) / pointerSize;
		s.add(DWordDataType.dataType, -1, "ParameterSize", null);

		// incoming_new_target_or_generator_register: int32
		incoming = obj.getInt(kIncomingNewTargetOrGeneratorRegisterOffset);
		s.add(DWordDataType.dataType, -1, "Incoming", null);

		// osr_nesting_level (int8) and bytecode_age (int8) are packed at
		// kOsrNestingLevelOffset (52) and kBytecodeAgeOffset (53).
		// We read them from the same int32 word at kOsrNestingLevelOffset (aligned read).
		int tmp = obj.getInt(kOsrNestingLevelOffset);
		osrNestingLevel = (byte) ((tmp >> 0) & 0xFF);
		s.add(ByteDataType.dataType, 1, "OSRNestingLevel", null);

		bytecodeAge = (byte) ((tmp >> 8) & 0xFF);
		s.add(ByteDataType.dataType, 1, "BytecodeAge", null);

		// Read bytecodes starting at kHeaderSize (56).
		// The two padding bytes at [54..55] are consumed as part of this int32 read.
		ByteArrayOutputStream out = new ByteArrayOutputStream(length);
		out.write((byte) ((tmp >> 16) & 0xFF));
		out.write((byte) ((tmp >> 24) & 0xFF));
		for (int i = 0; i < (length - 2); i += 4) {
			byte[] bb = ObjectsAllocator.intToBytes(obj.getInt(kHeaderSize + i));
			out.write(bb);
		}
		bytecode = Arrays.copyOf(out.toByteArray(), length);

		s.add(new PointerDataType(ByteDataType.dataType), -1, "BytecodeData", null);

		size = s.getLength();
	}

	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));

		Address result = bcAllocator.allocateNew(this, size);
		bcAllocator.allocate(length);

		bcAllocator.allocate(cp);

		baseAddr = allocator.allocateInCode(bytecode);

		if (ht instanceof RootObject) {
			bcAllocator.allocate(ht);
		} else {
			bcAllocator.allocate((HandlerTableStruct) ht, baseAddr);
		}

		bcAllocator.allocate(spt, baseAddr);

		bcAllocator.allocate(frameSize);
		bcAllocator.allocate(parameterSize);
		bcAllocator.allocate(incoming);
		// NOTE: interruptBudget no longer allocated (field removed in V8 8.x)
		bcAllocator.allocate(osrNestingLevel);
		bcAllocator.allocate(bytecodeAge);

		bcAllocator.allocate(baseAddr);

		allocator.setDataStruct(result, this);

		return result;
	}

	public Address getBaseAddress() {
		return baseAddr;
	}

	public int getLength() {
		return length;
	}

	public ConstantPoolStruct getConstantPool() {
		if (cp instanceof ConstantPoolStruct) {
			return (ConstantPoolStruct) cp;
		}
		return null;
	}

	public HandlerTableStruct getHandlerTable() {
		if (ht instanceof HandlerTableStruct) {
			return (HandlerTableStruct) ht;
		}
		return null;
	}

	@Override
	public int hashCode() {
		return Objects.hash(funcIndex);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		BytecodeStruct other = (BytecodeStruct) obj;
		return funcIndex == other.funcIndex;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}
}
