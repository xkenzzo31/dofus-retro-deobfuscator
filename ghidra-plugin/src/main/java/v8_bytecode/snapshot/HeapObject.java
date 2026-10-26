package v8_bytecode.snapshot;

import java.util.Arrays;

/**
 * A heap object rebuilt from the code cache: its raw bytes, plus the tagged
 * slots the deserializer filled with references ({@link HeapObject} or
 * {@link Ref}). Slots without a reference hold raw data (Smis, integers,
 * characters, bytecode).
 */
public final class HeapObject {
	public final int space;
	public final int chunk;
	public final int offset;
	public final int size;
	public final int sequence;
	public final byte[] data;

	private int[] slotOffsets = new int[2];
	private Object[] slotValues = new Object[2];
	private int slots;

	HeapObject(int space, int chunk, int offset, int size, int sequence) {
		this.space = space;
		this.chunk = chunk;
		this.offset = offset;
		this.size = size;
		this.sequence = sequence;
		this.data = new byte[size];
	}

	void setSlot(int off, Object value) {
		int i = Arrays.binarySearch(slotOffsets, 0, slots, off);
		if (i >= 0) {
			slotValues[i] = value;
			return;
		}
		i = -i - 1;
		if (slots == slotOffsets.length) {
			slotOffsets = Arrays.copyOf(slotOffsets, slots * 2);
			slotValues = Arrays.copyOf(slotValues, slots * 2);
		}
		System.arraycopy(slotOffsets, i, slotOffsets, i + 1, slots - i);
		System.arraycopy(slotValues, i, slotValues, i + 1, slots - i);
		slotOffsets[i] = off;
		slotValues[i] = value;
		slots++;
	}

	/** Reference stored at {@code off}, or null when the slot holds raw data. */
	public Object slot(int off) {
		int i = Arrays.binarySearch(slotOffsets, 0, slots, off);
		return i >= 0 ? slotValues[i] : null;
	}

	public int slotCount() {
		return slots;
	}

	public int slotOffset(int i) {
		return slotOffsets[i];
	}

	public Object slotValue(int i) {
		return slotValues[i];
	}

	public Object map() {
		return slot(0);
	}

	public int uint8(int off) {
		return data[off] & 0xff;
	}

	public int uint16(int off) {
		return uint8(off) | (uint8(off + 1) << 8);
	}

	public int int16(int off) {
		return (short) uint16(off);
	}

	public int int32(int off) {
		return uint16(off) | (uint16(off + 2) << 16);
	}

	/** Smi stored in a 4-byte tagged slot (pointer compression: value << 1). */
	public int smi(int off) {
		return int32(off) >> 1;
	}

	public double float64(int off) {
		long lo = int32(off) & 0xffffffffL;
		long hi = int32(off + 4) & 0xffffffffL;
		return Double.longBitsToDouble(lo | (hi << 32));
	}

	@Override
	public String toString() {
		return String.format("HeapObject#%d(space %d, chunk %d +0x%x, %d bytes)", sequence, space,
			chunk, offset, size);
	}
}
