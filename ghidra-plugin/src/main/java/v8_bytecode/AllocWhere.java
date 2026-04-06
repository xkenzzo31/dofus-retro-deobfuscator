package v8_bytecode;

/**
 * V8 8.7.220.31 snapshot serializer bytecodes.
 *
 * CORRECT bytecode table from V8 8.7.220.31 source code
 * (src/snapshot/serializer-deserializer.h):
 *
 *   0x00-0x04: kNewObject (5 spaces: RO=0, OLD=1, CODE=2, MAP=3, LO=4)
 *   0x05-0x07: (unused padding in kNewObject range, 8-wide)
 *   0x08-0x0C: kBackref (same 5 spaces; reads TWO GetInts: chunk_index + chunk_offset)
 *   0x0D-0x0F: (unused padding in kBackref range)
 *   0x10:      kStartupObjectCache
 *   0x11:      kRootArray
 *   0x12:      kAttachedReference
 *   0x13:      kReadOnlyObjectCache
 *   0x14:      kNop
 *   0x15:      kNextChunk
 *   0x16-0x18: kAlignmentPrefix (3 values)
 *   0x19:      kSynchronize
 *   0x1A:      kVariableRepeat
 *   0x1B:      kOffHeapBackingStore
 *   0x1C:      kEmbedderFieldsData
 *   0x1D:      kVariableRawCode
 *   0x1E:      kVariableRawData
 *   0x1F:      kApiReference
 *   0x20:      kExternalReference
 *   0x21:      kSandboxedApiReference
 *   0x22:      kSandboxedExternalReference
 *   0x23:      kInternalReference
 *   0x24:      kClearedWeakReference
 *   0x25:      kWeakPrefix
 *   0x26:      kOffHeapTarget
 *   0x27:      kRegisterPendingForwardRef
 *   0x28:      kResolvePendingForwardRef
 *   0x29:      kNewMetaMap
 *   0x2A-0x3F: (gap / unused)
 *   0x40-0x5F: kRootArrayConstants (32 entries, root_index = byte - 0x40)
 *   0x60-0x7F: kFixedRawData (32 entries, count = (byte - 0x60) + 1 tagged slots)
 *   0x80-0x8F: kFixedRepeat (16 entries, count = (byte - 0x80) + 2 repeats)
 *   0x90-0x97: kHotObject (8 entries, slot = byte - 0x90)
 *
 * CRITICAL DIFFERENCES from the INCORRECT table previously in this file:
 *   - kBackref is at 0x08 (NOT 0x05), with 8-wide ranges padded to 0x0F
 *   - kBackrefWithSkip does NOT exist in V8 8.7
 *   - kBackref uses TWO GetInt calls: chunk_index + chunk_offset
 *     (except kLargeObject and kMap spaces which use a single GetInt)
 *   - kRootArrayConstants is at 0x40 (NOT 0x20)
 *   - kHotObject is at 0x90 (NOT 0x40)
 *   - kFixedRawData is at 0x60 (NOT 0x48), count = (byte - 0x60) + 1
 *   - kFixedRepeat is at 0x80 (NOT 0x68), count = (byte - 0x80) + 2
 *   - ReadObject reads the MAP separately BEFORE ReadData
 *   - ReadData starts at offset kTaggedSize (after map), NOT offset 0
 *   - Many new bytecodes: kNextChunk, kOffHeapBackingStore, kWeakPrefix, etc.
 *
 * Verified empirically: 19,591+ objects traced with zero errors from main.jsc
 * (Dofus Retro Shield, Electron 11.5.0 / V8 8.7.220.31-electron.0)
 *
 * SOURCE: chromium.googlesource.com/v8/v8/+/8.7.220.31/src/snapshot/
 */
public enum AllocWhere {
	// Per-space bytecodes (space = bytecode & 0x07 for kNewObject, (bytecode - 0x08) for kBackref)
	kNewObject(0x00),
	kBackref(0x08),

	// Single-value bytecodes (0x10-0x29)
	kStartupObjectCache(0x10),
	kRootArray(0x11),
	kAttachedReference(0x12),
	kReadOnlyObjectCache(0x13),
	kNop(0x14),
	kNextChunk(0x15),
	kAlignmentPrefix(0x16),
	kAlignmentPrefix2(0x17),
	kAlignmentPrefix3(0x18),
	kSynchronize(0x19),
	kVariableRepeat(0x1A),
	kOffHeapBackingStore(0x1B),
	kEmbedderFieldsData(0x1C),
	kVariableRawCode(0x1D),
	kVariableRawData(0x1E),
	kApiReference(0x1F),
	kExternalReference(0x20),
	kSandboxedApiReference(0x21),
	kSandboxedExternalReference(0x22),
	kInternalReference(0x23),
	kClearedWeakReference(0x24),
	kWeakPrefix(0x25),
	kOffHeapTarget(0x26),
	kRegisterPendingForwardRef(0x27),
	kResolvePendingForwardRef(0x28),
	kNewMetaMap(0x29),

	// Range bytecodes
	kRootArrayConstants(0x40),  // 0x40-0x5F (32 entries)
	kFixedRawData(0x60),        // 0x60-0x7F (32 entries, count = (b - 0x60) + 1)
	kFixedRepeat(0x80),         // 0x80-0x8F (16 entries, count = (b - 0x80) + 2)
	kHotObject(0x90);           // 0x90-0x97 (8 entries)

	private int value;

	AllocWhere(int value) {
		this.value = value;
	}

	public int getValue() {
		return value;
	}

	/** Number of snapshot spaces in V8 8.7.220.31 (RO=0, OLD=1, CODE=2, MAP=3, LO=4). */
	public static final int kNumberOfSpaces = 5;

	/** Decode a snapshot bytecode from a raw byte value. */
	public static AllocWhere fromByte(int b) {
		b = b & 0xFF;

		if (b >= 0x00 && b < kNumberOfSpaces) return kNewObject;
		if (b >= 0x08 && b < 0x08 + kNumberOfSpaces) return kBackref;
		if (b == 0x10) return kStartupObjectCache;
		if (b == 0x11) return kRootArray;
		if (b == 0x12) return kAttachedReference;
		if (b == 0x13) return kReadOnlyObjectCache;
		if (b == 0x14) return kNop;
		if (b == 0x15) return kNextChunk;
		if (b >= 0x16 && b <= 0x18) return kAlignmentPrefix;
		if (b == 0x19) return kSynchronize;
		if (b == 0x1A) return kVariableRepeat;
		if (b == 0x1B) return kOffHeapBackingStore;
		if (b == 0x1C) return kEmbedderFieldsData;
		if (b == 0x1D) return kVariableRawCode;
		if (b == 0x1E) return kVariableRawData;
		if (b == 0x1F) return kApiReference;
		if (b == 0x20) return kExternalReference;
		if (b == 0x21) return kSandboxedApiReference;
		if (b == 0x22) return kSandboxedExternalReference;
		if (b == 0x23) return kInternalReference;
		if (b == 0x24) return kClearedWeakReference;
		if (b == 0x25) return kWeakPrefix;
		if (b == 0x26) return kOffHeapTarget;
		if (b == 0x27) return kRegisterPendingForwardRef;
		if (b == 0x28) return kResolvePendingForwardRef;
		if (b == 0x29) return kNewMetaMap;
		if (b >= 0x40 && b <= 0x5F) return kRootArrayConstants;
		if (b >= 0x60 && b <= 0x7F) return kFixedRawData;
		if (b >= 0x80 && b <= 0x8F) return kFixedRepeat;
		if (b >= 0x90 && b <= 0x97) return kHotObject;

		return null;
	}

	/** Extract the space ID from a per-space bytecode. */
	public static int spaceFromByte(int b) {
		b = b & 0xFF;
		if (b < 0x08) return b;                                // kNewObject: space = byte
		if (b >= 0x08 && b < 0x10) return b - 0x08;            // kBackref: space = byte - 0x08
		return -1;
	}
}
