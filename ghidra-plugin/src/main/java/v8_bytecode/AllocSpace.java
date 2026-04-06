package v8_bytecode;

/**
 * V8 8.7 snapshot space allocation IDs.
 *
 * V8 8.7 defines these spaces in src/snapshot/serializer.h:
 *   kReadOnlyHeap = 0  (new in V8 8.x, holds immutable roots)
 *   kOld = 1           (OLD_SPACE: normal heap objects, SharedFunctionInfo, etc.)
 *   kCode = 2          (CODE_SPACE: executable code)
 *   kMap = 3            (MAP_SPACE: Map objects)
 *   kNew = 4            (NEW_SPACE: young generation / large objects)
 *
 * Note: V8 6.x used a different numbering where NEW_SPACE=0, OLD_SPACE=1, etc.
 * The serializer bytecode encoding has also changed significantly.
 */
public enum AllocSpace {
	READ_ONLY_SPACE(0x00),
	OLD_SPACE(0x01),
	CODE_SPACE(0x02),
	MAP_SPACE(0x03),
	NEW_SPACE(0x04);

	private final int value;

	AllocSpace(int value) {
		this.value = value;
	}

	public static AllocSpace fromInt(int value) {
		for (AllocSpace space : values()) {
			if (space.value == value) {
				return space;
			}
		}

		return null;
	}

	public int getValue() {
		return value;
	}
}
