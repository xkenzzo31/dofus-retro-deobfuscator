package v8_bytecode;

import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;

import v8_bytecode.allocator.JscParser;
import v8_bytecode.allocator.ObjectsAllocator;

public final class ReservObject {
	private final int kPointerSize;
	private final long size;
	private long _offset = 0L;
	private long lastAddAddress = 0L;
	private SortedMap<Long, Object> objects = new TreeMap<>();
	
	public ReservObject(long size, int pointerSize) {
		kPointerSize = pointerSize;
		this.size = size;
	}
	
	public Object getLastObject() {
		return objects.get(lastAddAddress);
	}
	
	public void setOffset(long offset) {
		this._offset = offset;
	}

	public long getOffset() {
		return _offset;
	}
	
	public Object getAlignedObject(long offset) {
		final Object obj = objects.get(offset);
		
		if (kPointerSize == 4) {
			return obj;
		}
		
		if (obj instanceof Integer) {
			final long obj2 = (int)objects.get(offset + 4);
			return obj2 << 32L;
		}
		
		return obj;
	}
	
	public int getInt(long offset) {
		return (int)objects.get(offset);
	}
	
	public int getSmiInt(long offset) {
		final int obj1 = (int)objects.get(offset);
		
		if (kPointerSize == 4) {
			return JscParser.smiToInt(obj1, kPointerSize);
		}
		
		final long obj2 = (int)objects.get(offset + 4);
		return JscParser.smiToInt(obj2 << 32L, kPointerSize);
	}
	
	public void addObject(long address, Object object) {
		lastAddAddress = address;
		
		if (object instanceof byte[]) {
			int[] objs = ObjectsAllocator.bytesToInts((byte[])object, 0);
			for (int i = 0; i < objs.length; ++i) {
				objects.put(address + i * 4, objs[i]);
			}
		} else {
			objects.put(address, object);
		}
	}

	public long getSize() {
		return size;
	}

	/**
	 * Return all (offset, object) entries stored in this ReservObject.
	 * Used by JscParser.loadSpaceObjects to iterate over sub-objects in a chunk.
	 */
	public java.util.Set<java.util.Map.Entry<Long, Object>> getObjectEntries() {
		return objects.entrySet();
	}

	@Override
	public int hashCode() {
		// Use identity-based hash to avoid recursive StackOverflow:
		// the objects map can contain other ReservObjects, creating
		// deep/circular hash chains.
		return System.identityHashCode(this);
	}

	@Override
	public boolean equals(Object obj) {
		// Use identity-based equality for the same reason as hashCode.
		return this == obj;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		
		for (final var item : objects.entrySet()) {
			sb.append(String.format("%04X, %d\n", item.getKey(), item.getValue()));
		}
		
		return sb.toString();
	}
}
