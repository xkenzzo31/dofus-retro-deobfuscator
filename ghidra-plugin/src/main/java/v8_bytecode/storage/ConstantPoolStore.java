package v8_bytecode.storage;

import java.io.Serializable;
import java.util.List;

public final class ConstantPoolStore implements Serializable {

	private final List<ConstantPoolItemStore> items;
	
	public ConstantPoolStore(final List<ConstantPoolItemStore> items) {
		this.items = items;
	}
	
	public Object getConstItem(int index) {
		if (index < 0 || index >= items.size()) return null;
		final ConstantPoolItemStore item = items.get(index);
		return item != null ? item.getItem() : null;
	}

	public long getConstItemAddress(int index) {
		if (index < 0 || index >= items.size()) return -1;
		final ConstantPoolItemStore item = items.get(index);
		return item != null ? item.getAddress() : -1;
	}
}
