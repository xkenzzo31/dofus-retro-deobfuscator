package v8_bytecode.snapshot;

/**
 * A tagged slot value that does not point into the deserialized object graph.
 * Slots that point into the graph hold the {@link HeapObject} itself.
 */
public sealed interface Ref {

	/** Read-only root, by index into the roots table (data/v8_roots.json). */
	record Root(int index) implements Ref {
	}

	/**
	 * Object of the isolate's own read-only heap, by page and offset. The cache
	 * is loaded into a fully set-up isolate, so these are not part of it.
	 */
	record ReadOnlyHeap(int chunk, int offset) implements Ref {
	}

	/** Object supplied by the embedder at load time; index 0 is the script source. */
	record Attached(int index) implements Ref {
	}

	/** Entry of the startup (or read-only) object cache of the isolate. */
	record ObjectCache(boolean readOnly, int index) implements Ref {
	}

	/** External or API reference, by table index; it fills a system-pointer slot. */
	record External(boolean api, int index) implements Ref {
	}

	/** Weak reference that was already cleared when the cache was written. */
	record ClearedWeak() implements Ref {
	}
}
