package v8_bytecode.loader;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

import v8_bytecode.loader.FunctionImporter.JsFunction;

/**
 * JavaScript values and operations for the bytecode interpreter (see
 * Interpreter). Numbers are Doubles, strings Strings, booleans Booleans; the
 * other values are the classes below. Conversions and operators follow
 * ECMAScript for primitives, arrays and plain objects; anything else throws
 * Unsupported, which stops the evaluation instead of guessing.
 */
final class Js {
	/** undefined, null, the hole (let/const before initialization) and the boilerplate placeholder. */
	enum Oddball {
		UNDEFINED, NULL, HOLE, UNINITIALIZED
	}

	static final Object UNDEFINED = Oddball.UNDEFINED;
	static final Object NULL = Oddball.NULL;
	static final Object HOLE = Oddball.HOLE;

	/** A value from outside (Node's require, module...) or that an analysis does not know. */
	static final class Opaque {
		final String name;

		Opaque(String name) {
			this.name = name;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	static final Opaque UNKNOWN = new Opaque("unknown");

	/** TestTypeOf's literal flags (TestTypeOfFlags::LiteralFlag). */
	private static final String[] TYPEOF_LITERALS =
		{ "number", "string", "symbol", "boolean", "bigint", "undefined", "function", "object", "other" };

	/** The evaluation needs something the interpreter does not model. */
	static final class Unsupported extends RuntimeException {
		Unsupported(String what) {
			super(what, null, false, false);
		}
	}

	/** A JavaScript exception being thrown. */
	static final class Throw extends Exception {
		final Object value;

		Throw(Object value) {
			super(null, null, false, false);
			this.value = value;
		}
	}

	static class JsObject {
		final Map<String, Object> properties = new LinkedHashMap<>();
		/** Evaluation that created the object (Interpreter sandboxing). */
		final int epoch;
		/** False once value flow saw the object change or escape after its creation. */
		boolean constant = true;

		JsObject(int epoch) {
			this.epoch = epoch;
		}
	}

	static final class JsArray extends JsObject {
		final List<Object> elements;

		JsArray(int epoch, List<Object> elements) {
			super(epoch);
			this.elements = elements;
		}
	}

	/** A function value: bytecode with the context it was created in. */
	record Closure(JsFunction function, Context context) {
	}

	/** A built-in function, with the properties of its function object (String.fromCharCode). */
	static final class Native {
		interface Body {
			Object call(Object receiver, Object[] args) throws Throw;
		}

		final String name;
		/** Pure built-ins have no effect besides their result. */
		final boolean pure;
		final Body body;
		final Map<String, Object> properties = new HashMap<>();

		Native(String name, boolean pure, Body body) {
			this.name = name;
			this.pure = pure;
			this.body = body;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	/**
	 * Slots of one instance of a scope. The static context stands for every
	 * context the interpreter did not create: its slots are the variable cells
	 * the loader resolved.
	 */
	static final class Context {
		static final Context STATIC = new Context(null, null, null, -1);

		final Object scope;
		final Object[] slots;
		final Context previous;
		final int epoch;

		Context(Object scope, Object[] slots, Context previous, int epoch) {
			this.scope = scope;
			this.slots = slots;
			this.previous = previous;
			this.epoch = epoch;
		}

		boolean isStatic() {
			return slots == null;
		}
	}

	private Js() {
	}

	static boolean isPrimitive(Object v) {
		return v instanceof Double || v instanceof String || v instanceof Boolean || v == UNDEFINED ||
			v == NULL;
	}

	static String describe(Object v) {
		if (v instanceof String s) {
			return FunctionImporter.quote(s);
		}
		if (v instanceof Double d) {
			return numberToString(d);
		}
		if (v instanceof Closure c) {
			return "function " + c.function().name;
		}
		if (v instanceof JsArray a) {
			return "array[" + a.elements.size() + "]";
		}
		if (v instanceof JsObject) {
			return "object";
		}
		return String.valueOf(v).toLowerCase(Locale.ROOT);
	}

	// ---- conversions ------------------------------------------------------------

	static boolean toBoolean(Object v) {
		if (v instanceof Boolean b) {
			return b;
		}
		if (v instanceof Double d) {
			return !(d == 0 || d.isNaN());
		}
		if (v instanceof String s) {
			return !s.isEmpty();
		}
		if (v == UNDEFINED || v == NULL) {
			return false;
		}
		if (v instanceof Opaque || v instanceof Oddball) {
			throw new Unsupported("ToBoolean(" + describe(v) + ")");
		}
		return true;
	}

	static double toNumber(Object v) {
		if (v instanceof Double d) {
			return d;
		}
		if (v instanceof Boolean b) {
			return b ? 1 : 0;
		}
		if (v instanceof String s) {
			return stringToNumber(s);
		}
		if (v == UNDEFINED) {
			return Double.NaN;
		}
		if (v == NULL) {
			return 0;
		}
		if (v instanceof JsObject) {
			return stringToNumber(toStr(v));
		}
		throw new Unsupported("ToNumber(" + describe(v) + ")");
	}

	static String toStr(Object v) {
		if (v instanceof String s) {
			return s;
		}
		if (v instanceof Double d) {
			return numberToString(d);
		}
		if (v instanceof Boolean b) {
			return b.toString();
		}
		if (v == UNDEFINED) {
			return "undefined";
		}
		if (v == NULL) {
			return "null";
		}
		if (v instanceof JsArray a) {
			return join(a, ",");
		}
		if (v instanceof JsObject o && !o.properties.containsKey("toString") &&
			!o.properties.containsKey("valueOf")) {
			return "[object Object]";
		}
		throw new Unsupported("ToString(" + describe(v) + ")");
	}

	/** ToPropertyKey: the string used to look a property up. */
	static String toKey(Object v) {
		if (v instanceof String s) {
			return s;
		}
		if (isPrimitive(v)) {
			return toStr(v);
		}
		throw new Unsupported("property key " + describe(v));
	}

	static int toInt32(double d) {
		if (Double.isNaN(d) || Double.isInfinite(d)) {
			return 0;
		}
		double t = d < 0 ? Math.ceil(d) : Math.floor(d);
		return (int) (long) (t % 4294967296.0);
	}

	static long toUint32(double d) {
		return toInt32(d) & 0xffffffffL;
	}

	/** Number::toString(10): shortest round-trip digits, laid out as ECMAScript does. */
	static String numberToString(double d) {
		if (Double.isNaN(d)) {
			return "NaN";
		}
		if (d == 0) {
			return "0";
		}
		if (Double.isInfinite(d)) {
			return d > 0 ? "Infinity" : "-Infinity";
		}
		if (d < 0) {
			return "-" + numberToString(-d);
		}
		if (d == Math.rint(d) && d < 1e21) {
			return d < 9.007199254740992e15 ? Long.toString((long) d)
					: new java.math.BigDecimal(d).toPlainString();
		}
		// Java prints the shortest round-trip digits; re-lay them out (Number::toString, step 6+).
		String s = Double.toString(d);
		int e = s.indexOf('E');
		int exponent = e < 0 ? 0 : Integer.parseInt(s.substring(e + 1));
		String mantissa = e < 0 ? s : s.substring(0, e);
		int dot = mantissa.indexOf('.');
		String digits = mantissa.substring(0, dot) + mantissa.substring(dot + 1);
		int n = dot + exponent;	// value = 0.digits * 10^n
		int lead = 0;
		while (lead < digits.length() - 1 && digits.charAt(lead) == '0') {
			lead++;
			n--;
		}
		digits = digits.substring(lead).replaceAll("0+$", "");
		if (digits.isEmpty()) {
			return "0";
		}
		int k = digits.length();
		if (k <= n && n <= 21) {
			return digits + "0".repeat(n - k);
		}
		if (0 < n && n <= 21) {
			return digits.substring(0, n) + "." + digits.substring(n);
		}
		if (-6 < n && n <= 0) {
			return "0." + "0".repeat(-n) + digits;
		}
		String exp = (n - 1 >= 0 ? "e+" : "e-") + Math.abs(n - 1);
		return k == 1 ? digits + exp : digits.charAt(0) + "." + digits.substring(1) + exp;
	}

	private static boolean isWhite(char c) {
		return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0x0b || c == 0x0c || c == 0xa0 ||
			c == 0xfeff || c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 ||
			c == 0x202f || c == 0x205f || c == 0x3000;
	}

	static String trim(String s) {
		int a = 0;
		int b = s.length();
		while (a < b && isWhite(s.charAt(a))) {
			a++;
		}
		while (b > a && isWhite(s.charAt(b - 1))) {
			b--;
		}
		return s.substring(a, b);
	}

	/** StringToNumber (7.1.4.1.1). */
	static double stringToNumber(String s) {
		String t = trim(s);
		if (t.isEmpty()) {
			return 0;
		}
		if (t.length() > 2 && t.charAt(0) == '0') {
			int radix = switch (t.charAt(1)) {
				case 'x', 'X' -> 16;
				case 'o', 'O' -> 8;
				case 'b', 'B' -> 2;
				default -> 0;
			};
			if (radix != 0) {
				double v = 0;
				for (int i = 2; i < t.length(); i++) {
					int digit = Character.digit(t.charAt(i), radix);
					if (digit < 0) {
						return Double.NaN;
					}
					v = v * radix + digit;
				}
				return v;
			}
		}
		switch (t) {
			case "Infinity":
			case "+Infinity":
				return Double.POSITIVE_INFINITY;
			case "-Infinity":
				return Double.NEGATIVE_INFINITY;
			default:
				break;
		}
		if (!t.matches("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")) {
			return Double.NaN;
		}
		return Double.parseDouble(t);
	}

	// ---- operators ------------------------------------------------------------------

	private static Object toPrimitive(Object v) {
		if (v instanceof JsObject) {
			return toStr(v);
		}
		if (v instanceof Opaque || v instanceof Closure || v instanceof Native || v == HOLE) {
			throw new Unsupported("ToPrimitive(" + describe(v) + ")");
		}
		return v;
	}

	static Object add(Object a, Object b) {
		Object x = toPrimitive(a);
		Object y = toPrimitive(b);
		if (x instanceof String || y instanceof String) {
			return toStr(x) + toStr(y);
		}
		return toNumber(x) + toNumber(y);
	}

	/** The arithmetic and bitwise binary operators, by bytecode name without "Smi". */
	static Object binary(String op, Object a, Object b) {
		switch (op) {
			case "Add":
				return add(a, b);
			case "Sub":
				return toNumber(a) - toNumber(b);
			case "Mul":
				return toNumber(a) * toNumber(b);
			case "Div":
				return toNumber(a) / toNumber(b);
			case "Mod":
				return toNumber(a) % toNumber(b);
			case "Exp":
				return pow(toNumber(a), toNumber(b));
			case "BitwiseOr":
				return (double) (toInt32(toNumber(a)) | toInt32(toNumber(b)));
			case "BitwiseXor":
				return (double) (toInt32(toNumber(a)) ^ toInt32(toNumber(b)));
			case "BitwiseAnd":
				return (double) (toInt32(toNumber(a)) & toInt32(toNumber(b)));
			case "ShiftLeft":
				return (double) (toInt32(toNumber(a)) << (toUint32(toNumber(b)) & 31));
			case "ShiftRight":
				return (double) (toInt32(toNumber(a)) >> (toUint32(toNumber(b)) & 31));
			case "ShiftRightLogical":
				return (double) (toUint32(toNumber(a)) >>> (toUint32(toNumber(b)) & 31));
			default:
				throw new Unsupported(op);
		}
	}

	static double pow(double base, double exponent) {
		if (Double.isNaN(exponent)) {
			return Double.NaN;
		}
		if (Math.abs(base) == 1 && Double.isInfinite(exponent)) {
			return Double.NaN;
		}
		return Math.pow(base, exponent);
	}

	static boolean strictEquals(Object a, Object b) {
		if (a instanceof Double x && b instanceof Double y) {
			return x.doubleValue() == y.doubleValue();
		}
		if (a instanceof String || a instanceof Boolean) {
			return a.equals(b);
		}
		checkComparable(a);
		checkComparable(b);
		return a == b;
	}

	private static void checkComparable(Object v) {
		if (v instanceof Opaque || v == HOLE) {
			throw new Unsupported("comparison with " + describe(v));
		}
	}

	static boolean looseEquals(Object a, Object b) {
		checkComparable(a);
		checkComparable(b);
		if ((a == UNDEFINED || a == NULL) || (b == UNDEFINED || b == NULL)) {
			return (a == UNDEFINED || a == NULL) && (b == UNDEFINED || b == NULL);
		}
		if (a.getClass() == b.getClass() && !(a instanceof JsObject)) {
			return strictEquals(a, b);
		}
		if (a instanceof JsObject && b instanceof JsObject) {
			return a == b;
		}
		if (a instanceof Closure || a instanceof Native || b instanceof Closure || b instanceof Native) {
			return a == b;
		}
		Object x = toPrimitive(a);
		Object y = toPrimitive(b);
		if (x instanceof String && y instanceof String) {
			return x.equals(y);
		}
		return toNumber(x) == toNumber(y);
	}

	/** a < b, a > b, a <= b, a >= b (IsLessThan, 7.2.13). */
	static boolean compare(String op, Object a, Object b) {
		Object x = toPrimitive(a);
		Object y = toPrimitive(b);
		if (x instanceof String s && y instanceof String t) {
			int c = s.compareTo(t);
			return switch (op) {
				case "TestLessThan" -> c < 0;
				case "TestGreaterThan" -> c > 0;
				case "TestLessThanOrEqual" -> c <= 0;
				default -> c >= 0;
			};
		}
		double p = toNumber(x);
		double q = toNumber(y);
		return switch (op) {
			case "TestLessThan" -> p < q;
			case "TestGreaterThan" -> p > q;
			case "TestLessThanOrEqual" -> p <= q;
			default -> p >= q;
		};
	}

	/** The typeof result a TestTypeOf flag compares with. */
	static String typeofLiteral(long flag) {
		return flag >= 0 && flag < TYPEOF_LITERALS.length ? TYPEOF_LITERALS[(int) flag] : "other";
	}

	static String typeOf(Object v) {
		if (v == UNDEFINED) {
			return "undefined";
		}
		if (v == NULL || v instanceof JsObject) {
			return "object";
		}
		if (v instanceof Boolean) {
			return "boolean";
		}
		if (v instanceof Double) {
			return "number";
		}
		if (v instanceof String) {
			return "string";
		}
		if (v instanceof Closure || v instanceof Native) {
			return "function";
		}
		throw new Unsupported("typeof " + describe(v));
	}

	// ---- properties ---------------------------------------------------------------

	private static final Set<String> OBJECT_PROTOTYPE = Set.of("constructor", "toString", "valueOf",
		"hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString", "__proto__",
		"__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__");

	/** Index of a canonical array index key ("0", "17"), or -1. */
	static int arrayIndex(String key) {
		int n = key.length();
		if (n == 0 || n > 9 || (n > 1 && key.charAt(0) == '0')) {
			return -1;
		}
		int v = 0;
		for (int i = 0; i < n; i++) {
			char c = key.charAt(i);
			if (c < '0' || c > '9') {
				return -1;
			}
			v = v * 10 + (c - '0');
		}
		return v;
	}

	static Object getProperty(Object target, Object keyValue) throws Throw {
		if (target == UNDEFINED || target == NULL) {
			throw new Throw(error("TypeError", "Cannot read property of " + describe(target)));
		}
		String key = toKey(keyValue);
		if (target instanceof String s) {
			if (key.equals("length")) {
				return (double) s.length();
			}
			int i = arrayIndex(key);
			if (i >= 0) {
				return i < s.length() ? String.valueOf(s.charAt(i)) : UNDEFINED;
			}
			Native m = STRING_METHODS.get(key);
			if (m == null) {
				throw new Unsupported("String.prototype." + key);
			}
			return m;
		}
		if (target instanceof JsArray a) {
			if (key.equals("length")) {
				return (double) a.elements.size();
			}
			int i = arrayIndex(key);
			if (i >= 0) {
				Object v = i < a.elements.size() ? a.elements.get(i) : UNDEFINED;
				return v == HOLE ? UNDEFINED : v;
			}
			Object own = a.properties.get(key);
			if (own != null) {
				return own;
			}
			Native m = ARRAY_METHODS.get(key);
			if (m == null) {
				throw new Unsupported("Array.prototype." + key);
			}
			return m;
		}
		if (target instanceof JsObject o) {
			Object v = o.properties.get(key);
			if (v == Oddball.UNINITIALIZED) {
				throw new Unsupported("computed literal property " + key);
			}
			if (v != null) {
				return v;
			}
			if (OBJECT_PROTOTYPE.contains(key)) {
				throw new Unsupported("Object.prototype." + key);
			}
			return UNDEFINED;
		}
		if (target instanceof Native n && n.properties.containsKey(key)) {
			return n.properties.get(key);
		}
		throw new Unsupported("property " + key + " of " + describe(target));
	}

	static void setProperty(Object target, Object keyValue, Object value) throws Throw {
		if (target == UNDEFINED || target == NULL) {
			throw new Throw(error("TypeError", "Cannot set property of " + describe(target)));
		}
		String key = toKey(keyValue);
		if (target instanceof JsArray a) {
			int i = arrayIndex(key);
			if (i >= 0) {
				if (i > 1 << 24) {
					throw new Unsupported("sparse array");
				}
				while (a.elements.size() <= i) {
					a.elements.add(UNDEFINED);
				}
				a.elements.set(i, value);
				return;
			}
			if (key.equals("length")) {
				int n = (int) toNumber(value);
				while (a.elements.size() > n) {
					a.elements.remove(a.elements.size() - 1);
				}
				while (a.elements.size() < n) {
					a.elements.add(UNDEFINED);
				}
				return;
			}
		}
		if (target instanceof JsObject o) {
			o.properties.put(key, value);
			return;
		}
		throw new Unsupported("store to " + describe(target));
	}

	static JsObject error(String name, String message) {
		JsObject e = new JsObject(-1);
		e.properties.put("name", name);
		e.properties.put("message", message);
		return e;
	}

	// ---- built-ins -------------------------------------------------------------------

	private static Object arg(Object[] args, int i) {
		return i < args.length ? args[i] : UNDEFINED;
	}

	private static JsArray array(Object receiver) {
		if (receiver instanceof JsArray a) {
			return a;
		}
		throw new Unsupported("array method on " + describe(receiver));
	}

	private static String string(Object receiver) {
		if (receiver instanceof String s) {
			return s;
		}
		throw new Unsupported("string method on " + describe(receiver));
	}

	private static int relativeIndex(Object v, int length, int absent) {
		if (v == UNDEFINED) {
			return absent;
		}
		double d = toNumber(v);
		if (Double.isNaN(d)) {
			return 0;
		}
		double t = d < 0 ? Math.ceil(d) : Math.floor(d);
		if (t < 0) {
			return (int) Math.max(length + t, 0);
		}
		return (int) Math.min(t, length);
	}

	static String join(JsArray a, String separator) {
		StringJoiner j = new StringJoiner(separator);
		for (Object v : a.elements) {
			j.add(v == UNDEFINED || v == NULL || v == HOLE ? "" : toStr(v));
		}
		return j.toString();
	}

	static final Map<String, Native> ARRAY_METHODS = Map.of(
		"push", new Native("push", false, (r, args) -> {
			JsArray a = array(r);
			a.elements.addAll(Arrays.asList(args));
			return (double) a.elements.size();
		}),
		"shift", new Native("shift", false, (r, args) -> {
			JsArray a = array(r);
			return a.elements.isEmpty() ? UNDEFINED : a.elements.remove(0);
		}),
		"pop", new Native("pop", false, (r, args) -> {
			JsArray a = array(r);
			return a.elements.isEmpty() ? UNDEFINED : a.elements.remove(a.elements.size() - 1);
		}),
		"unshift", new Native("unshift", false, (r, args) -> {
			JsArray a = array(r);
			a.elements.addAll(0, Arrays.asList(args));
			return (double) a.elements.size();
		}),
		"join", new Native("join", true, (r, args) -> join(array(r),
			arg(args, 0) == UNDEFINED ? "," : toStr(arg(args, 0)))),
		"indexOf", new Native("indexOf", true, (r, args) -> {
			List<Object> e = array(r).elements;
			for (int i = 0; i < e.size(); i++) {
				if (strictEquals(e.get(i), arg(args, 0))) {
					return (double) i;
				}
			}
			return -1.0;
		}));

	static final Map<String, Native> STRING_METHODS = Map.of(
		"charCodeAt", new Native("charCodeAt", true, (r, args) -> {
			String s = string(r);
			double i = arg(args, 0) == UNDEFINED ? 0 : toNumber(arg(args, 0));
			return i >= 0 && i < s.length() ? (double) s.charAt((int) i) : Double.NaN;
		}),
		"charAt", new Native("charAt", true, (r, args) -> {
			String s = string(r);
			double i = arg(args, 0) == UNDEFINED ? 0 : toNumber(arg(args, 0));
			return i >= 0 && i < s.length() ? String.valueOf(s.charAt((int) i)) : "";
		}),
		"indexOf", new Native("indexOf", true, (r, args) -> (double) string(r).indexOf(toStr(arg(args, 0)))),
		"slice", new Native("slice", true, (r, args) -> {
			String s = string(r);
			int from = relativeIndex(arg(args, 0), s.length(), 0);
			int to = relativeIndex(arg(args, 1), s.length(), s.length());
			return from < to ? s.substring(from, to) : "";
		}),
		"substring", new Native("substring", true, (r, args) -> {
			String s = string(r);
			int a = clampIndex(arg(args, 0), s.length(), 0);
			int b = clampIndex(arg(args, 1), s.length(), s.length());
			return s.substring(Math.min(a, b), Math.max(a, b));
		}),
		"split", new Native("split", true, (r, args) -> {
			String s = string(r);
			if (arg(args, 0) == UNDEFINED || arg(args, 1) != UNDEFINED) {
				throw new Unsupported("split form");
			}
			String sep = toStr(arg(args, 0));
			List<Object> parts = new ArrayList<>();
			if (sep.isEmpty()) {
				for (int i = 0; i < s.length(); i++) {
					parts.add(String.valueOf(s.charAt(i)));
				}
			}
			else {
				int from = 0;
				for (int at; (at = s.indexOf(sep, from)) >= 0; from = at + sep.length()) {
					parts.add(s.substring(from, at));
				}
				parts.add(s.substring(from));
			}
			return new JsArray(Interpreter.NO_EPOCH, parts);
		}),
		"toLowerCase", new Native("toLowerCase", true, (r, args) -> string(r).toLowerCase(Locale.ROOT)),
		"toUpperCase", new Native("toUpperCase", true, (r, args) -> string(r).toUpperCase(Locale.ROOT)),
		"toString", new Native("toString", true, (r, args) -> string(r)));

	private static int clampIndex(Object v, int length, int absent) {
		if (v == UNDEFINED) {
			return absent;
		}
		double d = toNumber(v);
		return Double.isNaN(d) ? 0 : (int) Math.max(0, Math.min(d, length));
	}

	/** parseInt (19.2.5). */
	static double parseInt(Object input, Object radixValue) {
		String s = trim(toStr(input));
		int sign = 1;
		if (!s.isEmpty() && (s.charAt(0) == '-' || s.charAt(0) == '+')) {
			sign = s.charAt(0) == '-' ? -1 : 1;
			s = s.substring(1);
		}
		int radix = toInt32(radixValue == UNDEFINED ? 0 : toNumber(radixValue));
		boolean stripPrefix = true;
		if (radix != 0) {
			if (radix < 2 || radix > 36) {
				return Double.NaN;
			}
			stripPrefix = radix == 16;
		}
		else {
			radix = 10;
		}
		if (stripPrefix && s.length() >= 2 && s.charAt(0) == '0' &&
			(s.charAt(1) == 'x' || s.charAt(1) == 'X')) {
			s = s.substring(2);
			radix = 16;
		}
		int end = 0;
		while (end < s.length() && Character.digit(s.charAt(end), radix) >= 0 && s.charAt(end) < 128) {
			end++;
		}
		if (end == 0) {
			return Double.NaN;
		}
		if (radix == 10) {
			return sign * Double.parseDouble(s.substring(0, end));
		}
		double v = 0;
		for (int i = 0; i < end; i++) {
			v = v * radix + Character.digit(s.charAt(i), radix);
		}
		return sign * v;
	}

	static Object decodeURIComponent(String s) throws Throw {
		StringBuilder out = new StringBuilder();
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		for (int i = 0; i < s.length();) {
			char c = s.charAt(i);
			if (c != '%') {
				out.append(c);
				i++;
				continue;
			}
			bytes.reset();
			while (i < s.length() && s.charAt(i) == '%') {
				int hi = i + 2 < s.length() ? Character.digit(s.charAt(i + 1), 16) : -1;
				int lo = i + 2 < s.length() ? Character.digit(s.charAt(i + 2), 16) : -1;
				if (hi < 0 || lo < 0) {
					throw new Throw(error("URIError", "URI malformed"));
				}
				bytes.write(hi * 16 + lo);
				i += 3;
			}
			out.append(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
		}
		return out.toString();
	}

	/** The global object's built-ins. */
	static JsObject globals() {
		JsObject g = new JsObject(-1);
		g.properties.put("parseInt",
			new Native("parseInt", true, (r, args) -> parseInt(arg(args, 0), arg(args, 1))));
		g.properties.put("parseFloat", new Native("parseFloat", true, (r, args) -> {
			String s = trim(toStr(arg(args, 0)));
			java.util.regex.Matcher m =
				java.util.regex.Pattern.compile("^[+-]?(Infinity|(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?)")
						.matcher(s);
			if (!m.find()) {
				return Double.NaN;
			}
			String t = m.group();
			return t.endsWith("Infinity") ? (t.startsWith("-") ? Double.NEGATIVE_INFINITY
					: Double.POSITIVE_INFINITY) : Double.parseDouble(t);
		}));
		g.properties.put("isNaN", new Native("isNaN", true, (r, args) -> Double.isNaN(toNumber(arg(args, 0)))));
		g.properties.put("decodeURIComponent",
			new Native("decodeURIComponent", true, (r, args) -> decodeURIComponent(toStr(arg(args, 0)))));
		Native string = new Native("String", true, (r, args) -> args.length == 0 ? "" : toStr(args[0]));
		string.properties.put("fromCharCode", new Native("fromCharCode", true, (r, args) -> {
			StringBuilder b = new StringBuilder();
			for (Object a : args) {
				b.append((char) toUint32(toNumber(a)));
			}
			return b.toString();
		}));
		g.properties.put("String", string);
		JsObject math = new JsObject(-1);
		math.properties.put("floor", new Native("floor", true, (r, args) -> Math.floor(toNumber(arg(args, 0)))));
		math.properties.put("ceil", new Native("ceil", true, (r, args) -> Math.ceil(toNumber(arg(args, 0)))));
		math.properties.put("abs", new Native("abs", true, (r, args) -> Math.abs(toNumber(arg(args, 0)))));
		math.properties.put("pow",
			new Native("pow", true, (r, args) -> pow(toNumber(arg(args, 0)), toNumber(arg(args, 1)))));
		g.properties.put("Math", math);
		return g;
	}
}
