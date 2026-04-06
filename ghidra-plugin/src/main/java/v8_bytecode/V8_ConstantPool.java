package v8_bytecode;

import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Program;
import v8_bytecode.allocator.JscParser;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.enums.RootsEnum;
import v8_bytecode.enums.TypeOfEnum;
import v8_bytecode.storage.ArrayStore;
import v8_bytecode.storage.ContextVarStore;
import v8_bytecode.storage.RuntimesIntrinsicsStore;
import v8_bytecode.storage.RootsStore;
import v8_bytecode.storage.ScopeInfoStore;
import v8_bytecode.storage.SharedFunctionStore;
import v8_bytecode.storage.FuncsStorage;
import v8_bytecode.storage.InstructionsStorage;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Function;

public class V8_ConstantPool extends ConstantPool {
	private final FuncsStorage funcsStorage;
	
	private final FlatProgramAPI fpa;
	private final DataTypeManager mgr;

	public V8_ConstantPool(Program program) {
		fpa = new FlatProgramAPI(program);
		
		mgr = program.getDataTypeManager();

		funcsStorage = FuncsStorage.load(program);
	}

	@Override
	public Record getRecord(long[] ref) {
		Record res = new Record();
		long address = ref[0];
		int index = (int) ref[1];
		int indexType = (int) ref[2];

		try {
		// System.out.println(String.format("%04X %04X", address, index));
		switch (indexType) {
		case 0: { // constant pool
			final Object cpItem = funcsStorage.getConstItem(fpa.toAddr(address), index);
			if (cpItem == null) break;

			if (cpItem instanceof String) {
				res.tag = ConstantPool.STRING_LITERAL;
				res.type = new PointerDataType(CharDataType.dataType);
				res.byteData = ((String)cpItem).getBytes();
			} else if (cpItem instanceof Integer) {
				res.tag = ConstantPool.PRIMITIVE;
				res.type = IntegerDataType.dataType;
				res.value = (Integer)cpItem;
				res.token = "int";
			} else if (cpItem instanceof Long) {
				res.tag = ConstantPool.PRIMITIVE;
				res.type = LongLongDataType.dataType;
				res.value = (Long)cpItem;
				res.token = "longlong";
			} else if (cpItem instanceof Double) {
				res.tag = ConstantPool.PRIMITIVE;
				res.type = DoubleDataType.dataType;

				final int[] halfs = ObjectsAllocator.doubleToInts((Double)cpItem);
				res.value = (((long)halfs[1]) << 32 ) + (halfs[0] & 0xffffffffL);
				res.token = "double";
			} else if (cpItem instanceof RootObject) {
				res.tag = ConstantPool.PRIMITIVE;
				res.type = mgr.getRootCategory().getDataType(RootsEnum.NAME);
				final RootsStore roots = funcsStorage.getRoots();
				if (roots != null) {
					res.value = roots.fromString((RootObject)cpItem);
				}
				res.token = ((RootObject)cpItem).getName();
			} else if (cpItem instanceof SharedFunctionStore) {
				final Address funcAddr = fpa.toAddr(((SharedFunctionStore)cpItem).getAddress());
				final Function funcAt = fpa.getFunctionAt(funcAddr);
				if (funcAt != null) {
					res.tag = ConstantPool.POINTER_METHOD;
					res.type = new PointerDataType(VoidDataType.dataType);
					res.token = funcAt.getName();
				}
			} else if (cpItem instanceof ArrayStore){
				res.tag = ConstantPool.POINTER_FIELD;
				res.type = mgr.getRootCategory().getDataType(((ArrayStore)cpItem).getName());
				res.token = ((ArrayStore)cpItem).getName();
			} else if (cpItem instanceof ScopeInfoStore) {
				res.tag = ConstantPool.POINTER_FIELD;
				res.type = mgr.getRootCategory().getDataType(((ScopeInfoStore)cpItem).getName());
				res.token = ((ScopeInfoStore)cpItem).getName();
			} else {
				//System.out.println(cpItem);
			}
		} break;
		case 1: // intrinsics
		case 2: { // runtimes
			final RuntimesIntrinsicsStore runsIntrsStore = funcsStorage.getRuntimesIntrinsicsStore();
			if (runsIntrsStore != null) {
				res.tag = ConstantPool.POINTER_METHOD;
				res.type = new PointerDataType(VoidDataType.dataType);
				res.token = (indexType == 1) ? runsIntrsStore.getIntrinsicName(index) : runsIntrsStore.getRuntimeName(index);
			}
		} break;
		case 3: { // context slot
			final InstructionsStorage instrStorage = InstructionsStorage.load(fpa.getCurrentProgram(), address);

			if (instrStorage == null) {
				break;
			}

			final ScopeInfoStore scopeInfo = instrStorage.getScopeInfo();
			if (scopeInfo == null) break;
			final ContextVarStore ctxVar = scopeInfo.getContextVar(index);
			if (ctxVar == null) break;

			res.tag = ConstantPool.POINTER_METHOD;
			res.type = new PointerDataType(VoidDataType.dataType);
			res.token = ctxVar.getName();
		} break;
		case 4: {
			final DataType dtypeOf = mgr.getRootCategory().getDataType(TypeOfEnum.NAME);
			if (!(dtypeOf instanceof Enum)) break;
			final Enum typeOf = (Enum) dtypeOf;

			res.tag = ConstantPool.PRIMITIVE;
			res.type = typeOf;
			res.value = index;
			res.token = typeOf.getName(index);
		} break;
		case 5: {
			final Object cpItem = funcsStorage.getConstItem(fpa.toAddr(address), index);
			if (cpItem == null) break;

			final long val;
			if (cpItem instanceof Integer) {
				val = JscParser.smiToInt((int)cpItem, ObjectsAllocator.getPointerSize(fpa.getCurrentProgram()));
			} else if (cpItem instanceof Long) {
				val = JscParser.smiToInt((long)cpItem, ObjectsAllocator.getPointerSize(fpa.getCurrentProgram()));
			} else {
				break;
			}

			res.tag = ConstantPool.PRIMITIVE;
			res.type = LongLongDataType.dataType;
			res.value = val;
			res.token = "longlong";
		} break;
		}
		} catch (Exception e) {
			// Never let constant pool resolution throw
		}

		return res;
	}
}
