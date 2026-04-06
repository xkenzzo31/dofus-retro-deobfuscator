/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package v8_bytecode;

import ghidra.program.model.listing.Listing;
import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.allocator.JscParser;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.enums.IntrinsicsEnum;
import v8_bytecode.enums.JsRuntimesEnum;
import v8_bytecode.enums.RuntimesEnum;
import v8_bytecode.enums.TypeOfEnum;
import v8_bytecode.storage.ContextVarStore;
import v8_bytecode.storage.RuntimesIntrinsicsStore;
import v8_bytecode.storage.ScopeInfoStore;
import v8_bytecode.storage.SharedFunctionStore;
import v8_bytecode.storage.FuncsStorage;
import v8_bytecode.storage.InstructionsStorage;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.data.Enum;

import static java.util.Map.entry;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class V8_bytecodeAnalyzer extends AbstractAnalyzer {
	// V8 8.7 constant pool referencing opcodes.
	// Keys are instruction mnemonics as displayed in the Ghidra listing (from SLEIGH).
	// Values are the operand indices that reference the constant pool.
	//
	// Removed vs V8 8.6:
	//   - LdaNamedPropertyNoFeedback : does not exist in V8 8.7
	//   - StaNamedPropertyStrict     : replaced by StaNamedProperty (op=0x35)
	//   - StaNamedPropertyNoFeedback : does not exist in V8 8.7
	// Changed vs V8 8.6:
	//   - CreateCatchContext: V8 8.7 has only 2 operands (reg, idx), so CP is at index 1
	// Added vs V8 8.6:
	//   - LdaNamedPropertyFromSuper : new opcode 0x31 in V8 8.7
	//   - StaNamedProperty          : op=0x35 (was StaNamedPropertyStrict in 8.6)
	private static final Map<String, List<Integer>> CP_FUNCS = Map.ofEntries(
        	entry("LdaNamedProperty", List.of(1)),
        	entry("LdaNamedPropertyFromSuper", List.of(1)),
        	entry("StaNamedProperty", List.of(1)),
        	entry("StaNamedOwnProperty", List.of(1)),
        	entry("CreateObjectLiteral", List.of(0)),
        	entry("CreateClosure", List.of(0)),
        	entry("LdaConstant", List.of(0)),
        	entry("LdaGlobal", List.of(0)),
        	entry("LdaGlobalInsideTypeof", List.of(0)),
        	entry("StaGlobal", List.of(0)),
        	entry("CallRuntime", List.of(0)),
        	entry("InvokeIntrinsic", List.of(0)),
        	entry("CreateBlockContext", List.of(0)),
        	entry("CreateCatchContext", List.of(1)),
        	entry("SwitchOnSmiNoFeedback", List.of(0)),
        	entry("ThrowReferenceErrorIfHole", List.of(0))
	        );
	
	// V8 8.7 constant-pool-indirect jump opcodes (op=0x90..0x9a).
	// JumpIfUndefinedOrNullConstant (op=0x95) is new in V8 8.7.
	private static final Map<String, List<Integer>> JUMP_FUNCS = Map.ofEntries(
        	entry("JumpConstant", List.of(0)),
        	entry("JumpIfNullConstant", List.of(0)),
        	entry("JumpIfNotNullConstant", List.of(0)),
        	entry("JumpIfUndefinedConstant", List.of(0)),
        	entry("JumpIfNotUndefinedConstant", List.of(0)),
        	entry("JumpIfUndefinedOrNullConstant", List.of(0)),
        	entry("JumpIfTrueConstant", List.of(0)),
        	entry("JumpIfFalseConstant", List.of(0)),
        	entry("JumpIfJSReceiverConstant", List.of(0)),
        	entry("JumpIfToBooleanTrueConstant", List.of(0)),
        	entry("JumpIfToBooleanFalseConstant", List.of(0))
			);
	
	private static final Map<String, List<Integer>> CTX_FUNCS = Map.ofEntries(
			entry("CreateFunctionContext", List.of(0)),
			entry("LdaImmutableCurrentContextSlot", List.of(0)),
			entry("LdaImmutableContextSlot", List.of(1)),
			entry("LdaCurrentContextSlot", List.of(0)),
			entry("LdaContextSlot", List.of(1)),
			entry("StaCurrentContextSlot", List.of(0)),
			entry("StaContextSlot", List.of(1))
			);
	
	private static final List<String> CTX_CHANGER = List.of(
			"PushContext",
			"PopContext"
			);
	
	private static final Map<String, List<Integer>> JSRUN_CALLS = Map.ofEntries(
			entry("CallJSRuntime", List.of(0))
			);
	
	private static final Map<String, List<Integer>> TYPEOFS = Map.ofEntries(
			entry("TestTypeOf", List.of(0))
			);
	
	private FuncsStorage funcsStorage;
	
	public V8_bytecodeAnalyzer() {
		super("V8RefsAnalyzer", "Analyzes refs to ConstantPool, Intrinsics and Runtime functions", AnalyzerType.FUNCTION_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(V8_bytecodeLoader.LDR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(V8_bytecodeLoader.LDR_NAME);
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		funcsStorage = FuncsStorage.load(program);
		
		final Listing listing = program.getListing();
		final FlatProgramAPI fpa = new FlatProgramAPI(program);
		final FunctionManager mgr = program.getFunctionManager();

		monitor.setIndeterminate(true);

		final String _context = "_context";
		ScopeInfoStore currentScope = null;
		
		AddressIterator fiter = set.getAddresses(true);
		
		int switchNum = 0;

		while (fiter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			final Address addr = fiter.next();

			Function func = mgr.getFunctionContaining(addr);

			if (func != null) {
				final String logString = String.format("Applying references for \"%s\"", func.getName());
				monitor.setMessage(logString);
			}

			Instruction instruction = listing.getInstructionAt(addr);

			if (instruction == null) {
				continue;
			}

			String mnemonic = trimMnemonic(instruction.getMnemonicString());

			// System.out.println(String.format("0x%08X - %s", addr.getOffset(), instruction));

		  try {
			if (hasConstantPoolReference(mnemonic)) {
				for (int opIndex : CP_FUNCS.get(mnemonic)) {
				  try {
					var scalar = instruction.getScalar(opIndex);
					if (scalar == null) continue;
					int index = (int) (scalar.getValue() & 0xFFFFFFFF);
					instruction.removeOperandReference(opIndex, fpa.toAddr(index));

					switch(mnemonic) {
						case "CallRuntime":
						case "InvokeIntrinsic": {
							final RuntimesIntrinsicsStore runsIntrsStore = funcsStorage.getRuntimesIntrinsicsStore();
							if (runsIntrsStore == null) break;

							final String enumName;
							if (!mnemonic.equals("InvokeIntrinsic")) {
								enumName = runsIntrsStore.getRuntimeName(index);
							} else {
								enumName = runsIntrsStore.getIntrinsicName(index);
							}
							if (enumName == null) break;

							switch(enumName) {
							case "Abort": {
								patchWithNop(instruction, 2, 2, "ldasmi", "star", true, fpa, log);
							} break;
							case "_GeneratorGetContext": {
								patchWithNop(instruction, 2, 3, "ldar", "star", true, fpa, log);
							} break;
							case "_CreateJSGeneratorObject": {
								patchWithNop(instruction, 2, 1, "mov", "star", true, fpa, log);
							} break;
							case "_GeneratorGetInputOrDebugPos": {
								patchWithNop(instruction, 5, 0, "suspendgenerator", "invokeintrinsic", true, fpa, log);
							} break;
							case "_GeneratorGetResumeMode": {
								patchWithNop(instruction, 0, 0, "invokeintrinsic", "invokeintrinsic", true, fpa, log);
							} break;
							}

							if (!mnemonic.equals("InvokeIntrinsic")) {
								setEnumOperand(program, RuntimesEnum.NAME, addr, opIndex, index);
							} else {
								setEnumOperand(program, IntrinsicsEnum.NAME, addr, opIndex, index);
							}
						} break;
						case "CreateClosure": {
							final Object cpItem = funcsStorage.getConstItem(addr, index);
							if (!(cpItem instanceof SharedFunctionStore)) break;
							final SharedFunctionStore sfItem = (SharedFunctionStore) cpItem;
							instruction.addOperandReference(opIndex, fpa.toAddr(sfItem.getAddress()), RefType.DATA, SourceType.ANALYSIS);
						} break;
						case "CreateBlockContext": {
							final Object cpItem = funcsStorage.getConstItem(addr, index);
							if (cpItem instanceof ScopeInfoStore) {
								currentScope = (ScopeInfoStore) cpItem;
							}

							long itemAddrVal = funcsStorage.getConstItemAddress(addr, index);
							if (itemAddrVal >= 0) {
								final Address itemAddr = fpa.toAddr(itemAddrVal);
								instruction.addOperandReference(opIndex, itemAddr, RefType.DATA, SourceType.ANALYSIS);
							}
						} break;
						case "CreateCatchContext": {
							// V8 8.7: CreateCatchContext reg, [idx] — only one CP operand at index 1.
							// The ScopeInfo is always the CP operand (opIndex == 1).
							final Object cpItem = funcsStorage.getConstItem(addr, index);
							if (cpItem instanceof ScopeInfoStore) {
								currentScope = (ScopeInfoStore) cpItem;
							}

							long itemAddrVal = funcsStorage.getConstItemAddress(addr, index);
							if (itemAddrVal >= 0) {
								final Address itemAddr = fpa.toAddr(itemAddrVal);
								instruction.addOperandReference(opIndex, itemAddr, RefType.DATA, SourceType.ANALYSIS);
							}
						} break;
						case "SwitchOnSmiNoFeedback": {
							var countScalar = instruction.getScalar(opIndex + 1);
							if (countScalar == null) break;
							int itemsCount = (int) (countScalar.getValue() & 0xFFFFFFFF);

							final List<Address> refs = new ArrayList<>();
							boolean hasNullItem = false;
							for (int ic = 0; ic < itemsCount; ++ic) {
								final Object item = funcsStorage.getConstItem(addr, index + ic);
								if (item == null) { hasNullItem = true; break; }

								final Address refAddr;

								if (item instanceof Integer) {
									refAddr = addr.add(JscParser.smiToInt((int)item, ObjectsAllocator.getPointerSize(program)));
								} else if (item instanceof Long) {
									refAddr = addr.add(JscParser.smiToInt((long)item, ObjectsAllocator.getPointerSize(program)));
								} else {
									hasNullItem = true; break;
								}

								refs.add(refAddr);
								instruction.addMnemonicReference(refAddr, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
								ObjectsAllocator.disassemble(program, TaskMonitor.DUMMY, refAddr);
							}
							if (hasNullItem) break;

							switch (switchNum) {
							case 0:
								patchWithNop(instruction, 0, 0, "switchonsminofeedback", "switchonsminofeedback", true, fpa, log);
								switchNum = 1;
								break;
							case 1: {
								if (!patchWithNop(instruction, 0, 1, "switchonsminofeedback", "jump", false, fpa, log)) {
									patchWithNop(instruction, 0, 4, "switchonsminofeedback", "return", false, fpa, log);
								}

								if (itemsCount >= 3 && refs.size() >= 2) {
									instruction = fpa.getInstructionAt(refs.get(0));
									if (instruction != null) {
										final Address dis = instruction.getAddress();
										while (instruction != null && instruction.getAddress().getOffset() < refs.get(1).getOffset()) {
											nopInstruction(instruction, fpa, log);
											instruction = instruction.getNext();
										}
										ObjectsAllocator.disassemble(program, monitor, dis);
									}

									instruction = fpa.getInstructionAt(refs.get(refs.size() - 1));
									if (instruction != null) {
										while (true) {
											nopInstruction(instruction, fpa, log);

											if (instruction.getMnemonicString().equalsIgnoreCase("return")) {
												break;
											}

											instruction = instruction.getNext();
											if (instruction == null) break;
										}
										ObjectsAllocator.disassemble(program, monitor, refs.get(refs.size() - 1));
									}
								}

								switchNum = 0;
							} break;
							}
						} break;
						default: {
							long constAddr = funcsStorage.getConstItemAddress(addr, index);
							if (constAddr >= 0) {
								instruction.addOperandReference(opIndex, fpa.toAddr(constAddr), RefType.READ, SourceType.ANALYSIS);
							}
						}
					}
				  } catch (Exception e) {
					// Skip CP resolution for functions without structured data
				  }
				}
			} else if (hasContextReference(mnemonic)) {
				for (int opIndex : CTX_FUNCS.get(mnemonic)) {
				  try {
					var scalar = instruction.getScalar(opIndex);
					if (scalar == null) continue;
					int index = (int) (scalar.getValue() & 0xFFFFFFFF);
					instruction.removeOperandReference(opIndex, fpa.toAddr(index));

					RefType refType = RefType.READ;

					if (mnemonic.startsWith("Sta")) {
						refType = RefType.WRITE;
					}

					ContextVarStore var = null;
					switch (mnemonic) {
					case "CreateFunctionContext": {
						currentScope = funcsStorage.getScopeInfo(addr, _context);
						if (currentScope == null) break;
						instruction.addOperandReference(opIndex, fpa.toAddr(currentScope.getOffset()), refType, SourceType.ANALYSIS);
					} break;
					default: {
						try {
							final ScopeInfoStore scope;

							if (mnemonic.contains("Current")) {
								scope = funcsStorage.getScopeInfo(addr, _context);
								if (scope == null) break;
								var = scope.getContextVar(index);
							}
							else {
								final Register reg = instruction.getRegister(0);
								if (reg == null) break;
								var regScalar = instruction.getScalar(opIndex + 1);
								if (regScalar == null) break;
								int depth = (int) (regScalar.getValue() & 0xFFFFFFFF);
								scope = funcsStorage.getScopeInfo(addr, reg.getName());
								if (scope == null) break;
								var = scope.getContextVar(index, depth);
							}

							if (var != null) {
								instruction.addOperandReference(opIndex, fpa.toAddr(var.getAddress()), refType, SourceType.ANALYSIS);
							}

							InstructionsStorage.create(program, addr.getOffset(), scope);
						} catch (Exception e) {
							// Skip context var resolution silently
						}
					}
					}
				  } catch (Exception e) {
					// Skip context resolution for functions without structured data
				  }
				}
			} else if (isContextChanger(mnemonic)) {
				switch (mnemonic) {
				case "PushContext": {
					final Register reg = instruction.getRegister(0);
					if (reg != null) {
						funcsStorage.pushScopeInfo(addr, reg.getName(), currentScope);
					}
				} break;
				case "PopContext": {
					final Register reg = instruction.getRegister(0);
					if (reg != null) {
						currentScope = funcsStorage.popScopeInfo(addr, reg.getName());
					}
				} break;
				}
			} else if (isJsRuntimeCaller(mnemonic)) {
				for (int opIndex : JSRUN_CALLS.get(mnemonic)) {
				  try {
					var scalar = instruction.getScalar(opIndex);
					if (scalar == null) continue;
					int index = (int) (scalar.getValue() & 0xFFFFFFFF);
					instruction.removeOperandReference(opIndex, fpa.toAddr(index));

					DataType dt = setEnumOperand(program, JsRuntimesEnum.NAME, addr, opIndex, index);
					if (!(dt instanceof Enum)) continue;
					Enum jsRun = (Enum) dt;
					String jsRunName = jsRun.getName(index);
					if (jsRunName == null) continue;

					switch (jsRunName) {
					case "async_function_promise_release": {
						patchWithNop(instruction, 35, 3, "jump", "ldar", true, fpa, log);
					} break;
					case "async_function_promise_create": {
						patchWithNop(instruction, 3, 3, "stackcheck", "mov", true, fpa, log);
					} break;
					case "promise_resolve": {
						patchWithNop(instruction, 0, 0, "calljsruntime", "calljsruntime", true, fpa, log);
					} break;
					}
				  } catch (Exception e) {
					// Skip JS runtime resolution silently
				  }
				}
			} else if (testsType(mnemonic)) {
				for (int opIndex : TYPEOFS.get(mnemonic)) {
				  try {
					var scalar = instruction.getScalar(opIndex);
					if (scalar == null) continue;
					int index = (int) (scalar.getValue() & 0xFFFFFFFF);

					setEnumOperand(program, TypeOfEnum.NAME, addr, opIndex, index);
				  } catch (Exception e) {
					// Skip typeof resolution silently
				  }
				}
			} else if (isJumper(mnemonic)) {
				for (int opIndex : JUMP_FUNCS.get(mnemonic)) {
				  try {
					var scalar = instruction.getScalar(opIndex);
					if (scalar == null) continue;
					int index = (int) (scalar.getValue() & 0xFFFFFFFF);
					instruction.removeOperandReference(opIndex, fpa.toAddr(index));

					final Object item = funcsStorage.getConstItem(addr, index);
					if (item == null) continue;

					final Address refAddr;

					if (item instanceof Integer) {
						refAddr = addr.add(JscParser.smiToInt((int)item, ObjectsAllocator.getPointerSize(program)));
					} else if (item instanceof Long) {
						refAddr = addr.add(JscParser.smiToInt((long)item, ObjectsAllocator.getPointerSize(program)));
					} else {
						continue;
					}

					boolean jumpConst = mnemonic.equals("JumpConstant");

					instruction.addOperandReference(opIndex, refAddr, jumpConst ? RefType.UNCONDITIONAL_JUMP : RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS);
					ObjectsAllocator.disassemble(program, TaskMonitor.DUMMY, refAddr);
				  } catch (Exception e) {
					// Skip jump resolution silently
				  }
				}
			}
		  } catch (Exception e) {
			// Outer safety net: never let the instruction-level loop throw
		  }
		}

		monitor.setIndeterminate(false);

		return true;
	}
	
	private boolean patchWithNop(final Instruction instr, int toLeft, int toRight, final String left, final String right, boolean throwExceptions, final FlatProgramAPI fpa, MessageLog log) throws CancelledException {
		final List<Instruction> toRemove = new ArrayList<>();
		
		toRemove.add(instr);
		
		Instruction instruction = instr;
		for (int i = 0; i < toLeft; ++i) {
			instruction = instruction.getPrevious();
			toRemove.add(0, instruction);
		}
		
		instruction = instr;
		for (int i = 0; i < toRight; ++i) {
			instruction = instruction.getNext();
			toRemove.add(instruction);
		}
		
		if (!left.isEmpty() && !toRemove.get(0).getMnemonicString().equalsIgnoreCase(left)) {
			if (throwExceptions) {
				log.appendException(new Exception(String.format("Check patchWithNop() at %s", instr.getAddress())));
			}
			return false;
		}
		
		if (!right.isEmpty() && !toRemove.get(toRemove.size() - 1).getMnemonicString().equalsIgnoreCase(right)) {
			if (throwExceptions) {
				log.appendException(new Exception(String.format("Check patchWithNop() at %s", instr.getAddress())));
			}
			return false;
		}
		
		for (final Instruction inst : toRemove) {
			nopInstruction(inst, fpa, log);
		}
		
		ObjectsAllocator.disassemble(fpa.getCurrentProgram(), TaskMonitor.DUMMY, toRemove.get(0).getAddress());
		return true;
	}
	
	private void nopInstruction(final Instruction inst, final FlatProgramAPI fpa, final MessageLog log) throws CancelledException {
		fpa.setEOLComment(inst.getAddress(), inst.toString());
		fpa.clearListing(inst.getAddress());
		
		try {
			byte[] fill = new byte[inst.getLength()];
			Arrays.fill(fill, (byte)0xA8);
			fpa.setBytes(inst.getAddress(), fill);
		} catch (MemoryAccessException e) {
			e.printStackTrace();
			log.appendException(e);
		}
	}
	
	private DataType setEnumOperand(final Program program, final String dt, final Address addr, int opIndex, int enumIndex) {
		final DataType pre = program.getDataTypeManager().getRootCategory().getDataType(dt);
		final String enumName = EquateManager.formatNameForEquate(pre.getUniversalID(), enumIndex);
		SetEquateCmd eqCmd = new SetEquateCmd(enumName, addr, opIndex, enumIndex);
		eqCmd.applyTo(program);
		return pre;
	}
	
	private static String trimMnemonic(final String mnemonic) {
		int dotPos = mnemonic.indexOf(".");
		
		if (dotPos != -1) {
			return mnemonic.substring(0, dotPos);
		}
		
		return mnemonic;
	}
	
	private static boolean isJsRuntimeCaller(final String mnemonic) {
		return JSRUN_CALLS.containsKey(mnemonic);
	}
	
	private static boolean isContextChanger(final String mnemonic) {
		return CTX_CHANGER.contains(mnemonic);
	}
	
	private static boolean hasContextReference(final String mnemonic) {
		return CTX_FUNCS.containsKey(mnemonic);
	}
	
	private static boolean hasConstantPoolReference(final String mnemonic) {
		return CP_FUNCS.containsKey(mnemonic);
	}
	
	private static boolean testsType(final String mnemonic) {
		return TYPEOFS.containsKey(mnemonic);
	}
	
	private static boolean isJumper(final String mnemonic) {
		return JUMP_FUNCS.containsKey(mnemonic);
	}
	
	@Override
	public void analysisEnded(Program program) {
		super.analysisEnded(program);
		
		if (funcsStorage != null) {
			funcsStorage.store(program);
		}
	}
}
