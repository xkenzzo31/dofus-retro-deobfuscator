#!/usr/bin/env python3
"""
v8decompiler.py — V8 8.7 Ignition bytecode decompiler

Full pipeline: parse v8dasm output -> build CFG -> symbolic execution -> JavaScript

Usage:
  python3 v8decompiler.py <ignition_disasm.txt> <output_dir>
  python3 v8decompiler.py <ignition_disasm.txt> <output_dir> --function "createEncryptor"
  python3 v8decompiler.py <ignition_disasm.txt> <output_dir> --search "shield"

Author: Luska
"""
import gc
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional


def log(msg):
    print(msg, flush=True)


# ════════════════════════════════════════════════════════════════════════════
# PHASE 1 — Parser
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Instruction:
    offset: int
    source_pos: Optional[int]
    source_type: str       # 'S', 'E', or ''
    opcode: str            # base opcode (without .Wide/.ExtraWide)
    raw_opcode: str
    operands: str
    jump_target: Optional[int] = None


@dataclass
class ConstEntry:
    index: int
    raw: str
    kind: str = ''         # string, sfi, smi, heap_num, scope, object, array, other
    value: object = None


@dataclass
class HandlerEntry:
    from_off: int
    to_off: int
    handler_off: int
    prediction: int
    data: int


@dataclass
class ParsedFunction:
    name: str
    addr: str
    param_count: int = 0
    register_count: int = 0
    frame_size: int = 0
    instructions: list = field(default_factory=list)
    constants: list = field(default_factory=list)
    handlers: list = field(default_factory=list)
    strings: dict = field(default_factory=dict)
    subfunctions: dict = field(default_factory=dict)


# Regex patterns
RE_FUNC = re.compile(r'^=== Function: (0x[0-9a-f]+) <String\[\d+\]: #(.*)> ===$')
RE_PARAM = re.compile(r'^Parameter count (\d+)')
RE_REG = re.compile(r'^Register count (\d+)')
RE_FRAME = re.compile(r'^Frame size (\d+)')
RE_INSTR = re.compile(
    r'^\s*(?:(\d+)\s+([SE])>\s+)?'
    r'0x[0-9a-f]+\s+@\s+(\d+)\s*:\s+'
    r'[0-9a-f ]+\s+'
    r'(\S+)'
    r'(?:\s+(.*))?$'
)
RE_CONST_POOL = re.compile(r'^Constant pool \(size = (\d+)\)')
RE_CONST_ENTRY = re.compile(r'^\s+(\d+): (.+)')
RE_HANDLER = re.compile(r'^\s+\(\s*(\d+),\s*(\d+)\)\s+->\s+(\d+)\s+\(prediction=(\d+),\s*data=(\d+)\)')
RE_HANDLER_TABLE = re.compile(r'^Handler Table')
RE_SOURCE_POS = re.compile(r'^Source Position Table')

RE_STR = re.compile(r'<String\[\d+\]: #(.*)>')
RE_SFI = re.compile(r'<SharedFunctionInfo\s*(.*)>')
RE_SMI = re.compile(r'<Smi (\d+)>')
RE_HEAP = re.compile(r'<HeapNumber ([\d.eE+-]+)>')
RE_JUMP_TARGET = re.compile(r'\(0x[0-9a-f]+ @ (\d+)\)')


def parse_const_entry(idx, raw):
    e = ConstEntry(index=idx, raw=raw)
    m = RE_STR.search(raw)
    if m:
        e.kind, e.value = 'string', m.group(1)
        return e
    m = RE_SFI.search(raw)
    if m:
        e.kind, e.value = 'sfi', m.group(1).strip()
        return e
    m = RE_SMI.search(raw)
    if m:
        e.kind, e.value = 'smi', int(m.group(1))
        return e
    m = RE_HEAP.search(raw)
    if m:
        e.kind, e.value = 'heap_num', float(m.group(1))
        return e
    if 'ScopeInfo' in raw:
        e.kind = 'scope'
    elif 'ObjectBoilerplate' in raw:
        e.kind = 'object'
    elif 'ArrayBoilerplate' in raw:
        e.kind = 'array'
    else:
        e.kind = 'other'
    return e


def parse_dump_streaming(filepath):
    """Generator: yields one ParsedFunction at a time."""
    current = None
    section = 'none'

    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')

            m = RE_FUNC.match(line)
            if m:
                if current:
                    yield current
                current = ParsedFunction(name=m.group(2), addr=m.group(1))
                section = 'header'
                continue

            if not current:
                continue

            if section == 'header':
                m = RE_PARAM.match(line)
                if m:
                    current.param_count = int(m.group(1))
                    continue
                m = RE_REG.match(line)
                if m:
                    current.register_count = int(m.group(1))
                    continue
                m = RE_FRAME.match(line)
                if m:
                    current.frame_size = int(m.group(1))
                    section = 'bytecode'
                    continue

            if RE_CONST_POOL.match(line):
                section = 'constpool'
                continue

            if section == 'constpool':
                m = RE_CONST_ENTRY.match(line)
                if m:
                    idx = int(m.group(1))
                    entry = parse_const_entry(idx, m.group(2))
                    current.constants.append(entry)
                    if entry.kind == 'string':
                        current.strings[idx] = entry.value
                    elif entry.kind == 'sfi':
                        current.subfunctions[idx] = entry.value
                    continue
                if line.startswith(' - ') or line.startswith('0x'):
                    continue

            if RE_HANDLER_TABLE.match(line):
                section = 'handler'
                continue

            if section == 'handler':
                m = RE_HANDLER.match(line)
                if m:
                    current.handlers.append(HandlerEntry(
                        from_off=int(m.group(1)), to_off=int(m.group(2)),
                        handler_off=int(m.group(3)), prediction=int(m.group(4)),
                        data=int(m.group(5)),
                    ))
                    continue

            if RE_SOURCE_POS.match(line):
                section = 'srcpos'
                continue

            if section in ('bytecode', 'header'):
                m = RE_INSTR.match(line)
                if m:
                    section = 'bytecode'
                    offset = int(m.group(3))
                    raw_op = m.group(4)
                    operands = (m.group(5) or '').strip()
                    base_op = raw_op.replace('.ExtraWide', '').replace('.Wide', '')
                    jt = None
                    jm = RE_JUMP_TARGET.search(operands)
                    if jm:
                        jt = int(jm.group(1))
                    current.instructions.append(Instruction(
                        offset=offset,
                        source_pos=int(m.group(1)) if m.group(1) else None,
                        source_type=m.group(2) or '',
                        opcode=base_op, raw_opcode=raw_op,
                        operands=operands, jump_target=jt,
                    ))

    if current:
        yield current


# ════════════════════════════════════════════════════════════════════════════
# PHASE 2 — CFG Builder
# ════════════════════════════════════════════════════════════════════════════

JUMP_OPS = {
    'Jump', 'JumpConstant',
    'JumpIfTrue', 'JumpIfTrueConstant',
    'JumpIfFalse', 'JumpIfFalseConstant',
    'JumpIfNull', 'JumpIfNotNull',
    'JumpIfUndefined', 'JumpIfNotUndefined',
    'JumpIfUndefinedOrNull',
    'JumpIfToBooleanTrue', 'JumpIfToBooleanTrueConstant',
    'JumpIfToBooleanFalse', 'JumpIfToBooleanFalseConstant',
    'JumpIfJSReceiver',
    'JumpLoop',
}
UNCONDITIONAL_JUMPS = {'Jump', 'JumpConstant', 'JumpLoop'}
TERMINATORS = {'Return', 'Throw', 'ReThrow'}


@dataclass
class BasicBlock:
    id: int
    start: int
    end: int
    successors: list = field(default_factory=list)
    predecessors: list = field(default_factory=list)
    is_loop_header: bool = False


def build_cfg(func):
    instrs = func.instructions
    if not instrs:
        return []

    leaders = {0}
    off_to_idx = {inst.offset: i for i, inst in enumerate(instrs)}

    for i, inst in enumerate(instrs):
        if inst.opcode in JUMP_OPS and inst.jump_target is not None:
            target = off_to_idx.get(inst.jump_target)
            if target is not None:
                leaders.add(target)
            if i + 1 < len(instrs):
                leaders.add(i + 1)
        elif inst.opcode in TERMINATORS:
            if i + 1 < len(instrs):
                leaders.add(i + 1)

    for h in func.handlers:
        hidx = off_to_idx.get(h.handler_off)
        if hidx is not None:
            leaders.add(hidx)

    sorted_leaders = sorted(leaders)
    leader_to_block = {}
    blocks = []

    for bid, start in enumerate(sorted_leaders):
        end = sorted_leaders[bid + 1] if bid + 1 < len(sorted_leaders) else len(instrs)
        block = BasicBlock(id=bid, start=start, end=end)
        blocks.append(block)
        leader_to_block[start] = bid

    for block in blocks:
        last = instrs[block.end - 1]
        if last.opcode in JUMP_OPS and last.jump_target is not None:
            target = off_to_idx.get(last.jump_target)
            if target is not None and target in leader_to_block:
                block.successors.append(leader_to_block[target])
                if last.opcode == 'JumpLoop':
                    blocks[leader_to_block[target]].is_loop_header = True
            if last.opcode not in UNCONDITIONAL_JUMPS:
                if block.end in leader_to_block:
                    block.successors.append(leader_to_block[block.end])
        elif last.opcode not in TERMINATORS:
            if block.end in leader_to_block:
                block.successors.append(leader_to_block[block.end])
        for sid in block.successors:
            blocks[sid].predecessors.append(block.id)

    return blocks


# ════════════════════════════════════════════════════════════════════════════
# PHASE 3 — Symbolic Executor + JS Emitter
# ════════════════════════════════════════════════════════════════════════════

DECODED_STRINGS = None
SOURCE_POS_STRINGS = None

BUILTINS = {
    'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'eval',
    'String', 'Number', 'Boolean', 'Object', 'Array', 'Date',
    'Math', 'JSON', 'RegExp', 'Error', 'Promise', 'Symbol',
    'Map', 'Set', 'console', 'process', 'Buffer', 'require',
    'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
    'decodeURI', 'encodeURI', 'decodeURIComponent', 'encodeURIComponent',
}


class SymExec:
    """Symbolic execution: translates V8 Ignition bytecode to JS expressions."""

    MAX_EXPR = 120

    def __init__(self, func, blocks):
        self.func = func
        self.blocks = blocks
        self.regs = {}
        self.acc = 'undefined'
        self.ctx = {}
        self.output = []
        self.indent = 1
        self.tmp_counter = 0

    def _spill(self, expr):
        if len(expr) <= self.MAX_EXPR:
            return expr
        self.tmp_counter += 1
        name = f't{self.tmp_counter}'
        self._emit(f'var {name} = {expr};')
        return name

    def _const(self, operands, idx=0):
        parts = self._parse_operands(operands)
        if idx < len(parts):
            try:
                ci = int(parts[idx].strip('[]'))
            except (ValueError, IndexError):
                return f'const_{idx}'
            for c in self.func.constants:
                if c.index == ci:
                    if c.kind == 'string':
                        s = c.value
                        if s.startswith('_0x') or s.startswith('a0_0x'):
                            return s
                        if s in BUILTINS:
                            return s
                        return repr(s)
                    elif c.kind == 'sfi':
                        return c.value if c.value else '_fn_'
                    elif c.kind == 'smi':
                        return str(c.value)
                    elif c.kind == 'heap_num':
                        return str(c.value)
                    elif c.kind == 'object':
                        return '{}'
                    elif c.kind == 'array':
                        return '[]'
                    return f'const_{ci}'
            return f'const_{ci}'
        return '?'

    def _parse_operands(self, s):
        s = re.sub(r'\(0x[0-9a-f]+ @ \d+\)', '', s).strip()
        if not s:
            return []
        return [p.strip() for p in s.split(',') if p.strip()]

    def _reg(self, name):
        name = name.strip().rstrip(',')
        if re.match(r'r\d+-r\d+', name):
            return '_args_'
        if name == '<this>':
            return 'this'
        if name == '<context>':
            return 'context'
        if name.startswith('a'):
            try:
                n = int(name[1:])
                return 'this' if n == 0 else f'arg{n}'
            except ValueError:
                return name
        return self.regs.get(name, name)

    def _emit(self, code):
        self.output.append('  ' * self.indent + code)

    def _expand_reg_range(self, s):
        s = s.strip().rstrip(',')
        m = re.match(r'(r)(\d+)-(r)(\d+)', s)
        if m:
            return ', '.join(self._reg(f'r{i}') for i in range(int(m.group(2)), int(m.group(4)) + 1))
        return self._reg(s)

    def decompile(self):
        name = self.func.name or 'anonymous'
        params = ', '.join(f'arg{i}' for i in range(1, self.func.param_count))

        is_async = any(i.opcode == 'InvokeIntrinsic' and 'AsyncFunction' in i.operands
                       for i in self.func.instructions)
        is_gen = any(i.opcode == 'SuspendGenerator' for i in self.func.instructions)

        if not name or (not name[0].isalpha() and name[0] != '_'):
            name = f'fn_{name}'

        prefix = 'async ' if is_async else ''
        star = '*' if is_gen else ''
        self.output.append(f'{prefix}function{star} {name}({params}) {{')

        if self.blocks:
            self._decompile_blocks()
        else:
            self._decompile_linear()

        self.output.append('}')
        return '\n'.join(self.output)

    def _decompile_blocks(self):
        instrs = self.func.instructions
        handler_map = {}
        for h in self.func.handlers:
            handler_map[(h.from_off, h.to_off)] = h

        active_try = None
        for block in self.blocks:
            if block.start < len(instrs):
                block_off = instrs[block.start].offset
                for (f, t), h in handler_map.items():
                    if f == block_off and active_try is None:
                        self._emit('try {')
                        self.indent += 1
                        active_try = (f, t, h.handler_off)

            if active_try and block.start < len(instrs):
                if instrs[block.start].offset == active_try[2]:
                    self.indent -= 1
                    self._emit('} catch (e) {')
                    self.indent += 1
                    active_try = None

            if block.is_loop_header:
                self._emit('while (true) {  // loop')
                self.indent += 1

            for idx in range(block.start, block.end):
                self._translate(instrs[idx])

            if block.end > 0 and instrs[block.end - 1].opcode == 'JumpLoop':
                self.indent -= 1
                self._emit('}  // end loop')

        if active_try:
            self.indent -= 1
            self._emit('}')

    def _decompile_linear(self):
        for inst in self.func.instructions:
            self._translate(inst)

    def _translate(self, inst):
        op = inst.opcode
        raw = inst.operands
        parts = self._parse_operands(raw)

        # ── Loads ──
        if op == 'LdaZero':
            self.acc = '0'
        elif op == 'LdaSmi':
            self.acc = parts[0].strip('[]') if parts else '0'
        elif op == 'LdaUndefined':
            self.acc = 'undefined'
        elif op == 'LdaNull':
            self.acc = 'null'
        elif op == 'LdaTrue':
            self.acc = 'true'
        elif op == 'LdaFalse':
            self.acc = 'false'
        elif op == 'LdaTheHole':
            pass
        elif op == 'LdaConstant':
            self.acc = self._const(raw, 0)
        elif op in ('LdaGlobal', 'LdaGlobalInsideTypeof'):
            self.acc = self._const(raw, 0)

        # ── Store/Load register ──
        elif op == 'Star':
            if parts:
                self.regs[parts[0]] = self._spill(self.acc)
        elif op.startswith('Star') and len(op) <= 6:
            self.regs[f'r{op[3:]}'] = self._spill(self.acc)
        elif op == 'Ldar':
            if parts:
                self.acc = self._reg(parts[0])
        elif op == 'Mov':
            if len(parts) >= 2:
                self.regs[parts[1]] = self._reg(parts[0])

        # ── Context slots ──
        elif op in ('LdaCurrentContextSlot', 'LdaImmutableCurrentContextSlot'):
            slot = parts[0].strip('[]') if parts else '?'
            self.acc = self.ctx.get(slot, f'ctx_{slot}')
        elif op == 'StaCurrentContextSlot':
            slot = parts[0].strip('[]') if parts else '?'
            self.ctx[slot] = self.acc
        elif op in ('LdaContextSlot', 'LdaImmutableContextSlot'):
            slot = parts[1].strip('[]') if len(parts) > 1 else (parts[0].strip('[]') if parts else '?')
            self.acc = f'ctx_{slot}'
        elif op == 'StaContextSlot':
            slot = parts[1].strip('[]') if len(parts) > 1 else '?'
            self.ctx[slot] = self.acc

        # ── Lookup slots ──
        elif op in ('LdaLookupSlot', 'LdaLookupContextSlot', 'LdaLookupGlobalSlot',
                     'LdaLookupSlotInsideTypeof', 'LdaLookupContextSlotInsideTypeof',
                     'LdaLookupGlobalSlotInsideTypeof'):
            self.acc = self._const(raw, 0)
        elif op == 'StaLookupSlot':
            self._emit(f'{self._const(raw, 0)} = {self.acc};')

        # ── Property access ──
        elif op == 'LdaNamedProperty':
            obj = self._reg(parts[0]) if parts else '?'
            prop = self._const(raw, 1)
            if prop.startswith("'") or prop.startswith('"'):
                pc = prop.strip("'\"")
                self.acc = f'{obj}.{pc}' if pc.isidentifier() else f'{obj}[{prop}]'
            elif prop.startswith('_0x') or prop.startswith('a0_0x'):
                self.acc = f'{obj}[{prop}]'
            else:
                self.acc = f'{obj}.{prop}'
        elif op == 'LdaNamedPropertyFromSuper':
            self.acc = f'super.{self._const(raw, 1)}'
        elif op == 'StaNamedProperty':
            obj = self._reg(parts[0]) if parts else '?'
            prop = self._const(raw, 1)
            if prop.startswith("'") or prop.startswith('"'):
                pc = prop.strip("'\"")
                self._emit(f'{obj}.{pc} = {self.acc};' if pc.isidentifier() else f'{obj}[{prop}] = {self.acc};')
            else:
                self._emit(f'{obj}.{prop} = {self.acc};')
        elif op == 'StaNamedOwnProperty':
            obj = self._reg(parts[0]) if parts else '?'
            prop = self._const(raw, 1)
            ps = prop.strip("'\"") if prop.startswith("'") or prop.startswith('"') else prop
            self._emit(f'{obj}.{ps} = {self.acc};')
        elif op == 'LdaKeyedProperty':
            obj = self._reg(parts[0]) if parts else '?'
            self.acc = f'{obj}[{self.acc}]'
        elif op == 'StaKeyedProperty':
            obj = self._reg(parts[0]) if parts else '?'
            key = self._reg(parts[1]) if len(parts) > 1 else self.acc
            self._emit(f'{obj}[{key}] = {self.acc};')
        elif op == 'StaInArrayLiteral':
            arr = self._reg(parts[0]) if parts else '?'
            idx_r = self._reg(parts[1]) if len(parts) > 1 else '?'
            self._emit(f'{arr}[{idx_r}] = {self.acc};')
        elif op == 'StaDataPropertyInLiteral':
            obj = self._reg(parts[0]) if parts else '?'
            key = self._reg(parts[1]) if len(parts) > 1 else '?'
            self._emit(f'{obj}[{key}] = {self.acc};')

        elif op == 'LdaModuleVariable':
            self.acc = f'module_var_{parts[0].strip("[]")}' if parts else 'module_var'
        elif op == 'StaModuleVariable':
            self._emit(f'module_var_{parts[0].strip("[]")} = {self.acc};')
        elif op == 'StaGlobal':
            self._emit(f'{self._const(raw, 0)} = {self.acc};')

        # ── Binary ops ──
        elif op == 'Add':
            self.acc = f'{self._reg(parts[0])} + {self.acc}'
        elif op == 'Sub':
            self.acc = f'{self._reg(parts[0])} - {self.acc}'
        elif op == 'Mul':
            self.acc = f'{self._reg(parts[0])} * {self.acc}'
        elif op == 'Div':
            self.acc = f'{self._reg(parts[0])} / {self.acc}'
        elif op == 'Mod':
            self.acc = f'{self._reg(parts[0])} % {self.acc}'
        elif op == 'Exp':
            self.acc = f'{self._reg(parts[0])} ** {self.acc}'
        elif op == 'BitwiseAnd':
            self.acc = f'{self._reg(parts[0])} & {self.acc}'
        elif op == 'BitwiseOr':
            self.acc = f'{self._reg(parts[0])} | {self.acc}'
        elif op == 'BitwiseXor':
            self.acc = f'{self._reg(parts[0])} ^ {self.acc}'
        elif op == 'ShiftLeft':
            self.acc = f'{self._reg(parts[0])} << {self.acc}'
        elif op == 'ShiftRight':
            self.acc = f'{self._reg(parts[0])} >> {self.acc}'
        elif op == 'ShiftRightLogical':
            self.acc = f'{self._reg(parts[0])} >>> {self.acc}'

        # ── Smi binary ops (immediate) ──
        elif op in ('AddSmi', 'SubSmi', 'MulSmi', 'DivSmi', 'ModSmi', 'ExpSmi',
                     'BitwiseOrSmi', 'BitwiseXorSmi', 'BitwiseAndSmi',
                     'ShiftLeftSmi', 'ShiftRightSmi', 'ShiftRightLogicalSmi'):
            val = parts[0].strip('[]') if parts else '0'
            op_map = {
                'AddSmi': '+', 'SubSmi': '-', 'MulSmi': '*', 'DivSmi': '/',
                'ModSmi': '%', 'ExpSmi': '**',
                'BitwiseOrSmi': '|', 'BitwiseXorSmi': '^', 'BitwiseAndSmi': '&',
                'ShiftLeftSmi': '<<', 'ShiftRightSmi': '>>', 'ShiftRightLogicalSmi': '>>>',
            }
            self.acc = f'{self.acc} {op_map[op]} {val}'

        # ── Unary ops ──
        elif op == 'Inc':
            self.acc = f'{self.acc} + 1'
        elif op == 'Dec':
            self.acc = f'{self.acc} - 1'
        elif op == 'Negate':
            self.acc = f'-({self.acc})'
        elif op == 'BitwiseNot':
            self.acc = f'~({self.acc})'
        elif op in ('ToBooleanLogicalNot', 'LogicalNot'):
            self.acc = f'!{self.acc}'
        elif op == 'TypeOf':
            self.acc = f'typeof {self.acc}'
        elif op in ('DeletePropertyStrict', 'DeletePropertySloppy'):
            self._emit(f'delete {self._reg(parts[0])};')

        # ── Comparisons ──
        elif op == 'TestEqual':
            self.acc = f'{self._reg(parts[0])} == {self.acc}'
        elif op in ('TestEqualStrict', 'TestReferenceEqual'):
            self.acc = f'{self._reg(parts[0])} === {self.acc}'
        elif op == 'TestLessThan':
            self.acc = f'{self._reg(parts[0])} < {self.acc}'
        elif op == 'TestGreaterThan':
            self.acc = f'{self._reg(parts[0])} > {self.acc}'
        elif op == 'TestLessThanOrEqual':
            self.acc = f'{self._reg(parts[0])} <= {self.acc}'
        elif op == 'TestGreaterThanOrEqual':
            self.acc = f'{self._reg(parts[0])} >= {self.acc}'
        elif op == 'TestInstanceOf':
            self.acc = f'{self._reg(parts[0])} instanceof {self.acc}'
        elif op == 'TestIn':
            self.acc = f'{self.acc} in {self._reg(parts[0])}'
        elif op == 'TestNull':
            self.acc = f'{self.acc} === null'
        elif op == 'TestUndefined':
            self.acc = f'{self.acc} === undefined'
        elif op == 'TestUndetectable':
            self.acc = f'{self.acc} == null'
        elif op == 'TestTypeOf':
            tv = parts[0].strip('[]#') if parts else '?'
            self.acc = f'typeof {self.acc} === {repr(tv)}'

        # ── Type conversions ──
        elif op == 'ToName':
            pass
        elif op in ('ToNumber', 'ToNumeric'):
            self.acc = f'+{self.acc}'
        elif op == 'ToObject':
            self.acc = f'Object({self.acc})'
        elif op == 'ToString':
            self.acc = f'String({self.acc})'

        # ── Calls ──
        elif op == 'CallAnyReceiver':
            fn = self._reg(parts[0]) if parts else '?'
            self.acc = f'{fn}(...)'
            self._emit(f'{self.acc};')
        elif op == 'CallProperty':
            fn = self._reg(parts[0]) if parts else '?'
            recv = self._reg(parts[1]) if len(parts) > 1 else '?'
            self.acc = f'{recv}.{fn}(...)'
            self._emit(f'{self.acc};')
        elif op == 'CallProperty0':
            fn = self._reg(parts[0]) if parts else '?'
            recv = self._reg(parts[1]) if len(parts) > 1 else '?'
            self.acc = f'{recv}.{fn}()'
            self._emit(f'{self.acc};')
        elif op == 'CallProperty1':
            fn = self._reg(parts[0]) if parts else '?'
            recv = self._reg(parts[1]) if len(parts) > 1 else '?'
            a1 = self._reg(parts[2]) if len(parts) > 2 else '?'
            self.acc = f'{recv}.{fn}({a1})'
            self._emit(f'{self.acc};')
        elif op == 'CallProperty2':
            fn = self._reg(parts[0]) if parts else '?'
            recv = self._reg(parts[1]) if len(parts) > 1 else '?'
            a1 = self._reg(parts[2]) if len(parts) > 2 else '?'
            a2 = self._reg(parts[3]) if len(parts) > 3 else '?'
            self.acc = f'{recv}.{fn}({a1}, {a2})'
            self._emit(f'{self.acc};')
        elif op in ('CallUndefinedReceiver', 'CallUndefinedReceiver0',
                     'CallUndefinedReceiver1', 'CallUndefinedReceiver2'):
            fn = self._reg(parts[0]) if parts else '?'
            if fn == 'this':
                fn = '_self_'
            if op == 'CallUndefinedReceiver0':
                self.acc = f'{fn}()'
            elif op == 'CallUndefinedReceiver1':
                a1 = self._reg(parts[1]) if len(parts) > 1 else '?'
                self.acc = f'{fn}({a1})'
            elif op == 'CallUndefinedReceiver2':
                a1 = self._reg(parts[1]) if len(parts) > 1 else '?'
                a2 = self._reg(parts[2]) if len(parts) > 2 else '?'
                self.acc = f'{fn}({a1}, {a2})'
            else:
                args_str = self._expand_reg_range(parts[1]) if len(parts) > 1 else ''
                self.acc = f'{fn}({args_str})'
            self._emit(f'{self.acc};')
        elif op == 'CallWithSpread':
            fn = self._reg(parts[0]) if parts else '?'
            self.acc = f'{fn}(...spread)'
            self._emit(f'{self.acc};')
        elif op == 'CallRuntime':
            runtime = parts[0].strip('[]') if parts else '?'
            self.acc = f'%{runtime}()'
            if 'Throw' in runtime:
                self._emit(f'%{runtime}();')
        elif op == 'CallRuntimeForPair':
            self.acc = f'%{parts[0].strip("[]") if parts else "?"}()'
        elif op == 'CallJSRuntime':
            idx = parts[0].strip('[]') if parts else '?'
            self.acc = f'%JSRuntime_{idx}()'
            self._emit(f'{self.acc};')
        elif op == 'InvokeIntrinsic':
            name = parts[0].strip('[]') if parts else '?'
            self.acc = f'%{name}()'

        # ── Construct ──
        elif op == 'Construct':
            ctor = self._reg(parts[0]) if parts else '?'
            args_str = self._expand_reg_range(parts[1]) if len(parts) > 1 else ''
            self.acc = f'new {ctor}({args_str})'
            self._emit(f'{self.acc};')
        elif op == 'ConstructWithSpread':
            ctor = self._reg(parts[0]) if parts else '?'
            self.acc = f'new {ctor}(...spread)'
            self._emit(f'{self.acc};')
        elif op == 'GetSuperConstructor':
            self.acc = 'super'

        # ── Literals ──
        elif op in ('CreateObjectLiteral', 'CreateEmptyObjectLiteral'):
            self.acc = '{}'
        elif op in ('CreateArrayLiteral', 'CreateEmptyArrayLiteral'):
            self.acc = '[]'
        elif op == 'CreateArrayFromIterable':
            self.acc = f'[...{self.acc}]'
        elif op == 'CloneObject':
            self.acc = f'{{...{self._reg(parts[0])}}}'
        elif op == 'CreateRegExpLiteral':
            pattern = self._const(raw, 0)
            self.acc = f'/{pattern.strip(chr(39))}/'
        elif op == 'GetTemplateObject':
            self.acc = 'template_object'

        # ── Closures / Contexts ──
        elif op == 'CreateClosure':
            name = self._const(raw, 0)
            self.acc = name if name and name != '?' else '_fn_'
        elif op in ('CreateFunctionContext', 'CreateBlockContext', 'CreateCatchContext',
                     'CreateEvalContext', 'CreateWithContext', 'PushContext', 'PopContext'):
            pass

        # ── Arguments ──
        elif op == 'CreateMappedArguments':
            self.acc = 'arguments'
        elif op == 'CreateUnmappedArguments':
            self.acc = 'arguments'
        elif op == 'CreateRestParameter':
            self.acc = '...rest'

        # ── Control flow ──
        elif op in ('JumpIfTrue', 'JumpIfTrueConstant',
                     'JumpIfToBooleanTrue', 'JumpIfToBooleanTrueConstant'):
            self._emit(f'if ({self.acc}) {{')
            self.indent += 1
        elif op in ('JumpIfFalse', 'JumpIfFalseConstant',
                     'JumpIfToBooleanFalse', 'JumpIfToBooleanFalseConstant'):
            self._emit(f'if (!({self.acc})) {{')
            self.indent += 1
        elif op == 'JumpIfNull':
            self._emit(f'if ({self.acc} === null) {{')
            self.indent += 1
        elif op == 'JumpIfNotNull':
            self._emit(f'if ({self.acc} !== null) {{')
            self.indent += 1
        elif op == 'JumpIfUndefined':
            self._emit(f'if ({self.acc} === undefined) {{')
            self.indent += 1
        elif op == 'JumpIfNotUndefined':
            self._emit(f'if ({self.acc} !== undefined) {{')
            self.indent += 1
        elif op == 'JumpIfUndefinedOrNull':
            self._emit(f'if ({self.acc} == null) {{')
            self.indent += 1
        elif op == 'JumpIfJSReceiver':
            self._emit(f'if (typeof {self.acc} === "object") {{')
            self.indent += 1
        elif op in ('Jump', 'JumpConstant'):
            if self.indent > 1:
                self.indent -= 1
                self._emit('}')
        elif op == 'JumpLoop':
            pass

        # ── Switch ──
        elif op == 'SwitchOnSmiNoFeedback':
            self._emit(f'switch ({self.acc}) {{')
            self.indent += 1
        elif op == 'SwitchOnGeneratorState':
            self._emit('switch (generator_state) {')
            self.indent += 1

        # ── For-in ──
        elif op == 'ForInEnumerate':
            obj = self._reg(parts[0]) if parts else '?'
            self.acc = f'Object.keys({obj})'
        elif op == 'ForInPrepare':
            self._emit(f'for (var key in {self.acc}) {{')
            self.indent += 1
        elif op == 'ForInContinue':
            pass
        elif op == 'ForInNext':
            obj = self._reg(parts[0]) if parts else '?'
            self.acc = f'{obj}[key]'
        elif op == 'ForInStep':
            pass

        # ── Iterator ──
        elif op == 'GetIterator':
            obj = self._reg(parts[0]) if parts else '?'
            self.acc = f'{obj}[Symbol.iterator]()'

        # ── Return / Throw ──
        elif op == 'Return':
            self._emit(f'return {self.acc};')
        elif op in ('Throw', 'ReThrow'):
            self._emit(f'throw {self.acc};')

        # ── Error throws (TDZ checks) ──
        elif op in ('ThrowReferenceErrorIfHole', 'ThrowSuperNotCalledIfHole',
                     'ThrowSuperAlreadyCalledIfNotHole', 'ThrowIfNotSuperConstructor'):
            pass

        # ── Generator ──
        elif op == 'SuspendGenerator':
            self._emit(f'yield {self.acc};')
        elif op == 'ResumeGenerator':
            self.acc = 'resumed_value'

        # ── Misc ──
        elif op in ('SetPendingMessage', 'IncBlockCounter', 'CollectTypeProfile'):
            pass
        elif op == 'Debugger':
            self._emit('debugger;')
        elif op.startswith('DebugBreak'):
            pass
        elif op == 'Abort':
            self._emit('/* abort */;')
        elif op == 'Illegal':
            self._emit('/* unreachable */;')
        else:
            self._emit(f'/* {inst.raw_opcode} {raw} */')


# ════════════════════════════════════════════════════════════════════════════
# PHASE 4 — Output Generation
# ════════════════════════════════════════════════════════════════════════════

CATEGORIES = {
    'crypto': ['encrypt', 'decrypt', 'hash', 'hmac', 'aes', 'cipher', 'key', 'digest',
               'processBlock', 'encryptBlock', 'decryptBlock', 'createEncryptor',
               'createDecryptor', '_doReset', '_doCryptBlock', '_doFinalize',
               'CryptoJS', 'SHA', 'MD5', 'HMAC', 'AES', 'DES', 'RC4',
               'WordArray', 'BlockCipher', 'CipherParams'],
    'shield': ['shield', 'Shield', 'SecurityCode', 'ValidateCode', 'certificat',
               'createHmEncoders', 'generateHashFromCertif', 'machineId',
               'fingerprint', 'hm1', 'hm2'],
    'network': ['socket', 'connect', 'send', 'receive', 'tcp', 'websocket', 'http',
                'request', 'response', 'fetch', 'XMLHttpRequest', 'net.'],
    'auth': ['auth', 'login', 'token', 'oauth', 'session', 'credential', 'certificate',
             'apikey', 'haapi', 'HAAPI', 'createApiKey', 'signOn'],
    'electron': ['app', 'BrowserWindow', 'ipcMain', 'ipcRenderer', 'electron',
                 'webContents', 'protocol', 'autoUpdater', 'Tray', 'Menu',
                 'ElectronJSON', 'dialog'],
    'zaap': ['zaap', 'Zaap', 'thrift', 'Thrift', 'TBinaryProtocol', 'gameToken',
             'ZaapService', 'zaap_start', 'instanceId'],
    'game': ['dofus', 'ankama', 'retro', 'flashGame', 'GameSession', 'character',
             'spell', 'inventory', 'combat', 'map', 'pathfind'],
}


def categorize_function(func):
    matches = []
    name_lower = func.name.lower()
    all_strings = ' '.join(func.strings.values()).lower()
    for cat, keywords in CATEGORIES.items():
        for kw in keywords:
            if kw.lower() in name_lower or kw.lower() in all_strings:
                matches.append(cat)
                break
    return matches


def decompile_one(func):
    try:
        blocks = build_cfg(func)
        sx = SymExec(func, blocks)
        return sx.decompile()
    except Exception as e:
        return f'// ERROR decompiling {func.name}: {e}'


def main():
    import argparse
    parser = argparse.ArgumentParser(description='V8 Ignition Bytecode Decompiler — by Luska')
    parser.add_argument('input', help='Path to ignition_disasm.txt')
    parser.add_argument('output', help='Output directory')
    parser.add_argument('--function', '-f', help='Decompile a specific function by name')
    parser.add_argument('--search', '-s', help='Search functions by keyword')
    parser.add_argument('--index-only', action='store_true', help='Only generate index')
    parser.add_argument('--strings', help='Path to decoded_strings.json')
    args = parser.parse_args()

    global DECODED_STRINGS, SOURCE_POS_STRINGS

    # Auto-load decoded strings
    if args.strings and os.path.exists(args.strings):
        DECODED_STRINGS = json.load(open(args.strings))
        log(f'Loaded {len(DECODED_STRINGS)} decoded strings')
    else:
        auto = os.path.join(os.path.dirname(args.input), 'decoded_strings.json')
        if os.path.exists(auto):
            DECODED_STRINGS = json.load(open(auto))
            log(f'Auto-loaded {len(DECODED_STRINGS)} decoded strings')

    sps = os.path.join(os.path.dirname(args.input), 'source_pos_strings.json')
    if os.path.exists(sps):
        SOURCE_POS_STRINGS = json.load(open(sps))
        log(f'Loaded {len(SOURCE_POS_STRINGS)} source position mappings')

    os.makedirs(args.output, exist_ok=True)
    t0 = time.time()

    outpath = os.path.join(args.output, 'decompiled.js')
    cat_files = {cat: open(os.path.join(args.output, f'{cat}.js'), 'w') for cat in CATEGORIES}
    cat_counts = {cat: 0 for cat in CATEGORIES}
    index = []
    total_bytes = 0
    count = 0
    search_q = args.search.lower() if args.search else None

    out = open(outpath, 'w') if not args.search and not args.index_only and not args.function else None

    log(f'Streaming {args.input}...')

    for func in parse_dump_streaming(args.input):
        cats = categorize_function(func)
        readable = [s for s in func.strings.values()
                    if not s.startswith('_0x') and not s.startswith('a0_0x')][:10]
        entry = {'id': count, 'name': func.name, 'instructions': len(func.instructions),
                 'strings': readable, 'categories': cats}
        index.append(entry)

        if search_q:
            if search_q in func.name.lower() or any(search_q in s.lower() for s in readable):
                cats_s = ', '.join(cats) if cats else ''
                log(f'  [{count:5d}] {func.name:<30s} {len(func.instructions):4d} instr  {cats_s}')
        elif args.function:
            if args.function in func.name:
                log(decompile_one(func))
                log('')
        elif not args.index_only and out:
            js = decompile_one(func)
            out.write(js)
            out.write('\n\n')
            total_bytes += len(js) + 2
            for cat in cats:
                if cat in cat_files:
                    cat_files[cat].write(js)
                    cat_files[cat].write('\n\n')
                    cat_counts[cat] += 1
            del js

        count += 1
        if count % 500 == 0:
            elapsed = time.time() - t0
            log(f'  {count} functions ({count / elapsed:.0f}/s, {elapsed:.1f}s)')

    if out:
        out.close()
    for f in cat_files.values():
        f.close()

    with open(os.path.join(args.output, 'index.json'), 'w') as f:
        json.dump(index, f, ensure_ascii=False)

    elapsed = time.time() - t0
    log(f'\nDone: {count} functions in {elapsed:.1f}s')

    if not args.search and not args.index_only and not args.function:
        log(f'decompiled.js: {total_bytes // 1024} KB')
        for cat in CATEGORIES:
            if cat_counts[cat] > 0:
                log(f'  {cat}.js: {cat_counts[cat]} functions')
            else:
                try:
                    os.remove(os.path.join(args.output, f'{cat}.js'))
                except OSError:
                    pass


if __name__ == '__main__':
    main()
