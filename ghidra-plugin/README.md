# ghidra-v8-87

Ghidra extension that loads, disassembles and decompiles V8 8.7 code caches:
the `.jsc` files [bytenode](https://github.com/bytenode/bytenode) writes, as
used by Electron 11 / Node 15 applications (V8 8.7.220.31).

Built for Dofus Retro's Electron main process (`Resources/app/main.jsc`,
12.7 MB, V8 8.7.220.31-electron.0). Started from
[PositiveTechnologies/ghidra_nodejs](https://github.com/PositiveTechnologies/ghidra_nodejs)
(V8 6.x / Node 8), rewritten for V8 8.7.

## Results on Dofus Retro 1.49 `main.jsc`

| | |
|---|---|
| Objects deserialized | 235,728 (pointer compression, all in old space) |
| Functions | 8,622, named from their SharedFunctionInfo |
| Instructions | 1,375,041; 4,438,469 of 4,438,469 bytecode bytes disassembled, 0 errors |
| Disassembly check | identical to an independent Python decoder for every function |
| Variables | 14,348 global names and 12,366 closure variables, 202,629 of 202,629 accesses resolved |
| Decompiler | 8,622 of 8,622 functions decompile (42 s for all of them) |
| Strings (obfuscator.io) | string array of 8,664 strings, rotated 103 times at start-up; 25,119 wrapper calls decoded, 14,009 keyed accesses named, 5,661 concatenations and 1,608 comparisons of known strings folded |
| Import time | about 45 s |

## Install

Pick the zip that matches your Ghidra (`dist/ghidra_<version>_PUBLIC_<date>_ghidra_v8_87.zip`,
built for 12.0.4 and 12.1.4), then *File > Install Extensions*, restart, and
import the `.jsc`: the loader is **V8 8.7 code cache (bytenode .jsc)**. Leave
auto-analysis off; the loader does everything itself.

## Using it from REA

REA 6.7.0 (`rea-agents`) classifies a target before it picks a provider, and
refuses a `.jsc`. `tools/rea_v8_patch.py` patches the copy of REA in the npx
cache so that it hands V8 code caches to Ghidra, which imports them with this
extension's loader and decompiles them with the program's options (Java
output). With the extension installed in the Ghidra REA uses:

```bash
python3 -I tools/rea_v8_patch.py apply      # or status, revert
```

then reconnect the REA MCP server. `revert` restores the original files, kept
in `~/.npm/_npx/<hash>/rea-v8-patch-backup`.

## Build

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra   # the Ghidra you will run it in
gradle buildExtension                       # also compiles the SLEIGH spec
```

The SLEIGH spec and the bytecode tables are generated; regenerate them after
changing the generator or for another V8 version:

```bash
python3 tools/extract_v8_tables.py <v8 source dir> data/v8_87_bytecodes.json
python3 tools/gen_sleigh.py                 # writes data/languages/v8_87.slaspec
```

The strings of V8's read-only heap that are not roots come from the
snapshot of the Electron build:

```bash
python3 tools/extract_ro_strings.py \
  "<app>/Contents/Frameworks/Electron Framework.framework/Resources/v8_context_snapshot.x86_64.bin" \
  data/v8_ro_strings.json
```

## How it works

1. **Deserialization** (`snapshot/CodeCache`): a port of V8 8.7's
   `Deserializer` reads the code cache into heap objects. References to the
   isolate's read-only roots, read-only heap and embedder objects stay
   symbolic.
2. **Heap image** (`loader/HeapImage`): every object is placed at its snapshot
   position in `v8_heap`, with its tagged fields rewritten as pointers.
   Read-only roots (`v8_roots`), read-only heap objects (`v8_ro_heap`) and the
   embedder's objects (`v8_embedder`) get labelled placeholder blocks; the
   read-only heap strings of `data/v8_ro_strings.json` are written there as
   strings. Strings, SharedFunctionInfos, BytecodeArrays and HeapNumbers are
   typed.
3. **Functions** (`loader/FunctionImporter`): one function per
   SharedFunctionInfo with bytecode, named after it (`anonymous_<literal id>`
   when it has no name, webpack modules by their numeric id). Each function
   gets its parameters (`receiver`, `a0`...) and a plate comment giving its
   creator. Labels `sfi_`, `bytecode_`, `constants_` and `scope_` mark its
   objects. Exception handlers are labelled `catch_N`, and switch tables become
   jump tables.
4. **Context tracking** (`loader/ContextTracker`): follows the context chain
   along the control flow (Create*Context, PushContext, PopContext, registers,
   exception handlers) to name the variable behind every context slot access.
5. **Variables**: each global name and each closure variable gets a 4-byte
   cell in `js_variables`, labelled with its name, so the decompiler prints
   `require`, `module`, `this_1`... Short minified names that occur in several
   scopes get the literal id of their function. The cell's references list
   every read and write of the variable.
6. **Strings** (`loader/StringDecoder`): obfuscator.io moved the string
   literals into one array, which a loop rotates at start-up until a checksum
   of decoded strings matches, and replaced each literal with a call to the
   decoder through wrapper functions; their arguments are offsets, partly read
   from constant object literals. A small Ignition interpreter
   (`loader/Interpreter`, JavaScript semantics in `loader/Js`) runs the start
   of the script as Node would, which builds and rotates the array, and stops
   at the first thing it does not model (here `Function.prototype.toString` in
   the self-defending code). Values then flow through every function: a
   variable gets the value all the stores of the program agree on (in the
   module scope, the one the start-up left), and a call whose callee is known
   is evaluated in a sandbox that cannot change existing objects. Calls that
   read the array and returned a string, keyed accesses whose key is a known
   string, and concatenations and comparisons of two known strings are kept:
   the strings go to the `js_strings` block.
7. **Disassembly**: SLEIGH (`data/languages/v8_87.slaspec`, generated by
   `tools/gen_sleigh.py`) decodes all 183 bytecodes with their Wide and
   ExtraWide forms. Two context fields carry what the bytes cannot:
   `cpbase`, the constant pool of the function, and `aux`, either a
   Jump*Constant target, a variable cell, or a decoded string (the
   `js_strings` entry, or 1 / 2 for a comparison that is false / true).
8. **Decompiler**: constant pool operands go through `cpool`, resolved by
   `V8_ConstantPool` from the heap image. The program's output language is set
   to Java, which prints property accesses as `obj.name`.

## Reading the decompiler output

- Calls are `Call(f, args...)`, `CallProperty(f, receiver, args...)`,
  `Construct(...)`. Runtime functions print as `%Name` and intrinsics as
  `%_Name`.
- `GetProperty(o, k)` / `SetProperty(o, k, v)` are keyed accesses (`o[k]`).
- `CreateClosure(fn)` names the function created, and
  `CreateObjectLiteral({a, b, ...})` shows the literal's keys.
  `CreateFunctionContext(scope_fn)` gives the scope it opens.
- Numbers come from Smis: negative constants show as `0xfffff9ac`.
- Decoded strings replace the calls that returned them, e.g.
  `CallProperty(_0x1abaeb.on,_0x1abaeb,"ready",uVar6)` in Dofus Retro's entry
  module, where `_0x1abaeb` holds Electron's `app`. A keyed access with a
  decoded key reads `obj.name` (`obj.["key"]` when the key is not an
  identifier). Concatenations of decoded pieces show their result, and
  comparisons of two known strings (obfuscator.io's dead-code guards) are
  folded, so the decompiler drops the dead branch (`Removing unreachable
  block` warnings).
- In the listing these instructions keep their operands, with the string (or
  `always false`) as an end-of-line comment and a reference into
  `js_strings`. Plate comments mark the string array function (`a0_0x2162`)
  and the decoder.

## Limitations

- **Exception handlers** are not edges of the control flow graph, so the
  decompiler leaves out catch blocks; they are disassembled and labelled
  (`catch_N`, with the try range in a comment).
- **Calls are user operations** (CALLOTHER). The decompiler may print a
  property read after a call that follows it in the bytecode, when the value
  is used only once.
- **Read-only heap objects** that are not roots are named from
  `data/v8_ro_strings.json`: the 15 that main.jsc uses (565 references) are
  strings such as `size`, `join` or `" "`. The table covers Electron 11's
  read-only page up to its first Code object; other objects would show as
  `ro_heap_<offset>`.
- **Obfuscation**: strings are decoded where the wrapper and its arguments
  can be known without running the application. Calls in dead code, and
  wrappers reached through parameters or unknown objects, stay calls.
  Control-flow flattening (dispatch loops over `"3|0|1".split("|")`) is not
  undone, and the obfuscator's constant objects still show as
  `CreateObjectLiteral` stores.

## Other files

`tools/*.js` and `tools/*.py` (besides `extract_v8_tables.py`, `gen_sleigh.py`,
`extract_ro_strings.py` and `rea_v8_patch.py`),
`ghidra_scripts/{CreateV8Functions,ResolveWrappers,AnnotateHandlers}.java` and
the JSON captures in `data/` come from the earlier runtime-capture approach.
They are kept in the repository but not packaged, because they rely on that
approach's data files and on the previous loader's layout.

## License

Apache License 2.0
