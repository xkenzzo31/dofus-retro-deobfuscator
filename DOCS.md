# Technical Documentation

In-depth documentation of the Dofus Retro 1.48 client architecture, obfuscation techniques, and the research behind this deobfuscation pipeline.

## Table of Contents

- [Client Architecture](#client-architecture)
- [Obfuscation Analysis](#obfuscation-analysis)
- [V8 Bytecode Internals](#v8-bytecode-internals)
- [Cytrus CDN Protocol](#cytrus-cdn-protocol)
- [Shield Security Module](#shield-security-module)
- [Decompiler Design](#decompiler-design)
- [Tools Evaluated](#tools-evaluated)
- [Research Methodology](#research-methodology)
- [Known Limitations](#known-limitations)
- [References](#references)

---

## Client Architecture

### Stack

Dofus Retro 1.48 runs as an **Electron 11.5.0** application:

| Component | Version | Role |
|-----------|---------|------|
| Electron | 11.5.0 | Desktop shell |
| Node.js | 12.18.3 | Backend runtime |
| V8 | 8.7.220.31-electron.0 | JavaScript engine |
| Chromium | 87.0.4280.141 | Renderer |
| bytenode | 1.3.7 | .jsc bytecode compiler |
| Flash (Pepper) | Embedded | Game rendering (SWF) |

### Process Model

```
┌──────��─────────────────────��────────────────────────────┐
│  Main Process (main.jsc)                                │
│  ├── Shield security module (AES-256-CBC, fingerprint)  │
│  ├── Zaap/Thrift RPC client                             │
│  ├── CryptoJS (121 functions)                           │
│  ├── systeminformation v5.16.6 (~1,200 functions)       │
│  └── obfuscator.io wrappers (~6,800 functions)          │
├──────────────────────┬──────────────────────────────────┤
│  34 IPC channels     │                                  │
├──────────���───────────┘                                  │
│  Renderer Process (D1ElectronLauncher.js)               │
│  ├── 76 exports to Flash via ExternalInterface          │
│  ├── Packet relay (game ↔ main process)                 │
│  ├── Discord RPC integration                            ���
│  └── UI management (login dialog, game window)          │
├────────────────────��─┬──────────────────��───────────────┤
│  ExternalInterface   │                                  │
├───────────────────��──┘                                  │
│  Flash SWF (loader.swf)                                 │
│  ├── 4,258 ActionScript 2 scripts                       │
│  ├── Game rendering, combat, maps, inventory            │
│  ├── Network packet construction                        │
│  └── 72+ client→server packet types                     │
└─────────────────────────────────────────────────────────┘
         │
         │ TCP/TLS :443
         ▼
  Dofus Retro Servers
```

### Deobfuscation Targets

| Target | Size | Protection | Deob Status |
|--------|------|------------|-------------|
| `main.jsc` | 12.7 MB | V8 bytecode + obfuscator.io | Decompiled (8,611 functions) |
| `D1ElectronLauncher.js` | 644 KB | obfuscator.io (RC4 strings) | Fully deobfuscated (29 KB) |
| `loader.swf` | 3.3 MB | Hex-mangled names | Decompiled (JPEXS, not in this pipeline) |
| `D1Chat.js` | 25 KB | obfuscator.io | Deobfuscated |
| `D1Console.js` | 15 KB | obfuscator.io | Deobfuscated |

### main.jsc Composition

Based on runtime analysis and function categorization:

```
┌────────���─────────────────────────────────┐
│  main.jsc — 8,611 functions              │
├──────────────────────────────────────────┤
│  79%  obfuscator.io wrappers   (~6,800)  │  ← noise / indirection
│  14%  systeminformation        (~1,200)  │  ← hardware fingerprinting
│  1.4% CryptoJS                 (121)     │  ← AES, SHA, HMAC, etc.
│  0.4% Electron lifecycle       (33)      │  ← app events, windows
│  0.2% Network/socket           (18)      │  ← TCP connections
│  ~1%  Business logic           (~90)     │  ← actual Shield code
│  ~4%  Other/uncategorized      (~350)    │
└──────────────────────────────────────────┘
```

The ~90 business logic functions are the actual target. Everything else is either protection overhead or standard library code.

### D1ElectronLauncher.js (D1EL)

After deobfuscation with webcrack:
- **729 lines** of readable code
- **76 exports** to Flash via `externalInterface` (game API surface)
- **34 IPC listeners** connecting renderer ↔ main process
- Key responsibilities: packet relay, Discord RPC, Zaap connection, login dialog management, system info forwarding

### IPC Channels (34 total)

The main process and renderer communicate through Electron IPC. Key channels include:

| Channel | Direction | Purpose |
|---------|-----------|---------|
| `shield-init` | main → renderer | Initialize Shield module |
| `shield-hash` | renderer → main | Request packet signature |
| `shield-hash-response` | main → renderer | Return signed packet |
| `game-packet` | renderer → main | Forward game packet for signing |
| `zaap-connect` | main → renderer | Zaap Thrift RPC status |
| `system-info` | renderer → main | Hardware fingerprint request |
| `discord-rpc` | renderer → main | Update Discord presence |

---

## Obfuscation Analysis

### obfuscator.io Configuration

The client is protected with [obfuscator.io](https://obfuscator.io/) using these settings:

#### String Array

- **8,676 elements** after array rotation
- **Base offset**: 276 (all indices start at 276)
- **Rotation**: applied at startup, makes static analysis harder
- **Decoder function**: `a0_0x2c3b(idx, key)` → subtracts 276, returns `a0_0x4ebe()[idx]`

```javascript
// After rotation, the string array looks like:
["addEventListener", "createElement", "appendChild", "prototype", ...]
// 8,676 elements, indexed from 276 to 8,951
```

#### Wrapper Functions (~6,800)

The majority of functions in main.jsc are obfuscator.io indirection wrappers:

```javascript
// Typical wrapper pattern:
function _0x3a2b1c(arg1, arg2, arg3, arg4, arg5) {
  ctx_42(arg1, arg3, arg5);      // call decoder with specific args
  return ctx_42(arg1, arg3, arg5); // return decoded string
}
```

These wrappers:
- Use **closure slots** (`ctx_N`) to capture the decoder function
- Accept 5 arguments but only use 2-3 (the rest are dead parameters)
- Each wrapper resolves to one or more strings depending on arguments
- Cannot be resolved statically without knowing the closure context

**Our approach**: runtime capture via Electron hook (229 unique indices captured across 76,947 calls).

#### Dead Code Injection

obfuscator.io inserts opaque predicates using 5-character random mixed-case tags:

```javascript
_0x3a2b1c(args);  // evaluates to "AbCdE" (dead tag)
_0x4b5c6d(args);  // evaluates to "FgHiJ" (different tag)
if (_0x3a2b1c(...) === _0x4b5c6d(...)) {
  // Dead code — condition is always false (two different random tags)
  // ... unreachable code ...
}
```

Our pipeline removes the standalone evaluation statements. The conditional blocks are kept because we can't always determine true vs. false statically.

#### Control Flow Flattening

Some functions use switch-dispatch state machines:

```javascript
var state = "0|3|1|4|2".split("|"), idx = 0;
while (true) {
  switch (state[idx++]) {
    case "0": /* step 1 */ break;
    case "1": /* step 3 */ break;
    // ...
  }
}
```

**Status**: not yet reversed by this pipeline. webcrack handles some simpler cases.

---

## V8 Bytecode Internals

### Why V8 8.7?

Dofus Retro uses **Electron 11.5.0** which bundles **V8 8.7.220.31**. The `main.jsc` file is compiled with [bytenode](https://github.com/nicedoc/bytenode), which uses `v8::ScriptCompiler::CreateCodeCache()` to produce a cached bytecode file.

### .jsc File Format

```
Offset  Size    Field
0       4       Magic (same as V8 version hash)
4       4       Source hash
8       4       Source length (bit 31 = flag)
12      4       Flags hash
16+     var     Serialized bytecode (SharedFunctionInfo tree)
```

The bytecode is version-locked: V8 checks the version hash, source hash, flags hash, and a checksum before deserializing. Our patch bypasses all four checks.

### Ignition Bytecode

V8's Ignition interpreter uses a register-based bytecode format:

- **Accumulator**: implicit register for most operations
- **Registers**: `r0`, `r1`, ... (local variables)
- **Parameters**: `a0` (this), `a1`, `a2`, ... (arguments)
- **Context slots**: closure variables captured from outer scopes
- **Constant pool**: per-function table of strings, numbers, SharedFunctionInfos

Each function has:
- A **bytecode array** (the instructions)
- A **constant pool** (strings, numbers, nested functions)
- A **handler table** (try/catch regions)
- A **source position table** (for debugging)

### Patches Applied (4 total)

| Patch | File | What |
|-------|------|------|
| 1 | `code-serializer.cc` | Add `#include <iostream>` |
| 2 | `code-serializer.cc` | Bypass version/source/flags hash checks |
| 3 | `code-serializer.cc` | Bypass checksum verification |
| 4 | `code-serializer.cc` | Enumerate all SharedFunctionInfo and print bytecode after deserialization |

The key insight is that V8's `CompileUnboundScript` with `kConsumeCodeCache` triggers full deserialization. Our patch hooks into the post-deserialization path to iterate every `SharedFunctionInfo` in the script and call `BytecodeArray::Disassemble()`.

---

## Cytrus CDN Protocol

### Overview

Ankama distributes game files via **Cytrus v6**, a custom CDN protocol built on FlatBuffers manifests and content-addressed bundle storage.

### Flow

```
1. GET https://cytrus.cdn.ankama.com/cytrus.json
   → Game index: names, platforms, versions, meta hashes

2. GET https://cytrus.cdn.ankama.com/{game}/releases/{release}/{platform}/{version}.manifest
   → Binary FlatBuffers manifest describing all files

3. GET https://cytrus.cdn.ankama.com/{game}/bundles/{hash[0:2]}/{hash}
   → Content-addressed bundle containing file chunks
```

### Manifest Schema (Reverse-Engineered)

```
Manifest {
  fragments: [Fragment]
}

Fragment {
  name: string              // e.g. "main", "resources"
  files: [File]
  bundles: [Bundle]
}

File {
  name: string              // e.g. "main.jsc"
  size: uint64
  hash: bytes (SHA-1)
  chunks: [Chunk]           // maps to bundle chunks
  executable: bool
  symlink: string
}

Bundle {
  hash: bytes (SHA-1)       // content address
  chunks: [Chunk]
}

Chunk {
  hash: bytes (SHA-1)
  size: uint64
  offset: uint64            // position within bundle
}
```

Files are split into chunks, chunks are packed into bundles. To reconstruct a file:
1. Parse the manifest to find the target file
2. For each file chunk, locate which bundle contains it (by chunk hash)
3. Download the bundle(s) and extract the relevant byte ranges
4. Concatenate chunks in order
5. Verify SHA-1 hash

### Implementation Note

The manifest is a **FlatBuffers** binary. We wrote a minimal FlatBuffers reader (`manifest.mjs`) that navigates vtables and indirect offsets without requiring a schema file or code generation.

---

## Shield Security Module

### Overview

Shield is the in-game security module embedded in `main.jsc`. It provides:

1. **Per-packet cryptographic signing** — every outgoing game packet is signed
2. **Hardware fingerprinting** — machine identification via systeminformation
3. **Anti-cheat process scanning** — detects debuggers, memory editors, sniffers
4. **Telemetry** — encrypted reports sent to Ankama

### Architecture

```
Flash SWF
  │ packet to send
  ▼
D1ElectronLauncher (renderer)
  │ IPC: shield-hash
  ▼
main.jsc Shield module
  ├── applyPacketToSendPostProcessing(packet)
  │   ├── SHA256(packet + counter)
  │   ├── AES-256-CBC encrypt (4 steps, nested)
  │   └── Output: packet + "\xf9" + base64(IV) + base64(ct) + "\xf9"
  │
  ├── getRandomNetworkKey()
  │   ├── Encrypt username
  │   ├── Encrypt system info
  │   ├── Encrypt system hash
  │   └── Output: 560-char base64 key
  │
  └── getSystemInformation()
      └── systeminformation v5.16.6 fingerprint
```

### API Surface (10 methods)

| Method | Purpose |
|--------|---------|
| `init()` | Initialize Shield, load keys |
| `getHash()` | Get current signature hash |
| `getRandomNetworkKey()` | Generate 560-char network key |
| `getSystemInformation()` | Collect hardware fingerprint |
| `getTelemetry()` | Respond to server telemetry challenge |
| `applyPacketToSendPostProcessing()` | Sign outgoing packet (4-step AES) |
| `onPacketSent()` | Post-send hook (counter increment) |
| `onPacketReceived()` | Received packet hook |
| `parseBasicCryptedPacket()` | Decrypt incoming signed packet |
| `cryptBasicPacket()` | Encrypt outgoing packet body |

### Cryptographic Primitives

- **Algorithm**: AES-256-CBC via CryptoJS (not Node.js native crypto)
- **Padding**: PKCS7
- **Key storage**: 9 keys in a hash array within a closure, plus 2 wrap keys
- **IV**: 16 bytes, a combination of static IV and per-packet `crypto.randomBytes(16)`
- **Counter**: 5-digit zero-padded string ("00000", "00001", ...), must stay synchronized with server

### Packet Signing Flow

```
Input: raw_packet (string)

Step 1: hash = SHA256(raw_packet + counter_string)
Step 2: ct1 = AES_CBC_encrypt(hash, key=hash_array[k1], iv=static_iv)
Step 3: ct2 = AES_CBC_encrypt(ct1, key=hash_array[k2], iv=static_iv)
Step 4: iv_rand = randomBytes(16)
        ct3 = AES_CBC_encrypt(ct2, key=WRAP_KEY, iv=iv_rand)

Output: raw_packet + "\xf9" + base64(iv_rand) + base64(ct3) + "\xf9"
        (adds ~304 chars to each packet)

counter++
```

### Hardware Fingerprinting

Uses `systeminformation` v5.16.6 to collect:

| Category | Data Points |
|----------|-------------|
| CPU | Model, vendor, cores, threads, frequency, flags, cache, socket |
| GPU | Model, vendor, VRAM, driver version, resolution |
| RAM | Slots, size, type, speed, layout |
| Disk | Model, serial, size, interface type |
| Motherboard | Board name, vendor, BIOS version/date, chassis type |
| Network | MAC addresses, IP, gateway, DNS, SSID |
| System IDs | UUID, board UUID, DMI identifiers |
| VM detection | Docker container enumeration, process scanning |

### Anti-Cheat Scanning

Every ~30 seconds, Shield scans the process list for:

| Category | Tools Detected |
|----------|---------------|
| Debuggers | x64dbg, OllyDbg, WinDbg, gdb, lldb |
| Reverse engineering | IDA Pro, Ghidra, Radare2, Binary Ninja |
| Network sniffers | Wireshark, Fiddler, Charles Proxy, mitmproxy |
| Memory editors | Cheat Engine, ArtMoney, GameGuardian |
| Instrumentation | Frida, Xposed, Substrate |
| Process monitors | Process Explorer, Process Hacker, API Monitor |

---

## Decompiler Design

### Architecture

```
ignition_disasm.txt (v8dasm output, ~115 MB)
        │
        ▼
  ┌─────────────┐
  │   Parser    │  Streaming: 1 function at a time
  │             │  Extracts: instructions, constants, handlers
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ CFG Builder │  Basic blocks, loop headers, try/catch regions
  │             │  Jump target resolution, predecessor/successor edges
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │  SymExec    │  Accumulator + register state machine
  │             │  Translates opcodes → JS expressions
  │             │  Temp variable spilling for long expressions
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ Categorizer │  Tags: crypto, shield, network, auth, electron, zaap, game
  │             │  Based on function name + constant pool strings
  └──────┬──────┘
         ▼
  decompiled.js + index.json + category files
```

### Streaming Architecture

The decompiler processes the 115 MB disassembly file in a single pass:

1. Parse one function at a time (generator pattern)
2. Build its CFG
3. Run symbolic execution
4. Write output immediately
5. Free memory before parsing the next function

Peak memory usage: ~50 MB regardless of input size. This matters because the full disassembly contains 8,611 functions totaling 115 MB of text.

### Opcode Coverage

All 155+ V8 8.7 Ignition opcodes are handled:

| Category | Opcodes | Examples |
|----------|---------|---------|
| Loads | 15 | LdaZero, LdaSmi, LdaConstant, LdaGlobal |
| Stores | 8 | Star, Star0-Star4, StaGlobal |
| Properties | 10 | LdaNamedProperty, StaKeyedProperty |
| Binary ops | 24 | Add, Sub, Mul, BitwiseAnd, ShiftLeft (+Smi variants) |
| Unary ops | 7 | Inc, Dec, Negate, TypeOf, LogicalNot |
| Comparisons | 12 | TestEqual, TestLessThan, TestInstanceOf, TestIn |
| Calls | 14 | CallProperty0-2, CallUndefinedReceiver0-2, Construct |
| Control flow | 16 | JumpIfTrue/False/Null/Undefined, JumpLoop, Switch |
| Closures | 7 | CreateClosure, CreateFunctionContext, PushContext |
| Generators | 2 | SuspendGenerator, ResumeGenerator |
| Try/Catch | Via handler table | Mapped to try { } catch (e) { } |
| For-in | 5 | ForInEnumerate, ForInPrepare, ForInNext |

---

## Tools Evaluated

During research, we evaluated every available V8 bytecode analysis tool:

| Tool | Version Support | Result |
|------|----------------|--------|
| **v8dasm** | Any (compile from source) | **Used** — core of our pipeline |
| **bytenode** | V8 version-matched | Compiler only, no decompiler |
| **Ghidra_NodeJS** (PositiveTechnologies) | V8 ≤ 8.6 | Plugin for Ghidra. Fails on 8.7 (version hash lookup). Abandoned since 2021 |
| **Ghidra** (custom scripts) | N/A | **Used** — custom scripts for string array deob and control flow analysis |
| **View8** (suleram) | V8 ≥ 9.4 | Too new for 8.7 |
| **jsc2js** (xqy2006) | V8 14.x only | Wrong version entirely |
| **jscdecompiler.com** | Electron 17+ | Too new for Electron 11 |
| **webcrack** | JS source | **Used** — excellent for obfuscator.io |
| **obfuscator-io-deobfuscator** (ben-sb) | JS source | Works on D1EL, crashes on large files |
| **JPEXS FFDec** | SWF/AS2 | **Used** — for loader.swf (separate) |

### Why We Built Our Own Decompiler

No existing tool supports V8 8.7 bytecode decompilation. The gap:
- `v8dasm` produces disassembly (bytecode listing), not JavaScript
- All existing decompilers target different V8 versions
- The obfuscator.io layer requires post-decompilation processing

So we built `v8decompiler.py`: a custom Ignition-to-JavaScript decompiler with streaming architecture, CFG reconstruction, and symbolic execution.

---

## Research Methodology

### Phase 1: Client Discovery

1. Located the Dofus Retro installation (`/Applications/Ankama/Retro/`)
2. Identified Electron 11.5.0 via `package.json` and `electron.asar`
3. Found `main.jsc` (bytenode compiled) and `D1ElectronLauncher.js` (obfuscator.io)
4. Extracted V8 version from Electron headers: `8.7.220.31-electron.0`

### Phase 2: Tool Survey

Evaluated every known V8 bytecode tool (see [Tools Evaluated](#tools-evaluated)). All failed for V8 8.7. Decided to build a custom pipeline based on compiling V8 8.7 from source.

### Phase 3: V8 Build + Patching

1. Set up Docker build for reproducibility
2. Fetched V8 8.7.220.31 via `depot_tools`/`gclient`
3. Identified 4 verification checks in `code-serializer.cc`
4. Wrote `patch_v8.py` to bypass checks and inject bytecode printing
5. Compiled as static monolith (`v8_monolith`) + custom `v8dasm.cc`

### Phase 4: Decompiler Development

1. Analyzed v8dasm output format (function boundaries, constant pools, handler tables)
2. Built streaming parser (generator-based, O(1) memory per function)
3. Implemented CFG builder (basic blocks, loop detection, try/catch regions)
4. Built symbolic executor for all 155+ opcodes
5. Added function categorization by keyword matching

### Phase 5: Deobfuscation

1. Deobfuscated D1EL with webcrack (baseline: what clean code looks like)
2. Identified obfuscator.io patterns in decompiled main.jsc
3. Built string array prelude injection (`clean-js.py`)
4. Built runtime hook for live string capture (`preloader-hook.js`, not shipped)
5. Built post-processor for annotation + dead code removal (`resolve-strings.py`)

### Phase 6: Cytrus CDN

1. Captured Zaap launcher network traffic
2. Identified `cytrus.cdn.ankama.com` as the distribution endpoint
3. Reverse-engineered the FlatBuffers manifest format (no public schema)
4. Built downloader that reconstructs files from content-addressed bundles
5. Integrated into the pipeline as Step 1

---

## Known Limitations

### Decompiler

- **No SSA/phi nodes**: the symbolic executor uses a flat register map, which can produce incorrect expressions at control flow merge points
- **Expression explosion**: complex bytecode can produce deeply nested expressions before temp variable spilling kicks in (threshold: 120 chars)
- **No scope analysis**: closure variable names are lost (appear as `ctx_N`)
- **16% Babel failure rate**: 1,373 functions produce syntactically invalid JavaScript (usually due to complex control flow)

### Deobfuscation

- **6,838 unresolved wrapper calls**: these pass through closure slots and cannot be resolved without runtime execution or advanced symbolic analysis
- **Control flow flattening**: switch-dispatch patterns are not reversed
- **Opaque predicates**: only standalone evaluations are removed; conditional blocks are kept (conservative approach)

### Pipeline

- **V8 8.7 only**: the pipeline is specifically built for V8 8.7.220.31. Other V8 versions would require rebuilding the Docker image with the matching V8 source
- **Linux/amd64 only**: the Docker image builds for `linux/amd64` (V8 compilation is architecture-specific)
- **~30 min first build**: compiling V8 from source takes time (subsequent builds use Docker layer cache)

---

## References

### V8 / Bytecode

- [V8 Ignition Design Document](https://docs.google.com/document/d/11T2CRex9hXxoJwbYqVQ32yIPMh0uouUZLdyrtmMoL44)
- [Understanding V8 Bytecode](https://medium.com/nicedoc/understanding-v8s-bytecode-317d46c94775)
- [nicedoc/v8dasm](https://github.com/nicedoc/v8dasm) — base for our disassembler
- [nicedoc/bytenode](https://github.com/nicedoc/bytenode) — the tool that compiles `.jsc` files

### Deobfuscation

- [nicedoc/webcrack](https://github.com/nicedoc/webcrack) — JavaScript deobfuscator used in our pipeline
- [obfuscator.io](https://obfuscator.io/) — the obfuscation tool used by Ankama

### Dofus Community

- [Cadernis](https://cadernis.fr/) — French Dofus development community
- [Dofus Retro Protocol](https://github.com/nicedoc/nicedoc.io) — community protocol documentation

---

*By Luska — research conducted 2026*
