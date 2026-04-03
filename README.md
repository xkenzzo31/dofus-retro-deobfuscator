# 🔓 Dofus Retro Deobfuscator

**Automated deobfuscation pipeline for the Dofus Retro 1.48 Electron client.**

Downloads, disassembles, and decompiles the entire client — from raw V8 8.7 bytecode to structured JavaScript with function categorization. Fully deobfuscates the renderer process. One command.

> 📚 For deep technical documentation (bytecode internals, crypto analysis, protocol details), see **[DOCS.md](DOCS.md)**.

---

## ⚡ Quick Start

```bash
# Build the Docker image (~30 min first time — compiles V8 8.7 from source)
docker build --platform linux/amd64 -t dofus-deob .

# Run the pipeline — outputs to ./output/
docker run --rm --platform linux/amd64 -v ./output:/output dofus-deob
```

That's it. Everything lands in `./output/`.

---

## 🏗️ Client Architecture

Dofus Retro 1.48 is an **Electron 11.5.0** desktop application with a multi-layer architecture:

```
┌─────────────────────────────────────────────────────────────┐
│  🧠 Main Process (main.jsc)                                │
│  ├── Shield security module (AES-256-CBC, fingerprint)      │
│  ├── Zaap/Thrift RPC client                                 │
│  ├── CryptoJS (121 functions)                               │
│  ├── systeminformation v5.16.6 (~1,200 functions)           │
│  └── obfuscator.io wrappers (~6,800 functions)              │
├──────────────────────┬──────────────────────────────────────┤
│  34 IPC channels     │                                      │
├──────────────────────┘                                      │
│  🖥️ Renderer Process (D1ElectronLauncher.js)                │
│  ├── 76 exports to Flash via ExternalInterface              │
│  ├── Packet relay (game ↔ main process)                     │
│  ├── Discord RPC integration                                │
│  └── UI management (login dialog, game window)              │
├──────────────────────┬──────────────────────────────────────┤
│  ExternalInterface   │                                      │
├──────────────────────┘                                      │
│  🎮 Flash SWF (loader.swf)                                  │
│  ├── 4,258 ActionScript 2 scripts                           │
│  ├── Game rendering, combat, maps, inventory                │
│  ├── Network packet construction                            │
│  └── 72+ client→server packet types                         │
└─────────────────────────────────────────────────────────────┘
         │
         │ TCP/TLS :443
         ▼
  Dofus Retro Servers
```

### 📊 Client Technology Stack

| Component | Version | Role |
|:----------|:--------|:-----|
| Electron | 11.5.0 | Desktop shell |
| Node.js | 12.18.3 | Backend runtime |
| V8 | 8.7.220.31-electron.0 | JavaScript engine |
| Chromium | 87.0.4280.141 | Renderer |
| bytenode | 1.3.7 | `.jsc` bytecode compiler |
| Flash (Pepper) | Embedded | Game rendering (SWF) |

---

## 🎯 What We Extract — Honest Assessment

### Deobfuscation Targets & Real Results

| Target | Size | Protection | Deob Level | What You Actually Get |
|:-------|:-----|:-----------|:----------:|:----------------------|
| `D1ElectronLauncher.js` | 644 KB | obfuscator.io (RC4) | ✅ **Fully clean** | 29 KB of readable code — IPC channels, Flash exports, UI logic |
| `main.jsc` | 12.7 MB | V8 bytecode + obfuscator.io | ⚠️ **Decompiled, still obfuscated** | 8,611 functions in valid JS syntax, but wrapper calls unresolved |
| `loader.swf` | 3.3 MB | Hex-mangled class names | ✅ **Decompiled** | 4,258 AS2 scripts (via JPEXS, separate tool) |

### 🟢 What's Genuinely Useful

**D1ElectronLauncher.js → D1EL_clean.js** — This is the real win. 644 KB of obfuscated code becomes 29 KB of clean, readable JavaScript. You can see every IPC channel, every Flash ExternalInterface export, the full packet relay logic, Discord RPC setup, and window management. This is a complete, readable reverse of the renderer process.

**Bytecode disassembly (ignition_disasm.txt)** — 115 MB of raw V8 Ignition bytecodes for all 8,611 functions. Useful for manual analysis with Ghidra or your own tooling.

**Function categorization (index.json + category files)** — Every function is tagged by domain (crypto, network, auth, electron, game, zaap) based on constant pool strings. The category boundaries are correct — you know *which* functions handle crypto, *which* handle network — even if the code inside is still obfuscated.

**String array (8,676 entries)** — The full decoded obfuscator.io string table is extracted and available. Every string the client uses is in there.

### 🔴 What's NOT Deobfuscated (Being Honest)

**main.jsc business logic is still obfuscated.** The decompiled output for `main.jsc` contains:

- **12,101 lines** with unresolved `_0x...()` wrapper calls
- **19,437 lines** with opaque `ctx_N` closure references
- The "readable" version is only **8 KB smaller** than the webcrack output (0.3% actual resolution)

The root cause: **79% of functions (~6,800) are obfuscator.io wrapper functions** that resolve strings through closure-captured decoder references. These cannot be resolved statically — they need runtime closure contexts. Our runtime capture (229 indices from 76,947 calls) only scratches the surface.

**What the category files (crypto.js, auth.js, etc.) look like in practice:**

```javascript
// What you might expect:
var hash = CryptoJS.SHA256(packet + counter);
var encrypted = CryptoJS.AES.encrypt(hash, key, { iv: iv });

// What you actually get:
_0x2fc62a(865, ctx_334[_0x3a2a3a], 3043, ctx_334[_0x450905], ctx_334[_0x50a1b0]);
_0x22a54d(ctx_334[_0x437fe0], 4963, 5075, ctx_334[_0x316c8d], 8193);
```

The structure is valid JS, the categories are correct, but the semantic content is still buried under wrapper indirection. You can see function boundaries, argument counts, control flow — but not what the code actually does without further work.

### 🧬 main.jsc Composition (8,611 functions)

```
 79.0%  ██████████████████████████████████████░░  obfuscator.io wrappers  (~6,800)  ← unresolved noise
 14.0%  ███████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  systeminformation       (~1,200)  ← fingerprinting lib
  1.4%  █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  CryptoJS                (121)     ← AES, SHA, HMAC
  1.0%  █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  Shield business logic   (~90)     ← the real target
  0.4%  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  Electron lifecycle      (33)
  0.2%  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  Network/socket          (18)
  4.0%  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  Other/uncategorized     (~350)
```

### 📂 Category Files

The decompiler auto-categorizes functions and exports domain-specific files:

| Category | File | Functions | Content Quality |
|:---------|:-----|----------:|:----------------|
| 🔐 Crypto | `crypto.js` | ~121 | Structure visible, CryptoJS function names preserved (e.g. `_doReset`, `_doProcessBlock`). Wrapper calls unresolved. |
| 🌐 Network | `network.js` | ~18 | Function boundaries clear. String references still wrapped. |
| 🔑 Auth | `auth.js` | ~30 | Categorization correct. Code semantics obfuscated. |
| ⚡ Electron | `electron.js` | ~33 | Some readable strings (`"app"`, `"BrowserWindow"`). Better than average. |
| 🎮 Game | `game.js` | ~15 | Minimal code, heavily wrapped. |
| 📡 Zaap | `zaap.js` | ~25 | Thrift RPC structure visible. String references wrapped. |

> 💡 Shield functions are distributed across `crypto.js` and `auth.js`. The Shield API (10 methods) was reverse-engineered by combining decompiled structure with runtime analysis — not from the decompiled code alone.

---

## 🔬 Pipeline Steps

| Step | What | Tool | Output |
|:----:|:-----|:-----|:-------|
| 1️⃣ | Download `main.jsc` + `D1ElectronLauncher.js` from Cytrus CDN | Node.js | Raw client files |
| 2️⃣ | Disassemble V8 8.7 Ignition bytecode | `v8dasm` (custom patched) | ~115 MB disassembly |
| 3️⃣ | Decompile bytecode to JavaScript (8,611 functions) | `v8decompiler.py` | 13 MB decompiled JS |
| 4️⃣ | Post-process: syntax fixes, Babel validation, webcrack | Python + Node.js | 2.3 MB validated JS (84% pass rate) |
| 5️⃣ | Deobfuscate D1ElectronLauncher.js | webcrack | ✅ 29 KB clean, readable code |
| 6️⃣ | Annotate + categorize functions, attempt string resolution | `resolve-strings.py` | Category tags + minimal string resolution |
| 7️⃣ | Package everything as a versioned ZIP | zip | Release-ready archive |

### 📦 Output Structure

```
output/
├── raw/
│   ├── main.jsc                       # 12.7 MB — Original V8 bytecode
│   └── D1ElectronLauncher.js          # 644 KB  — Original launcher (obfuscated)
├── jsc_decompiled/
│   ├── ignition_disasm.txt            # 115 MB  — Raw V8 disassembly (useful for Ghidra)
│   └── v2/
│       ├── decompiled.js              # 13 MB   — Full decompiled JavaScript
│       ├── decompiled_valid.js        # 2.3 MB  — Babel-validated (84% of functions)
│       ├── decompiled_webcrack.js     # 2.3 MB  — After webcrack pass
│       ├── decompiled_readable.js     # 2.3 MB  — Final annotated version
│       ├── index.json                 # 788 KB  — Function index with categories
│       ├── crypto.js                  # Extracted: crypto functions (CryptoJS)
│       ├── network.js                 # Extracted: network/socket
│       ├── auth.js                    # Extracted: authentication
│       ├── electron.js                # Extracted: Electron lifecycle
│       ├── game.js                    # Extracted: game logic
│       └── zaap.js                    # Extracted: Zaap/Thrift RPC
├── webcrack_d1el/
│   └── D1EL_clean.js                  # 29 KB   — ✅ Fully deobfuscated launcher
└── dofus-retro_VERSION_DATE.zip       # Everything packaged
```

---

## 🛡️ Shield Security Module — Deep Dive

Shield is the anti-cheat/anti-bot module embedded inside `main.jsc`. This was reverse-engineered through a combination of decompiled structure analysis, runtime tracing, and manual reconstruction — **not** from the decompiled code alone.

### API Surface (10 methods)

| Method | Purpose | How We Reversed It |
|:-------|:--------|:-------------------|
| `init()` | Initialize Shield, load keys | Runtime tracing + IPC channel analysis |
| `getHash()` | Get current signature hash | D1EL IPC handler analysis |
| `getRandomNetworkKey()` | Generate 560-char network key | Runtime capture + crypto analysis |
| `getSystemInformation()` | Collect hardware fingerprint | systeminformation lib identification |
| `getTelemetry()` | Respond to server telemetry challenge | Network packet analysis |
| `applyPacketToSendPostProcessing()` | Sign outgoing packet (4-step AES) | Runtime tracing + crypto reconstruction |
| `onPacketSent()` | Post-send hook (counter increment) | D1EL IPC + packet analysis |
| `onPacketReceived()` | Received packet hook | D1EL IPC analysis |
| `parseBasicCryptedPacket()` | Decrypt incoming signed packet | Crypto pattern matching |
| `cryptBasicPacket()` | Encrypt outgoing packet body | Runtime tracing |

### 🔐 Packet Signing Flow

```
Input: raw_packet (string)

Step 1: hash = SHA256(raw_packet + counter_string)
Step 2: ct1 = AES_CBC_encrypt(hash, key=hash_array[k1], iv=static_iv)
Step 3: ct2 = AES_CBC_encrypt(ct1, key=hash_array[k2], iv=static_iv)
Step 4: iv_rand = randomBytes(16)
        ct3 = AES_CBC_encrypt(ct2, key=WRAP_KEY, iv=iv_rand)

Output: raw_packet + "\xf9" + base64(iv_rand) + base64(ct3) + "\xf9"

counter++  (5-digit zero-padded, must stay synced with server)
```

### 🖥️ Hardware Fingerprinting

| Category | Data Points |
|:---------|:------------|
| CPU | Model, vendor, cores, threads, frequency, flags, cache, socket |
| GPU | Model, vendor, VRAM, driver version, resolution |
| RAM | Slots, size, type, speed, layout |
| Disk | Model, serial, size, interface type |
| Motherboard | Board name, vendor, BIOS version/date, chassis type |
| Network | MAC addresses, IP, gateway, DNS, SSID |
| System IDs | UUID, board UUID, DMI identifiers |
| VM detection | Docker container enumeration, process scanning |

### 🚨 Anti-Cheat Process Scanning

Every ~30 seconds, Shield scans for:

| Category | Tools Detected |
|:---------|:---------------|
| 🔍 Debuggers | x64dbg, OllyDbg, WinDbg, gdb, lldb |
| 🔧 Reverse Engineering | IDA Pro, Ghidra, Radare2, Binary Ninja |
| 📡 Network Sniffers | Wireshark, Fiddler, Charles Proxy, mitmproxy |
| 🎯 Memory Editors | Cheat Engine, ArtMoney, GameGuardian |
| 🪝 Instrumentation | Frida, Xposed, Substrate |
| 📊 Process Monitors | Process Explorer, Process Hacker, API Monitor |

---

## 🧩 Obfuscation Layers

The client uses [obfuscator.io](https://obfuscator.io/) with 5 protection layers:

| Layer | Description | Status | Impact |
|:------|:------------|:------:|:-------|
| 🔤 String Array | 8,676 strings encoded + rotated | ✅ Resolved | Array decoded, but most call sites go through wrappers |
| 🔀 Wrapper Functions | ~6,800 indirection layers via closures | ❌ **Unresolved** | **This is the main blocker.** Wrappers use closure-captured decoder refs that need runtime data. 229 of ~6,800 captured. |
| 💀 Dead Code Injection | Opaque predicates with 5-char tags | ✅ Removed | Standalone evals stripped |
| 🌀 Control Flow Flattening | Switch-dispatch state machines | ❌ Not reversed | webcrack handles some simple cases |
| 🔒 RC4 String Encoding | Applied to D1EL launcher strings | ✅ Resolved | Via webcrack |

### Why Wrappers Are the Hard Problem

```javascript
// The string array is decoded:
["addEventListener", "createElement", "appendChild", "prototype", ...]  // 8,676 entries

// Direct calls to the decoder ARE resolved:
a0_0x2c3b(0x1a4)  →  "addEventListener"  ✅

// But 99% of calls go through wrappers like this:
function _0x3a2b1c(a, b, c, d, e) {
    return ctx_42(a, c - 113, d);  // ctx_42 = closure-captured decoder
}
// ctx_42 is bound at runtime when the function is created inside a closure.
// Without knowing what ctx_42 points to, we can't resolve the string.
```

This is why `crypto.js` contains `_0x2fc62a(865, ctx_334[_0x3a2a3a], 3043, ...)` instead of `CryptoJS.AES.encrypt(...)`.

---

## ⚙️ How It Works

### V8 Bytecode Disassembly

Dofus Retro's `main.jsc` is a V8 8.7 compiled bytecode cache (produced by [bytenode](https://github.com/nicedoc/bytenode)). No existing tool supports V8 8.7 decompilation, so we built our own:

1. Compile V8 8.7.220.31 from source inside Docker
2. Patch `code-serializer.cc` — bypass version, source, flags, and checksum checks (4 patches)
3. Inject bytecode printing after deserialization
4. The patched V8 deserializes the `.jsc` and dumps every function's Ignition bytecode

### Custom Decompiler (`v8decompiler.py`)

A full Ignition bytecode-to-JavaScript decompiler with streaming architecture:

```
ignition_disasm.txt (115 MB)
        │
        ▼
  ┌─────────────┐
  │   Parser     │  Streaming: 1 function at a time (~50 MB peak RAM)
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ CFG Builder  │  Basic blocks, loop headers, try/catch regions
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │  SymExec     │  Accumulator + register state → JS expressions
  └──────┬──────┘
         ▼
  ┌─────────────┐
  │ Categorizer  │  Tags: crypto, network, auth, electron, zaap, game
  └──────┬──────┘
         ▼
  decompiled.js + index.json + category files
```

**Opcode coverage:** all 155+ V8 8.7 Ignition opcodes — loads, stores, calls, jumps, closures, generators, async, for-in/of, destructuring, spread, try/catch.

**Babel validation:** 84% pass rate (7,238 / 8,611 functions syntactically valid).

### Cytrus CDN Downloader

Ankama distributes game files via **Cytrus v6**, a custom CDN using FlatBuffers manifests:

```
1. GET cytrus.cdn.ankama.com/cytrus.json           → game versions
2. GET cytrus.cdn.ankama.com/{game}/.../manifest    → FlatBuffers binary manifest
3. GET cytrus.cdn.ankama.com/{game}/bundles/{hash}  → content-addressed bundles
```

We reverse-engineered the FlatBuffers manifest schema (no public documentation exists) and wrote a minimal parser that reconstructs files from content-addressed bundle chunks with SHA-1 verification.

---

## 🛠️ Tools Evaluated

| Tool | V8 Support | Result | Notes |
|:-----|:-----------|:------:|:------|
| **v8dasm** | Any (compile from source) | ✅ Used | Core of our pipeline |
| **webcrack** | JS source | ✅ Used | Excellent for obfuscator.io (D1EL) |
| **JPEXS FFDec** | SWF/AS2 | ✅ Used | For `loader.swf` (separate tool) |
| **Ghidra** (custom SLEIGH) | V8 8.7 ✅ | ✅ Built | Custom processor — see below |
| Ghidra_NodeJS (PositiveTechnologies) | V8 ≤ 8.6 | ❌ Failed | Abandoned 2021, no 8.7 support |
| View8 (suleram) | V8 ≥ 9.4 | ❌ Failed | Too new for 8.7 |
| jsc2js (xqy2006) | V8 14.x only | ❌ Failed | Wrong version entirely |
| jscdecompiler.com | Electron 17+ | ❌ Failed | Too new for Electron 11 |
| obfuscator-io-deobfuscator (ben-sb) | JS source | ⚠️ Partial | Works on D1EL, crashes on 13 MB output |

---

## 🔭 Unexplored Avenues & Future Potential

The main unsolved problem is **wrapper resolution** — the ~6,800 closure-based string decoder wrappers that make `main.jsc` output unreadable. These approaches could crack it:

### 🟢 High Potential — Would Unlock Readable main.jsc

| Approach | What It Would Solve | Difficulty | Current Status |
|:---------|:--------------------|:----------:|:---------------|
| **Runtime Electron Hook** | Resolve ALL 6,800 wrappers by intercepting live closure contexts | 🟡 Medium | Preloader hook exists, captures 229/6,800 indices. Needs `DYLD_INSERT_LIBRARIES` injection — not shipped. |
| **Symbolic Execution of Wrappers** | Resolve wrappers statically by emulating closure scope chains | 🔴 Hard | Each wrapper uses `ctx_N` referencing a captured decoder + argument transform. Need to trace scope creation across 8,611 functions. |
| **Ghidra + Custom SLEIGH (full analysis)** | Cross-references, call graphs, data flow on V8 bytecode | 🟡 Medium | SLEIGH processor built (`V8:LE:32:8.7`), import scripts exist. Not automated into pipeline. |
| **Control Flow Unflattening** | Restore original code structure from switch-dispatch | 🔴 Hard | Well-studied problem, obfuscator.io has edge cases |

### 🟡 Medium Potential

| Approach | What It Could Unlock | Difficulty | Notes |
|:---------|:---------------------|:----------:|:------|
| **Ghidra P-code Decompiler** | Ghidra's native decompiler on V8 bytecode — might handle wrappers better | 🔴 Hard | Requires mapping 155+ opcodes to P-code |
| **Frida Instrumentation** | Hook V8 runtime to trace execution live | 🟡 Medium | Powerful but Shield detects Frida |
| **Differential Analysis** | Compare bytecode across client versions | 🟢 Easy | Pipeline versions output — just needs diff tooling |
| **SWF Protocol Extraction** | Auto-extract packet builders from `loader.swf` AS2 | 🟡 Medium | JPEXS decompiles it, mapping to protocol needs work |
| **Unicorn Engine Emulation** | Emulate V8 bytecodes in sandbox to resolve wrappers | 🔴 Hard | Avoids running real client |

### 🔵 Research Avenues

| Approach | Notes |
|:---------|:------|
| V8 Snapshot Diffing | Compare constant pools across versions |
| ML-based Deobfuscation | Train on the 229 captured decoder mappings |
| Binary Ninja Plugin | Alternative analysis platform to Ghidra |
| Bytecode Mutation Testing | Patch bytecodes, observe crashes to find live code |

### 🔧 Ghidra Integration (Built But Not Shipped)

We built a complete Ghidra toolchain for V8 8.7 analysis:

| Component | Purpose |
|:----------|:--------|
| `v8_87.slaspec` | Custom SLEIGH processor definition for V8 8.7 Ignition |
| `v8_87.ldefs` / `.pspec` / `.cspec` | Language, processor, and calling convention definitions |
| `ImportV8Binary.java` | Import parsed bytecodes into Ghidra with named functions |
| `annotate_v8_runtime.py` | Annotate runtime calls with symbolic names |
| `deobfuscate_string_array.py` | In-situ string array resolution within Ghidra |
| `deobfuscate_control_flow.py` | In-situ control flow deobfuscation |

```
Workflow:
1. Import main.jsc with processor V8:LE:32:8.7
2. Run ImportV8Binary.java → 8,611 functions created with names
3. Run annotate_v8_runtime.py → runtime call annotations
4. Run deobfuscate_*.py → string/control flow deob passes
5. Use Ghidra's cross-references, call graphs, and data flow
```

> 🔬 This gives full Ghidra analysis capabilities on V8 bytecode — something no public tool provides for V8 8.7. Not included in Docker because it requires a Ghidra installation.

---

## 📈 Results Summary

| Metric | Value |
|:-------|------:|
| Functions decompiled | **8,611** |
| Babel-valid functions | **7,238** (84%) |
| Ignition opcodes handled | **155+** |
| D1EL deobfuscation | **644 KB → 29 KB** ✅ fully readable |
| String array decoded | **8,676 entries** |
| Wrapper calls resolved (main.jsc) | **~229 / ~6,800** ⚠️ (3.4%) |
| Runtime decoder calls captured | **76,947** (229 unique indices) |
| Shield API methods documented | **10/10** |
| IPC channels documented | **34** |
| Flash exports documented | **76** |
| Build time (first run) | **~30 min** (V8 compilation) |

---

## 🔧 Options

```bash
# Force re-download and reprocess
docker run --rm --platform linux/amd64 -v ./output:/output dofus-deob --force

# Use a different platform (darwin, linux, windows)
docker run --rm --platform linux/amd64 -v ./output:/output dofus-deob --platform darwin

# Skip download (use existing raw files)
docker run --rm --platform linux/amd64 -v ./output:/output dofus-deob --skip-download
```

## 🏗️ Building Without Docker

If you already have `v8dasm` compiled for V8 8.7:

```bash
npm install -g webcrack@2
export OUTPUT_DIR=./output
./scripts/deobfuscate.sh --platform darwin
```

## 📁 Project Structure

```
├── Dockerfile                  # Multi-stage build (V8 compiler + runtime)
├── DOCS.md                     # In-depth technical documentation
├── v8dasm/
│   ├── v8dasm.cc               # V8 bytecode disassembler source
│   └── patch_v8.py             # 4 patches for V8 8.7 code-serializer.cc
└── scripts/
    ├── deobfuscate.sh          # Pipeline orchestrator (7 steps)
    ├── v8decompiler.py         # Ignition bytecode → JavaScript decompiler
    ├── clean-js.py             # Babel validation + string array prelude
    ├── resolve-strings.py      # String resolution + annotation + dead code removal
    └── download/
        ├── cytrus.mjs          # Cytrus v6 CDN API client
        ├── download.mjs        # File reconstruction from CDN bundles
        └── manifest.mjs        # FlatBuffers manifest parser (reverse-engineered)
```

## ⚖️ Disclaimer

This tool is provided for **educational and research purposes only**. It is intended to help understand how Electron-based game clients work under the hood. The author does not endorse or encourage any violation of Ankama's Terms of Service. Use responsibly.

## 📄 License

MIT — see [LICENSE](LICENSE)

---

*Built by Luska — research conducted 2026*
