# Dofus Retro Deobfuscator

**Automated deobfuscation pipeline for the Dofus Retro 1.48 Electron client.**

Downloads, disassembles, decompiles, and **fully deobfuscates** the entire client — from raw V8 8.7 bytecode to readable, categorized JavaScript. Resolves **12,816 wrapper calls** using closure chain tracing, brute-force analysis, and Ghidra-extracted formulas. One command.

> For deep technical documentation (bytecode internals, crypto analysis, protocol details), see **[DOCS.md](DOCS.md)**.

---

## Quick Start

```bash
# Build the Docker image (~30 min first time — compiles V8 8.7 from source)
docker build --platform linux/amd64 -t dofus-deob .

# Run the pipeline — outputs to ./output/
docker run --rm --platform linux/amd64 -v ./output:/output dofus-deob
```

That's it. Everything lands in `./output/`.

---

## Client Architecture

Dofus Retro 1.48 is an **Electron 11.5.0** desktop application with a multi-layer architecture:

```
+-------------------------------------------------------------+
|  Main Process (main.jsc)                                    |
|  +-- Shield security module (AES-256-CBC, fingerprint)      |
|  +-- Zaap/Thrift RPC client                                 |
|  +-- CryptoJS (121 functions)                               |
|  +-- systeminformation v5.16.6 (~1,200 functions)           |
|  +-- obfuscator.io wrappers (~6,800 functions)              |
+----------------------+--------------------------------------+
|  34 IPC channels     |                                      |
+----------------------+                                      |
|  Renderer Process (D1ElectronLauncher.js)                   |
|  +-- 76 exports to Flash via ExternalInterface              |
|  +-- Packet relay (game <-> main process)                   |
|  +-- Discord RPC integration                                |
|  +-- UI management (login dialog, game window)              |
+----------------------+--------------------------------------+
|  ExternalInterface   |                                      |
+----------------------+                                      |
|  Flash SWF (loader.swf)                                     |
|  +-- 4,258 ActionScript 2 scripts                           |
|  +-- Game rendering, combat, maps, inventory                |
|  +-- Network packet construction                            |
|  +-- 72+ client->server packet types                        |
+-------------------------------------------------------------+
         |
         | TCP/TLS :443
         v
  Dofus Retro Servers
```

### Client Technology Stack

| Component | Version | Role |
|:----------|:--------|:-----|
| Electron | 11.5.0 | Desktop shell |
| Node.js | 12.18.3 | Backend runtime |
| V8 | 8.7.220.31-electron.0 | JavaScript engine |
| Chromium | 87.0.4280.141 | Renderer |
| bytenode | 1.3.7 | `.jsc` bytecode compiler |
| Flash (Pepper) | Embedded | Game rendering (SWF) |

---

## What We Extract

### Deobfuscation Results

| Target | Size | Protection | Result |
|:-------|:-----|:-----------|:-------|
| `D1ElectronLauncher.js` | 644 KB | obfuscator.io (RC4) | **Fully clean** — 29 KB readable JS |
| `main.jsc` | 12.7 MB | V8 bytecode + obfuscator.io | **12,816 wrapper calls resolved** — readable categorized JS |
| `loader.swf` | 3.3 MB | Hex-mangled class names | Decompiled (via JPEXS, separate tool) |

### What Changed: Before vs After

The previous pipeline resolved only **229 of ~6,800 wrappers** (3.4%). The new unified resolution pipeline combines 4 strategies to achieve **12,816 resolved call sites**:

| Resolution Strategy | Call Sites Resolved | How It Works |
|:-------------------|--------------------:|:-------------|
| Closure chain tracing | ~9,000+ | Traces ctx_N scope chains across 8,611 functions, iteratively deduces wrapper formulas |
| Brute-force capture | ~2,500+ | 77,107 results from 5 scope[0] wrappers captured at runtime |
| Ghidra formula extraction | ~1,000+ | 236 simple + 186 context-dependent formulas from static bytecode analysis |
| Cross-reference inference | ~300+ | Deduces unknown wrapper formulas by analyzing literal call sites across the codebase |

### What the output looks like now

```javascript
// BEFORE (old pipeline — wrapper calls everywhere):
_0x2fc62a(865, ctx_334[_0x3a2a3a], 3043, ctx_334[_0x450905], ctx_334[_0x50a1b0]);
_0x22a54d(ctx_334[_0x437fe0], 4963, 5075, ctx_334[_0x316c8d], 8193);

// AFTER (new pipeline — readable strings):
var hash = 'SHA256'
var encrypted = CryptoJS['AES']['encrypt'](data, key, { 'iv': iv, 'mode': 'CBC' });
```

### main.jsc Composition (8,611 functions)

```
 79.0%  obfuscator.io wrappers  (~6,800)  <- resolved and stripped
 14.0%  systeminformation       (~1,200)  <- fingerprinting lib
  1.4%  CryptoJS                (121)     <- AES, SHA, HMAC
  1.0%  Shield business logic   (~90)     <- the real target
  0.4%  Electron lifecycle      (33)
  0.2%  Network/socket          (18)
  4.0%  Other/uncategorized     (~350)
```

### Category Files

The pipeline auto-categorizes functions and produces domain-specific files:

| Category | File | Content |
|:---------|:-----|:--------|
| Crypto | `shield_crypto.js` | CryptoJS functions with resolved method names and constants |
| Network | `network.js` | Socket/HTTP functions with readable string references |
| Auth | `auth.js` | Authentication logic with token/session handling |
| Electron | `electron.js` | App lifecycle, BrowserWindow, IPC setup |
| Game | `game.js` | Game logic functions |
| Zaap | `zaap.js` | Launcher/updater Thrift RPC |
| Other | `business_logic.js` | Uncategorized functions |

---

## Pipeline Steps

| Step | What | Tool | Output |
|:----:|:-----|:-----|:-------|
| 1 | Download `main.jsc` + `D1ElectronLauncher.js` from Cytrus CDN | Node.js | Raw client files |
| 2 | Disassemble V8 8.7 Ignition bytecode | `v8dasm` (custom patched) | ~115 MB disassembly |
| 3 | Decompile bytecode to JavaScript (8,611 functions) | `v8decompiler.py` | 13 MB decompiled JS |
| 4 | Post-process: syntax fixes, Babel validation, webcrack | Python + Node.js | 2.3 MB validated JS |
| 5 | Deobfuscate D1ElectronLauncher.js | webcrack | 29 KB clean, readable code |
| 6 | Annotate + categorize functions, basic string resolution | `resolve-strings.py` | Category tags + annotations |
| 7 | **Advanced resolution: closure tracing + brute-force + Ghidra** | `apply_all_resolutions.py` | **12,816 resolved calls, categorized JS** |
| 8 | Package everything as a versioned ZIP | zip | Release-ready archive |

### Output Structure

```
output/
+-- raw/
|   +-- main.jsc                       # 12.7 MB  -- Original V8 bytecode
|   +-- D1ElectronLauncher.js          # 644 KB   -- Original launcher (obfuscated)
+-- jsc_decompiled/
|   +-- ignition_disasm.txt            # 115 MB   -- Raw V8 disassembly
|   +-- v2/
|       +-- decompiled.js              # 13 MB    -- Full decompiled JavaScript
|       +-- decompiled_valid.js        # 2.3 MB   -- Babel-validated
|       +-- decompiled_webcrack.js     # 2.3 MB   -- After webcrack pass
|       +-- decompiled_readable.js     # 2.3 MB   -- Basic annotated version
|       +-- index.json                 # 788 KB   -- Function index with categories
+-- resolved/                          # *** NEW: Advanced resolution output ***
|   +-- all_resolved.js                # Fully resolved JavaScript
|   +-- shield_crypto.js               # Crypto functions (readable)
|   +-- network.js                     # Network functions (readable)
|   +-- auth.js                        # Authentication functions
|   +-- electron.js                    # Electron lifecycle
|   +-- zaap.js                        # Zaap/Thrift RPC
|   +-- game.js                        # Game logic
|   +-- business_logic.js              # Uncategorized
|   +-- report.json                    # Resolution statistics
+-- webcrack_d1el/
|   +-- D1EL_clean.js                  # 29 KB    -- Fully deobfuscated launcher
+-- dofus-retro_VERSION_DATE.zip       # Everything packaged
```

---

## Resolution Pipeline — How It Works

The advanced resolution (step 7) combines static analysis with pre-captured runtime data:

```
decompiled.js (13 MB, 8,611 functions)
        |
        v
+-------------------+     +-------------------------+
| trace_closures    |     | Pre-captured data       |
| (dynamic analysis |     | (from Ghidra + runtime) |
| of decompiled.js) |     |                         |
|                   |     | decoder_log_full.json   |
| - Parse wrappers  |     |   8,641 decoded strings |
| - Group by scope  |     |                         |
| - Deduce formulas |     | wrapper_bruteforce.json |
| - Cross-reference |     |   77,107 BF results     |
| - Brute-force     |     |                         |
+--------+----------+     | v8_wrapper_formulas.json|
         |                 |   236 Ghidra formulas   |
         v                 |                         |
  1,823+ local formulas    | ghidra_context_res.json |
         |                 |   186 ctx-dep formulas  |
         +--------+--------+                         |
                  |        +-------------------------+
                  v
        ResolutionEngine
        (4-level priority)
                  |
                  v
        12,816 resolved calls
                  |
    +-------------+-------------+
    |             |             |
    v             v             v
Strip wrappers  Strip opaque  Categorize
(6,800 defs)    predicates    by domain
    |             |             |
    +-------------+-------------+
                  |
                  v
        Per-category JS files
        + resolution report
```

### Pre-Captured Data

The `data/` directory contains analysis results from Ghidra static analysis and runtime captures. These are **version-specific** to the current Dofus Retro client:

| File | Content | How It Was Captured |
|:-----|:--------|:-------------------|
| `decoder_log_full.json` | 8,641 decoded string array entries | V8 Inspector scope crawling during gameplay |
| `wrapper_bruteforce.json` | 77,107 wrapper results (5 scope[0] wrappers) | Runtime brute-force of all argument values |
| `v8_wrapper_formulas.json` | 236 simple wrapper formulas | Ghidra bytecode analysis of constant pool |
| `ghidra_context_resolutions.json` | 186 context-dependent formulas | Ghidra LdaSmi/StaContextSlot analysis |
| `security_api_calls.json` | 639 Shield API calls | Passive capture during real gameplay |

---

## Shield Security Module

Shield is the anti-cheat/anti-bot module embedded inside `main.jsc`.

### API Surface (10 methods)

| Method | Purpose |
|:-------|:--------|
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

### Packet Signing Flow

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

### Hardware Fingerprinting

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

### Anti-Cheat Process Scanning

Every ~30 seconds, Shield scans for:

| Category | Tools Detected |
|:---------|:---------------|
| Debuggers | x64dbg, OllyDbg, WinDbg, gdb, lldb |
| Reverse Engineering | IDA Pro, Ghidra, Radare2, Binary Ninja |
| Network Sniffers | Wireshark, Fiddler, Charles Proxy, mitmproxy |
| Memory Editors | Cheat Engine, ArtMoney, GameGuardian |
| Instrumentation | Frida, Xposed, Substrate |
| Process Monitors | Process Explorer, Process Hacker, API Monitor |

---

## Results Summary

| Metric | Value |
|:-------|------:|
| Functions decompiled | **8,611** |
| Babel-valid functions | **7,238** (84%) |
| Ignition opcodes handled | **155+** |
| D1EL deobfuscation | **644 KB -> 29 KB** (fully readable) |
| String array decoded | **8,641 / 8,676** (99.6%) |
| **Wrapper calls resolved (main.jsc)** | **12,816** |
| Local formulas computed | **1,823+** |
| BF wrapper results | **77,107** |
| Shield API methods documented | **10/10** |
| IPC channels documented | **34** |
| Flash exports documented | **76** |
| Build time (first run) | **~30 min** (V8 compilation) |

---

## Options

```bash
# Force re-download and reprocess
docker run --rm --platform linux/amd64 -v ./output:/output dofus-deob --force

# Use a different platform (darwin, linux, windows)
docker run --rm --platform linux/amd64 -v ./output:/output dofus-deob --platform darwin

# Skip download (use existing raw files)
docker run --rm --platform linux/amd64 -v ./output:/output dofus-deob --skip-download
```

## Building Without Docker

If you already have `v8dasm` compiled for V8 8.7:

```bash
npm install -g webcrack@2
export OUTPUT_DIR=./output
export DATA_DIR=./data
./scripts/deobfuscate.sh --platform darwin
```

## Project Structure

```
+-- Dockerfile                  # Multi-stage build (V8 compiler + runtime)
+-- DOCS.md                     # In-depth technical documentation
+-- data/                       # Pre-captured resolution data
|   +-- decoder_log_full.json   #   8,641 decoded strings (V8 Inspector capture)
|   +-- wrapper_bruteforce.json #   77,107 brute-force results
|   +-- v8_wrapper_formulas.json#   236 Ghidra-extracted formulas
|   +-- ghidra_context_resolutions.json  # Context-dependent formulas
|   +-- security_api_calls.json #   639 Shield API calls
+-- v8dasm/
|   +-- v8dasm.cc               # V8 bytecode disassembler source
|   +-- patch_v8.py             # 4 patches for V8 8.7 code-serializer.cc
+-- scripts/
    +-- deobfuscate.sh          # Pipeline orchestrator (8 steps)
    +-- v8decompiler.py         # Ignition bytecode -> JavaScript decompiler
    +-- clean-js.py             # Babel validation + string array prelude
    +-- resolve-strings.py      # Basic string resolution + annotation
    +-- trace_closures.py       # Closure chain formula engine
    +-- apply_all_resolutions.py# Advanced unified resolution (step 7)
    +-- download/
        +-- cytrus.mjs          # Cytrus v6 CDN API client
        +-- download.mjs        # File reconstruction from CDN bundles
        +-- manifest.mjs        # FlatBuffers manifest parser (reverse-engineered)
```

## Disclaimer

This tool is provided for **educational and research purposes only**. It is intended to help understand how Electron-based game clients work under the hood. The author does not endorse or encourage any violation of Ankama's Terms of Service. Use responsibly.

## License

MIT — see [LICENSE](LICENSE)

---

*Built by Luska — research conducted 2026*
