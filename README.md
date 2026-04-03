# Dofus Retro Deobfuscator

Automated deobfuscation pipeline for the **Dofus Retro 1.48** Electron client.

Downloads `main.jsc` and `D1ElectronLauncher.js` from Ankama's Cytrus CDN, disassembles the V8 8.7 bytecode, decompiles it to readable JavaScript, and applies multiple deobfuscation passes.

**One command. Full deobfuscation.**

> For in-depth technical documentation on the client architecture, obfuscation layers, and research findings, see **[DOCS.md](DOCS.md)**.

## Quick Start

```bash
# Build the Docker image (~30 min first time — compiles V8 8.7)
docker build --platform linux/amd64 -t dofus-deob .

# Run the pipeline — outputs to ./output/
docker run --rm --platform linux/amd64 -v ./output:/output dofus-deob
```

That's it. Check `./output/` for the results.

## What It Does

The pipeline runs 7 automated steps:

| Step | What | Tool |
|------|------|------|
| 1 | Download `main.jsc` + `D1ElectronLauncher.js` from Cytrus CDN | Node.js |
| 2 | Disassemble V8 8.7 Ignition bytecode | `v8dasm` (custom patched) |
| 3 | Decompile bytecode to JavaScript (8600+ functions) | `v8decompiler.py` |
| 4 | Post-process: syntax fixes, Babel validation, webcrack | Python + Node.js |
| 5 | Deobfuscate D1ElectronLauncher.js | webcrack |
| 6 | Resolve obfuscated strings + annotate functions | `resolve-strings.py` |
| 7 | Package everything as a versioned ZIP | zip |

### Output Files

```
output/
├── raw/
│   ├── main.jsc                    # Original V8 bytecode
│   └── D1ElectronLauncher.js       # Original launcher (obfuscated)
├── jsc_decompiled/
│   ├── ignition_disasm.txt         # Raw V8 disassembly (~115 MB)
│   └── v2/
│       ├── decompiled.js           # Full decompiled JavaScript
│       ├── decompiled_valid.js     # Babel-validated version
│       ├── decompiled_webcrack.js  # After webcrack pass
│       ├── decompiled_readable.js  # Final annotated version
│       ├── index.json              # Function index with categories
��       ├── crypto.js               # Extracted: crypto functions
│       ├── shield.js               # Extracted: Shield anti-bot
│       ├── network.js              # Extracted: network/socket
│       ├── auth.js                 # Extracted: authentication
│       └── ...                     # Other category files
├── webcrack_d1el/
│   └── D1EL_clean.js              # Deobfuscated launcher
└── dofus-retro_VERSION_DATE.zip   # Everything packaged
```

## Options

```bash
# Force re-download and reprocess
docker run --rm -v ./output:/output dofus-deob --force

# Use a different platform (darwin, linux, windows)
docker run --rm -v ./output:/output dofus-deob --platform darwin

# Skip download (use existing raw files)
docker run --rm -v ./output:/output dofus-deob --skip-download
```

## What Was Accomplished

### Fully Working

- **V8 8.7 bytecode disassembly** via custom-patched V8 build in Docker — bypasses version, flags, and checksum verification
- **Full decompilation** of 8,611 functions from `main.jsc` (12.7 MB bytecode) to readable JavaScript
- **155+ Ignition opcodes** handled (loads, stores, calls, jumps, closures, generators, try/catch, for-in, etc.)
- **D1ElectronLauncher.js** fully deobfuscated: 644 KB obfuscated down to 29 KB clean, readable code
- **Cytrus CDN downloader**: reverse-engineered FlatBuffers manifest parser, downloads latest game files automatically
- **Function categorization**: auto-tags functions as crypto, shield, network, auth, electron, zaap, game
- **84% Babel pass rate**: 7,238 out of 8,611 decompiled functions are syntactically valid JavaScript
- **Runtime string capture**: Electron hook captures 229 unique string decoder indices across 76,947 calls

### Partially Working

- **String resolution**: direct `a0_0x102a()` decoder calls are resolved, but **6,838 wrapper-based calls** using closure slots remain obfuscated (they require runtime data)
- **Dead code removal**: standalone opaque predicate evaluations are stripped, but conditional blocks (where we can't determine true/false statically) are kept
- **Control flow**: try/catch and loops are reconstructed from the CFG, but complex switch-based control flow flattening is not fully reversed

### What Didn't Work (Tools We Tried)

| Tool | Why It Failed |
|------|---------------|
| Ghidra_NodeJS (PositiveTechnologies) | Plugin for Ghidra — max V8 8.6, does NOT support 8.7. Abandoned since 2021 |
| View8 (suleram) | Supports V8 9.4+ only, not 8.7 |
| jsc2js (xqy2006) | All 216 releases target V8 14.x only |
| jscdecompiler.com | Targets Electron 17+, does not handle Electron 11 / V8 8.7 |
| obfuscator-io-deobfuscator (ben-sb) | Works for D1EL but crashes on 13 MB decompiled output |

> **Note**: Ghidra itself works fine for binary analysis. It's the *Ghidra_NodeJS plugin* (for V8 bytecode) that doesn't support our V8 version. We wrote custom Ghidra scripts for string array deobfuscation and control flow analysis that work independently.

### What's Left To Do

- **Complete wrapper resolution**: the ~6,800 obfuscator.io wrapper functions need runtime tracing or symbolic analysis to fully resolve
- **Control flow unflattening**: switch-dispatch patterns from obfuscator.io are not yet reversed
- **Full closure variable tracing**: only crypto/network/game categories have been sampled
- **SWF decompilation integration**: `loader.swf` (4,258 AS2 scripts) is decompiled separately via JPEXS but not included in this pipeline
- **Automated runtime hook**: the Electron preloader hook for live string capture exists but is not shipped in this repo (requires DYLD injection)

## How It Works

### V8 Bytecode Disassembly

Dofus Retro's `main.jsc` is a V8 8.7 compiled bytecode cache (produced by [bytenode](https://github.com/nicedoc/bytenode)). To disassemble it:

1. We compile V8 8.7.220.31 from source inside Docker
2. We patch `code-serializer.cc` to bypass version/checksum checks
3. We inject bytecode printing after deserialization
4. The patched V8 deserializes the `.jsc` and dumps every function's Ignition bytecode

### Decompilation

`v8decompiler.py` is a full Ignition bytecode decompiler:

- **Parser**: Streams v8dasm output one function at a time (never more than 1 function in memory)
- **CFG Builder**: Constructs basic blocks, identifies loops and exception handlers
- **Symbolic Executor**: Translates each opcode to JavaScript expressions with register tracking and temp variable spilling
- **Categorizer**: Tags functions by domain (crypto, network, auth, shield, electron, zaap, game)

Handles all 155+ V8 8.7 Ignition opcodes including generators, async functions, for-in/of, destructuring, and spread.

### Cytrus CDN

Ankama distributes game files via their Cytrus v6 CDN. Our downloader:

1. Fetches `cytrus.json` for the latest version number
2. Downloads the FlatBuffers binary manifest for the target platform
3. Parses the manifest (reverse-engineered schema: fragments, files, bundles, chunks)
4. Reconstructs target files by downloading and reassembling bundle chunks
5. Verifies SHA-1 hash integrity

### Obfuscation Layers

The client uses [obfuscator.io](https://obfuscator.io/) with these protections:

| Layer | Description | Status |
|-------|-------------|--------|
| String array | 8,676 strings encoded + rotated | Resolved |
| Wrapper functions | ~6,800 indirection layers via closures | Partial (runtime needed) |
| Dead code injection | Opaque predicates with random 5-char tags | Removed (standalone evals) |
| Control flow flattening | Switch-dispatch state machines | Not yet reversed |
| RC4 string encoding | Applied to D1EL launcher strings | Resolved (via webcrack) |

### Post-Processing Pipeline

1. **Syntax correction** — fixes decompiler artifacts (`t1.t1[` → `t1[`, `(...)` → `()`, etc.)
2. **Babel validation** — parses each function individually, keeps only valid ones (84% pass rate)
3. **String array prelude** — prepends the decoded 8,676-element string array + decoder functions
4. **webcrack** — resolves remaining obfuscator.io patterns (variable renaming, constant folding)
5. **String resolution** — replaces wrapper calls with resolved strings using runtime decoder log
6. **Function annotation** — adds metadata comments (category, key strings, instruction count)
7. **Dead code removal** — strips standalone opaque predicate evaluation statements

## Project Structure

```
├── Dockerfile              # Multi-stage build (V8 compiler + runtime)
├── DOCS.md                 # In-depth technical documentation
├── v8dasm/
│   ├── v8dasm.cc           # V8 bytecode disassembler source
│   └── patch_v8.py         # 4 patches for V8 8.7 code-serializer.cc
└── scripts/
    ├── deobfuscate.sh      # Pipeline orchestrator (7 steps)
    ├── v8decompiler.py     # Ignition bytecode → JavaScript decompiler
    ├── clean-js.py         # Babel validation + string array prelude
    ├── resolve-strings.py  # String resolution + annotation + dead code removal
    └── download/
        ├── cytrus.mjs      # Cytrus v6 CDN API client
        ├── download.mjs    # File reconstruction from CDN bundles
        └── manifest.mjs    # FlatBuffers manifest parser (reverse-engineered)
```

## Building Without Docker

If you already have `v8dasm` compiled for V8 8.7:

```bash
# Install dependencies
npm install -g webcrack@2

# Make sure v8dasm is in PATH, then:
export OUTPUT_DIR=./output
./scripts/deobfuscate.sh --platform darwin
```

## CI/CD

Docker images are built automatically on push via GitHub Actions (self-hosted runner) and published to:

```
ghcr.io/xkenzzo31/dofus-retro-deobfuscator:latest
```

## Disclaimer

This tool is provided for **educational and research purposes only**. It is intended to help understand how Electron-based game clients work under the hood. The author does not endorse or encourage any violation of Ankama's Terms of Service. Use responsibly.

## License

MIT — see [LICENSE](LICENSE)

---

*By Luska*
