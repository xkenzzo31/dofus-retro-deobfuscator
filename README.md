# Dofus Retro Deobfuscator

Automated deobfuscation pipeline for the Dofus Retro 1.48 Electron client.

Downloads `main.jsc` and `D1ElectronLauncher.js` from Ankama's Cytrus CDN, disassembles the V8 8.7 bytecode, decompiles it to readable JavaScript, and applies multiple deobfuscation passes.

**One command. Full deobfuscation.**

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
| 3 | Decompile bytecode → JavaScript (8600+ functions) | `v8decompiler.py` |
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
│       ├── crypto.js               # Extracted: crypto functions
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

## How It Works

### V8 Bytecode Disassembly

Dofus Retro's `main.jsc` is a V8 8.7 compiled bytecode cache (produced by [bytenode](https://github.com/nicedoc/bytenode)). To disassemble it:

1. We compile V8 8.7.220.31 from source inside Docker
2. We patch `code-serializer.cc` to bypass version/checksum checks
3. We inject bytecode printing after deserialization
4. The patched V8 deserializes the `.jsc` and dumps every function's Ignition bytecode

### Decompilation

`v8decompiler.py` is a full Ignition bytecode decompiler:

- **Parser**: Streams v8dasm output, extracts functions/constants/handlers
- **CFG Builder**: Constructs basic blocks, identifies loops and exception handlers
- **Symbolic Executor**: Translates each opcode to JavaScript expressions
- **Categorizer**: Tags functions by domain (crypto, network, auth, shield, etc.)

Handles all 155+ V8 8.7 Ignition opcodes.

### Deobfuscation

The client uses [obfuscator.io](https://obfuscator.io/) with:
- String array rotation + encoding
- Wrapper functions (indirection layers)
- Dead code injection (opaque predicates)
- Control flow flattening (partial)

Our pipeline:
1. Resolves the string array (8676 elements after rotation)
2. Removes dead code evaluation statements
3. Strips wrapper function definitions
4. Annotates functions with metadata and resolved strings
5. Uses [webcrack](https://github.com/nicedoc/webcrack) for additional cleanup

## Project Structure

```
├── Dockerfile              # Multi-stage build (V8 compiler + runtime)
├── v8dasm/
│   ├── v8dasm.cc           # V8 bytecode disassembler source
│   └── patch_v8.py         # Patches for V8 8.7 code-serializer.cc
└── scripts/
    ├── deobfuscate.sh      # Pipeline orchestrator (7 steps)
    ├── v8decompiler.py     # Ignition bytecode → JavaScript decompiler
    ├── clean-js.py         # Babel validation + string prelude
    ├── resolve-strings.py  # String resolution + annotation
    └── download/
        ├── cytrus.mjs      # Cytrus v6 CDN client
        ├── download.mjs    # File reconstruction from bundles
        └── manifest.mjs    # FlatBuffers manifest parser
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

## Disclaimer

This tool is provided for **educational and research purposes only**. It is intended to help understand how Electron-based game clients work under the hood. The author does not endorse or encourage any violation of Ankama's Terms of Service. Use responsibly.

## License

MIT — see [LICENSE](LICENSE)

---

*By Luska*
