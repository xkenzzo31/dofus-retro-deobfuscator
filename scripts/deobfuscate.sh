#!/bin/bash
# ============================================================================
# deobfuscate.sh — Dofus Retro deobfuscation pipeline
#
# Downloads, disassembles, decompiles, and cleans the Dofus Retro client.
# Designed to run inside the Docker container, where v8dasm and webcrack
# are already available. Can also run standalone with the right tools.
#
# Usage:
#   ./deobfuscate.sh [--force] [--platform PLATFORM] [--skip-download]
#
# Author: Luska
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
FORCE=false
PLATFORM="linux"
SKIP_DOWNLOAD=false

# ── Arguments ───────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)          FORCE=true;          shift ;;
    --skip-download)  SKIP_DOWNLOAD=true;  shift ;;
    --platform)       PLATFORM="$2";       shift 2 ;;
    --output)         OUTPUT_DIR="$2";     shift 2 ;;
    -h|--help)
      cat <<'HELP'
Dofus Retro Deobfuscator — by Luska

Automated pipeline that downloads and deobfuscates the Dofus Retro client.

Steps:
  1. Download main.jsc + D1ElectronLauncher.js from Cytrus CDN
  2. Disassemble V8 8.7 bytecode (v8dasm)
  3. Decompile bytecode to JavaScript (v8decompiler.py)
  4. Post-process: syntax fixes + Babel validation + webcrack
  5. Deobfuscate D1ElectronLauncher.js (webcrack)
  6. Annotate and resolve strings (resolve-strings.py)
  7. Package results as a versioned ZIP

Usage:
  ./deobfuscate.sh [options]

Options:
  --force           Re-download and reprocess even if files exist
  --platform NAME   Target platform: linux (default), darwin, windows
  --skip-download   Skip Cytrus download (use existing raw files)
  --output DIR      Output directory (default: /output)
  -h, --help        Show this help

Prerequisites (in Docker, all are pre-installed):
  node, python3, v8dasm, webcrack
HELP
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Setup ───────────────────────────────────────────────────────────────────

mkdir -p \
  "$OUTPUT_DIR/raw" \
  "$OUTPUT_DIR/jsc_decompiled/v2" \
  "$OUTPUT_DIR/webcrack_d1el"

file_size() {
  if [ -f "$1" ]; then
    ls -lh "$1" | awk '{print $5}'
  else
    echo "-"
  fi
}

echo ""
echo "  ____        __                ____        _     "
echo " |  _ \\  ___ / _|_   _ ___    |  _ \\  ___ | |__  "
echo " | | | |/ _ \\ |_| | | / __|   | | | |/ _ \\| '_ \\ "
echo " | |_| |  __/  _| |_| \\__ \\   | |_| | (_) | |_) |"
echo " |____/ \\___|_|  \\__,_|___/   |____/ \\___/|_.__/ "
echo ""
echo "  Dofus Retro Deobfuscator — by Luska"
echo "  Platform: $PLATFORM"
echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 0: Check prerequisites
# ════════════════════════════════════════════════════════════════════════════

echo "=== [0/7] Prerequisites ==="

check_cmd() { command -v "$1" &>/dev/null; }

check_cmd node    && echo "  ok  Node.js $(node --version)" \
                  || { echo "  FAIL  node not found"; exit 1; }
check_cmd python3 && echo "  ok  Python3 $(python3 --version 2>&1 | head -1)" \
                  || { echo "  FAIL  python3 not found"; exit 1; }
check_cmd v8dasm  && echo "  ok  v8dasm" \
                  || { echo "  FAIL  v8dasm not found (run inside Docker)"; exit 1; }

WEBCRACK_CMD=""
if check_cmd webcrack; then
  WEBCRACK_CMD="webcrack"
  echo "  ok  webcrack"
elif npx webcrack --version &>/dev/null 2>&1; then
  WEBCRACK_CMD="npx webcrack"
  echo "  ok  webcrack (via npx)"
else
  echo "  warn  webcrack not found — steps 4c and 5 will be skipped"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 1: Download from Cytrus CDN
# ════════════════════════════════════════════════════════════════════════════

echo "=== [1/7] Download from Cytrus CDN ==="

CURRENT_VERSION="unknown"
if [ "$SKIP_DOWNLOAD" = false ]; then
  CURRENT_VERSION=$(curl -s "https://cytrus.cdn.ankama.com/cytrus.json" | \
    node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8')); \
    console.log(d.games?.retro?.platforms?.${PLATFORM}?.main || 'unknown')" 2>/dev/null \
    || echo "unknown")

  echo "  Current version: $CURRENT_VERSION"

  if [ -f "$OUTPUT_DIR/.version" ] && [ "$FORCE" = false ]; then
    STORED_VERSION=$(head -1 "$OUTPUT_DIR/.version")
    if [ "$CURRENT_VERSION" = "$STORED_VERSION" ]; then
      echo "  Already up to date ($STORED_VERSION) — use --force to re-download"
    fi
  fi

  download_file() {
    local file_name="$1"
    local output_name="$2"
    if [ -f "$OUTPUT_DIR/raw/$output_name" ] && [ "$FORCE" = false ]; then
      echo "  $output_name already present (skip)"
      return
    fi
    echo "  Downloading $file_name..."
    node "$SCRIPT_DIR/download/download.mjs" \
      --game retro --platform "$PLATFORM" \
      --file "$file_name" --output "$OUTPUT_DIR/raw" 2>&1 | tail -1 || true
    local base
    base=$(basename "$file_name")
    if [ "$base" != "$output_name" ] && [ -f "$OUTPUT_DIR/raw/$base" ]; then
      mv "$OUTPUT_DIR/raw/$base" "$OUTPUT_DIR/raw/$output_name"
    fi
  }

  download_file "main.jsc"              "main.jsc"
  download_file "D1ElectronLauncher.js" "D1ElectronLauncher.js"
else
  echo "  Skipped (--skip-download)"
  if [ -f "$OUTPUT_DIR/.version" ]; then
    CURRENT_VERSION=$(head -1 "$OUTPUT_DIR/.version")
  fi
fi

echo "  main.jsc              : $(file_size "$OUTPUT_DIR/raw/main.jsc")"
echo "  D1ElectronLauncher.js : $(file_size "$OUTPUT_DIR/raw/D1ElectronLauncher.js")"
echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 2: Disassemble V8 bytecode
# ════════════════════════════════════════════════════════════════════════════

echo "=== [2/7] V8 bytecode disassembly ==="

DISASM="$OUTPUT_DIR/jsc_decompiled/ignition_disasm.txt"

if [ -f "$DISASM" ] && [ "$FORCE" = false ]; then
  FUNC_COUNT=$(grep -c "^=== Function:" "$DISASM" 2>/dev/null || echo "0")
  echo "  Already present ($FUNC_COUNT functions)"
elif [ -f "$OUTPUT_DIR/raw/main.jsc" ]; then
  echo "  Running v8dasm..."
  v8dasm "$OUTPUT_DIR/raw/main.jsc" > "$DISASM" 2>"$OUTPUT_DIR/jsc_decompiled/v8dasm_stderr.txt"
  FUNC_COUNT=$(grep -c "^=== Function:" "$DISASM" 2>/dev/null || echo "0")
  echo "  $FUNC_COUNT functions disassembled ($(file_size "$DISASM"))"
else
  echo "  SKIP: main.jsc not found"
  FUNC_COUNT=0
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 3: Decompile bytecode -> JavaScript
# ════════════════════════════════════════════════════════════════════════════

echo "=== [3/7] Decompile bytecode -> JavaScript ==="

if [ -f "$DISASM" ]; then
  python3 "$SCRIPT_DIR/v8decompiler.py" "$DISASM" "$OUTPUT_DIR/jsc_decompiled/v2/"
  echo "  decompiled.js : $(file_size "$OUTPUT_DIR/jsc_decompiled/v2/decompiled.js")"
  echo "  index.json    : $(file_size "$OUTPUT_DIR/jsc_decompiled/v2/index.json")"
else
  echo "  SKIP: no disassembly output"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 4: Post-processing (syntax fix + Babel + webcrack)
# ════════════════════════════════════════════════════════════════════════════

echo "=== [4/7] Post-processing ==="

DECOMPILED="$OUTPUT_DIR/jsc_decompiled/v2/decompiled.js"

if [ -f "$DECOMPILED" ]; then
  # 4a. Inline syntax fixes
  echo "  Syntax corrections..."
  python3 -c "
import re
text = open('$DECOMPILED').read()
text = re.sub(r'\b(t\d+)\.\1\[', r'\1[', text)
text = re.sub(r'\b(t\d+)\.\1\.', r'\1.', text)
text = re.sub(r'\b(ctx_\d+)\.\1\b', r'\1', text)
text = text.replace('/* abort */;', 'void 0;').replace('/* unreachable */;', 'void 0;')
text = re.sub(r'/\* [^*]+ \*/', '0', text)
text = re.sub(r'\(\.\.\.\)', '()', text)
text = re.sub(r'\(\.\.\.spread\)', '()', text)
text = re.sub(r'\{\}\[', '_obj_[', text)
text = re.sub(r'\{\}\.', '_obj_.', text)
text = re.sub(r'\.new\s+', '._new_', text)
text = re.sub(r'\)\s+(\d+);', r', \1);', text)
open('$DECOMPILED', 'w').write(text)
" 2>/dev/null
  echo "  ok"

  # 4b. Babel validation + string array prelude
  echo "  Babel validation (clean-js.py)..."
  python3 "$SCRIPT_DIR/clean-js.py" \
    "$DECOMPILED" \
    "$OUTPUT_DIR/jsc_decompiled/v2/decompiled_valid.js" \
    2>/dev/null
  echo "  decompiled_valid.js : $(file_size "$OUTPUT_DIR/jsc_decompiled/v2/decompiled_valid.js")"

  # 4c. webcrack pass
  VALID_JS="$OUTPUT_DIR/jsc_decompiled/v2/decompiled_valid.js"
  if [ -n "$WEBCRACK_CMD" ] && [ -f "$VALID_JS" ]; then
    echo "  Running webcrack..."
    $WEBCRACK_CMD "$VALID_JS" \
      > "$OUTPUT_DIR/jsc_decompiled/v2/decompiled_webcrack.js" 2>/dev/null || true
    echo "  decompiled_webcrack.js : $(file_size "$OUTPUT_DIR/jsc_decompiled/v2/decompiled_webcrack.js")"
  fi
else
  echo "  SKIP: decompiled.js not found"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 5: Deobfuscate D1ElectronLauncher.js
# ════════════════════════════════════════════════════════════════════════════

echo "=== [5/7] D1ElectronLauncher.js deobfuscation ==="

D1EL="$OUTPUT_DIR/raw/D1ElectronLauncher.js"
if [ -n "$WEBCRACK_CMD" ] && [ -f "$D1EL" ]; then
  $WEBCRACK_CMD "$D1EL" > "$OUTPUT_DIR/webcrack_d1el/D1EL_clean.js" 2>/dev/null || true
  echo "  D1EL_clean.js : $(file_size "$OUTPUT_DIR/webcrack_d1el/D1EL_clean.js")"
else
  echo "  SKIP: D1ElectronLauncher.js not found or webcrack unavailable"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 6: Annotate and resolve strings
# ════════════════════════════════════════════════════════════════════════════

echo "=== [6/7] String resolution and annotation ==="

WEBCRACK_JS="$OUTPUT_DIR/jsc_decompiled/v2/decompiled_webcrack.js"
READABLE_JS="$OUTPUT_DIR/jsc_decompiled/v2/decompiled_readable.js"
RUNTIME_LOG="$OUTPUT_DIR/jsc_decompiled/decoder_log_runtime.json"

if [ -f "$WEBCRACK_JS" ]; then
  RESOLVE_ARGS=("$WEBCRACK_JS" "$READABLE_JS")
  if [ -f "$RUNTIME_LOG" ]; then
    echo "  Runtime log found"
    RESOLVE_ARGS+=("$RUNTIME_LOG")
  fi
  python3 "$SCRIPT_DIR/resolve-strings.py" "${RESOLVE_ARGS[@]}" 2>/dev/null || true
  echo "  decompiled_readable.js : $(file_size "$READABLE_JS")"
else
  echo "  SKIP: no webcrack output"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 7: Package
# ════════════════════════════════════════════════════════════════════════════

echo "=== [7/7] Packaging ==="

echo "$CURRENT_VERSION" > "$OUTPUT_DIR/.version"
date -u +"%Y-%m-%dT%H:%M:%SZ" >> "$OUTPUT_DIR/.version"

ZIP_DATE=$(date +"%Y%m%d")
ZIP_NAME="dofus-retro_${CURRENT_VERSION}_${ZIP_DATE}.zip"
ZIP_PATH="$OUTPUT_DIR/$ZIP_NAME"

cd "$OUTPUT_DIR"
zip -r "$ZIP_PATH" \
  jsc_decompiled/v2/ \
  webcrack_d1el/ \
  raw/D1ElectronLauncher.js \
  .version \
  -x "*.DS_Store" 2>/dev/null || true
cd - >/dev/null

echo "  $ZIP_NAME : $(file_size "$ZIP_PATH")"
echo ""

# ════════════════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════════════════

V2="$OUTPUT_DIR/jsc_decompiled/v2"

echo "========================================================"
echo "  Pipeline complete!"
echo "========================================================"
echo ""
printf "  Version   : %s\n" "$CURRENT_VERSION"
printf "  Functions : %s disassembled\n" "${FUNC_COUNT:-?}"
echo ""
echo "  Output files:"
printf "    raw/main.jsc                    %6s  V8 bytecode\n" "$(file_size "$OUTPUT_DIR/raw/main.jsc")"
printf "    raw/D1ElectronLauncher.js       %6s  launcher (obfuscated)\n" "$(file_size "$D1EL")"
printf "    jsc_decompiled/ignition_disasm  %6s  disassembly\n" "$(file_size "$DISASM")"
printf "    v2/decompiled.js               %6s  decompiled JS\n" "$(file_size "$V2/decompiled.js")"
printf "    v2/decompiled_valid.js         %6s  Babel-valid JS\n" "$(file_size "$V2/decompiled_valid.js")"
printf "    v2/decompiled_webcrack.js      %6s  webcrack output\n" "$(file_size "$V2/decompiled_webcrack.js")"
printf "    v2/decompiled_readable.js      %6s  annotated final\n" "$(file_size "$READABLE_JS")"
printf "    v2/index.json                  %6s  function index\n" "$(file_size "$V2/index.json")"
printf "    webcrack_d1el/D1EL_clean.js    %6s  launcher (clean)\n" "$(file_size "$OUTPUT_DIR/webcrack_d1el/D1EL_clean.js")"
printf "    %s     %6s  archive\n" "$ZIP_NAME" "$(file_size "$ZIP_PATH")"
echo ""
echo "========================================================"
