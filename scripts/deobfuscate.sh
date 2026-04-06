#!/bin/bash
# ============================================================================
# deobfuscate.sh — Dofus Retro deobfuscation pipeline (fully autonomous)
#
# Downloads, disassembles, decompiles, and fully deobfuscates the Dofus Retro
# client from scratch. No pre-captured data needed — everything is derived
# from main.jsc automatically.
#
# Usage:
#   ./deobfuscate.sh [--force] [--platform PLATFORM] [--skip-download]
#
# Author: Luska
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
GHIDRA_DIR="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
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

Fully autonomous pipeline: downloads and deobfuscates the Dofus Retro client
from scratch. No pre-captured data needed.

Steps:
  1.  Download main.jsc + D1ElectronLauncher.js from Cytrus CDN
  2.  Disassemble V8 8.7 bytecode (v8dasm)
  3.  Decode obfuscator.io string array (v8dasm --decode-strings)
  4.  Decompile bytecode to JavaScript (v8decompiler.py)
  5.  Post-process: syntax fixes + Babel validation + webcrack
  6.  Deobfuscate D1ElectronLauncher.js (webcrack)
  7.  Ghidra headless analysis: extract wrapper formulas
  8.  Advanced resolution: closure tracing + formula engine
  9.  Generate comprehensive report
  10. Package results as a versioned ZIP

Usage:
  ./deobfuscate.sh [options]

Options:
  --force           Re-download and reprocess even if files exist
  --platform NAME   Target platform: linux (default), darwin, windows
  --skip-download   Skip Cytrus download (use existing raw files)
  --output DIR      Output directory (default: /output)
  -h, --help        Show this help

Prerequisites (in Docker, all are pre-installed):
  node, python3, v8dasm, webcrack, ghidra (optional)
HELP
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Setup ───────────────────────────────────────────────────────────────────

mkdir -p \
  "$OUTPUT_DIR/raw" \
  "$OUTPUT_DIR/jsc_decompiled/v2" \
  "$OUTPUT_DIR/webcrack_d1el" \
  "$OUTPUT_DIR/resolved" \
  "$OUTPUT_DIR/data"

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
echo "  Mode: Fully autonomous (no pre-captured data)"
echo "  Platform: $PLATFORM"
echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 0: Check prerequisites
# ════════════════════════════════════════════════════════════════════════════

echo "=== [0/10] Prerequisites ==="

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
  echo "  warn  webcrack not found — steps 5c and 6 will be skipped"
fi

HAS_GHIDRA=false
if [ -d "$GHIDRA_DIR" ] && [ -f "$GHIDRA_DIR/support/analyzeHeadless" ]; then
  HAS_GHIDRA=true
  echo "  ok  Ghidra ($GHIDRA_DIR)"
else
  echo "  warn  Ghidra not found — step 7 will be skipped (trace_closures handles it)"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 1: Download from Cytrus CDN
# ════════════════════════════════════════════════════════════════════════════

echo "=== [1/10] Download from Cytrus CDN ==="

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

echo "=== [2/10] V8 bytecode disassembly ==="

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
# STEP 3: Decode obfuscator.io string array
# ════════════════════════════════════════════════════════════════════════════

echo "=== [3/10] Decode string array (v8dasm --decode-strings) ==="

STRING_MAP="$OUTPUT_DIR/data/string_map.json"

if [ -f "$STRING_MAP" ] && [ "$FORCE" = false ]; then
  STRING_COUNT=$(python3 -c "import json; d=json.load(open('$STRING_MAP')); print(len(d.get('mappings',{})))" 2>/dev/null || echo "0")
  echo "  Already present ($STRING_COUNT strings)"
elif [ -f "$OUTPUT_DIR/raw/main.jsc" ]; then
  echo "  Executing script in V8 sandbox to decode strings..."
  v8dasm "$OUTPUT_DIR/raw/main.jsc" --decode-strings > "$STRING_MAP" 2>"$OUTPUT_DIR/data/decode_stderr.txt"
  STRING_COUNT=$(python3 -c "import json; d=json.load(open('$STRING_MAP')); print(len(d.get('mappings',{})))" 2>/dev/null || echo "0")
  echo "  $STRING_COUNT strings decoded"
  cat "$OUTPUT_DIR/data/decode_stderr.txt" | head -5 | sed 's/^/  /'
else
  echo "  SKIP: main.jsc not found"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 4: Decompile bytecode -> JavaScript
# ════════════════════════════════════════════════════════════════════════════

echo "=== [4/10] Decompile bytecode -> JavaScript ==="

if [ -f "$DISASM" ]; then
  python3 "$SCRIPT_DIR/v8decompiler.py" "$DISASM" "$OUTPUT_DIR/jsc_decompiled/v2/"
  echo "  decompiled.js : $(file_size "$OUTPUT_DIR/jsc_decompiled/v2/decompiled.js")"
  echo "  index.json    : $(file_size "$OUTPUT_DIR/jsc_decompiled/v2/index.json")"
else
  echo "  SKIP: no disassembly output"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 5: Post-processing (syntax fix + Babel + webcrack)
# ════════════════════════════════════════════════════════════════════════════

echo "=== [5/10] Post-processing ==="

DECOMPILED="$OUTPUT_DIR/jsc_decompiled/v2/decompiled.js"

if [ -f "$DECOMPILED" ]; then
  # 5a. Inline syntax fixes
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

  # 5b. Babel validation + string array prelude
  echo "  Babel validation (clean-js.py)..."
  python3 "$SCRIPT_DIR/clean-js.py" \
    "$DECOMPILED" \
    "$OUTPUT_DIR/jsc_decompiled/v2/decompiled_valid.js" \
    2>/dev/null
  echo "  decompiled_valid.js : $(file_size "$OUTPUT_DIR/jsc_decompiled/v2/decompiled_valid.js")"

  # 5c. webcrack pass
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
# STEP 6: Deobfuscate D1ElectronLauncher.js
# ════════════════════════════════════════════════════════════════════════════

echo "=== [6/10] D1ElectronLauncher.js deobfuscation ==="

D1EL="$OUTPUT_DIR/raw/D1ElectronLauncher.js"
if [ -n "$WEBCRACK_CMD" ] && [ -f "$D1EL" ]; then
  $WEBCRACK_CMD "$D1EL" > "$OUTPUT_DIR/webcrack_d1el/D1EL_clean.js" 2>/dev/null || true
  echo "  D1EL_clean.js : $(file_size "$OUTPUT_DIR/webcrack_d1el/D1EL_clean.js")"
else
  echo "  SKIP: D1ElectronLauncher.js not found or webcrack unavailable"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 7: Ghidra headless analysis (extract wrapper formulas)
# ════════════════════════════════════════════════════════════════════════════

echo "=== [7/10] Ghidra headless analysis ==="

GHIDRA_FORMULAS="$OUTPUT_DIR/data/ghidra_wrapper_formulas.json"

if [ "$HAS_GHIDRA" = true ] && [ -f "$OUTPUT_DIR/raw/main.jsc" ]; then
  echo "  Running Ghidra headless analysis..."
  GHIDRA_PROJECT="/tmp/ghidra_project"
  rm -rf "$GHIDRA_PROJECT"
  mkdir -p "$GHIDRA_PROJECT"

  "$GHIDRA_DIR/support/analyzeHeadless" \
    "$GHIDRA_PROJECT" DofusRetro \
    -import "$OUTPUT_DIR/raw/main.jsc" \
    -processor "V8:LE:32:8.7" \
    -scriptPath /app/ghidra_scripts \
    -postScript ExportWrapperFormulas.java "$OUTPUT_DIR/data" \
    -deleteProject \
    2>&1 | grep -E "INFO|WARN|ERROR|formulas|export" | head -20 | sed 's/^/  /' || true

  if [ -f "$GHIDRA_FORMULAS" ]; then
    FORMULA_COUNT=$(python3 -c "import json; d=json.load(open('$GHIDRA_FORMULAS')); print(len(d.get('wrappers',[])))" 2>/dev/null || echo "0")
    echo "  Extracted $FORMULA_COUNT wrapper formulas"
  else
    echo "  warn: formula export not found (trace_closures will handle it)"
  fi

  rm -rf "$GHIDRA_PROJECT"
else
  echo "  SKIP: Ghidra not available (trace_closures will compute formulas from code)"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 8: Advanced resolution (closure tracing + formula engine)
# ════════════════════════════════════════════════════════════════════════════

echo "=== [8/10] Advanced wrapper resolution ==="

RESOLVED_DIR="$OUTPUT_DIR/resolved"

if [ -f "$OUTPUT_DIR/jsc_decompiled/v2/decompiled.js" ] && [ -f "$STRING_MAP" ]; then
  echo "  Running apply_all_resolutions.py..."
  echo "  (closure tracing + cross-reference + iterative deduction)"

  RESOLVE_ARGS=(
    --input "$OUTPUT_DIR/jsc_decompiled/v2/decompiled.js"
    --index "$OUTPUT_DIR/jsc_decompiled/v2/index.json"
    --string-map "$STRING_MAP"
    --output-dir "$RESOLVED_DIR"
  )

  # Add Ghidra formulas if available
  if [ -f "$GHIDRA_FORMULAS" ]; then
    RESOLVE_ARGS+=(--ghidra-formulas "$GHIDRA_FORMULAS")
  fi

  python3 "$SCRIPT_DIR/apply_all_resolutions.py" "${RESOLVE_ARGS[@]}" \
    2>&1 | while IFS= read -r line; do echo "  $line"; done || true

  echo ""
  echo "  Output files:"
  for f in "$RESOLVED_DIR"/*.js; do
    [ -f "$f" ] && printf "    %-30s %6s\n" "$(basename "$f")" "$(file_size "$f")"
  done
  [ -f "$RESOLVED_DIR/report.json" ] && printf "    %-30s %6s\n" "report.json" "$(file_size "$RESOLVED_DIR/report.json")"
else
  echo "  SKIP: decompiled.js or string_map.json not found"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 9: Generate comprehensive report
# ════════════════════════════════════════════════════════════════════════════

echo "=== [9/10] Comprehensive report ==="

if [ -f "$RESOLVED_DIR/report.json" ]; then
  python3 -c "
import json
r = json.load(open('$RESOLVED_DIR/report.json'))
s = r['summary']
print(f'  Functions:     {s[\"total_functions\"]}')
print(f'  Wrappers:      {s[\"wrapper_definitions\"]}')
print(f'  Business:      {s[\"business_functions\"]}')
print(f'  Formulas:      {s[\"local_formulas_computed\"]} ({s[\"formula_coverage_pct\"]}%)')
print(f'  Resolved:      {s[\"total_call_sites_resolved\"]} call sites')
print(f'  Strings:       {s[\"unique_strings_decoded\"]} unique')
print(f'  Stripped:      {s[\"wrapper_defs_stripped\"]} wrapper defs')
print(f'  Time:          {r[\"elapsed_seconds\"]}s')
" 2>/dev/null || echo "  (report parsing failed)"
else
  echo "  No report available"
fi

echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 10: Package
# ════════════════════════════════════════════════════════════════════════════

echo "=== [10/10] Packaging ==="

echo "$CURRENT_VERSION" > "$OUTPUT_DIR/.version"
date -u +"%Y-%m-%dT%H:%M:%SZ" >> "$OUTPUT_DIR/.version"

ZIP_DATE=$(date +"%Y%m%d")
ZIP_NAME="dofus-retro_${CURRENT_VERSION}_${ZIP_DATE}.zip"
ZIP_PATH="$OUTPUT_DIR/$ZIP_NAME"

cd "$OUTPUT_DIR"
zip -r "$ZIP_PATH" \
  jsc_decompiled/v2/ \
  resolved/ \
  webcrack_d1el/ \
  data/ \
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
echo "  Pipeline complete! (autonomous — no pre-captured data)"
echo "========================================================"
echo ""
printf "  Version   : %s\n" "$CURRENT_VERSION"
printf "  Functions : %s disassembled\n" "${FUNC_COUNT:-?}"
printf "  Strings   : %s decoded\n" "${STRING_COUNT:-?}"
echo ""
echo "  Output files:"
printf "    raw/main.jsc                    %6s  V8 bytecode\n" "$(file_size "$OUTPUT_DIR/raw/main.jsc")"
printf "    raw/D1ElectronLauncher.js       %6s  launcher (obfuscated)\n" "$(file_size "$D1EL")"
printf "    jsc_decompiled/ignition_disasm  %6s  disassembly\n" "$(file_size "$DISASM")"
printf "    data/string_map.json           %6s  decoded strings\n" "$(file_size "$STRING_MAP")"
printf "    v2/decompiled.js               %6s  decompiled JS\n" "$(file_size "$V2/decompiled.js")"
printf "    v2/index.json                  %6s  function index\n" "$(file_size "$V2/index.json")"
printf "    webcrack_d1el/D1EL_clean.js    %6s  launcher (clean)\n" "$(file_size "$OUTPUT_DIR/webcrack_d1el/D1EL_clean.js")"
echo ""
echo "  Resolved output:"
printf "    resolved/all_resolved.js       %6s  fully resolved JS\n" "$(file_size "$RESOLVED_DIR/all_resolved.js")"
printf "    resolved/shield_crypto.js      %6s  crypto functions\n" "$(file_size "$RESOLVED_DIR/shield_crypto.js")"
printf "    resolved/network.js            %6s  network functions\n" "$(file_size "$RESOLVED_DIR/network.js")"
printf "    resolved/auth.js               %6s  auth functions\n" "$(file_size "$RESOLVED_DIR/auth.js")"
printf "    resolved/electron.js           %6s  electron functions\n" "$(file_size "$RESOLVED_DIR/electron.js")"
printf "    resolved/report.json           %6s  resolution report\n" "$(file_size "$RESOLVED_DIR/report.json")"
echo ""
printf "    %s     %6s  archive\n" "$ZIP_NAME" "$(file_size "$ZIP_PATH")"
echo ""
echo "========================================================"
