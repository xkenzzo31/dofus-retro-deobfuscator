#!/usr/bin/env python3
"""
patch_v8.py — Patch V8 8.7 source to enable .jsc bytecode disassembly.

Four patches applied to src/snapshot/code-serializer.cc:
  1. Add #include <iostream> (needed for std::cout)
  2. Bypass version/source/flags sanity checks
  3. Bypass checksum verification
  4. Print all bytecodes after deserialization

Author: Luska
"""
import sys

FILE = 'src/snapshot/code-serializer.cc'

with open(FILE, 'r') as f:
    content = f.read()

print("=== Patching V8 8.7 for bytecode disassembly ===")

# --- Patch 1: Add #include <iostream> ---
include_marker = '#include "src/snapshot/code-serializer.h"'
include_add = '#include <iostream>'
if include_add not in content:
    content = content.replace(include_marker, include_marker + '\n' + include_add)
    print("  [1/4] Added #include <iostream>")
else:
    print("  [1/4] Already present")

# --- Patch 2: Bypass version/source/flags checks ---
old_checks = (
    "  if (version_hash != Version::Hash()) return VERSION_MISMATCH;\n"
    "  if (source_hash != expected_source_hash) return SOURCE_MISMATCH;\n"
    "  if (flags_hash != FlagList::Hash()) return FLAGS_MISMATCH;"
)
new_checks = (
    "  // [patch] Bypass version/source/flags checks for Electron .jsc\n"
    "  (void)version_hash; (void)source_hash; (void)flags_hash;"
)
if old_checks in content:
    content = content.replace(old_checks, new_checks)
    print("  [2/4] Bypassed version/source/flags checks")
elif new_checks in content:
    print("  [2/4] Already patched")
else:
    print("  [2/4] WARNING: could not locate version check code")

# --- Patch 3: Bypass checksum verification ---
old_checksum = '  if (Checksum(ChecksummedContent()) != c) return CHECKSUM_MISMATCH;'
new_checksum = '  // [patch] Bypass checksum verification\n  (void)c;'
if old_checksum in content:
    content = content.replace(old_checksum, new_checksum)
    print("  [3/4] Bypassed checksum verification")
elif new_checksum in content:
    print("  [3/4] Already patched")
else:
    print("  [3/4] WARNING: could not locate checksum code")

# --- Patch 4: Print all bytecodes after deserialization ---
disasm_marker = '    PrintF("[Deserializing from %d bytes took %0.3f ms]\\n", length, ms);\n  }'
disasm_code = """
  // [patch] Enumerate every SharedFunctionInfo and print its bytecode
  {
    Handle<Script> script(Script::cast(result->script()), isolate);
    SharedFunctionInfo::ScriptIterator iter(isolate, *script);
    for (SharedFunctionInfo info = iter.Next(); !info.is_null(); info = iter.Next()) {
      if (info.HasBytecodeArray()) {
        std::cout << "\\n=== Function: ";
        info.Name().ShortPrint(std::cout);
        std::cout << " ===" << std::endl;
        info.GetBytecodeArray().Disassemble(std::cout);
        std::cout << std::flush;
      }
    }
  }
"""
if '[patch] Enumerate every SharedFunctionInfo' not in content:
    if disasm_marker in content:
        content = content.replace(disasm_marker, disasm_marker + '\n' + disasm_code)
        print("  [4/4] Added bytecode printing after deserialization")
    else:
        print("  [4/4] WARNING: could not locate deserialization marker")
else:
    print("  [4/4] Already patched")

with open(FILE, 'w') as f:
    f.write(content)

print("=== All patches applied ===")
