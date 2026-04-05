#!/usr/bin/env python3
"""
apply_all_resolutions.py -- Advanced wrapper resolution for the deobfuscation pipeline.

Combines ALL captured string data sources to produce fully deobfuscated JavaScript:

1. Wrapper brute-force (77K results from 5 scope[0] wrappers via runtime capture)
2. Closure chain formulas (1,823+ local wrapper formulas from trace_closures engine)
3. Base decoder strings (8,641 mappings from a0_0x102a)
4. Security API captures (639 gameplay calls for annotation)

Resolution priority (per call site):
  A. Wrapper BF + local formula -- highest confidence
  B. Direct BF -- scope[0] wrapper called directly with a literal active param
  C. Formula + decoder -- local wrapper formula resolves to a decoder string index
  D. Base decoder -- a0_0x102a(N) direct calls

Output: split per-category JS files + comprehensive report.

Usage:
  python3 apply_all_resolutions.py --input FILE --index FILE --output-dir DIR --data-dir DIR
"""

import argparse
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

# Import trace_closures from same directory
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))
import trace_closures as tc

# Category keywords for function classification
CATEGORY_KEYWORDS = {
    "shield_crypto": [
        "shield", "Shield", "crypto", "Crypto", "hash", "Hash", "sha", "SHA",
        "md5", "MD5", "aes", "AES", "hmac", "HMAC", "encrypt", "decrypt",
        "cipher", "Cipher", "digest", "pbkdf", "WordArray", "CryptoJS",
        "createHash", "createHmac", "fingerprint", "Fingerprint",
        "FingerPrint", "collectHardware", "antiCheat", "AntiCheat",
        "SecurityModule", "securityModule", "PacketsSent", "PacketsReceived",
        "SharedSize", "shieldKey", "ShieldKey",
    ],
    "network": [
        "socket", "Socket", "WebSocket", "websocket", "onPacket", "packet",
        "Packet", "onMessage", "sendMessage", "connect", "disconnect",
        "tcp", "TCP", "http", "HTTP", "https", "HTTPS", "fetch", "XMLHttp",
        "request", "response", "url", "URL", "host", "port",
    ],
    "auth": [
        "login", "Login", "auth", "Auth", "token", "Token", "session",
        "Session", "password", "Password", "credential", "apiKey", "oauth",
        "OAuth", "haapi", "HAAPI", "certif", "certificate",
    ],
    "electron": [
        "electron", "Electron", "BrowserWindow", "ipcMain", "ipcRenderer",
        "remote", "app.get", "app.on", "nativeTheme", "Tray", "Menu",
        "dialog", "shell.open", "webContents", "preload",
    ],
    "zaap": [
        "zaap", "Zaap", "launcher", "Launcher", "updater", "Updater",
        "ankama", "Ankama", "cytrus", "Cytrus",
    ],
    "game": [
        "dofus", "Dofus", "map", "Map", "combat", "Combat", "spell",
        "Spell", "inventory", "character", "Character", "cell", "Cell",
        "pathfind", "movement", "interaction", "npc", "NPC",
    ],
}


def log(msg):
    print(f"[apply_all] {msg}", file=sys.stderr)


# ════════════════════════════════════════════════════════════════════════════
# Data Loading
# ════════════════════════════════════════════════════════════════════════════

def load_wrapper_bruteforce(path):
    """Load brute-force results for scope[0] wrappers."""
    with open(path) as f:
        data = json.load(f)

    wrappers = {}
    for wname, entries in data["wrappers"].items():
        by_prefix = defaultdict(dict)
        for key, value in entries.items():
            prefix, val = key.split("_", 1)
            by_prefix[prefix][int(val)] = value

        active_prefix = None
        active_results = {}
        for prefix in sorted(by_prefix.keys()):
            results = by_prefix[prefix]
            non_junk = sum(1 for v in results.values() if v != "FbJiX")
            if non_junk > len(results) * 0.5:
                active_prefix = prefix
                active_results = {k: v for k, v in results.items() if v != "FbJiX"}
                break

        if active_prefix:
            param_num = int(active_prefix[1:])
            wrappers[wname] = {
                "active_call_position": param_num - 1,
                "active_param_name": f"arg{param_num}",
                "results": active_results,
            }

    return wrappers


def load_security_api_calls(path):
    """Load security API captures for annotation."""
    if not Path(path).exists():
        return []
    with open(path) as f:
        return json.load(f).get("calls", [])


def load_index_json(path):
    """Load function metadata index."""
    if not Path(path).exists():
        return []
    with open(path) as f:
        return json.load(f)


# ════════════════════════════════════════════════════════════════════════════
# Unified Resolution Engine
# ════════════════════════════════════════════════════════════════════════════

def try_parse_literal(expr):
    """Try to parse an expression as a literal integer."""
    expr = expr.strip()
    try:
        if expr.startswith("-(") and expr.endswith(")"):
            return -int(expr[2:-1]), True
        if expr.startswith("-"):
            return int(expr), True
        return int(expr), True
    except (ValueError, IndexError):
        return None, False


class ResolutionEngine:
    """Unified engine combining BF + formula resolution strategies."""

    def __init__(self, bf_wrappers, local_formulas, string_map):
        self.bf_wrappers = bf_wrappers
        self.local_formulas = local_formulas
        self.string_map = string_map
        self.stats = Counter()
        self._all_known = set(bf_wrappers.keys()) | set(local_formulas.keys())

    @property
    def known_names(self):
        return self._all_known

    def resolve_call(self, wrapper_name, args):
        """Try to resolve a wrapper call."""
        if wrapper_name in self.bf_wrappers:
            result = self._try_bf_direct(wrapper_name, args)
            if result:
                self.stats["bf_direct"] += 1
                return result, "bf_direct"
            self.stats["bf_no_literal"] += 1
            return None, None

        if wrapper_name in self.local_formulas:
            result = self._try_formula(wrapper_name, args)
            if result:
                self.stats["formula_resolved"] += 1
                return result, "formula"
            self.stats["formula_no_literal"] += 1
            return None, None

        self.stats["unknown_wrapper"] += 1
        return None, None

    def _try_bf_direct(self, wrapper_name, args):
        bf = self.bf_wrappers[wrapper_name]
        pos = bf["active_call_position"]
        if pos >= len(args):
            return None
        val, ok = try_parse_literal(args[pos])
        if not ok:
            return None
        result = bf["results"].get(val)
        return result if result and result != "FbJiX" else None

    def _try_formula(self, wrapper_name, args):
        formula = self.local_formulas[wrapper_name]
        pi = formula["paramIndex"]
        offset = formula["offset"]
        if pi < 0 or pi > 4 or pi >= len(args):
            return None
        val, ok = try_parse_literal(args[pi])
        if not ok:
            return None
        idx = val + offset
        return self.string_map.get(idx)


# ════════════════════════════════════════════════════════════════════════════
# Resolution Application
# ════════════════════════════════════════════════════════════════════════════

def find_and_resolve_all_calls(content, engine):
    """Find all resolvable wrapper calls and compute replacements."""
    known = engine.known_names
    pattern = re.compile(r"(?<!\w)(_0x[a-f0-9]+|a0_0x[a-f0-9]+)\(")
    resolutions = []

    for m in pattern.finditer(content):
        fname = m.group(1)
        if fname not in known:
            continue

        paren_open = m.end() - 1
        depth = 1
        i = paren_open + 1
        limit = min(i + 2000, len(content))
        while i < limit and depth > 0:
            ch = content[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1

        if depth != 0:
            continue

        call_end = i
        args_str = content[paren_open + 1 : call_end - 1]
        args = tc.parse_ctx_args(args_str)

        resolved, source = engine.resolve_call(fname, args)
        if resolved is not None:
            resolutions.append({
                "start": m.start(),
                "end": call_end,
                "original": content[m.start() : call_end],
                "string": resolved,
                "source": source,
                "wrapper": fname,
            })

    resolutions.sort(key=lambda r: r["start"], reverse=True)
    return resolutions


def apply_resolutions(content, resolutions):
    """Replace resolved wrapper calls with string literals."""
    result = content
    for r in resolutions:
        escaped = (
            r["string"]
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )
        result = result[: r["start"]] + f"'{escaped}'" + result[r["end"] :]
    return result


# ════════════════════════════════════════════════════════════════════════════
# Wrapper Stripping
# ════════════════════════════════════════════════════════════════════════════

def strip_wrapper_definitions(content, wrapper_names):
    """Remove wrapper function definitions from the content."""
    func_ranges = []
    for m in re.finditer(r"^function\s+(\S+?)\((.*?)\)\s*\{", content, re.MULTILINE):
        name = m.group(1)
        if name not in wrapper_names:
            continue
        start = m.start()
        brace_start = content.index("{", start)
        depth = 0
        end = brace_start + 1
        for i in range(brace_start + 1, min(brace_start + 10000, len(content))):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                if depth == 0:
                    end = i + 1
                    break
                depth -= 1
        func_ranges.append((start, end))

    func_ranges.sort(reverse=True)
    result = content
    for start, end in func_ranges:
        while end < len(result) and result[end] in ("\n", "\r", " "):
            end += 1
        result = result[:start] + result[end:]

    return result, len(func_ranges)


def strip_opaque_predicates(content):
    """Remove opaque predicate blocks."""
    pattern = re.compile(
        r"if\s*\(!\(\[\]\)\)\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\}",
        re.DOTALL,
    )
    content, n = pattern.subn("/* [opaque predicate removed] */", content)
    return content, n


# ═════════════════════════════════════════════════════════════���══════════════
# Function Categorization
# ════════════════════════════════════════════════════════════════════════════

def parse_functions_with_boundaries(content):
    """Parse all functions with start/end boundaries."""
    functions = []
    for m in re.finditer(r"^function\s+(\S+?)\((.*?)\)\s*\{", content, re.MULTILINE):
        start = m.start()
        brace_start = content.index("{", start)
        depth = 0
        end = brace_start + 1
        for i in range(brace_start + 1, min(brace_start + 50000, len(content))):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                if depth == 0:
                    end = i + 1
                    break
                depth -= 1
        functions.append({
            "id": len(functions),
            "name": m.group(1),
            "params": m.group(2),
            "start": start,
            "end": end,
        })
    return functions


def categorize_functions(functions, resolutions, index_entries, wrapper_names):
    """Categorize non-wrapper functions by their resolved strings and metadata."""
    index_by_id = {e["id"]: e for e in index_entries}

    resolution_ranges = []
    for r in resolutions:
        resolution_ranges.append((r["start"], r["string"]))
    resolution_ranges.sort()

    category_map = {}
    for fd in functions:
        if fd["name"] in wrapper_names:
            continue

        func_strings = []
        for pos, s in resolution_ranges:
            if pos < fd["start"]:
                continue
            if pos >= fd["end"]:
                break
            func_strings.append(s)

        categories = set()
        idx_entry = index_by_id.get(fd["id"])
        if idx_entry:
            for cat in idx_entry.get("categories", []):
                if cat == "crypto":
                    categories.add("shield_crypto")
                elif cat in CATEGORY_KEYWORDS:
                    categories.add(cat)

        check_text = " ".join(func_strings)
        for cat, keywords in CATEGORY_KEYWORDS.items():
            for kw in keywords:
                if kw in check_text:
                    categories.add(cat)
                    break

        if not categories:
            categories.add("business_logic")

        category_map[fd["id"]] = {
            "name": fd["name"],
            "categories": categories,
            "resolved_strings": func_strings[:20],
        }

    return category_map


def split_by_category(content, functions, category_map, wrapper_names):
    """Split content into per-category files."""
    PRIORITY = [
        "shield_crypto", "network", "auth", "electron", "zaap", "game",
        "business_logic",
    ]

    category_functions = defaultdict(list)
    for fd in functions:
        if fd["name"] in wrapper_names:
            continue
        cm = category_map.get(fd["id"])
        if not cm:
            category_functions["business_logic"].append(fd)
            continue
        primary = "business_logic"
        for cat in PRIORITY:
            if cat in cm["categories"]:
                primary = cat
                break
        category_functions[primary].append(fd)

    category_files = {}
    for cat, funcs in category_functions.items():
        parts = [f"// {'='*3} {cat.upper()} {'='*3}", f"// {len(funcs)} functions", ""]
        for fd in funcs:
            func_text = content[fd["start"]:fd["end"]]
            cm = category_map.get(fd["id"])
            if cm and cm["resolved_strings"]:
                sample = ", ".join(repr(s) for s in cm["resolved_strings"][:5])
                parts.append(f"// Strings: [{sample}]")
            parts.append(func_text)
            parts.append("")
        category_files[cat] = "\n".join(parts)

    return category_files


# ════════════════════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Apply all resolutions to decompiled JS")
    parser.add_argument("--input", type=Path, required=True,
                        help="Path to decompiled.js")
    parser.add_argument("--index", type=Path, required=True,
                        help="Path to index.json")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Output directory for resolved files")
    parser.add_argument("--data-dir", type=Path, default=Path("/app/data"),
                        help="Directory containing static resolution data files")
    args = parser.parse_args()

    data_dir = args.data_dir
    t0 = time.time()

    # Resolve data file paths
    wrapper_bf_path = data_dir / "wrapper_bruteforce.json"
    decoder_log_path = data_dir / "decoder_log_full.json"
    security_api_path = data_dir / "security_api_calls.json"
    v8_wrapper_formulas_path = data_dir / "v8_wrapper_formulas.json"
    ghidra_resolutions_path = data_dir / "ghidra_context_resolutions.json"

    # Validate required files
    missing = []
    for label, path in [
        ("Decompiled JS", args.input),
        ("Function index", args.index),
        ("Decoder log", decoder_log_path),
        ("Wrapper formulas", v8_wrapper_formulas_path),
    ]:
        if not path.exists():
            missing.append(f"  MISSING: {label} -> {path}")
    if missing:
        log("ERROR: Required input files not found:")
        for m in missing:
            log(m)
        return 1

    # ── Phase 1: Load data sources ──
    log("Phase 1: Loading data sources...")

    string_map = tc.load_decoder_log(str(decoder_log_path))
    log(f"  Decoder strings: {len(string_map)}")

    bf_wrappers = {}
    if wrapper_bf_path.exists():
        bf_wrappers = load_wrapper_bruteforce(wrapper_bf_path)
        total_bf = sum(len(w["results"]) for w in bf_wrappers.values())
        log(f"  Brute-force wrappers: {len(bf_wrappers)} ({total_bf:,} entries)")
    else:
        total_bf = 0
        log("  Brute-force data: not found (skipping)")

    security_calls = load_security_api_calls(security_api_path)
    log(f"  Security API calls: {len(security_calls)}")

    index_entries = load_index_json(args.index)
    log(f"  Index entries: {len(index_entries)}")

    # ── Phase 2: Run trace_closures formula computation ──
    log("\nPhase 2: Computing local wrapper formulas (trace_closures engine)...")

    v8_formulas = tc.load_v8_wrapper_formulas(str(v8_wrapper_formulas_path))
    log(f"  V8 wrapper formulas: {len(v8_formulas)}")

    ghidra_formulas, bc_formulas, decomp_to_bc = {}, {}, {}
    if ghidra_resolutions_path.exists():
        ghidra_formulas, bc_formulas, decomp_to_bc = tc.load_ghidra_resolutions(
            str(ghidra_resolutions_path)
        )
        log(f"  Ghidra formulas: {len(ghidra_formulas)} decomp + {len(bc_formulas)} bc")
    else:
        log("  Ghidra resolutions: not found (skipping)")

    log(f"  Loading decompiled JS from {args.input}...")
    with open(args.input) as f:
        original_content = f.read()
    log(f"  {len(original_content):,} chars, {original_content.count(chr(10)):,} lines")

    log("  Parsing functions...")
    func_defs = tc.parse_all_functions(original_content)
    log(f"  {len(func_defs)} functions")

    log("  Extracting wrapper info...")
    tc_wrappers = tc.extract_wrapper_info(func_defs)
    n_2arg = sum(1 for w in tc_wrappers.values() if w["n_args"] == 2)
    n_5arg = sum(1 for w in tc_wrappers.values() if w["n_args"] == 5)
    log(f"  {len(tc_wrappers)} wrappers ({n_2arg} x 2-arg, {n_5arg} x 5-arg)")

    log("  Grouping by scope...")
    groups, wrapper_to_group = tc.group_wrappers_by_scope(func_defs, tc_wrappers)
    log(f"  {len(groups)} groups")

    # Build formula database
    all_formulas = {}
    all_formulas.update(v8_formulas)
    all_formulas.update(ghidra_formulas)
    for decomp_name, bc_names in decomp_to_bc.items():
        if decomp_name in all_formulas:
            continue
        for bc_name in bc_names:
            if bc_name in bc_formulas:
                all_formulas[decomp_name] = bc_formulas[bc_name]
                break
    log(f"  External formulas: {len(all_formulas)}")

    # 2-arg literal formulas
    two_arg_formulas, two_arg_ctx_dep = tc.extract_2arg_formulas(tc_wrappers)
    for name, f in two_arg_formulas.items():
        if name not in all_formulas:
            all_formulas[name] = f

    # Ctx-dependent 2-arg resolution
    resolved_ctx, ctx_values = tc.resolve_ctx_dependent_2arg(two_arg_ctx_dep, all_formulas)
    for name, f in resolved_ctx.items():
        if name not in all_formulas:
            all_formulas[name] = f
    log(f"  After 2-arg: {len(all_formulas)} (ctx_values: {len(ctx_values)})")

    # Iterative group deduction
    for iteration in range(5):
        before = len(all_formulas)
        inferred, group_ctx_info = tc.deduce_ctx_formulas_from_groups(
            tc_wrappers, groups, all_formulas
        )
        for name, f in inferred.items():
            if name not in all_formulas:
                all_formulas[name] = f
        ctx_inferred = tc.propagate_ctx_values_to_5arg(
            tc_wrappers, groups, wrapper_to_group, all_formulas, group_ctx_info, ctx_values
        )
        for name, f in ctx_inferred.items():
            if name not in all_formulas:
                all_formulas[name] = f
        gained = len(all_formulas) - before
        if gained == 0:
            break
        log(f"  Group deduction iter {iteration+1}: +{gained}")

    # Pre-collect literal call sites
    literal_call_sites = tc.collect_literal_call_sites(original_content, tc_wrappers)

    # Cross-reference
    xref = tc.cross_reference_call_sites(
        original_content, tc_wrappers, all_formulas, string_map, literal_call_sites
    )
    for name, f in xref.items():
        if name not in all_formulas:
            all_formulas[name] = f

    # Post-xref group deduction
    for iteration in range(3):
        before = len(all_formulas)
        inferred, group_ctx_info = tc.deduce_ctx_formulas_from_groups(
            tc_wrappers, groups, all_formulas
        )
        for name, f in inferred.items():
            if name not in all_formulas:
                all_formulas[name] = f
        ctx_inferred = tc.propagate_ctx_values_to_5arg(
            tc_wrappers, groups, wrapper_to_group, all_formulas, group_ctx_info, ctx_values
        )
        for name, f in ctx_inferred.items():
            if name not in all_formulas:
                all_formulas[name] = f
        if len(all_formulas) == before:
            break

    # Brute-force remaining groups
    bf_inferred, _ = tc.brute_force_5arg_formulas(
        tc_wrappers, groups, wrapper_to_group, all_formulas, string_map, literal_call_sites
    )
    for name, f in bf_inferred.items():
        if name not in all_formulas:
            all_formulas[name] = f

    # Convergence loop
    for mega in range(5):
        before = len(all_formulas)
        for _ in range(3):
            b2 = len(all_formulas)
            inferred, group_ctx_info = tc.deduce_ctx_formulas_from_groups(
                tc_wrappers, groups, all_formulas
            )
            for name, f in inferred.items():
                if name not in all_formulas:
                    all_formulas[name] = f
            ctx_inferred = tc.propagate_ctx_values_to_5arg(
                tc_wrappers, groups, wrapper_to_group, all_formulas, group_ctx_info, ctx_values
            )
            for name, f in ctx_inferred.items():
                if name not in all_formulas:
                    all_formulas[name] = f
            if len(all_formulas) == b2:
                break
        xref2 = tc.cross_reference_call_sites(
            original_content, tc_wrappers, all_formulas, string_map, literal_call_sites
        )
        for name, f in xref2.items():
            if name not in all_formulas:
                all_formulas[name] = f
        if len(all_formulas) == before:
            break

    # Validate formulas
    invalid = set()
    for fname, f in list(all_formulas.items()):
        if fname not in literal_call_sites or not literal_call_sites[fname]:
            continue
        pi = f["paramIndex"]
        offset = f["offset"]
        if pi > 4 or pi < 0:
            continue
        calls = literal_call_sites[fname]
        valid = total = 0
        for ca in calls:
            if pi < len(ca):
                total += 1
                if (ca[pi] + offset) in string_map:
                    valid += 1
        if total >= 3 and valid < total * 0.5:
            invalid.add(fname)
    for fname in invalid:
        del all_formulas[fname]
    if invalid:
        log(f"  Removed {len(invalid)} invalid formulas")

    log(f"  TOTAL LOCAL FORMULAS: {len(all_formulas)}")
    log(f"  Coverage: {len(all_formulas)}/{len(tc_wrappers)} wrappers "
        f"({100*len(all_formulas)/max(1,len(tc_wrappers)):.1f}%)")

    # ── Phase 3: Build unified resolution engine ──
    log("\nPhase 3: Building unified resolution engine...")
    engine = ResolutionEngine(bf_wrappers, all_formulas, string_map)
    log(f"  BF wrappers: {len(bf_wrappers)}")
    log(f"  Formula wrappers: {len(all_formulas)}")
    log(f"  Total known: {len(engine.known_names)}")

    # ── Phase 4: Find and resolve all calls ──
    log("\nPhase 4: Resolving all wrapper calls...")
    resolutions = find_and_resolve_all_calls(original_content, engine)
    log(f"  Total resolved: {len(resolutions)}")
    log(f"  Engine stats: {dict(engine.stats)}")

    resolved_content = apply_resolutions(original_content, resolutions)
    log(f"  Applied {len(resolutions)} replacements")

    # ── Phase 5: Strip wrapper definitions ──
    log("\nPhase 5: Stripping wrapper definitions...")
    wrapper_names = set(tc_wrappers.keys())
    stripped, strip_count = strip_wrapper_definitions(resolved_content, wrapper_names)
    log(f"  Stripped {strip_count} wrapper definitions")

    # ── Phase 6: Strip opaque predicates ──
    log("  Stripping opaque predicates...")
    cleaned, opaque_count = strip_opaque_predicates(stripped)
    log(f"  Removed {opaque_count} opaque predicates")

    # ── Phase 7: Categorize and split ──
    log("\nPhase 7: Categorizing and splitting...")
    orig_functions = parse_functions_with_boundaries(original_content)
    category_map = categorize_functions(
        orig_functions, resolutions, index_entries, wrapper_names
    )
    cat_dist = Counter()
    for cm in category_map.values():
        for cat in cm["categories"]:
            cat_dist[cat] += 1
    log(f"  Category distribution: {dict(cat_dist)}")

    final_functions = parse_functions_with_boundaries(cleaned)
    final_wrappers = set()
    for fd in final_functions:
        body = cleaned[fd["start"]:fd["end"]]
        if len(body) < 500 and re.search(r"return ctx_\d+\(", body):
            if fd["name"].startswith("_0x") or fd["name"].startswith("a0_0x"):
                final_wrappers.add(fd["name"])

    final_cat_map = categorize_functions(
        final_functions, resolutions, index_entries, final_wrappers
    )
    category_files = split_by_category(cleaned, final_functions, final_cat_map, final_wrappers)

    # ── Write output ──
    log("\nPhase 8: Writing output...")
    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    all_path = output_dir / "all_resolved.js"
    with open(all_path, "w") as f:
        f.write(cleaned)
    log(f"  {all_path} ({len(cleaned):,} chars)")

    for cat, text in category_files.items():
        cat_path = output_dir / f"{cat}.js"
        with open(cat_path, "w") as f:
            f.write(text)
        n_funcs = text.count("\nfunction ") + (1 if text.startswith("function ") else 0)
        log(f"  {cat_path} ({n_funcs} functions)")

    # ── Report ──
    elapsed = time.time() - t0
    unique_strings = set(r["string"] for r in resolutions)
    source_counts = Counter(r["source"] for r in resolutions)
    string_freq = Counter(r["string"] for r in resolutions)

    sec_methods = Counter(c.get("method", "?") for c in security_calls)

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_seconds": round(elapsed, 1),
        "summary": {
            "total_functions": len(orig_functions),
            "wrapper_definitions": len(wrapper_names),
            "business_functions": len(orig_functions) - len(wrapper_names),
            "local_formulas_computed": len(all_formulas),
            "formula_coverage_pct": round(
                100 * len(all_formulas) / max(1, len(tc_wrappers)), 1
            ),
            "total_call_sites_resolved": len(resolutions),
            "unique_strings_decoded": len(unique_strings),
            "wrapper_defs_stripped": strip_count,
            "opaque_predicates_removed": opaque_count,
        },
        "resolution_sources": dict(source_counts),
        "engine_stats": dict(engine.stats),
        "data_sources": {
            "bf_wrappers": len(bf_wrappers),
            "bf_total_entries": total_bf,
            "formula_wrappers": len(all_formulas),
            "decoder_strings": len(string_map),
            "security_api_calls": len(security_calls),
        },
        "category_distribution": dict(cat_dist),
        "top_30_strings": [
            {"string": s, "count": c} for s, c in string_freq.most_common(30)
        ],
        "security_api": {
            "method_counts": dict(sec_methods),
        },
    }

    report_path = output_dir / "report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    log(f"  {report_path}")

    # ── Summary ──
    log(f"\n{'='*60}")
    log("SUMMARY")
    log(f"{'='*60}")
    log(f"  Total functions:          {len(orig_functions)}")
    log(f"  Wrapper definitions:      {len(wrapper_names)}")
    log(f"  Business functions:       {len(orig_functions) - len(wrapper_names)}")
    log(f"  Local formulas computed:  {len(all_formulas)} ({100*len(all_formulas)/max(1,len(tc_wrappers)):.1f}%)")
    log(f"  Call sites resolved:      {len(resolutions)}")
    for src, cnt in source_counts.most_common():
        log(f"    {src}: {cnt}")
    log(f"  Wrapper defs stripped:    {strip_count}")
    log(f"  Unique strings decoded:   {len(unique_strings)}")
    log(f"  Output:                   {output_dir}")
    log(f"  Elapsed:                  {elapsed:.1f}s")
    log(f"{'='*60}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
