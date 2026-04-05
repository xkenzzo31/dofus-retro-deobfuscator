#!/usr/bin/env python3
"""
trace_closures.py - Closure chain tracer for V8 8.7 deobfuscation

Resolves context-dependent wrapper calls in Dofus Retro's main.jsc by:
1. Parsing all wrapper function definitions from decompiled.js
2. Extracting formulas (paramIndex + offset) for 2-arg wrappers with literal offsets
3. Merging with Ghidra bc_formulas and v8_wrapper_formulas
4. Grouping wrappers by their parent scope (module) to propagate ctx_N formulas
5. Iteratively inferring formulas for unknown wrappers via group propagation
6. Resolving all possible wrapper call sites and replacing with decoded strings

Adapted for the Docker pipeline — all paths are passed as arguments.
"""

import re
import json
import sys
import os
from collections import Counter, defaultdict

VALID_INDEX_MIN = 261
VALID_INDEX_MAX = 8901

PARAM_MAP = {"arg1": 0, "arg2": 1, "arg3": 2, "arg4": 3, "arg5": 4, "this": 5}


def log(msg):
    print(f"[trace_closures] {msg}", file=sys.stderr)


# ──── Data Loading ────

def load_decoder_log(path):
    """Load the decoded string mappings: index -> string"""
    with open(path) as f:
        data = json.load(f)
    return {int(k): v for k, v in data["mappings"].items()}


def load_v8_wrapper_formulas(path):
    """Load formulas from v8_wrapper_formulas.json"""
    with open(path) as f:
        data = json.load(f)
    formulas = {}
    for w in data["wrappers"]:
        effective_offset = w["offset"] if w["operation"] == "+" else -w["offset"]
        formulas[w["name"]] = {"paramIndex": w["paramIndex"], "offset": effective_offset}
    return formulas


def load_ghidra_resolutions(path):
    """Load formulas from ghidra_context_resolutions.json"""
    with open(path) as f:
        data = json.load(f)

    formulas = {}
    for name, f in data.get("decompiled_formulas", {}).items():
        effective_offset = f["offset"] if f["operation"] == "+" else -f["offset"]
        formulas[name] = {"paramIndex": f["paramIndex"], "offset": effective_offset}

    bc_formulas = {}
    for name, f in data.get("bc_formulas", {}).items():
        effective_offset = f["offset"] if f.get("opSign", 1) == 1 else -f["offset"]
        bc_formulas[name] = {"paramIndex": f["paramIndex"], "offset": effective_offset}

    bc_to_decomp = data.get("bc_to_decomp_names", {})
    decomp_to_bc = defaultdict(list)
    for bc_name, decomp_name in bc_to_decomp.items():
        decomp_to_bc[decomp_name].append(bc_name)

    return formulas, bc_formulas, dict(decomp_to_bc)


# ──── Parsing ────

def parse_ctx_args(args_str):
    """Parse comma-separated arguments, respecting parentheses depth."""
    depth = 0
    current = ""
    result = []
    for ch in args_str:
        if ch == "(":
            depth += 1
            current += ch
        elif ch == ")":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            result.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        result.append(current.strip())
    return result


def parse_index_expression(expr):
    """Parse a single index expression from a wrapper body."""
    expr = expr.strip()

    m = re.match(r"^(arg[1-5]|this)$", expr)
    if m:
        return (PARAM_MAP[m.group(1)], 0)

    m = re.match(r"^(arg[1-5]|this)\s*\+\s*(\d+)$", expr)
    if m:
        return (PARAM_MAP[m.group(1)], int(m.group(2)))

    m = re.match(r"^(arg[1-5]|this)\s*-\s*(\d+)$", expr)
    if m:
        return (PARAM_MAP[m.group(1)], -int(m.group(2)))

    m = re.match(r"^(arg[1-5]|this)\s*-\s*-(\d+)$", expr)
    if m:
        return (PARAM_MAP[m.group(1)], int(m.group(2)))

    m = re.match(r"^(arg[1-5]|this)\s*-\s*-\(?(ctx_(\d+)\[(_0x[a-f0-9]+)\])\)?$", expr)
    if m:
        return (PARAM_MAP[m.group(1)], ("ctx_plus", int(m.group(3)), m.group(4)))

    m = re.match(r"^(arg[1-5]|this)\s*-\s*ctx_(\d+)\[(_0x[a-f0-9]+)\]$", expr)
    if m:
        return (PARAM_MAP[m.group(1)], ("ctx_minus", int(m.group(2)), m.group(3)))

    return None


def parse_all_functions(content):
    """Parse all function definitions from decompiled.js"""
    func_defs = []
    for m in re.finditer(r"^function\s+(\S+?)\((.*?)\)\s*\{", content, re.MULTILINE):
        name = m.group(1)
        params = m.group(2)
        pos = m.start()

        brace_start = content.index("{", pos)
        brace_depth = 0
        body_start = brace_start + 1
        body_end = body_start
        for i in range(body_start, min(body_start + 10000, len(content))):
            if content[i] == "{":
                brace_depth += 1
            elif content[i] == "}":
                if brace_depth == 0:
                    body_end = i
                    break
                brace_depth -= 1

        body = content[body_start:body_end]
        func_defs.append({
            "id": len(func_defs),
            "name": name,
            "params": params,
            "body": body,
            "pos": pos,
        })
    return func_defs


def extract_wrapper_info(func_defs):
    """Extract wrapper formula information from each function definition."""
    wrappers = {}
    for fd in func_defs:
        m = re.search(r"return\s+ctx_(\d+)\(([^;]+?)\);", fd["body"])
        if not m:
            continue
        if not (fd["name"].startswith("_0x") or fd["name"].startswith("a0_0x")):
            continue

        ctx_n = int(m.group(1))
        args_str = m.group(2)
        ctx_args = parse_ctx_args(args_str)
        parsed = [parse_index_expression(a) for a in ctx_args]

        wrappers[fd["name"]] = {
            "ctx_n": ctx_n,
            "n_args": len(ctx_args),
            "parsed": parsed,
            "func_id": fd["id"],
            "raw_args": ctx_args,
        }
    return wrappers


def group_wrappers_by_scope(func_defs, wrappers):
    """Group wrapper functions by their parent scope (consecutive wrapper blocks)."""
    groups = []
    current_group = []

    for fd in func_defs:
        if fd["name"] in wrappers:
            current_group.append(fd["name"])
        else:
            if current_group:
                groups.append(current_group)
                current_group = []
    if current_group:
        groups.append(current_group)

    wrapper_to_group = {}
    for gi, group in enumerate(groups):
        for name in group:
            wrapper_to_group[name] = gi

    return groups, wrapper_to_group


# ──── Formula Building ────

def extract_2arg_formulas(wrappers):
    """Extract formulas from 2-arg wrappers that call ctx_N directly."""
    formulas = {}
    ctx_dependent = {}

    for name, w in wrappers.items():
        if w["n_args"] != 2:
            continue
        parsed = w["parsed"]
        if not parsed or parsed[0] is None:
            continue

        param_idx, offset_info = parsed[0]

        if isinstance(offset_info, int):
            formulas[name] = {"paramIndex": param_idx, "offset": offset_info}
        elif isinstance(offset_info, tuple):
            sign_type, ctx_n, prop = offset_info
            ctx_dependent[name] = {
                "paramIndex": param_idx,
                "sign": 1 if sign_type == "ctx_plus" else -1,
                "ctx_n": ctx_n,
                "prop": prop,
            }

    return formulas, ctx_dependent


def deduce_ctx_formulas_from_groups(wrappers, groups, all_formulas):
    """Deduce ctx_N behavior from groups of wrappers with known formulas."""
    inferred = {}
    group_ctx_info = {}

    wrapper_to_group = {}
    for gi, group in enumerate(groups):
        for name in group:
            wrapper_to_group[name] = gi

    for gi, group in enumerate(groups):
        ctx_deductions = defaultdict(list)

        for fname in group:
            w = wrappers.get(fname)
            if w is None or w["n_args"] != 5:
                continue
            if fname not in all_formulas:
                continue

            known = all_formulas[fname]
            bc_pi = known["paramIndex"]
            effective_offset = known["offset"]

            for pos, parsed in enumerate(w["parsed"]):
                if parsed is None:
                    continue
                p_param, p_offset = parsed
                if p_param != bc_pi:
                    continue
                if not isinstance(p_offset, int):
                    continue
                ctx_own = effective_offset - p_offset
                ctx_deductions[w["ctx_n"]].append((pos, ctx_own))

        for ctx_n, deductions in ctx_deductions.items():
            if not deductions:
                continue
            vote = Counter(deductions).most_common(1)[0]
            group_ctx_info.setdefault(gi, {})[ctx_n] = vote[0]

    for gi, group in enumerate(groups):
        if gi not in group_ctx_info:
            continue

        for fname in group:
            if fname in all_formulas or fname in inferred:
                continue
            w = wrappers.get(fname)
            if w is None or w["n_args"] != 5:
                continue

            ctx_n = w["ctx_n"]
            if ctx_n not in group_ctx_info[gi]:
                continue

            picked_pos, ctx_own_offset = group_ctx_info[gi][ctx_n]
            if picked_pos >= len(w["parsed"]) or w["parsed"][picked_pos] is None:
                continue

            p_param, p_offset = w["parsed"][picked_pos]
            if isinstance(p_offset, int):
                total_offset = p_offset + ctx_own_offset
                inferred[fname] = {
                    "paramIndex": p_param,
                    "offset": total_offset,
                    "source": "group_deduction",
                }

    return inferred, group_ctx_info


def resolve_ctx_dependent_2arg(ctx_dependent, all_formulas):
    """Resolve 2-arg wrappers with ctx-dependent offsets."""
    resolved = {}
    ctx_values = {}

    for fname, cd in ctx_dependent.items():
        if fname in all_formulas:
            known = all_formulas[fname]
            ctx_value = known["offset"] / cd["sign"] if cd["sign"] != 0 else None
            if ctx_value is not None and ctx_value == int(ctx_value):
                ctx_value = int(ctx_value)
                ctx_values[(cd["ctx_n"], cd["prop"])] = ctx_value
                resolved[fname] = {
                    "paramIndex": cd["paramIndex"],
                    "offset": known["offset"],
                    "source": "ctx_value_known",
                }

    for fname, cd in ctx_dependent.items():
        if fname in resolved or fname in all_formulas:
            continue
        key = (cd["ctx_n"], cd["prop"])
        if key in ctx_values:
            val = ctx_values[key]
            total_offset = cd["sign"] * val
            resolved[fname] = {
                "paramIndex": cd["paramIndex"],
                "offset": total_offset,
                "source": "ctx_value_propagated",
            }

    return resolved, ctx_values


def propagate_ctx_values_to_5arg(wrappers, groups, wrapper_to_group,
                                  all_formulas, group_ctx_info, ctx_values):
    """Propagate discovered ctx values to 5-arg wrappers."""
    inferred = {}

    for gi, group in enumerate(groups):
        if gi not in group_ctx_info:
            continue

        for fname in group:
            if fname in all_formulas or fname in inferred:
                continue
            w = wrappers.get(fname)
            if w is None or w["n_args"] != 5:
                continue

            ctx_n = w["ctx_n"]
            if ctx_n not in group_ctx_info[gi]:
                continue

            picked_pos, ctx_own_offset = group_ctx_info[gi][ctx_n]
            if picked_pos >= len(w["parsed"]) or w["parsed"][picked_pos] is None:
                continue

            p_param, p_offset = w["parsed"][picked_pos]

            if isinstance(p_offset, int):
                total_offset = p_offset + ctx_own_offset
                inferred[fname] = {
                    "paramIndex": p_param,
                    "offset": total_offset,
                    "source": "group_ctx_literal",
                }
            elif isinstance(p_offset, tuple):
                sign_type, off_ctx_n, off_prop = p_offset
                key = (off_ctx_n, off_prop)
                if key in ctx_values:
                    val = ctx_values[key]
                    if sign_type == "ctx_plus":
                        wrapper_offset = val
                    else:
                        wrapper_offset = -val
                    total_offset = wrapper_offset + ctx_own_offset
                    inferred[fname] = {
                        "paramIndex": p_param,
                        "offset": total_offset,
                        "source": "group_ctx_resolved",
                    }

    return inferred


def cross_reference_call_sites(content, wrappers, all_formulas, string_map,
                               literal_call_sites=None):
    """Analyze call sites to deduce formulas for unknown wrappers."""
    inferred = {}

    unknown_wrappers = set(wrappers.keys()) - set(all_formulas.keys())
    if not unknown_wrappers:
        return inferred

    if literal_call_sites is not None:
        call_sites = {k: v for k, v in literal_call_sites.items() if k in unknown_wrappers}
    else:
        call_sites = collect_literal_call_sites(content,
                                                 {k: v for k, v in wrappers.items()
                                                  if k in unknown_wrappers})

    for fname, calls in call_sites.items():
        if len(calls) < 2:
            continue

        w = wrappers.get(fname)
        if w is None:
            continue

        valid_calls = [c for c in calls if len(c) == w["n_args"]]
        if len(valid_calls) < 2:
            continue

        best = None
        best_score = 0

        n_positions = w["n_args"]
        for pos in range(n_positions):
            if pos >= len(w["parsed"]) or w["parsed"][pos] is None:
                continue

            p_param, p_offset = w["parsed"][pos]
            if not isinstance(p_offset, int):
                continue
            if p_param > 4:
                continue

            expr_vals = []
            for call_args in valid_calls:
                if p_param < len(call_args):
                    expr_vals.append(call_args[p_param] + p_offset)

            if len(expr_vals) < 2:
                continue

            offset_votes = Counter()
            for ev in expr_vals:
                for valid_idx in string_map:
                    ctx_off = valid_idx - ev
                    if -3000 <= ctx_off <= 3000:
                        offset_votes[ctx_off] += 1

            if not offset_votes:
                continue

            best_off, score = offset_votes.most_common(1)[0]
            if score > best_score and score >= max(2, len(valid_calls) * 0.5):
                best_score = score
                total_offset = p_offset + best_off
                best = (p_param, total_offset, score, len(valid_calls))

        if best:
            p_param, offset, valid, total = best
            inferred[fname] = {
                "paramIndex": p_param,
                "offset": offset,
                "source": f"cross_reference({valid}/{total})",
            }

    return inferred


def collect_literal_call_sites(content, wrappers):
    """Pre-collect all literal-only call sites for all wrappers."""
    call_sites = defaultdict(list)

    call_pattern = re.compile(r"(?<!\w)(_0x[a-f0-9]+)\(([^)]*)\)")
    for m in call_pattern.finditer(content):
        fname = m.group(1)
        if fname not in wrappers:
            continue

        args_str = m.group(2)
        if "ctx_" in args_str or "_fn_" in args_str or "_obj_" in args_str or "_0x" in args_str:
            continue

        args = parse_ctx_args(args_str)
        try:
            nums = []
            for a in args:
                a = a.strip()
                if a.startswith("-(") and a.endswith(")"):
                    nums.append(-int(a[2:-1]))
                elif a.startswith("-"):
                    nums.append(int(a))
                else:
                    nums.append(int(a))
            if len(nums) == wrappers[fname]["n_args"]:
                call_sites[fname].append(nums)
        except (ValueError, IndexError):
            continue

    return call_sites


def brute_force_5arg_formulas(wrappers, groups, wrapper_to_group, all_formulas, string_map,
                              literal_call_sites):
    """Brute-force the ctx_N behavior for 5-arg wrapper groups without known formulas."""
    inferred = {}
    new_group_ctx = {}

    for gi, group in enumerate(groups):
        group_5arg = [fname for fname in group
                      if fname in wrappers and wrappers[fname]["n_args"] == 5
                      and fname not in all_formulas]

        if not group_5arg:
            continue

        has_known = any(fname in all_formulas for fname in group)
        if has_known:
            continue

        group_call_data = []
        for fname in group_5arg:
            w = wrappers[fname]
            for call_args in literal_call_sites.get(fname, []):
                if len(call_args) == w["n_args"]:
                    group_call_data.append((fname, call_args, w["parsed"]))

        if not group_call_data:
            continue

        best_pos = None
        best_ctx_offset = None
        best_score = 0

        for test_pos in range(5):
            offset_votes = Counter()

            for fname, call_args, parsed in group_call_data:
                if test_pos >= len(parsed) or parsed[test_pos] is None:
                    continue
                p_param, p_offset = parsed[test_pos]
                if not isinstance(p_offset, int):
                    continue
                if p_param > 4:
                    continue
                expr_value = call_args[p_param] + p_offset
                for valid_idx in string_map:
                    test_ctx_off = valid_idx - expr_value
                    if -3000 <= test_ctx_off <= 3000:
                        offset_votes[test_ctx_off] += 1

            if not offset_votes:
                continue

            top_off, score = offset_votes.most_common(1)[0]
            if score > best_score:
                best_score = score
                best_pos = test_pos
                best_ctx_offset = top_off

        min_score = max(1, len(group_call_data) * 0.3)
        if best_score >= min_score and best_pos is not None:
            new_group_ctx[gi] = (best_pos, best_ctx_offset)

            for fname in group_5arg:
                w = wrappers[fname]
                if best_pos >= len(w["parsed"]) or w["parsed"][best_pos] is None:
                    continue
                p_param, p_offset = w["parsed"][best_pos]
                if isinstance(p_offset, int):
                    total = p_offset + best_ctx_offset
                    inferred[fname] = {
                        "paramIndex": p_param,
                        "offset": total,
                        "source": f"brute_force_group(score={best_score})",
                    }

    return inferred, new_group_ctx


def find_and_resolve_call_sites(content, all_formulas, string_map):
    """Find all wrapper call sites and resolve those with literal arguments."""
    resolutions = []
    unresolved_literal = 0
    unresolved_ctx = 0
    unresolved_no_formula = 0

    call_pattern = re.compile(r"(?<!\w)(_0x[a-f0-9]+)\(([^)]*)\)")

    for m in call_pattern.finditer(content):
        fname = m.group(1)
        args_str = m.group(2)

        if fname not in all_formulas:
            unresolved_no_formula += 1
            continue

        formula = all_formulas[fname]
        pi = formula["paramIndex"]
        offset = formula["offset"]

        args = parse_ctx_args(args_str)

        if pi == 5 or pi == -1:
            unresolved_literal += 1
            continue

        if pi >= len(args):
            unresolved_literal += 1
            continue

        relevant = args[pi].strip()

        try:
            if relevant.startswith("-(") and relevant.endswith(")"):
                val = -int(relevant[2:-1])
            elif relevant.startswith("-"):
                val = int(relevant)
            else:
                val = int(relevant)

            idx = val + offset
            if idx in string_map:
                decoded = string_map[idx]
                resolutions.append({
                    "start": m.start(),
                    "end": m.end(),
                    "original": m.group(0),
                    "string": decoded,
                    "index": idx,
                    "wrapper": fname,
                })
            else:
                unresolved_literal += 1
        except ValueError:
            if "ctx_" in relevant:
                unresolved_ctx += 1
            else:
                unresolved_literal += 1

    return resolutions, unresolved_literal, unresolved_ctx, unresolved_no_formula


def apply_resolutions(content, resolutions):
    """Replace resolved wrapper calls with string literals."""
    sorted_res = sorted(resolutions, key=lambda r: r["start"], reverse=True)
    result = content
    applied = 0

    for r in sorted_res:
        decoded = r["string"]
        escaped = decoded.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")
        replacement = f"'{escaped}'"
        result = result[:r["start"]] + replacement + result[r["end"]:]
        applied += 1

    return result, applied
