#!/usr/bin/env python3
"""
resolve-strings.py — Resolve obfuscated strings in decompiled JS.

Combines multiple data sources:
  1. decoded_strings.json (string array after rotation, 8676 elements)
  2. index.json (function metadata: names, categories, known strings)
  3. decoder_log_runtime.json (optional: runtime-captured string resolutions)

Produces annotated JS with resolved strings inline.

Usage: python3 resolve-strings.py <decompiled.js> <output.js> [decoder_log.json]

Author: Luska
"""
import json
import os
import re
import sys
from collections import defaultdict


def load_decoded_strings(path):
    """Load the decoded string array from JSON."""
    data = json.load(open(path))
    if isinstance(data, dict):
        max_idx = max(int(k) for k in data.keys())
        return [data.get(str(i), '') for i in range(276, max_idx + 1)]
    return data


def load_dead_tags(str_array):
    """Identify dead code tags (5-char random mixed-case strings)."""
    tags = set()
    for s in str_array:
        if len(s) == 5 and s.isalpha() and any(c.isupper() for c in s) and any(c.islower() for c in s):
            tags.add(s)
    return tags


def load_decoder_log(path):
    """Load the optional runtime decoder log."""
    if not path or not os.path.exists(path):
        return None
    return json.load(open(path))


def parse_wrappers(code):
    """Parse obfuscator.io wrapper function definitions."""
    wrapper_re = re.compile(
        r'function (_0x[a-f0-9]+)\(arg1, arg2, arg3, arg4, arg5\) \{\n'
        r'  (ctx_\d+)\(([^)]+)\);\n'
        r'  return \2\(\3\);\n'
        r'\}'
    )
    wrappers = {}
    for m in wrapper_re.finditer(code):
        wrappers[m.group(1)] = {
            'ctx': m.group(2),
            'exprs': [p.strip() for p in m.group(3).split(', ')],
            'pos': m.start(),
            'full_match': m.group(0),
        }
    return wrappers


def remove_dead_code(code, dead_tags):
    """Remove dead code evaluation statements (opaque predicates)."""
    lines = code.split('\n')
    result = []
    i = 0
    standalone_removed = 0

    while i < len(lines):
        stripped = lines[i].strip()

        # Two standalone wrapper evaluations followed by if comparison = dead code
        if (re.match(r'^_0x[a-f0-9]+\([^;]*\);$', stripped)
                and i + 1 < len(lines)
                and re.match(r'^_0x[a-f0-9]+\([^;]*\);$', lines[i + 1].strip())
                and i + 2 < len(lines)
                and re.match(r'^if \(_0x[a-f0-9]+\(.*=== _0x[a-f0-9]+\(', lines[i + 2].strip())):
            standalone_removed += 2
            i += 2
            continue

        result.append(lines[i])
        i += 1

    return '\n'.join(result), standalone_removed


def annotate_functions(code, index_data):
    """Add metadata comments above function definitions."""
    func_meta = {}
    for func in index_data:
        name = func.get('name', '') or f"anon_{func['id']}"
        func_meta[name] = {
            'id': func['id'],
            'instructions': func.get('instructions', 0),
            'strings': func.get('strings', []),
            'categories': func.get('categories', []),
        }

    lines = code.split('\n')
    result = []
    for line in lines:
        m = re.match(r'^((?:async )?function (\w+)\()', line)
        if m:
            meta = func_meta.get(m.group(2))
            if not meta:
                for key in func_meta:
                    if m.group(2) == f'fn_{key}' or m.group(2) == key:
                        meta = func_meta[key]
                        break

            if meta and (meta['strings'] or meta['categories']):
                parts = []
                if meta['categories']:
                    parts.append(f'[{", ".join(meta["categories"])}]')
                if meta['strings']:
                    parts.append(f'strings: {", ".join(repr(s) for s in meta["strings"][:8])}')
                if meta['instructions'] > 100:
                    parts.append(f'{meta["instructions"]} ops')
                result.append(f'// {" | ".join(parts)}')

        result.append(line)

    return '\n'.join(result)


def resolve_from_decoder_log(code, decoder_log, wrappers):
    """Use runtime log to replace wrapper calls with resolved strings."""
    if not decoder_log:
        return code, 0

    decoder_data = decoder_log.get('decoderLog', {})
    if not decoder_data:
        return code, 0

    # func_name -> {string_index: call_count}
    func_to_indices = defaultdict(lambda: defaultdict(int))
    for idx_str, info in decoder_data.items():
        for caller_name, count in info.get('callers', {}).items():
            if caller_name.startswith('_0x') or caller_name.startswith('a0_0x'):
                func_to_indices[caller_name][idx_str] += count

    idx_to_string = {idx_str: info['result'] for idx_str, info in decoder_data.items()}

    print(f'  Functions in runtime log: {len(func_to_indices)}')

    # Functions that always resolve to one string (deterministic wrappers)
    single_string = {}
    for func_name, indices in func_to_indices.items():
        if len(indices) == 1:
            idx_str = list(indices.keys())[0]
            single_string[func_name] = idx_to_string.get(idx_str, '')

    print(f'  Single-string wrappers: {len(single_string)}')

    resolved = 0
    call_re = re.compile(r'(_0x[a-f0-9]+)\(([^)]*)\)')

    def replace_call(m):
        nonlocal resolved
        name = m.group(1)
        if name in single_string:
            resolved += 1
            return repr(single_string[name])
        return m.group(0)

    lines = code.split('\n')
    result = []
    for line in lines:
        stripped = line.strip()
        if re.match(r'^function _0x[a-f0-9]+\(arg1', stripped) or stripped.startswith('return ctx_'):
            result.append(line)
            continue
        result.append(call_re.sub(replace_call, line))

    # Annotate multi-string functions
    annotated = '\n'.join(result)
    for func_name, indices in func_to_indices.items():
        if len(indices) > 1:
            strings = [idx_to_string.get(k, '?')
                       for k in sorted(indices.keys(), key=lambda x: -indices[x])[:5]]
            comment = f'/* runtime: {", ".join(repr(s) for s in strings)} */'
            pattern = f'function {func_name}('
            if pattern in annotated:
                annotated = annotated.replace(pattern, f'{comment}\nfunction {func_name}(', 1)

    return annotated, resolved


def strip_wrapper_definitions(code):
    """Remove wrapper function definitions to reduce noise."""
    wrapper_re = re.compile(
        r'function _0x[a-f0-9]+\(arg1, arg2, arg3, arg4, arg5\) \{\n'
        r'  ctx_\d+\([^)]+\);\n'
        r'  return ctx_\d+\([^)]+\);\n'
        r'\}\n?'
    )
    stripped, count = wrapper_re.subn('', code)
    return stripped, count


def main():
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} <decompiled.js> <output.js> [decoder_log.json]')
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    decoder_log_path = sys.argv[3] if len(sys.argv) > 3 else None

    base_dir = os.path.dirname(input_path)
    parent_dir = os.path.dirname(base_dir)

    # Load data files
    strings_path = os.path.join(parent_dir, 'decoded_strings.json')
    if not os.path.exists(strings_path):
        strings_path = os.path.join(base_dir, 'decoded_strings.json')

    index_path = os.path.join(base_dir, 'index.json')

    code = open(input_path).read()
    print(f'Input: {len(code) // 1024} KB, {code.count(chr(10))} lines')

    str_array = load_decoded_strings(strings_path) if os.path.exists(strings_path) else []
    dead_tags = load_dead_tags(str_array) if str_array else set()
    print(f'String array: {len(str_array)} elements, {len(dead_tags)} dead tags')

    index_data = json.load(open(index_path)) if os.path.exists(index_path) else []
    print(f'Function index: {len(index_data)} functions')

    decoder_log = load_decoder_log(decoder_log_path)
    if decoder_log:
        meta = decoder_log['meta']
        print(f'Decoder log: {meta["totalCalls"]} calls, {meta["uniqueIndices"]} unique indices')

    wrappers = parse_wrappers(code)
    print(f'Wrapper definitions: {len(wrappers)}')

    # 1. Remove dead code
    code, standalone = remove_dead_code(code, dead_tags)
    print(f'Dead code: {standalone} standalone evals removed')

    # 2. Resolve from runtime log
    resolved_runtime = 0
    if decoder_log:
        code, resolved_runtime = resolve_from_decoder_log(code, decoder_log, wrappers)
        print(f'Strings resolved from runtime: {resolved_runtime}')

    # 3. Annotate functions
    if index_data:
        code = annotate_functions(code, index_data)
        print('Functions annotated')

    # 4. Strip wrapper definitions if enough were resolved
    if resolved_runtime > 100:
        code, stripped = strip_wrapper_definitions(code)
        print(f'Wrapper definitions stripped: {stripped}')

    # 5. Clean up excessive blank lines
    code = re.sub(r'\n{3,}', '\n\n', code)

    open(output_path, 'w').write(code)
    print(f'Output: {len(code) // 1024} KB, {code.count(chr(10))} lines')
    print(f'Remaining obfuscated calls: {len(re.findall(r"_0x[a-f0-9]+\\([^)]*\\)", code))}')


if __name__ == '__main__':
    main()
