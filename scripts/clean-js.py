#!/usr/bin/env python3
"""
clean-js.py — Produce syntactically valid JS from decompiled pseudo-JS.

Filters out unparsable functions via Babel, and prepends the obfuscator.io
string array + decoder prelude when decoded_strings.json is available.

Usage: python3 clean-js.py <input.js> <output.js>

Author: Luska
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile


def build_prelude(strings_path):
    """Build the obfuscator.io string array + decoder function prelude."""
    if not strings_path or not os.path.exists(strings_path):
        return ''

    strings = json.load(open(strings_path))
    if isinstance(strings, dict):
        max_idx = max(int(k) for k in strings.keys())
        arr = [strings.get(str(i), '') for i in range(276, max_idx + 1)]
    else:
        arr = strings

    return (
        f'var _stringArray = {json.dumps(arr)};\n'
        'function a0_0x4ebe() { var a = _stringArray; '
        'a0_0x4ebe = function() { return a; }; return a0_0x4ebe(); }\n'
        'function a0_0x2c3b(idx, key) { idx = idx - 276; '
        'return a0_0x4ebe()[idx]; }\n\n'
    )


def validate_functions(text):
    """Split JS into function blocks, validate each with Babel, keep only valid ones."""
    funcs = re.split(r'\n(?=(?:async )?function[\s*])', text)
    print(f'  {len(funcs)} function blocks', flush=True)

    tmpdir = tempfile.mkdtemp()
    for i, func in enumerate(funcs):
        func = func.strip()
        if func and len(func) >= 10:
            with open(os.path.join(tmpdir, f'f{i}.js'), 'w') as f:
                f.write(func)

    # Find or install @babel/parser
    babel_paths = [
        '/tmp/babel-test/node_modules/@babel/parser',
        os.path.join(os.path.dirname(__file__), 'node_modules', '@babel', 'parser'),
    ]
    babel_path = None
    for bp in babel_paths:
        if os.path.exists(bp):
            babel_path = bp
            break

    if not babel_path:
        subprocess.run(
            ['npm', 'install', '--prefix', '/tmp/babel-test', '@babel/parser'],
            capture_output=True, timeout=30,
        )
        babel_path = '/tmp/babel-test/node_modules/@babel/parser'

    if not os.path.exists(babel_path):
        print('  @babel/parser unavailable, skipping validation', flush=True)
        shutil.rmtree(tmpdir)
        return text

    test_script = f'''
const parser = require('{babel_path}');
const fs = require('fs');
const path = require('path');
const dir = '{tmpdir}';
const files = fs.readdirSync(dir).filter(f => f.endsWith('.js')).sort();
const valid = [];
for (const file of files) {{
    try {{
        parser.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
        valid.push(file);
    }} catch(e) {{}}
}}
fs.writeFileSync('/tmp/valid_funcs.json', JSON.stringify(valid));
console.log(valid.length + ' valid, ' + (files.length - valid.length) + ' invalid');
'''

    result = subprocess.run(
        ['node', '-e', test_script],
        capture_output=True, text=True, timeout=300,
    )
    print(f'  {result.stdout.strip()}', flush=True)

    try:
        valid_files = json.load(open('/tmp/valid_funcs.json'))
    except Exception:
        valid_files = []
        print('  Validation failed', flush=True)

    parts = []
    for vf in valid_files:
        parts.append(open(os.path.join(tmpdir, vf)).read())

    shutil.rmtree(tmpdir)
    return '\n\n'.join(parts)


def main():
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} <input.js> <output.js>')
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    text = open(input_path).read()
    print(f'Input: {len(text) // 1024} KB', flush=True)

    # Locate decoded_strings.json near input
    strings_path = os.path.join(os.path.dirname(input_path), '..', 'decoded_strings.json')
    if not os.path.exists(strings_path):
        strings_path = os.path.join(os.path.dirname(input_path), 'decoded_strings.json')

    prelude = build_prelude(strings_path)
    if prelude:
        print(f'  String array prelude: {len(prelude) // 1024} KB', flush=True)

    valid_text = validate_functions(text)
    output = prelude + valid_text
    open(output_path, 'w').write(output)
    print(f'Output: {len(output) // 1024} KB', flush=True)


if __name__ == '__main__':
    main()
