#!/usr/bin/env python3
"""Clone V8 8.7.220.31 deps from GitHub mirrors at exact pinned commits."""
import os
import subprocess
import sys

GH = "https://github.com"

# GitHub mirrors with pinned commits from V8 8.7.220.31 DEPS
DEPS = [
    ("build",                    f"{GH}/gsource-mirror/chromium-src-build.git",            "38a49c12ded01dd8c4628b432cb7eebfb29e77f1"),
    ("buildtools",               f"{GH}/gsource-mirror/chromium-src-buildtools.git",       "3ff4f5027b4b81a6c9c36d64d71444f2709a4896"),
    ("base/trace_event/common",  f"{GH}/QPDFium/common.git",                               "23ef5333a357fc7314630ef88b44c3a545881dee"),
    ("third_party/zlib",         f"{GH}/gsource-mirror/chromium-src-third_party-zlib.git", "4668feaaa47973a6f9d9f9caeb14cd03731854f1"),
    ("third_party/jinja2",       f"{GH}/QPDFium/jinja2.git",                               "a82a4944a7f2496639f34a89c9923be5908b80aa"),
    ("third_party/markupsafe",   f"{GH}/QPDFium/markupsafe.git",                           "f2fb0f21ef1e1d4ffd43be8c63fc3d4928dea7ab"),
    ("third_party/googletest/src", f"{GH}/google/googletest.git",                          "4fe018038f87675c083d0cfb6a6b57c274fb1753"),
    ("third_party/icu",            f"{GH}/denoland/icu.git",                               "aef20f06d47ba76fdf13abcdb033e2a408b5a94d"),
]

def run(cmd, **kw):
    print(f"  $ {cmd}")
    r = subprocess.run(cmd, shell=True, **kw)
    if r.returncode != 0:
        print(f"  FAILED (exit {r.returncode})")
        sys.exit(1)

root = os.getcwd()

for path, url, commit in DEPS:
    print(f"\n=== {path} @ {commit[:10]} ===")
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    run(f"git clone {url} {full}")
    os.chdir(full)
    run(f"git checkout {commit}")
    os.chdir(root)

print("\n=== All deps cloned successfully ===")
