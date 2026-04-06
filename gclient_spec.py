#!/usr/bin/env python3
"""Generate .gclient spec with GitHub mirrors for V8 8.7 deps.

Avoids ALL requests to chromium.googlesource.com by:
- Fetching V8 from github.com/v8/v8
- Redirecting essential deps to GitHub mirrors
- Skipping all unnecessary deps (test, android, fuchsia, etc.)
"""

GH = "https://github.com"

# GitHub mirrors for essential deps (verified to have the correct commits)
MIRRORS = {
    "v8/build":                    f"{GH}/gsource-mirror/chromium-src-build.git",
    "v8/buildtools":               f"{GH}/gsource-mirror/chromium-src-buildtools.git",
    "v8/base/trace_event/common":  f"{GH}/QPDFium/common.git",
    "v8/third_party/zlib":         f"{GH}/gsource-mirror/chromium-src-third_party-zlib.git",
    "v8/third_party/jinja2":       f"{GH}/QPDFium/jinja2.git",
    "v8/third_party/markupsafe":   f"{GH}/QPDFium/markupsafe.git",
}

# Deps not needed for building v8_monolith + v8dasm
SKIP = [
    "v8/third_party/icu",
    "v8/third_party/instrumented_libraries",
    "v8/third_party/android_ndk",
    "v8/third_party/android_platform",
    "v8/third_party/catapult",
    "v8/third_party/fuchsia-sdk",
    "v8/third_party/depot_tools",
    "v8/third_party/requests",
    "v8/third_party/colorama/src",
    "v8/third_party/google_benchmark/src",
    "v8/third_party/googletest/src",
    "v8/third_party/protobuf",
    "v8/third_party/ittapi",
    "v8/third_party/jsoncpp/source",
    "v8/third_party/perfetto",
    "v8/tools/clang",
    "v8/tools/swarming_client",
    "v8/buildtools/clang_format/script",
    "v8/buildtools/third_party/libc++/trunk",
    "v8/buildtools/third_party/libc++abi/trunk",
    "v8/buildtools/third_party/libunwind/trunk",
    "v8/test/benchmarks/data",
    "v8/test/mozilla/data",
    "v8/test/test262/data",
    "v8/test/test262/harness",
]

custom_deps = {}
for k, v in MIRRORS.items():
    custom_deps[k] = v
for s in SKIP:
    custom_deps[s] = None

print("solutions = [")
print("  {")
print('    "name": "v8",')
print('    "url": "https://github.com/v8/v8.git",')
print('    "deps_file": "DEPS",')
print('    "managed": False,')
print('    "custom_deps": {')
for k, v in custom_deps.items():
    if v is None:
        print(f'      "{k}": None,')
    else:
        print(f'      "{k}": "{v}",')
print("    },")
print("  },")
print("]")
