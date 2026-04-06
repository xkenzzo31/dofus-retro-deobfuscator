# ============================================================================
# dofus-retro-deobfuscator — Multi-stage Docker build
#
# Stage 1 (v8-builder): Compiles V8 8.7.220.31 with bytecode disassembly patches
# Stage 2 (runtime):    Node.js + Python3 runtime with the full deobfuscation pipeline
#
# ZERO requests to chromium.googlesource.com:
#   - V8 source from github.com/v8/v8
#   - Essential deps from GitHub mirrors (gsource-mirror, QPDFium)
#   - All unnecessary deps skipped via custom_deps
#
# Author: Luska
# ============================================================================

# ── Stage 1: Build V8 8.7 + v8dasm ─────────────────────────────────────────
FROM ubuntu:20.04 AS v8-builder

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/depot_tools:${PATH}"
ENV DEPOT_TOOLS_UPDATE=0

RUN apt-get update && apt-get install -y \
    git curl python3 python3-pip pkg-config \
    build-essential clang lld ninja-build \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && rm -rf /var/lib/apt/lists/*

# Install Chromium depot_tools (provides gclient, gn)
RUN git clone --depth=1 https://chromium.googlesource.com/chromium/tools/depot_tools.git /depot_tools

# Generate .gclient with GitHub mirrors and skipped deps
WORKDIR /v8_build
COPY gclient_spec.py /tmp/gclient_spec.py
RUN python3 /tmp/gclient_spec.py > .gclient \
    && cat .gclient \
    && gclient sync --no-history --shallow --revision v8@8.7.220.31 -D --nohooks --jobs 4 \
    && bash /depot_tools/ensure_bootstrap

# Apply patches to bypass version/checksum checks and enable bytecode printing
WORKDIR /v8_build/v8
COPY v8dasm/patch_v8.py /tmp/patch_v8.py
RUN python3 /tmp/patch_v8.py \
    && sed -i '/exec_script_whitelist/,/\]/d' .gn

# Configure and build V8 as a static monolith (no ICU, no custom libc++)
RUN mkdir -p out/Default \
    && printf 'is_debug = false\ntarget_cpu = "x64"\nv8_enable_disassembler = true\nv8_enable_object_print = true\nis_component_build = false\nv8_monolithic = true\nuse_custom_libcxx = false\nv8_use_external_startup_data = false\nv8_enable_i18n_support = false\ntreat_warnings_as_errors = false\n' > out/Default/args.gn \
    && gn gen out/Default \
    && /usr/bin/ninja -C out/Default v8_monolith -j$(nproc)

# Compile v8dasm against the monolith
COPY v8dasm/v8dasm.cc /tmp/v8dasm.cc
RUN g++ -std=c++17 -O2 \
    -DV8_COMPRESS_POINTERS -DV8_31BIT_SMIS_ON_64BIT_ARCH \
    -I include -I . \
    /tmp/v8dasm.cc \
    -o /usr/local/bin/v8dasm \
    -lv8_monolith -L out/Default/obj \
    -lm -ldl -lpthread -lz \
    && echo "v8dasm built successfully"


# ── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM node:18-slim

RUN apt-get update && apt-get install -y \
    python3 curl zip \
    && rm -rf /var/lib/apt/lists/*

# Copy v8dasm binary from builder
COPY --from=v8-builder /usr/local/bin/v8dasm /usr/local/bin/v8dasm

# Install webcrack globally
RUN npm install -g webcrack@2 2>/dev/null

# Copy pipeline scripts
WORKDIR /app
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/deobfuscate.sh

# Copy pre-captured resolution data (Ghidra analysis + runtime captures)
COPY data/ /app/data/

# Output directory (mount point)
VOLUME /output

ENTRYPOINT ["/app/scripts/deobfuscate.sh"]
CMD ["--help"]
