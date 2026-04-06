# ============================================================================
# dofus-retro-deobfuscator — Multi-stage Docker build
#
# Stage 1 (v8-builder): Compiles V8 8.7.220.31 with bytecode disassembly patches
# Stage 2 (runtime):    Node.js + Python3 runtime with the full deobfuscation pipeline
#
# Uses GitHub mirrors for V8 deps to avoid HTTP 429 rate-limiting
# from chromium.googlesource.com.
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
RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git /depot_tools

# Redirect rate-limited googlesource repos to GitHub mirrors
# This lets gclient sync work unchanged while fetching from GitHub
RUN git config --global url."https://github.com/gsource-mirror/chromium-src-build".insteadOf "https://chromium.googlesource.com/chromium/src/build" \
    && git config --global url."https://github.com/gsource-mirror/chromium-src-buildtools".insteadOf "https://chromium.googlesource.com/chromium/src/buildtools" \
    && git config --global url."https://github.com/QPDFium/common".insteadOf "https://chromium.googlesource.com/chromium/src/base/trace_event/common" \
    && git config --global url."https://github.com/gsource-mirror/chromium-src-third_party-zlib".insteadOf "https://chromium.googlesource.com/chromium/src/third_party/zlib" \
    && git config --global url."https://github.com/QPDFium/instrumented_libraries".insteadOf "https://chromium.googlesource.com/chromium/src/third_party/instrumented_libraries"

# Fetch V8 8.7.220.31 (matches Electron 11.x / Dofus Retro)
WORKDIR /v8_build
RUN echo 'solutions = [{"name": "v8", "url": "https://chromium.googlesource.com/v8/v8.git", "deps_file": "DEPS", "managed": False}]' > .gclient \
    && for attempt in 1 2 3; do \
         echo "=== gclient sync attempt $attempt/3 ===" ; \
         if gclient sync --no-history --shallow --revision v8@8.7.220.31 -D --jobs 4; then \
           echo "=== sync succeeded ===" ; break ; \
         fi ; \
         if [ "$attempt" -eq 3 ]; then echo "=== all attempts failed ===" ; exit 1; fi ; \
         echo "=== cleaning state and retrying in 30s ===" ; \
         rm -rf /v8_build/v8 /v8_build/_bad_scm ; \
         sleep 30 ; \
       done

# Apply patches to bypass version/checksum checks and enable bytecode printing
WORKDIR /v8_build/v8
COPY v8dasm/patch_v8.py /tmp/patch_v8.py
RUN python3 /tmp/patch_v8.py

# Configure and build V8 as a static monolith
RUN mkdir -p out/Default \
    && printf 'is_debug = false\ntarget_cpu = "x64"\nv8_enable_disassembler = true\nv8_enable_object_print = true\nis_component_build = false\nv8_monolithic = true\nuse_custom_libcxx = false\nv8_use_external_startup_data = false\ntreat_warnings_as_errors = false\n' > out/Default/args.gn \
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
