# ============================================================================
# dofus-retro-deobfuscator — Multi-stage Docker build
#
# Stage 1 (v8-builder):     Compiles V8 8.7.220.31 + v8dasm (with --decode-strings)
# Stage 2 (ghidra-builder): Compiles Ghidra V8 8.7 plugin for headless analysis
# Stage 3 (runtime):        Full deobfuscation pipeline (autonomous, no pre-captured data)
#
# Author: Luska
# ============================================================================

# ── Stage 1: Build V8 8.7 + v8dasm ─────────────────────────────────────────
FROM ubuntu:20.04 AS v8-builder

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/depot_tools:${PATH}"

RUN apt-get update && apt-get install -y \
    git curl python3 python3-pip pkg-config \
    build-essential clang lld ninja-build \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && rm -rf /var/lib/apt/lists/*

# Install Chromium depot_tools (provides gclient, gn)
RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git /depot_tools

# Fetch V8 8.7.220.31 (matches Electron 11.x / Dofus Retro)
WORKDIR /v8_build
RUN echo 'solutions = [{"name": "v8", "url": "https://chromium.googlesource.com/v8/v8.git", "deps_file": "DEPS", "managed": False}]' > .gclient \
    && gclient sync --no-history --shallow --revision v8@8.7.220.31 -D 2>&1 | tail -5 || true

# Apply patches to bypass version/checksum checks and enable bytecode printing
WORKDIR /v8_build/v8
COPY v8dasm/patch_v8.py /tmp/patch_v8.py
RUN python3 /tmp/patch_v8.py

# Configure and build V8 as a static monolith
RUN mkdir -p out/Default \
    && printf 'is_debug = false\ntarget_cpu = "x64"\nv8_enable_disassembler = true\nv8_enable_object_print = true\nis_component_build = false\nv8_monolithic = true\nuse_custom_libcxx = false\nv8_use_external_startup_data = false\ntreat_warnings_as_errors = false\n' > out/Default/args.gn \
    && gn gen out/Default \
    && /usr/bin/ninja -C out/Default v8_monolith -j4

# Compile v8dasm against the monolith (now with --decode-strings support)
COPY v8dasm/v8dasm.cc /tmp/v8dasm.cc
RUN g++ -std=c++17 -O2 \
    -DV8_COMPRESS_POINTERS -DV8_31BIT_SMIS_ON_64BIT_ARCH \
    -I include -I . \
    /tmp/v8dasm.cc \
    -o /usr/local/bin/v8dasm \
    -lv8_monolith -L out/Default/obj \
    -lm -ldl -lpthread -lz \
    && echo "v8dasm built successfully"


# ── Stage 2: Build Ghidra V8 plugin ────────────────────────────────────────
FROM eclipse-temurin:21-jdk-jammy AS ghidra-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Download Ghidra 12.0.4
RUN curl -fsSL -o /tmp/ghidra.zip \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip" \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip \
    && ln -s /opt/ghidra_12.0.4_PUBLIC /opt/ghidra

# Download Gradle
RUN curl -fsSL -o /tmp/gradle.zip \
    "https://services.gradle.org/distributions/gradle-8.5-bin.zip" \
    && unzip -q /tmp/gradle.zip -d /opt \
    && rm /tmp/gradle.zip \
    && ln -s /opt/gradle-8.5/bin/gradle /usr/local/bin/gradle

# Copy plugin source and build
COPY ghidra-plugin/ /tmp/ghidra-plugin/
WORKDIR /tmp/ghidra-plugin
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
RUN gradle buildExtension \
    && echo "Ghidra V8 plugin built successfully" \
    && ls dist/*.zip


# ── Stage 3: Runtime ───────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-jammy

RUN apt-get update && apt-get install -y \
    python3 curl zip nodejs npm \
    && npm install -g webcrack@2 2>/dev/null \
    && rm -rf /var/lib/apt/lists/*

# Copy v8dasm binary from builder
COPY --from=v8-builder /usr/local/bin/v8dasm /usr/local/bin/v8dasm

# Copy Ghidra + plugin from builder
COPY --from=ghidra-builder /opt/ghidra /opt/ghidra
COPY --from=ghidra-builder /tmp/ghidra-plugin/dist/*.zip /tmp/ghidra-plugin.zip
RUN mkdir -p /opt/ghidra/Ghidra/Extensions \
    && unzip -q /tmp/ghidra-plugin.zip -d /opt/ghidra/Ghidra/Extensions \
    && rm /tmp/ghidra-plugin.zip
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Copy Ghidra analysis scripts
COPY ghidra-plugin/ghidra_scripts/ /app/ghidra_scripts/

# Copy pipeline scripts
WORKDIR /app
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/deobfuscate.sh

# Output directory (mount point)
VOLUME /output

ENTRYPOINT ["/app/scripts/deobfuscate.sh"]
CMD ["--help"]
