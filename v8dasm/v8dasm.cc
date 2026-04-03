// v8dasm — V8 Ignition bytecode disassembler for .jsc files
//
// Deserializes V8 8.7.220.31 cached data (.jsc) and prints
// the Ignition bytecode of every SharedFunctionInfo in the script.
//
// Based on: https://github.com/nicedoc/v8dasm
// Adapted by: Luska
//
// Usage: v8dasm <input.jsc> [> output.txt]

#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

#include "include/libplatform/libplatform.h"
#include "include/v8.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: v8dasm <input.jsc> [> output.txt]" << std::endl;
        return 1;
    }

    const char* jsc_path = argv[1];

    // Read the .jsc file into memory
    std::ifstream file(jsc_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: cannot open " << jsc_path << std::endl;
        return 1;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "Error: cannot read " << jsc_path << std::endl;
        return 1;
    }
    file.close();

    std::cerr << "File: " << jsc_path << " (" << size << " bytes)" << std::endl;

    // Extract source_length from the .jsc header (offset 8, uint32 LE, mask off bit 31)
    uint32_t source_hash = *reinterpret_cast<uint32_t*>(buffer.data() + 8);
    uint32_t source_length = source_hash & 0x7FFFFFFF;
    std::cerr << "Source length from header: " << source_length << std::endl;

    // Initialize V8
    std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
    v8::V8::InitializePlatform(platform.get());
    v8::V8::Initialize();

    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);

    {
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);

        // Build a dummy source string of the expected length
        std::string dummy_source(source_length, ' ');
        v8::Local<v8::String> source = v8::String::NewFromUtf8(
            isolate, dummy_source.c_str(), v8::NewStringType::kNormal,
            source_length).ToLocalChecked();

        // Wrap the file buffer as V8 CachedData
        v8::ScriptCompiler::CachedData* cached_data =
            new v8::ScriptCompiler::CachedData(
                buffer.data(), buffer.size(),
                v8::ScriptCompiler::CachedData::BufferNotOwned);

        v8::ScriptCompiler::Source script_source(source, cached_data);

        // Compile — deserialization triggers our patched bytecode printer
        v8::Local<v8::UnboundScript> script;
        if (!v8::ScriptCompiler::CompileUnboundScript(
                isolate, &script_source,
                v8::ScriptCompiler::kConsumeCodeCache)
                .ToLocal(&script)) {
            std::cerr << "Error: CompileUnboundScript failed" << std::endl;
            if (cached_data->rejected) {
                std::cerr << "Error: cached data was rejected" << std::endl;
            }
        } else {
            if (cached_data->rejected) {
                std::cerr << "Warning: cached data was rejected (version mismatch?)" << std::endl;
            } else {
                std::cerr << "Success: bytecode deserialized and disassembled" << std::endl;
            }
        }
    }

    isolate->Dispose();
    v8::V8::Dispose();
    v8::V8::ShutdownPlatform();
    delete create_params.array_buffer_allocator;

    return 0;
}
