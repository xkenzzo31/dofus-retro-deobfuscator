// v8dasm — V8 Ignition bytecode disassembler for .jsc files
//
// Deserializes V8 8.7.220.31 cached data (.jsc) and prints
// the Ignition bytecode of every SharedFunctionInfo in the script.
//
// Modes:
//   v8dasm <input.jsc>                    Disassemble bytecode (default)
//   v8dasm <input.jsc> --decode-strings   Execute script, extract decoded string array as JSON
//
// Based on: https://github.com/nicedoc/v8dasm
// Adapted by: Luska

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "include/libplatform/libplatform.h"
#include "include/v8.h"

// ── Helpers for --decode-strings mode ──

static void DummyRequire(const v8::FunctionCallbackInfo<v8::Value>& args) {
    // Return an empty object for any require() call.
    // This lets the script run past require('electron'), require('path'), etc.
    // without crashing — the returned value is inert but won't throw.
    v8::Isolate* iso = args.GetIsolate();
    v8::Local<v8::Object> empty = v8::Object::New(iso);
    args.GetReturnValue().Set(empty);
}

static void DummyProcessExit(const v8::FunctionCallbackInfo<v8::Value>&) {
    // No-op: prevent process.exit() from terminating
}

static std::string EscapeJsonString(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    o << buf;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

// Inject globals that the obfuscated script expects (require, module, process, etc.)
static void InjectDummyGlobals(v8::Isolate* isolate, v8::Local<v8::Context> context) {
    auto global = context->Global();

    // require() — returns empty object
    auto require_fn = v8::FunctionTemplate::New(isolate, DummyRequire)
        ->GetFunction(context).ToLocalChecked();
    global->Set(context,
        v8::String::NewFromUtf8(isolate, "require").ToLocalChecked(),
        require_fn).Check();

    // module.exports
    auto module_obj = v8::Object::New(isolate);
    module_obj->Set(context,
        v8::String::NewFromUtf8(isolate, "exports").ToLocalChecked(),
        v8::Object::New(isolate)).Check();
    global->Set(context,
        v8::String::NewFromUtf8(isolate, "module").ToLocalChecked(),
        module_obj).Check();

    // exports
    global->Set(context,
        v8::String::NewFromUtf8(isolate, "exports").ToLocalChecked(),
        v8::Object::New(isolate)).Check();

    // __dirname / __filename
    global->Set(context,
        v8::String::NewFromUtf8(isolate, "__dirname").ToLocalChecked(),
        v8::String::NewFromUtf8(isolate, "/tmp").ToLocalChecked()).Check();
    global->Set(context,
        v8::String::NewFromUtf8(isolate, "__filename").ToLocalChecked(),
        v8::String::NewFromUtf8(isolate, "/tmp/main.js").ToLocalChecked()).Check();

    // process (minimal stub)
    auto process_obj = v8::Object::New(isolate);
    process_obj->Set(context,
        v8::String::NewFromUtf8(isolate, "platform").ToLocalChecked(),
        v8::String::NewFromUtf8(isolate, "linux").ToLocalChecked()).Check();
    process_obj->Set(context,
        v8::String::NewFromUtf8(isolate, "arch").ToLocalChecked(),
        v8::String::NewFromUtf8(isolate, "x64").ToLocalChecked()).Check();
    auto env_obj = v8::Object::New(isolate);
    process_obj->Set(context,
        v8::String::NewFromUtf8(isolate, "env").ToLocalChecked(),
        env_obj).Check();
    auto versions_obj = v8::Object::New(isolate);
    versions_obj->Set(context,
        v8::String::NewFromUtf8(isolate, "node").ToLocalChecked(),
        v8::String::NewFromUtf8(isolate, "12.18.3").ToLocalChecked()).Check();
    versions_obj->Set(context,
        v8::String::NewFromUtf8(isolate, "electron").ToLocalChecked(),
        v8::String::NewFromUtf8(isolate, "11.5.0").ToLocalChecked()).Check();
    process_obj->Set(context,
        v8::String::NewFromUtf8(isolate, "versions").ToLocalChecked(),
        versions_obj).Check();
    process_obj->Set(context,
        v8::String::NewFromUtf8(isolate, "exit").ToLocalChecked(),
        v8::FunctionTemplate::New(isolate, DummyProcessExit)
            ->GetFunction(context).ToLocalChecked()).Check();
    process_obj->Set(context,
        v8::String::NewFromUtf8(isolate, "cwd").ToLocalChecked(),
        v8::FunctionTemplate::New(isolate, [](const v8::FunctionCallbackInfo<v8::Value>& args) {
            args.GetReturnValue().Set(
                v8::String::NewFromUtf8(args.GetIsolate(), "/tmp").ToLocalChecked());
        })->GetFunction(context).ToLocalChecked()).Check();
    global->Set(context,
        v8::String::NewFromUtf8(isolate, "process").ToLocalChecked(),
        process_obj).Check();

    // global = globalThis
    global->Set(context,
        v8::String::NewFromUtf8(isolate, "global").ToLocalChecked(),
        global).Check();

    // Buffer (minimal)
    auto buffer_obj = v8::Object::New(isolate);
    buffer_obj->Set(context,
        v8::String::NewFromUtf8(isolate, "from").ToLocalChecked(),
        v8::FunctionTemplate::New(isolate, [](const v8::FunctionCallbackInfo<v8::Value>& args) {
            args.GetReturnValue().Set(args[0]);
        })->GetFunction(context).ToLocalChecked()).Check();
    global->Set(context,
        v8::String::NewFromUtf8(isolate, "Buffer").ToLocalChecked(),
        buffer_obj).Check();
}

// Find the string array by enumerating global functions and calling each.
// The string array function returns an Array of 5000+ string elements.
static bool ExtractDecodedStrings(v8::Isolate* isolate, v8::Local<v8::Context> context) {
    auto global = context->Global();
    auto prop_names = global->GetOwnPropertyNames(context).ToLocalChecked();
    uint32_t count = prop_names->Length();

    for (uint32_t i = 0; i < count; i++) {
        auto key = prop_names->Get(context, i).ToLocalChecked();
        v8::String::Utf8Value key_str(isolate, key);
        std::string name(*key_str);

        // Only check a0_0x* or _0x* named functions (obfuscator.io pattern)
        if (name.find("0x") == std::string::npos) continue;

        auto val = global->Get(context, key).ToLocalChecked();
        if (!val->IsFunction()) continue;

        // Try calling with no arguments
        v8::TryCatch call_try(isolate);
        auto fn = val.As<v8::Function>();
        auto result = fn->Call(context, global, 0, nullptr);

        if (call_try.HasCaught() || result.IsEmpty()) continue;
        auto result_val = result.ToLocalChecked();
        if (!result_val->IsArray()) continue;

        auto arr = result_val.As<v8::Array>();
        uint32_t len = arr->Length();
        if (len < 1000) continue; // Not the string array

        std::cerr << "Found string array: " << name << " (" << len << " elements)" << std::endl;

        // Determine base index by looking for the decoder function (a0_0x* with 2 params)
        // Default to 276 (known for current Dofus Retro)
        int base_index = 276;

        // Output as JSON
        std::cout << "{" << std::endl;
        std::cout << "  \"source\": \"v8dasm --decode-strings\"," << std::endl;
        std::cout << "  \"string_array_function\": \"" << EscapeJsonString(name) << "\"," << std::endl;
        std::cout << "  \"total_entries\": " << len << "," << std::endl;
        std::cout << "  \"base_index\": " << base_index << "," << std::endl;
        std::cout << "  \"mappings\": {" << std::endl;

        bool first = true;
        uint32_t valid_count = 0;
        for (uint32_t j = 0; j < len; j++) {
            auto elem = arr->Get(context, j).ToLocalChecked();
            if (!elem->IsString()) continue;

            v8::String::Utf8Value str(isolate, elem);
            if (*str == nullptr) continue;

            int index = base_index + j;
            if (!first) std::cout << "," << std::endl;
            std::cout << "    \"" << index << "\": \"" << EscapeJsonString(*str) << "\"";
            first = false;
            valid_count++;
        }

        std::cout << std::endl << "  }" << std::endl;
        std::cout << "}" << std::endl;

        std::cerr << "Extracted " << valid_count << " decoded strings" << std::endl;
        return true;
    }

    std::cerr << "Error: could not find string array function in globals" << std::endl;
    return false;
}


// ── Main ──

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: v8dasm <input.jsc> [> output.txt]" << std::endl;
        std::cerr << "       v8dasm <input.jsc> --decode-strings [> strings.json]" << std::endl;
        return 1;
    }

    const char* jsc_path = argv[1];
    bool decode_strings = (argc > 2 && strcmp(argv[2], "--decode-strings") == 0);

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

    int exit_code = 0;

    {
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        v8::Local<v8::Context> context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);

        // For --decode-strings, inject dummy Node.js globals before compilation
        if (decode_strings) {
            InjectDummyGlobals(isolate, context);
        }

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
            exit_code = 1;
        } else {
            if (cached_data->rejected) {
                std::cerr << "Warning: cached data was rejected (version mismatch?)" << std::endl;
            } else {
                std::cerr << "Success: bytecode deserialized" << std::endl;
            }

            // ── Decode strings mode ──
            if (decode_strings) {
                std::cerr << "Executing script to decode string array..." << std::endl;

                auto bound = script->BindToCurrentContext();
                v8::TryCatch try_catch(isolate);

                // Execute the script. The string array + rotation runs first.
                // It will eventually throw when it hits actual business code
                // that requires real Node.js APIs — that's fine.
                auto run_result = bound->Run(context);

                if (try_catch.HasCaught()) {
                    v8::String::Utf8Value err(isolate, try_catch.Exception());
                    std::cerr << "Script threw (expected): " << *err << std::endl;
                }

                // Now find and extract the decoded string array from global scope
                if (!ExtractDecodedStrings(isolate, context)) {
                    std::cerr << "Error: failed to extract decoded strings" << std::endl;
                    exit_code = 1;
                }
            }
        }
    }

    isolate->Dispose();
    v8::V8::Dispose();
    v8::V8::ShutdownPlatform();
    delete create_params.array_buffer_allocator;

    return exit_code;
}
