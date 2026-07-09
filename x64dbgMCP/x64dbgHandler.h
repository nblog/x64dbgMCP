#pragma once

#include "plugintemplate/pluginmain.h"
#include "plugintemplate/pluginsdk/lz4/lz4.h"
#include <msclr/marshal.h>
#include <msclr/marshal_cppstd.h>
#include <vector>

namespace x64dbgMCP {

    using namespace System;
    using namespace System::Collections::Generic;
    using namespace System::ComponentModel;
    using namespace System::Runtime::InteropServices;
    using namespace System::Text;
    using namespace System::Text::Json;
    using namespace System::Text::Json::Serialization;
    using namespace ModelContextProtocol::Protocol;
    using namespace ModelContextProtocol::Server;

    // ────────────────────────────────────────────────────────────────
    //  Result envelope (conventions.md §4, ADR-004)
    // ────────────────────────────────────────────────────────────────

    public ref class ErrorInfo
    {
    public:
        [JsonPropertyName("code")]
        property String^ Code;

        [JsonPropertyName("message")]
        property String^ Message;

        [JsonPropertyName("details")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Object^ Details;
    };

    public ref class LinkRef
    {
    public:
        [JsonPropertyName("uri")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Uri;

        [JsonPropertyName("tool")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Tool;

        [JsonPropertyName("args")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, Object^>^ Args;
    };

    public ref class PageInfo
    {
    public:
        [JsonPropertyName("offset")]  property int Offset;
        [JsonPropertyName("limit")]   property int Limit;
        [JsonPropertyName("total")]   property int Total;
        [JsonPropertyName("hasMore")] property bool HasMore;
    };

    public ref class McpResult
    {
    public:
        [JsonPropertyName("success")]
        property bool Success;

        [JsonPropertyName("error")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property ErrorInfo^ Error;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    // ────────────────────────────────────────────────────────────────
    //  Helpers (conventions.md §2, §3, §5; ADR-002)
    // ────────────────────────────────────────────────────────────────

    ref class Helpers abstract sealed
    {
    public:
        static String^ PluginVersion()
        {
            return (gcnew Version(
                (PLUGIN_VERSION >> 16) & 0xFF,
                (PLUGIN_VERSION >> 8) & 0xFF,
                PLUGIN_VERSION & 0xFF))->ToString();
        }

        static String^ Platform()
        {
#ifdef _WIN64
            return BridgeIsARM64Emulated() ? "arm64" : "x64";
#else
            return "x86";
#endif
        }

        static String^ X64dbgDirectory()
        {
            const wchar_t* p = BridgeUserDirectory();
            return p ? gcnew String(p) : String::Empty;
        }

        static String^ FormatAddress(duint addr)
        {
            return "0x" + addr.ToString("X");
        }

        static String^ FromCStr(const char* s)
        {
            return s ? gcnew String(s) : nullptr;
        }

        static bool ResolveExpression(String^ expr, [Out] duint% result)
        {
            result = 0;
            if (String::IsNullOrEmpty(expr)) return false;

            std::string s = msclr::interop::marshal_as<std::string>(expr);
            duint v = 0;
            if (!Script::Misc::ParseExpression(s.c_str(), &v)) return false;
            result = v;
            return true;
        }

        static ErrorInfo^ MakeError(String^ code, String^ message)
        {
            auto e = gcnew ErrorInfo();
            e->Code = code;
            e->Message = message;
            return e;
        }

        static LinkRef^ UriLink(String^ uri)
        {
            auto l = gcnew LinkRef();
            l->Uri = uri;
            return l;
        }

        static LinkRef^ ToolLink(String^ tool, Dictionary<String^, Object^>^ args)
        {
            auto l = gcnew LinkRef();
            l->Tool = tool;
            l->Args = args;
            return l;
        }
    };

    // ────────────────────────────────────────────────────────────────
    //  Resource payloads (tools-spec.md §2)
    // ────────────────────────────────────────────────────────────────

    public ref class SessionInfo
    {
    public:
        [JsonPropertyName("pluginVersion")]   property String^ PluginVersion;
        [JsonPropertyName("platform")]        property String^ Platform;
        [JsonPropertyName("x64dbgDirectory")] property String^ X64dbgDirectory;
        [JsonPropertyName("isDebugging")]     property bool IsDebugging;
        [JsonPropertyName("isRunning")]       property bool IsRunning;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    public ref class ModuleEntry
    {
    public:
        [JsonPropertyName("name")]         property String^ Name;
        [JsonPropertyName("path")]         property String^ Path;
        [JsonPropertyName("base")]         property String^ Base;
        [JsonPropertyName("size")]         property String^ Size;
        [JsonPropertyName("entry")]        property String^ Entry;
        [JsonPropertyName("isMainModule")] property bool IsMainModule;
    };

    public ref class ModulesPayload
    {
    public:
        [JsonPropertyName("data")] property List<ModuleEntry^>^ Data;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    // ────────────────────────────────────────────────────────────────
    //  Tool result types (tools-spec.md §3, §5)
    // ────────────────────────────────────────────────────────────────

    public ref class DisassembleEntry
    {
    public:
        [JsonPropertyName("address")]
        property String^ Address;

        [JsonPropertyName("mnemonic")]
        property String^ Mnemonic;

        [JsonPropertyName("operands")]
        property String^ Operands;

        [JsonPropertyName("bytes")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Bytes;

        [JsonPropertyName("size")]
        property int Size;

        [JsonPropertyName("comment")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Comment;
    };

    public ref class DisassembleResult : McpResult
    {
    public:
        [JsonPropertyName("data")]
        property List<DisassembleEntry^>^ Data;
    };

    public ref class MemoryReadResult : McpResult
    {
    public:
        [JsonPropertyName("address")]
        property String^ Address;

        [JsonPropertyName("size")]
        property int Size;

        [JsonPropertyName("encoding")]
        property String^ Encoding;

        [JsonPropertyName("base64")]
        property String^ Base64;

        [JsonPropertyName("compressedSize")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingDefault)]
        property int CompressedSize;
    };

    public ref class DebugControlResult : McpResult
    {
    public:
        [JsonPropertyName("action")]
        property String^ Action;

        [JsonPropertyName("isDebugging")]
        property bool IsDebugging;

        [JsonPropertyName("isRunning")]
        property bool IsRunning;

        [JsonPropertyName("commandOutput")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ CommandOutput;
    };

    public ref class RegistersOpResult : McpResult
    {
    public:
        [JsonPropertyName("name")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Name;

        [JsonPropertyName("value")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Value;

        [JsonPropertyName("previous")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Previous;
    };

    public ref class RegisterDumpResult : McpResult
    {
    public:
        [JsonPropertyName("threadId")]
        property int ThreadId;

        [JsonPropertyName("registers")]
        property Dictionary<String^, String^>^ Registers;

        [JsonPropertyName("flags")]
        property Dictionary<String^, bool>^ Flags;
    };

    // ────────────────────────────────────────────────────────────────
    //  Resources — McpResources (ADR-003 Layer A)
    // ────────────────────────────────────────────────────────────────

    [McpServerResourceType]
    public ref class McpResources abstract sealed
    {
    public:
        [McpServerResource(UriTemplate = "x64dbg://session", Name = "session", MimeType = "application/json")]
        [Description("Snapshot of the current x64dbg/plugin session: plugin version, target platform, debug state, and navigation links.")]
        static ResourceContents^ Session()
        {
            auto info = gcnew SessionInfo();
            info->PluginVersion = Helpers::PluginVersion();
            info->Platform = Helpers::Platform();
            info->X64dbgDirectory = Helpers::X64dbgDirectory();
            info->IsDebugging = DbgIsDebugging();
            info->IsRunning = info->IsDebugging && DbgIsRunning();
            info->Links = gcnew Dictionary<String^, LinkRef^>();
            info->Links["self"] = Helpers::UriLink("x64dbg://session");
            info->Links["modules"] = Helpers::UriLink("x64dbg://modules");

            return MakeJson(info, "x64dbg://session");
        }

        [McpServerResource(UriTemplate = "x64dbg://modules", Name = "modules", MimeType = "application/json")]
        [Description("List of all loaded modules in the debugged process. Empty when not debugging.")]
        static ResourceContents^ Modules()
        {
            auto payload = gcnew ModulesPayload();
            payload->Data = gcnew List<ModuleEntry^>();
            payload->Links = gcnew Dictionary<String^, LinkRef^>();
            payload->Links["self"] = Helpers::UriLink("x64dbg://modules");
            payload->Links["session"] = Helpers::UriLink("x64dbg://session");

            if (DbgIsDebugging())
            {
                BridgeList<Script::Module::ModuleInfo> list;
                if (Script::Module::GetList(&list))
                {
                    duint mainBase = Script::Module::GetMainModuleBase();
                    for (int i = 0; i < list.Count(); i++)
                    {
                        const auto& m = list[i];
                        auto e = gcnew ModuleEntry();
                        e->Name = Helpers::FromCStr(m.name);
                        e->Path = Helpers::FromCStr(m.path);
                        e->Base = Helpers::FormatAddress(m.base);
                        e->Size = Helpers::FormatAddress(m.size);
                        e->Entry = Helpers::FormatAddress(m.entry);
                        e->IsMainModule = (m.base == mainBase);
                        payload->Data->Add(e);
                    }
                }
            }

            return MakeJson(payload, "x64dbg://modules");
        }

    private:
        generic <typename T>
        static ResourceContents^ MakeJson(T value, String^ uri)
        {
            auto txt = gcnew TextResourceContents();
            txt->Text = JsonSerializer::Serialize<T>(value);
            txt->MimeType = "application/json";
            txt->Uri = uri;
            return txt;
        }
    };

    // ────────────────────────────────────────────────────────────────
    //  Analysis tools (rich-param) — McpAnalysisTools (ADR-003 Layer B)
    // ────────────────────────────────────────────────────────────────

    [McpServerToolType]
    public ref class McpAnalysisTools abstract sealed
    {
    public:
        [McpServerTool(ReadOnly = true)]
        [Description("Disassemble up to N instructions starting at the given address or x64dbg expression.")]
        static DisassembleResult^ Disassemble(
            [Description("Address or x64dbg expression (e.g. \"rax\", \"kernel32:CreateFileW\", \"cip+0x10\")")]
            String^ addr,
            [Description("Number of instructions to disassemble (1-200)")]
            int count,
            [Description("Include raw byte sequence for each instruction (default false)")]
            [DefaultValue(false)]
            bool withBytes)
        {
            auto r = gcnew DisassembleResult();
            r->Data = gcnew List<DisassembleEntry^>();

            if (count < 1 || count > 200)
            {
                r->Success = false;
                r->Error = Helpers::MakeError("invalid_argument", "count must be in [1, 200]");
                return r;
            }
            if (!DbgIsDebugging())
            {
                r->Success = false;
                r->Error = Helpers::MakeError("not_attached", "no active debug session");
                return r;
            }

            duint cur = 0;
            if (!Helpers::ResolveExpression(addr, cur))
            {
                r->Success = false;
                r->Error = Helpers::MakeError("not_found", "could not resolve address: " + addr);
                return r;
            }

            for (int i = 0; i < count; i++)
            {
                BASIC_INSTRUCTION_INFO bi;
                memset(&bi, 0, sizeof(bi));
                DbgDisasmFastAt(cur, &bi);
                int sz = bi.size > 0 ? bi.size : 1;

                auto e = gcnew DisassembleEntry();
                e->Address = Helpers::FormatAddress(cur);
                e->Size = sz;

                String^ full = Helpers::FromCStr(bi.instruction);
                if (full == nullptr) full = String::Empty;
                int sp = full->IndexOf(' ');
                if (sp > 0)
                {
                    e->Mnemonic = full->Substring(0, sp);
                    e->Operands = full->Substring(sp + 1)->Trim();
                }
                else
                {
                    e->Mnemonic = full;
                    e->Operands = String::Empty;
                }

                if (withBytes && sz > 0 && sz <= 16)
                {
                    array<unsigned char>^ bytes = gcnew array<unsigned char>(sz);
                    pin_ptr<unsigned char> p = &bytes[0];
                    if (DbgMemRead(cur, p, sz))
                    {
                        auto sb = gcnew StringBuilder(sz * 2);
                        for (int j = 0; j < sz; j++) sb->AppendFormat("{0:X2}", bytes[j]);
                        e->Bytes = sb->ToString();
                    }
                }

                r->Data->Add(e);
                cur += (duint)sz;
            }

            r->Success = true;
            return r;
        }

        [McpServerTool(ReadOnly = true)]
        [Description(
            "Read memory from the debugged process. Returns base64-encoded bytes.\n"
        )]
        static MemoryReadResult^ MemoryRead(
            [Description("Address or x64dbg expression (e.g. \"rax\", \"kernel32:CreateFileW\", \"cip+0x10\")")]
            String^ addr,
            [Description("Number of bytes to read (1-65536)")]
            int size,
            [Description("Compress payload with lz4 before base64 (recommended for size > ~4 KiB)")]
            [DefaultValue(false)]
            bool compress)
        {
            auto r = gcnew MemoryReadResult();
            if (size < 1 || size > 65536)
            {
                r->Success = false;
                r->Error = Helpers::MakeError("invalid_argument", "size must be in [1, 65536]");
                return r;
            }
            if (!DbgIsDebugging())
            {
                r->Success = false;
                r->Error = Helpers::MakeError("not_attached", "no active debug session");
                return r;
            }

            duint a = 0;
            if (!Helpers::ResolveExpression(addr, a))
            {
                r->Success = false;
                r->Error = Helpers::MakeError("not_found", "could not resolve address: " + addr);
                return r;
            }

            array<unsigned char>^ buf = gcnew array<unsigned char>(size);
            {
                pin_ptr<unsigned char> p = &buf[0];
                if (!DbgMemRead(a, p, (duint)size))
                {
                    r->Success = false;
                    r->Error = Helpers::MakeError("x64dbg_failed", "DbgMemRead failed");
                    return r;
                }
            }

            r->Address = Helpers::FormatAddress(a);
            r->Size = size;

            if (compress)
            {
                int bound = LZ4_compressBound(size);
                if (bound <= 0)
                {
                    r->Success = false;
                    r->Error = Helpers::MakeError("internal", "LZ4_compressBound returned non-positive");
                    return r;
                }
                std::vector<char> out((size_t)bound);
                int compressed;
                {
                    pin_ptr<unsigned char> p = &buf[0];
                    compressed = LZ4_compress(reinterpret_cast<const char*>(p), out.data(), size);
                }
                if (compressed <= 0)
                {
                    r->Success = false;
                    r->Error = Helpers::MakeError("internal", "LZ4_compress failed");
                    return r;
                }
                array<unsigned char>^ cbuf = gcnew array<unsigned char>(compressed);
                Marshal::Copy(IntPtr((void*)out.data()), cbuf, 0, compressed);

                r->Encoding = "lz4";
                r->Base64 = Convert::ToBase64String(cbuf);
                r->CompressedSize = compressed;
            }
            else
            {
                r->Encoding = "raw";
                r->Base64 = Convert::ToBase64String(buf);
            }

            r->Success = true;
            return r;
        }
    };

    // ────────────────────────────────────────────────────────────────
    //  Debug-mode tools (mega) — McpDebuggingTools (ADR-003 Layer C)
    // ────────────────────────────────────────────────────────────────

    [McpServerToolType]
    public ref class McpDebuggingTools abstract sealed
    {
    public:
        [McpServerTool]
        [Description(
            "Debug control. Drives the x64dbg debug session.\n"
            "Actions:\n"
            "  init        : { exePath, cmdLine?, curFolder? } -- load and start a new debuggee\n"
            "  stop        : detach/terminate the debuggee\n"
            "  run         : continue execution (returns immediately, does not wait for next pause)\n"
            "  pause       : break into the debugger\n"
            "  StepInto    : single-step into\n"
            "  StepOver    : single-step over calls\n"
            "  StepOut     : run until current function returns\n"
            "  run_command : { command, wait? } -- raw x64dbg command (https://help.x64dbg.com/en/latest/commands/index.html); wait=true uses DbgCmdExecDirect\n"
        )]
        static Object^ DebugControl(
            [Description("Action: \"run\"|\"pause\"|\"stop\"|\"StepInto\"|\"StepOver\"|\"StepOut\"|\"init\"|\"run_command\"")]
            String^ action,
            [Description("Path to executable (required for action=init)")]
            [DefaultValue("")]
            String^ exePath,
            [Description("Command line to pass to the debuggee (action=init only)")]
            [DefaultValue("")]
            String^ cmdLine,
            [Description("Current folder for the debuggee (action=init only)")]
            [DefaultValue("")]
            String^ curFolder,
            [Description("Raw x64dbg command (required for action=run_command)")]
            [DefaultValue("")]
            String^ command,
            [Description("If true and action=run_command, wait for completion via DbgCmdExecDirect")]
            [DefaultValue(false)]
            bool wait)
        {
            auto r = gcnew DebugControlResult();
            r->Action = action;

            String^ cmd = nullptr;
            bool needsAttach = true;
            bool useDirect = false;

            if (action == "run")             cmd = "run";
            else if (action == "pause")      cmd = "pause";
            else if (action == "stop")       cmd = "stop";
            else if (action == "StepInto")   cmd = "StepInto";
            else if (action == "StepOver")   cmd = "StepOver";
            else if (action == "StepOut")    cmd = "StepOut";
            else if (action == "init")
            {
                if (String::IsNullOrEmpty(exePath))
                {
                    r->Success = false;
                    r->Error = Helpers::MakeError("invalid_argument", "exePath is required for action=init");
                    return r;
                }
                cmd = BuildInitCommand(exePath, cmdLine, curFolder);
                needsAttach = false;
            }
            else if (action == "run_command")
            {
                if (String::IsNullOrEmpty(command))
                {
                    r->Success = false;
                    r->Error = Helpers::MakeError("invalid_argument", "command is required for action=run_command");
                    return r;
                }
                cmd = command;
                needsAttach = false;
                useDirect = wait;
            }
            else
            {
                r->Success = false;
                r->Error = Helpers::MakeError(
                    "invalid_argument",
                    "unknown action: " + (action ? action : "<null>"));
                return r;
            }

            if (needsAttach && !DbgIsDebugging())
            {
                r->Success = false;
                r->Error = Helpers::MakeError("not_attached", "no active debug session");
                return r;
            }

            std::string c = msclr::interop::marshal_as<std::string>(cmd);
            bool ok = useDirect ? DbgCmdExecDirect(c.c_str()) : DbgCmdExec(c.c_str());

            if (!ok)
            {
                r->Success = false;
                r->Error = Helpers::MakeError("x64dbg_failed", "command failed: " + cmd);
                return r;
            }

            r->Success = true;
            r->IsDebugging = DbgIsDebugging();
            r->IsRunning = r->IsDebugging && DbgIsRunning();
            return r;
        }

        [McpServerTool]
        [Description(
            "Registers control. Actions:\n"
            "  get  : { name } -> { name, value }       — name is any x64dbg-known register/flag (rax, eip, zf, r8d, _zf...).\n"
            "  set  : { name, value } -> { name, value, previous } — value accepts any x64dbg expression.\n"
            "  dump : { } -> { registers, flags }        — all GPRs (arch-agnostic) + flags."
        )]
        static Object^ Registers(
            [Description("Action: \"get\" | \"set\" | \"dump\"")]
            String^ action,
            [Description("Register/flag name (required for get/set; e.g. \"rax\", \"zf\")")]
            [DefaultValue("")]
            String^ name,
            [Description("Value or x64dbg expression (required for set; e.g. \"0x1000\", \"rax+8\")")]
            [DefaultValue("")]
            String^ value)
        {
            if (!DbgIsDebugging())
            {
                auto r = gcnew RegistersOpResult();
                r->Success = false;
                r->Error = Helpers::MakeError("not_attached", "no active debug session");
                return r;
            }

            if (action == "dump") return DumpAction();
            if (action == "get")  return GetAction(name);
            if (action == "set")  return SetAction(name, value);

            auto r = gcnew RegistersOpResult();
            r->Success = false;
            r->Error = Helpers::MakeError(
                "invalid_argument",
                "unknown action: " + (action ? action : "<null>") + "; expected get|set|dump");
            return r;
        }

    private:
        static String^ BuildInitCommand(String^ exePath, String^ cmdLine, String^ curFolder)
        {
            auto sb = gcnew StringBuilder("init ");
            AppendQuoted(sb, exePath);
            bool hasCmd = !String::IsNullOrEmpty(cmdLine);
            bool hasCwd = !String::IsNullOrEmpty(curFolder);
            if (hasCmd || hasCwd)
            {
                sb->Append(",");
                AppendQuoted(sb, hasCmd ? cmdLine : "");
            }
            if (hasCwd)
            {
                sb->Append(",");
                AppendQuoted(sb, curFolder);
            }
            return sb->ToString();
        }

        static void AppendQuoted(StringBuilder^ sb, String^ value)
        {
            sb->Append("\"")->Append(value->Replace("\"", "\\\""))->Append("\"");
        }

        static RegistersOpResult^ GetAction(String^ name)
        {
            auto r = gcnew RegistersOpResult();
            if (String::IsNullOrEmpty(name))
            {
                r->Success = false;
                r->Error = Helpers::MakeError("invalid_argument", "name is required for action=get");
                return r;
            }
            duint v = 0;
            if (!Helpers::ResolveExpression(name, v))
            {
                r->Success = false;
                r->Error = Helpers::MakeError("not_found", "could not resolve register/flag: " + name);
                return r;
            }
            r->Success = true;
            r->Name = name;
            r->Value = Helpers::FormatAddress(v);
            return r;
        }

        static RegistersOpResult^ SetAction(String^ name, String^ value)
        {
            auto r = gcnew RegistersOpResult();
            if (String::IsNullOrEmpty(name) || String::IsNullOrEmpty(value))
            {
                r->Success = false;
                r->Error = Helpers::MakeError("invalid_argument", "name and value are required for action=set");
                return r;
            }

            duint prev = 0;
            bool prevOk = Helpers::ResolveExpression(name, prev);

            duint v = 0;
            if (!Helpers::ResolveExpression(value, v))
            {
                r->Success = false;
                r->Error = Helpers::MakeError("invalid_argument", "could not parse value: " + value);
                return r;
            }

            std::string n = msclr::interop::marshal_as<std::string>(name);
            if (!DbgValToString(n.c_str(), v))
            {
                r->Success = false;
                r->Error = Helpers::MakeError("x64dbg_failed", "DbgValToString failed for: " + name);
                return r;
            }

            r->Success = true;
            r->Name = name;
            r->Value = Helpers::FormatAddress(v);
            if (prevOk) r->Previous = Helpers::FormatAddress(prev);
            return r;
        }

        static RegisterDumpResult^ DumpAction()
        {
            auto r = gcnew RegisterDumpResult();
            r->Success = true;
            { duint tid = -1; if (Helpers::ResolveExpression("tid()", tid)) r->ThreadId = (int)tid; }
            r->Registers = gcnew Dictionary<String^, String^>();
            r->Flags = gcnew Dictionary<String^, bool>();

            array<String^>^ regs = gcnew array<String^>{
#if 0
                "cax", "cbx", "ccx", "cdx", "csi", "cdi", "cbp", "csp", "cip",
#elif defined(_WIN64)
				"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
#else
				"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
#endif
            };
            for each (String ^ rn in regs)
            {
                duint v = 0;
                if (Helpers::ResolveExpression(rn, v))
                    r->Registers[rn] = Helpers::FormatAddress(v);
            }

            r->Flags["zf"] = Script::Flag::Get(Script::Flag::ZF);
            r->Flags["of"] = Script::Flag::Get(Script::Flag::OF);
            r->Flags["cf"] = Script::Flag::Get(Script::Flag::CF);
            r->Flags["pf"] = Script::Flag::Get(Script::Flag::PF);
            r->Flags["sf"] = Script::Flag::Get(Script::Flag::SF);
            r->Flags["tf"] = Script::Flag::Get(Script::Flag::TF);
            r->Flags["af"] = Script::Flag::Get(Script::Flag::AF);
            r->Flags["df"] = Script::Flag::Get(Script::Flag::DF);
            r->Flags["if"] = Script::Flag::Get(Script::Flag::IF);

            return r;
        }
    };
}
