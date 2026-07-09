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

        // https://help.x64dbg.com/en/latest/introduction/Expression-functions.html
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

    public ref class ProcessInfo
    {
    public:
        // [JsonPropertyName("handle")]         property String^ Handle;
        [JsonPropertyName("processId")]         property int ProcessId;
        [JsonPropertyName("threadId")]          property int ThreadId;
        [JsonPropertyName("base")]              property String^ ImageBase;
        [JsonPropertyName("entry")]             property String^ EntryPoint;
        [JsonPropertyName("peb")]               property String^ PebAddress;
        [JsonPropertyName("teb")]               property String^ TebAddress;
        [JsonPropertyName("kUserSharedData")]   property String^ KUserSharedData;
        [JsonPropertyName("path")]              property String^ Path;

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

        [JsonPropertyName("lastError")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ LastError;

        [JsonPropertyName("lastStatus")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ LastStatus;
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
            info->Links["process"] = Helpers::UriLink("x64dbg://process");
            info->Links["modules"] = Helpers::UriLink("x64dbg://modules");

            return MakeJson(info, "x64dbg://session");
        }

        [McpServerResource(UriTemplate = "x64dbg://process", Name = "process", MimeType = "application/json")]
        [Description("Information about the currently debugged process: PID, path, handle, image base, thread info, and system structures.")]
        static ResourceContents^ Process()
        {
            auto info = gcnew ProcessInfo();
            info->ProcessId = 0;
            info->ThreadId = 0;
            info->ImageBase = nullptr;
			info->EntryPoint = nullptr;
            info->PebAddress = nullptr;
            info->TebAddress = nullptr;
            info->KUserSharedData = nullptr;
            info->Path = nullptr;
            info->Links = gcnew Dictionary<String^, LinkRef^>();
            info->Links["self"] = Helpers::UriLink("x64dbg://process");
            info->Links["session"] = Helpers::UriLink("x64dbg://session");

            if (DbgIsDebugging())
            {
                duint value = 0;

                //// Get process handle
                //HANDLE hProcess = DbgGetProcessHandle();
                //if (hProcess)
                //    info->Handle = Helpers::FormatAddress((duint)hProcess);

                // Get process ID
				if (Script::Misc::ParseExpression("$pid", &value))
					info->ProcessId = (int)value;

                // Get current thread ID
                if (Script::Misc::ParseExpression("tid()", &value))
                    info->ThreadId = (int)value;

                // Get PEB address
				if (Script::Misc::ParseExpression("peb()", &value))
					info->PebAddress = Helpers::FormatAddress(value);

                // Get TEB address for current thread
                if (Script::Misc::ParseExpression("teb()", &value))
                    info->TebAddress = Helpers::FormatAddress(value);

				// Get KUSER_SHARED_DATA address (always 0x7FFE0000 on Windows)
				if (Script::Misc::ParseExpression("kusd()", &value))
					info->KUserSharedData = Helpers::FormatAddress(value);

                // Get main module info for path and image base
                Script::Module::ModuleInfo mod;
                if (Script::Module::GetMainModuleInfo(&mod))
                {
                    info->ImageBase = Helpers::FormatAddress(mod.base);
					info->EntryPoint = Helpers::FormatAddress(mod.entry);
                    info->Path = Helpers::FromCStr(mod.path);
                }

                info->Links["modules"] = Helpers::UriLink("x64dbg://modules");
                info->Links["threads"] = Helpers::UriLink("x64dbg://threads");
            }

            return MakeJson(info, "x64dbg://process");
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
    //  Unmanaged helpers for DbgGetRegDumpEx
    // ────────────────────────────────────────────────────────────────

#pragma unmanaged
    static bool GetRegisterDumpUnmanaged(REGDUMP_AVX512* regdump)
    {
        return DbgGetRegDumpEx(regdump, sizeof(REGDUMP_AVX512));
    }
#pragma managed

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
            if (!DbgValSetScalar(n.c_str(), v))
            {
                r->Success = false;
                r->Error = Helpers::MakeError("x64dbg_failed", "DbgValSetScalar/DbgValToString failed for: " + name);
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
            r->ThreadId = (int)DbgGetThreadId();
            r->Registers = gcnew Dictionary<String^, String^>();
            r->Flags = gcnew Dictionary<String^, bool>();

            // Allocate REGDUMP_AVX512 on unmanaged heap
            REGDUMP_AVX512* regdump = new REGDUMP_AVX512();
            if (!GetRegisterDumpUnmanaged(regdump))
            {
                delete regdump;
                r->Success = false;
				r->Error = Helpers::MakeError("not_attached", "DbgGetRegDumpEx failed - not debugging or no thread context");
                return r;
            }

            auto& ctx = regdump->regcontext;

            // General-purpose registers
#ifdef _WIN64
            r->Registers["rax"] = Helpers::FormatAddress(ctx.cax);
            r->Registers["rbx"] = Helpers::FormatAddress(ctx.cbx);
            r->Registers["rcx"] = Helpers::FormatAddress(ctx.ccx);
            r->Registers["rdx"] = Helpers::FormatAddress(ctx.cdx);
            r->Registers["rsi"] = Helpers::FormatAddress(ctx.csi);
            r->Registers["rdi"] = Helpers::FormatAddress(ctx.cdi);
            r->Registers["rbp"] = Helpers::FormatAddress(ctx.cbp);
            r->Registers["rsp"] = Helpers::FormatAddress(ctx.csp);
            r->Registers["rip"] = Helpers::FormatAddress(ctx.cip);
            r->Registers["r8"]  = Helpers::FormatAddress(ctx.r8);
            r->Registers["r9"]  = Helpers::FormatAddress(ctx.r9);
            r->Registers["r10"] = Helpers::FormatAddress(ctx.r10);
            r->Registers["r11"] = Helpers::FormatAddress(ctx.r11);
            r->Registers["r12"] = Helpers::FormatAddress(ctx.r12);
            r->Registers["r13"] = Helpers::FormatAddress(ctx.r13);
            r->Registers["r14"] = Helpers::FormatAddress(ctx.r14);
            r->Registers["r15"] = Helpers::FormatAddress(ctx.r15);
#else
            r->Registers["eax"] = Helpers::FormatAddress(ctx.cax);
            r->Registers["ebx"] = Helpers::FormatAddress(ctx.cbx);
            r->Registers["ecx"] = Helpers::FormatAddress(ctx.ccx);
            r->Registers["edx"] = Helpers::FormatAddress(ctx.cdx);
            r->Registers["esi"] = Helpers::FormatAddress(ctx.csi);
            r->Registers["edi"] = Helpers::FormatAddress(ctx.cdi);
            r->Registers["ebp"] = Helpers::FormatAddress(ctx.cbp);
            r->Registers["esp"] = Helpers::FormatAddress(ctx.csp);
            r->Registers["eip"] = Helpers::FormatAddress(ctx.cip);
#endif

            // Segment registers
            r->Registers["cs"] = Helpers::FormatAddress(ctx.cs);
            r->Registers["ds"] = Helpers::FormatAddress(ctx.ds);
            r->Registers["es"] = Helpers::FormatAddress(ctx.es);
            r->Registers["fs"] = Helpers::FormatAddress(ctx.fs);
            r->Registers["gs"] = Helpers::FormatAddress(ctx.gs);
            r->Registers["ss"] = Helpers::FormatAddress(ctx.ss);

            // Debug registers
            r->Registers["dr0"] = Helpers::FormatAddress(ctx.dr0);
            r->Registers["dr1"] = Helpers::FormatAddress(ctx.dr1);
            r->Registers["dr2"] = Helpers::FormatAddress(ctx.dr2);
            r->Registers["dr3"] = Helpers::FormatAddress(ctx.dr3);
            r->Registers["dr6"] = Helpers::FormatAddress(ctx.dr6);
            r->Registers["dr7"] = Helpers::FormatAddress(ctx.dr7);

            // Flags - extract from eflags (REGDUMP_AVX512 doesn't have FLAGS field)
            duint eflags = ctx.eflags;
            r->Flags["cf"] = (eflags & 0x0001) != 0;  // Carry Flag
            r->Flags["pf"] = (eflags & 0x0004) != 0;  // Parity Flag
            r->Flags["af"] = (eflags & 0x0010) != 0;  // Auxiliary Carry Flag
            r->Flags["zf"] = (eflags & 0x0040) != 0;  // Zero Flag
            r->Flags["sf"] = (eflags & 0x0080) != 0;  // Sign Flag
            r->Flags["tf"] = (eflags & 0x0100) != 0;  // Trap Flag
            r->Flags["if"] = (eflags & 0x0200) != 0;  // Interrupt Enable Flag
            r->Flags["df"] = (eflags & 0x0400) != 0;  // Direction Flag
            r->Flags["of"] = (eflags & 0x0800) != 0;  // Overflow Flag

            // LastError and LastStatus from REGDUMP_AVX512
            if (regdump->lastError != 0)
                r->LastError = Helpers::FormatAddress(regdump->lastError);

            if (regdump->lastStatus != 0)
                r->LastStatus = Helpers::FormatAddress(regdump->lastStatus);

            delete regdump;
            return r;
        }
    };
}
