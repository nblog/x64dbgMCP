#pragma once

#include "plugintemplate/pluginmain.h"
#include "plugintemplate/pluginsdk/lz4/lz4.h"
#include <atomic>
#include <chrono>
#include <cstddef>
#include <future>
#include <msclr/marshal.h>
#include <msclr/marshal_cppstd.h>
#include <mutex>
#include <objidl.h>
#include <string>
#include <wincodec.h>
#include <winternl.h>
#include <vector>

namespace x64dbgMCP {

    namespace {
        std::mutex g_attachMutex;
    }

    using namespace System;
    using namespace System::Collections::Generic;
    using namespace System::ComponentModel;
    using namespace System::Globalization;
    using namespace System::IO;
    using namespace System::Runtime::InteropServices;
    using namespace System::Security::Cryptography;
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

        static String^ FromCStrOrNull(const char* s)
        {
            return s && *s ? gcnew String(s) : nullptr;
        }

        static String^ FromUtf8OrNull(const char* s)
        {
            if (!s || !*s) return nullptr;

            int length = (int)strlen(s);
            auto bytes = gcnew array<unsigned char>(length);
            Marshal::Copy(IntPtr((void*)s), bytes, 0, length);
            return Encoding::UTF8->GetString(bytes);
        }

        static String^ BreakpointTypeName(BPXTYPE type)
        {
            switch (type)
            {
            case bp_normal:    return "normal";
            case bp_hardware:  return "hardware";
            case bp_memory:    return "memory";
            case bp_dll:       return "dll";
            case bp_exception: return "exception";
            default:           return "unknown";
            }
        }

        static String^ BreakpointSubtypeName(BPXTYPE type, unsigned char subtype)
        {
            switch (type)
            {
            case bp_hardware:
                switch ((BPHWTYPE)subtype)
                {
                case hw_access:  return "access";
                case hw_write:   return "write";
                case hw_execute: return "execute";
                default:         return "unknown";
                }
            case bp_memory:
                switch ((BPMEMTYPE)subtype)
                {
                case mem_access:  return "access";
                case mem_read:    return "read";
                case mem_write:   return "write";
                case mem_execute: return "execute";
                default:          return "unknown";
                }
            case bp_dll:
                switch ((BPDLLTYPE)subtype)
                {
                case dll_load:   return "load";
                case dll_unload: return "unload";
                case dll_all:    return "all";
                default:         return "unknown";
                }
            case bp_exception:
                switch ((BPEXTYPE)subtype)
                {
                case ex_firstchance:  return "first_chance";
                case ex_secondchance: return "second_chance";
                case ex_all:          return "all";
                default:              return "unknown";
                }
            default:
                return nullptr;
            }
        }

        static String^ HardwareBreakpointSizeName(unsigned char size)
        {
            switch ((BPHWSIZE)size)
            {
            case hw_byte:  return "byte";
            case hw_word:  return "word";
            case hw_dword: return "dword";
            case hw_qword: return "qword";
            default:       return "unknown";
            }
        }

        static String^ FormatMemoryProtection(DWORD protect)
        {
            char rights[RIGHTS_STRING_SIZE]{};
            return DbgFunctions()->PageRightsToString(protect, rights)
                ? Helpers::FromCStr(rights)
                : nullptr;
        }

        static String^ MemoryStateName(DWORD state)
        {
            switch (state)
            {
            case MEM_COMMIT:  return "commit";
            case MEM_RESERVE: return "reserve";
            case MEM_FREE:    return "free";
            default:          return "unknown";
            }
        }

        static String^ MemoryTypeName(DWORD type)
        {
            switch (type)
            {
            case MEM_IMAGE:   return "image";
            case MEM_MAPPED:  return "mapped";
            case MEM_PRIVATE: return "private";
            default:          return "unknown";
            }
        }

        static String^ ThreadPriorityName(THREADPRIORITY priority)
        {
            switch (priority)
            {
            case _PriorityIdle:         return "Idle";
            case _PriorityAboveNormal:  return "AboveNormal";
            case _PriorityBelowNormal:  return "BelowNormal";
            case _PriorityHighest:      return "Highest";
            case _PriorityLowest:       return "Lowest";
            case _PriorityNormal:       return "Normal";
            case _PriorityTimeCritical: return "TimeCritical";
            default:                    return "Unknown";
            }
        }

        static String^ ThreadWaitReasonName(THREADWAITREASON reason)
        {
            switch (reason)
            {
            case _Executive:        return "Executive";
            case _FreePage:         return "FreePage";
            case _PageIn:           return "PageIn";
            case _PoolAllocation:   return "PoolAllocation";
            case _DelayExecution:   return "DelayExecution";
            case _Suspended:        return "Suspended";
            case _UserRequest:      return "UserRequest";
            case _WrExecutive:      return "WrExecutive";
            case _WrFreePage:       return "WrFreePage";
            case _WrPageIn:         return "WrPageIn";
            case _WrPoolAllocation: return "WrPoolAllocation";
            case _WrDelayExecution: return "WrDelayExecution";
            case _WrSuspended:      return "WrSuspended";
            case _WrUserRequest:    return "WrUserRequest";
            case _WrEventPair:      return "WrEventPair";
            case _WrQueue:          return "WrQueue";
            case _WrLpcReceive:     return "WrLpcReceive";
            case _WrLpcReply:       return "WrLpcReply";
            case _WrVirtualMemory:  return "WrVirtualMemory";
            case _WrPageOut:        return "WrPageOut";
            case _WrRendezvous:     return "WrRendezvous";
            case _Spare2:           return "Spare2";
            case _Spare3:           return "Spare3";
            case _Spare4:           return "Spare4";
            case _Spare5:           return "Spare5";
            case _WrCalloutStack:   return "WrCalloutStack";
            case _WrKernel:         return "WrKernel";
            case _WrResource:       return "WrResource";
            case _WrPushLock:       return "WrPushLock";
            case _WrMutex:          return "WrMutex";
            case _WrQuantumEnd:     return "WrQuantumEnd";
            case _WrDispatchInt:    return "WrDispatchInt";
            case _WrPreempted:      return "WrPreempted";
            case _WrYieldExecution: return "WrYieldExecution";
            case _WrFastMutex:      return "WrFastMutex";
            case _WrGuardedMutex:   return "WrGuardedMutex";
            case _WrRundown:        return "WrRundown";
            default:                return "Unknown";
            }
        }

        static UInt64 FileTimeValue(FILETIME value)
        {
            return ((UInt64)value.dwHighDateTime << 32) | value.dwLowDateTime;
        }

        static String^ FormatFileTimeDuration(FILETIME value)
        {
            UInt64 ticks = FileTimeValue(value);
            UInt64 totalSeconds = ticks / 10000000;
            UInt64 days = totalSeconds / 86400;
            UInt64 hours = (totalSeconds / 3600) % 24;
            UInt64 minutes = (totalSeconds / 60) % 60;
            UInt64 seconds = totalSeconds % 60;
            UInt64 fraction = ticks % 10000000;
            String^ time = hours.ToString("D2") + ":"
                + minutes.ToString("D2") + ":"
                + seconds.ToString("D2") + "."
                + fraction.ToString("D7");
            return days == 0 ? time : days.ToString() + ":" + time;
        }

        static String^ FormatFileTimeUtc(FILETIME value)
        {
            UInt64 ticks = FileTimeValue(value);
            return ticks == 0 ? nullptr : DateTime::FromFileTimeUtc((Int64)ticks).ToString("O");
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

    public ref class ModuleInfo
    {
    public:
        [JsonPropertyName("name")]         property String^ Name;
        [JsonPropertyName("path")]         property String^ Path;
        [JsonPropertyName("base")]         property String^ Base;
        [JsonPropertyName("size")]         property String^ Size;
        [JsonPropertyName("entry")]        property String^ Entry;
        [JsonPropertyName("sectionCount")] property int SectionCount;
        [JsonPropertyName("isMainModule")] property bool IsMainModule;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    public ref class ModulesPayload
    {
    public:
        [JsonPropertyName("data")] property List<ModuleInfo^>^ Data;

        [JsonPropertyName("page")]
        property PageInfo^ Page;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    public ref class ModuleSection
    {
    public:
        [JsonPropertyName("name")]    property String^ Name;
        [JsonPropertyName("address")] property String^ Address;
        [JsonPropertyName("size")]    property String^ Size;
    };

    public ref class ModuleExport
    {
    public:
        [JsonPropertyName("name")]            property String^ Name;
        [JsonPropertyName("undecoratedName")] property String^ UndecoratedName;

        [JsonPropertyName("forwardName")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ ForwardName;

        [JsonPropertyName("ordinal")] property int Ordinal;
        [JsonPropertyName("rva")]     property String^ Rva;
        [JsonPropertyName("va")]      property String^ Va;
    };

    public ref class ModuleImport
    {
    public:
        [JsonPropertyName("name")]            property String^ Name;
        [JsonPropertyName("undecoratedName")] property String^ UndecoratedName;
        [JsonPropertyName("iatRva")]          property String^ IatRva;
        [JsonPropertyName("iatVa")]           property String^ IatVa;
    };

    public ref class MemoryRegion
    {
    public:
        [JsonPropertyName("base")]              property String^ Base;
        [JsonPropertyName("allocationBase")]    property String^ AllocationBase;
        [JsonPropertyName("size")]              property String^ Size;
        [JsonPropertyName("allocationProtect")] property String^ AllocationProtect;
        [JsonPropertyName("protect")]           property String^ Protect;
        [JsonPropertyName("state")]             property String^ State;
        [JsonPropertyName("type")]              property String^ Type;

        [JsonPropertyName("info")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Info;
    };

    public ref class MemoryMapsPayload
    {
    public:
        [JsonPropertyName("data")] property List<MemoryRegion^>^ Data;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    public ref class ThreadInfo
    {
    public:
        // [JsonPropertyName("handle")]       property String^ Handle;
        [JsonPropertyName("threadNumber")] property int ThreadNumber;
        [JsonPropertyName("threadId")]     property int ThreadId;

        [JsonPropertyName("name")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Name;

        [JsonPropertyName("pc")]           property String^ Cip;
        [JsonPropertyName("entryPoint")]   property String^ EntryPoint;
        [JsonPropertyName("tebAddress")]   property String^ TebAddress;
        [JsonPropertyName("suspendCount")] property UInt32 SuspendCount;
        [JsonPropertyName("priority")]     property String^ Priority;
        [JsonPropertyName("waitReason")]   property String^ WaitReason;
        [JsonPropertyName("lastError")]    property UInt32 LastError;
        [JsonPropertyName("userTime")]     property String^ UserTime;
        [JsonPropertyName("kernelTime")]   property String^ KernelTime;

        [JsonPropertyName("creationTime")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ CreationTime;

        [JsonPropertyName("cycles")]   property UInt64 Cycles;
        [JsonPropertyName("isActive")] property bool IsActive;
    };

    public ref class ThreadsPayload
    {
    public:
        [JsonPropertyName("data")] property List<ThreadInfo^>^ Data;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    public ref class BreakpointEntry
    {
    public:
        [JsonPropertyName("type")]
        property String^ Type;

        [JsonPropertyName("subtype")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Subtype;

        [JsonPropertyName("address")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Address;

        [JsonPropertyName("exceptionCode")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ ExceptionCode;

        [JsonPropertyName("hardwareSize")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ HardwareSize;

        [JsonPropertyName("hardwareSlot")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Nullable<int> HardwareSlot;

        [JsonPropertyName("enabled")]     property bool Enabled;
        [JsonPropertyName("singleShoot")] property bool SingleShoot;
        [JsonPropertyName("active")]      property bool Active;

        [JsonPropertyName("name")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Name;

        [JsonPropertyName("module")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Module;

        [JsonPropertyName("hitCount")]   property UInt32 HitCount;
        [JsonPropertyName("fastResume")] property bool FastResume;
        [JsonPropertyName("silent")]     property bool Silent;

        [JsonPropertyName("breakCondition")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ BreakCondition;

        [JsonPropertyName("logText")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ LogText;

        [JsonPropertyName("logCondition")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ LogCondition;

        [JsonPropertyName("commandText")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ CommandText;

        [JsonPropertyName("commandCondition")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ CommandCondition;
    };

    public ref class BreakpointsPayload
    {
    public:
        [JsonPropertyName("data")] property List<BreakpointEntry^>^ Data;
        [JsonPropertyName("page")] property PageInfo^ Page;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    public ref class WindowInfo
    {
    public:
        [JsonPropertyName("procedure")] property String^ Procedure;
        [JsonPropertyName("handle")]    property String^ Handle;
        [JsonPropertyName("title")]     property String^ Title;
        [JsonPropertyName("className")] property String^ ClassName;
        [JsonPropertyName("threadId")]  property UInt32 ThreadId;
        [JsonPropertyName("style")]     property String^ Style;
        [JsonPropertyName("styleEx")]   property String^ StyleEx;
        [JsonPropertyName("parent")]    property String^ Parent;
        [JsonPropertyName("left")]      property int Left;
        [JsonPropertyName("top")]       property int Top;
        [JsonPropertyName("width")]     property int Width;
        [JsonPropertyName("height")]    property int Height;
        [JsonPropertyName("enabled")]   property bool Enabled;
        [JsonPropertyName("userData")]  property String^ UserData;
    };

    public ref class WindowsPayload
    {
    public:
        [JsonPropertyName("data")] property List<WindowInfo^>^ Data;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    public ref class HandleInfo
    {
    public:
        [JsonPropertyName("type")]          property String^ Type;
        [JsonPropertyName("typeNumber")]    property String^ TypeNumber;
        [JsonPropertyName("handle")]       property String^ Handle;
        [JsonPropertyName("grantedAccess")] property String^ GrantedAccess;
        [JsonPropertyName("name")]         property String^ Name;
    };

    public ref class HandlesPayload
    {
    public:
        [JsonPropertyName("data")] property List<HandleInfo^>^ Data;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    public ref class TcpConnectionInfo
    {
    public:
        [JsonPropertyName("remoteAddress")] property String^ RemoteAddress;
        [JsonPropertyName("remotePort")]    property UInt16 RemotePort;
        [JsonPropertyName("localAddress")]  property String^ LocalAddress;
        [JsonPropertyName("localPort")]     property UInt16 LocalPort;
        [JsonPropertyName("stateText")]     property String^ StateText;
        [JsonPropertyName("state")]        property UInt32 State;
    };

    public ref class TcpConnectionsPayload
    {
    public:
        [JsonPropertyName("data")] property List<TcpConnectionInfo^>^ Data;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    public ref class DebuggeeInfo
    {
    public:
        // [JsonPropertyName("handle")]         property String^ Handle;
        [JsonPropertyName("elevated")]          property bool Elevated;
        [JsonPropertyName("processId")]         property int ProcessId;
        [JsonPropertyName("threadId")]          property int ThreadId;
        [JsonPropertyName("imageBase")]         property String^ ImageBase;
        [JsonPropertyName("entryPoint")]        property String^ EntryPoint;
        [JsonPropertyName("pebAddress")]        property String^ PebAddress;
        [JsonPropertyName("tebAddress")]        property String^ TebAddress;
        //[JsonPropertyName("kUserSharedData")]   property String^ KUserSharedData;
        [JsonPropertyName("path")]              property String^ Path;
        [JsonPropertyName("commandLine")]       property String^ CommandLine;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    public ref class AttachProcessInfo
    {
    public:
        [JsonPropertyName("processId")]            property int ProcessId;
        [JsonPropertyName("name")]                 property String^ Name;
        [JsonPropertyName("title")]                property String^ Title;
        [JsonPropertyName("path")]                 property String^ Path;
        [JsonPropertyName("commandLineArguments")] property String^ CommandLineArguments;
    };

    public ref class AttachProcessesPayload
    {
    public:
        [JsonPropertyName("data")] property List<AttachProcessInfo^>^ Data;
        [JsonPropertyName("page")] property PageInfo^ Page;

        [JsonPropertyName("_links")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property Dictionary<String^, LinkRef^>^ Links;
    };

    // ────────────────────────────────────────────────────────────────
    //  Tool result types (tools-spec.md §3, §5)
    // ────────────────────────────────────────────────────────────────

    public ref class DisassembleReference
    {
    public:
        [JsonPropertyName("kind")]
        property String^ Kind;

        [JsonPropertyName("address")]
        property String^ Address;

        [JsonPropertyName("name")]
        property String^ Name;
    };

    public ref class DisassembleEntry
    {
    public:
        [JsonPropertyName("address")]
        property String^ Address;

        [JsonPropertyName("mnemonic")]
        property String^ Mnemonic;

        [JsonPropertyName("operands")]
        property String^ Operands;

        [JsonPropertyName("display")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Display;

        [JsonPropertyName("reference")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property DisassembleReference^ Reference;

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

    public ref class DebugGUIRange
    {
    public:
        [JsonPropertyName("start")]
        property String^ Start;

        [JsonPropertyName("end")]
        property String^ End;
    };

    public ref class DebugGUIArtifact
    {
    public:
        [JsonPropertyName("type")]
        property String^ Type;

        [JsonPropertyName("mimeType")]
        property String^ MimeType;

        [JsonPropertyName("path")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property String^ Path;
    };

    public ref class DebugGUISnapshotData
    {
    public:
        [JsonPropertyName("action")]
        property String^ Action;

        [JsonPropertyName("artifact")]
        property DebugGUIArtifact^ Artifact;

        [JsonPropertyName("capturedAtUtc")]
        property String^ CapturedAtUtc;

        [JsonPropertyName("width")]
        property int Width;

        [JsonPropertyName("height")]
        property int Height;

        [JsonPropertyName("sha256")]
        property String^ Sha256;

        [JsonPropertyName("windowTitle")]
        property String^ WindowTitle;

        [JsonPropertyName("debuggeeProcessId")]
        property int DebuggeeProcessId;
    };

    public ref class DebugGUISnapshotResult : McpResult
    {
    public:
        [JsonPropertyName("data")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property DebugGUISnapshotData^ Data;
    };

    public ref class DebugGUIFocusData
    {
    public:
        [JsonPropertyName("action")]
        property String^ Action;

        [JsonPropertyName("window")]
        property String^ Window;

        [JsonPropertyName("refreshed")]
        property bool Refreshed;
    };

    public ref class DebugGUIFocusResult : McpResult
    {
    public:
        [JsonPropertyName("data")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property DebugGUIFocusData^ Data;
    };

    public ref class DebugGUIGetData
    {
    public:
        [JsonPropertyName("action")]
        property String^ Action;

        [JsonPropertyName("window")]
        property String^ Window;

        [JsonPropertyName("selection")]
        property DebugGUIRange^ Selection;
    };

    public ref class DebugGUIGetResult : McpResult
    {
    public:
        [JsonPropertyName("data")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property DebugGUIGetData^ Data;
    };

    public ref class DebugGUISetData
    {
    public:
        [JsonPropertyName("action")]
        property String^ Action;

        [JsonPropertyName("window")]
        property String^ Window;

        [JsonPropertyName("requested")]
        property DebugGUIRange^ Requested;

        [JsonPropertyName("actual")]
        property DebugGUIRange^ Actual;

        [JsonPropertyName("refreshed")]
        property bool Refreshed;
    };

    public ref class DebugGUISetResult : McpResult
    {
    public:
        [JsonPropertyName("data")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property DebugGUISetData^ Data;
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

    public ref class BreakpointResult : McpResult
    {
    public:
        [JsonPropertyName("data")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property BreakpointEntry^ Data;
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

    public ref class LoggingActionData
    {
    public:
        [JsonPropertyName("action")]
        property String^ Action;
    };

    public ref class LoggingResult : McpResult
    {
    public:
        [JsonPropertyName("data")]
        [JsonIgnore(Condition = JsonIgnoreCondition::WhenWritingNull)]
        property LoggingActionData^ Data;
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

#pragma unmanaged
    enum class DebugGUIWorkAction
    {
        Snapshot,
        Focus,
        Get,
        Set
    };

    enum class DebugGUIFailure
    {
        None,
        NotAttached,
        NotFound,
        X64dbgFailed
    };

    struct DebugGUIContext
    {
        std::atomic<int> references{ 2 };
        DebugGUIWorkAction action = DebugGUIWorkAction::Snapshot;
        GUISELECTIONTYPE selectionWindow = GUI_DISASSEMBLY;
        Script::Gui::Window scriptWindow = Script::Gui::DisassemblyWindow;
        duint requestedStart = 0;
        duint requestedEnd = 0;
        duint actualStart = 0;
        duint actualEnd = 0;
        int width = 0;
        int height = 0;
        DWORD debuggeeProcessId = 0;
        FILETIME capturedAtUtc{};
        std::wstring windowTitle;
        std::vector<unsigned char> png;
        DebugGUIFailure failure = DebugGUIFailure::None;
        std::string error;
        bool success = false;
        std::promise<void> completion;

        void Release()
        {
            if (references.fetch_sub(1) == 1)
                delete this;
        }
    };

    struct WindowBitmap
    {
        HWND window = nullptr;
        HDC windowDc = nullptr;
        HDC memoryDc = nullptr;
        HBITMAP bitmap = nullptr;
        HGDIOBJ previousBitmap = nullptr;
        void* bits = nullptr;

        ~WindowBitmap()
        {
            if (memoryDc && previousBitmap && previousBitmap != HGDI_ERROR)
                SelectObject(memoryDc, previousBitmap);
            if (bitmap)
                DeleteObject(bitmap);
            if (memoryDc)
                DeleteDC(memoryDc);
            if (windowDc)
                ReleaseDC(window, windowDc);
        }
    };

    struct ComApartmentScope
    {
        bool uninitialize = false;

        ~ComApartmentScope()
        {
            if (uninitialize)
                CoUninitialize();
        }
    };

    template <typename T>
    struct NativeComPtr
    {
        T* value = nullptr;

        NativeComPtr() = default;

        ~NativeComPtr()
        {
            if (value)
                value->Release();
        }

        T* Get() const
        {
            return value;
        }

        T** Address()
        {
            return &value;
        }

        T* operator->() const
        {
            return value;
        }

        NativeComPtr(const NativeComPtr&) = delete;
        NativeComPtr& operator=(const NativeComPtr&) = delete;
    };

    static std::string DebugGUIHResult(const char* operation, HRESULT result)
    {
        char buffer[128]{};
        sprintf_s(buffer, "%s failed with HRESULT 0x%08X", operation, (unsigned int)result);
        return buffer;
    }

    static bool EncodeWindowBitmapAsPng(
        const void* bits,
        int width,
        int height,
        std::vector<unsigned char>& png,
        std::string& error)
    {
        HRESULT initializeResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        ComApartmentScope apartment;
        apartment.uninitialize = SUCCEEDED(initializeResult);
        if (FAILED(initializeResult) && initializeResult != RPC_E_CHANGED_MODE)
        {
            error = DebugGUIHResult("CoInitializeEx", initializeResult);
            return false;
        }

        NativeComPtr<IWICImagingFactory> factory;
        HRESULT result = CoCreateInstance(
            CLSID_WICImagingFactory,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(factory.Address()));
        if (FAILED(result))
        {
            error = DebugGUIHResult("CoCreateInstance(CLSID_WICImagingFactory)", result);
            return false;
        }

        NativeComPtr<IStream> stream;
        result = CreateStreamOnHGlobal(nullptr, TRUE, stream.Address());
        if (FAILED(result))
        {
            error = DebugGUIHResult("CreateStreamOnHGlobal", result);
            return false;
        }

        NativeComPtr<IWICBitmapEncoder> encoder;
        result = factory->CreateEncoder(GUID_ContainerFormatPng, nullptr, encoder.Address());
        if (FAILED(result))
        {
            error = DebugGUIHResult("IWICImagingFactory::CreateEncoder", result);
            return false;
        }
        result = encoder->Initialize(stream.Get(), WICBitmapEncoderNoCache);
        if (FAILED(result))
        {
            error = DebugGUIHResult("IWICBitmapEncoder::Initialize", result);
            return false;
        }

        NativeComPtr<IWICBitmapFrameEncode> frame;
        result = encoder->CreateNewFrame(frame.Address(), nullptr);
        if (FAILED(result))
        {
            error = DebugGUIHResult("IWICBitmapEncoder::CreateNewFrame", result);
            return false;
        }
        result = frame->Initialize(nullptr);
        if (FAILED(result))
        {
            error = DebugGUIHResult("IWICBitmapFrameEncode::Initialize", result);
            return false;
        }
        result = frame->SetSize((UINT)width, (UINT)height);
        if (FAILED(result))
        {
            error = DebugGUIHResult("IWICBitmapFrameEncode::SetSize", result);
            return false;
        }

        WICPixelFormatGUID pixelFormat = GUID_WICPixelFormat32bppBGRA;
        result = frame->SetPixelFormat(&pixelFormat);
        if (FAILED(result) || !IsEqualGUID(pixelFormat, GUID_WICPixelFormat32bppBGRA))
        {
            error = FAILED(result)
                ? DebugGUIHResult("IWICBitmapFrameEncode::SetPixelFormat", result)
                : "PNG encoder did not accept 32bpp BGRA pixels";
            return false;
        }

        if ((unsigned long long)width * (unsigned long long)height * 4 > UINT_MAX)
        {
            error = "x64dbg capture bitmap exceeds the WIC input-size limit";
            return false;
        }
        UINT stride = (UINT)width * 4;
        UINT bufferSize = stride * (UINT)height;
        result = frame->WritePixels(
            (UINT)height,
            stride,
            bufferSize,
            const_cast<BYTE*>(static_cast<const BYTE*>(bits)));
        if (FAILED(result))
        {
            error = DebugGUIHResult("IWICBitmapFrameEncode::WritePixels", result);
            return false;
        }
        result = frame->Commit();
        if (FAILED(result))
        {
            error = DebugGUIHResult("IWICBitmapFrameEncode::Commit", result);
            return false;
        }
        result = encoder->Commit();
        if (FAILED(result))
        {
            error = DebugGUIHResult("IWICBitmapEncoder::Commit", result);
            return false;
        }

        STATSTG statistics{};
        result = stream->Stat(&statistics, STATFLAG_NONAME);
        if (FAILED(result) || statistics.cbSize.HighPart != 0 || statistics.cbSize.LowPart == 0)
        {
            error = FAILED(result)
                ? DebugGUIHResult("IStream::Stat", result)
                : "PNG stream size was invalid";
            return false;
        }

        LARGE_INTEGER beginning{};
        result = stream->Seek(beginning, STREAM_SEEK_SET, nullptr);
        if (FAILED(result))
        {
            error = DebugGUIHResult("IStream::Seek", result);
            return false;
        }

        png.resize(statistics.cbSize.LowPart);
        ULONG totalRead = 0;
        while (totalRead < png.size())
        {
            ULONG read = 0;
            ULONG remaining = (ULONG)png.size() - totalRead;
            result = stream->Read(png.data() + totalRead, remaining, &read);
            if (FAILED(result) || read == 0)
            {
                error = FAILED(result)
                    ? DebugGUIHResult("IStream::Read", result)
                    : "PNG stream ended before its reported size";
                png.clear();
                return false;
            }
            totalRead += read;
        }
        return true;
    }

    static bool CaptureMainWindowPng(DebugGUIContext* context)
    {
        HWND window = GuiGetWindowHandle();
        if (!window || !IsWindow(window))
        {
            context->error = "GuiGetWindowHandle returned no valid x64dbg window";
            return false;
        }

        RECT bounds{};
        if (!GetWindowRect(window, &bounds))
        {
            context->error = "GetWindowRect failed for the x64dbg main window";
            return false;
        }
        int width = bounds.right - bounds.left;
        int height = bounds.bottom - bounds.top;
        if (width <= 0 || height <= 0 || width > 32768 || height > 32768)
        {
            context->error = "x64dbg main-window dimensions were invalid";
            return false;
        }

        WindowBitmap capture;
        capture.window = window;
        capture.windowDc = GetWindowDC(window);
        if (!capture.windowDc)
        {
            context->error = "GetWindowDC failed for the x64dbg main window";
            return false;
        }
        capture.memoryDc = CreateCompatibleDC(capture.windowDc);
        if (!capture.memoryDc)
        {
            context->error = "CreateCompatibleDC failed for the x64dbg main window";
            return false;
        }

        BITMAPINFO bitmapInfo{};
        bitmapInfo.bmiHeader.biSize = sizeof(bitmapInfo.bmiHeader);
        bitmapInfo.bmiHeader.biWidth = width;
        bitmapInfo.bmiHeader.biHeight = -height;
        bitmapInfo.bmiHeader.biPlanes = 1;
        bitmapInfo.bmiHeader.biBitCount = 32;
        bitmapInfo.bmiHeader.biCompression = BI_RGB;
        capture.bitmap = CreateDIBSection(
            capture.windowDc,
            &bitmapInfo,
            DIB_RGB_COLORS,
            &capture.bits,
            nullptr,
            0);
        if (!capture.bitmap || !capture.bits)
        {
            context->error = "CreateDIBSection failed for the x64dbg main window";
            return false;
        }
        capture.previousBitmap = SelectObject(capture.memoryDc, capture.bitmap);
        if (!capture.previousBitmap || capture.previousBitmap == HGDI_ERROR)
        {
            context->error = "SelectObject failed for the x64dbg capture bitmap";
            return false;
        }

        if (!PrintWindow(window, capture.memoryDc, PW_RENDERFULLCONTENT))
        {
            context->error = "PrintWindow failed for the x64dbg main window";
            return false;
        }
        GdiFlush();

        DWORD* pixels = static_cast<DWORD*>(capture.bits);
        size_t pixelCount = (size_t)width * (size_t)height;
        DWORD first = pixels[0] & 0x00FFFFFF;
        bool hasVariation = false;
        for (size_t i = 1; i < pixelCount; i++)
        {
            if ((pixels[i] & 0x00FFFFFF) != first)
            {
                hasVariation = true;
                break;
            }
        }
        if (!hasVariation)
        {
            context->error = "PrintWindow produced a uniform image";
            return false;
        }

        // BI_RGB leaves the high byte undefined; PNG BGRA requires explicit opacity.
        for (size_t i = 0; i < pixelCount; i++)
            pixels[i] |= 0xFF000000;

        if (!EncodeWindowBitmapAsPng(
            capture.bits,
            width,
            height,
            context->png,
            context->error))
            return false;

        int titleLength = GetWindowTextLengthW(window);
        std::vector<wchar_t> title((size_t)titleLength + 1, L'\0');
        if (titleLength > 0)
            GetWindowTextW(window, title.data(), titleLength + 1);

        context->width = width;
        context->height = height;
        context->windowTitle.assign(title.data());
        context->debuggeeProcessId = DbgIsDebugging() ? DbgGetProcessId() : 0;
        GetSystemTimeAsFileTime(&context->capturedAtUtc);
        return true;
    }

    static void ExecuteDebugGUIOnGuiThread(void* userData)
    {
        auto context = static_cast<DebugGUIContext*>(userData);
        try
        {
            if (context->action != DebugGUIWorkAction::Snapshot && !DbgIsDebugging())
            {
                context->failure = DebugGUIFailure::NotAttached;
                context->error = "no active debug session";
            }
            else if (context->action == DebugGUIWorkAction::Snapshot)
            {
                Script::Gui::Refresh();
                GuiProcessEvents();
                context->success = CaptureMainWindowPng(context);
                if (!context->success)
                    context->failure = DebugGUIFailure::X64dbgFailed;
            }
            else if (context->action == DebugGUIWorkAction::Focus)
            {
                GuiShowCpu();
                GuiProcessEvents();
                GuiFocusView(context->selectionWindow);
                Script::Gui::Refresh();
                GuiProcessEvents();
                context->success = true;
            }
            else if (context->action == DebugGUIWorkAction::Get)
            {
                context->success = Script::Gui::SelectionGet(
                    context->scriptWindow,
                    &context->actualStart,
                    &context->actualEnd);
                if (!context->success)
                {
                    context->failure = DebugGUIFailure::X64dbgFailed;
                    context->error = "failed to read the x64dbg GUI selection";
                }
            }
            else
            {
                GuiShowCpu();
                switch (context->selectionWindow)
                {
                case GUI_DISASSEMBLY:
                    GuiDisasmAt(context->requestedStart, DbgValFromString("cip"));
                    break;
                case GUI_DUMP:
                    GuiDumpAt(context->requestedStart);
                    break;
                case GUI_STACK:
                    GuiStackDumpAt(context->requestedStart, DbgValFromString("csp"));
                    break;
                }
                GuiProcessEvents();

                if (!Script::Gui::SelectionSet(
                    context->scriptWindow,
                    context->requestedStart,
                    context->requestedEnd))
                {
                    context->failure = DebugGUIFailure::NotFound;
                    context->error = "requested range is outside the selected pane's addressable page";
                }
                else
                {
                    GuiFocusView(context->selectionWindow);
                    Script::Gui::Refresh();
                    GuiProcessEvents();
                    context->success = Script::Gui::SelectionGet(
                        context->scriptWindow,
                        &context->actualStart,
                        &context->actualEnd);
                    if (!context->success)
                    {
                        context->failure = DebugGUIFailure::X64dbgFailed;
                        context->error = "selection was set but readback failed";
                    }
                }
            }
        }
        catch (...)
        {
            context->success = false;
            context->failure = DebugGUIFailure::X64dbgFailed;
            context->error = "unexpected failure on the x64dbg GUI thread";
        }

        context->completion.set_value();
        context->Release();
    }

    struct LogSaveContext
    {
        std::string path;
        std::promise<void> completion;
    };

    struct BridgeBreakpointMap
    {
        BPMAP value{};

        ~BridgeBreakpointMap()
        {
            if (value.bp)
                BridgeFree(value.bp);
        }
    };

    static void SaveLogOnGuiThread(void* userData)
    {
        auto context = static_cast<LogSaveContext*>(userData);
        {
            GuiDisableLogScope suppressSaveMessage;
            GuiLogSave(context->path.c_str());
        }
        context->completion.set_value();
        delete context;
    }
#pragma managed

    ref class BreakpointSnapshots abstract sealed
    {
    public:
        static List<BreakpointEntry^>^ ReadAll()
        {
            auto result = gcnew List<BreakpointEntry^>();
            if (!DbgIsDebugging()) return result;

            BridgeBreakpointMap nativeBreakpoints;
            DbgGetBpList(bp_none, &nativeBreakpoints.value);
            for (int i = 0; i < nativeBreakpoints.value.count; i++)
                result->Add(FromNative(nativeBreakpoints.value.bp[i]));
            return result;
        }

        static BreakpointEntry^ Find(BPXTYPE type, duint address)
        {
            if (!DbgIsDebugging()) return nullptr;

            BridgeBreakpointMap nativeBreakpoints;
            DbgGetBpList(bp_none, &nativeBreakpoints.value);
            for (int i = 0; i < nativeBreakpoints.value.count; i++)
            {
                const auto& nativeBreakpoint = nativeBreakpoints.value.bp[i];
                if (nativeBreakpoint.type == type && nativeBreakpoint.addr == address)
                    return FromNative(nativeBreakpoint);
            }
            return nullptr;
        }

        static void FindNormalAndHardware(
            duint address,
            [Out] BreakpointEntry^% normal,
            [Out] BreakpointEntry^% hardware)
        {
            normal = nullptr;
            hardware = nullptr;
            if (!DbgIsDebugging()) return;

            BridgeBreakpointMap nativeBreakpoints;
            DbgGetBpList(bp_none, &nativeBreakpoints.value);
            for (int i = 0; i < nativeBreakpoints.value.count; i++)
            {
                const auto& nativeBreakpoint = nativeBreakpoints.value.bp[i];
                if (nativeBreakpoint.addr != address)
                    continue;
                if (nativeBreakpoint.type == bp_normal)
                    normal = FromNative(nativeBreakpoint);
                else if (nativeBreakpoint.type == bp_hardware)
                    hardware = FromNative(nativeBreakpoint);
            }
        }

    private:
        static BreakpointEntry^ FromNative(const BRIDGEBP& nativeBreakpoint)
        {
            auto item = gcnew BreakpointEntry();
            item->Type = Helpers::BreakpointTypeName(nativeBreakpoint.type);
            item->Subtype = Helpers::BreakpointSubtypeName(nativeBreakpoint.type, nativeBreakpoint.typeEx);

            if (nativeBreakpoint.type == bp_exception)
            {
                item->ExceptionCode = Helpers::FormatAddress(nativeBreakpoint.addr);
            }
            else if (nativeBreakpoint.type != bp_dll)
            {
                item->Address = Helpers::FormatAddress(nativeBreakpoint.addr);
            }

            if (nativeBreakpoint.type == bp_hardware)
            {
                item->HardwareSize = Helpers::HardwareBreakpointSizeName(nativeBreakpoint.hwSize);
                item->HardwareSlot = Nullable<int>((int)nativeBreakpoint.slot);
            }

            item->Enabled = nativeBreakpoint.enabled;
            item->SingleShoot = nativeBreakpoint.singleshoot;
            item->Active = nativeBreakpoint.active;
            item->Name = Helpers::FromCStrOrNull(nativeBreakpoint.name);
            item->Module = Helpers::FromCStrOrNull(nativeBreakpoint.mod);
            item->HitCount = nativeBreakpoint.hitCount;
            item->FastResume = nativeBreakpoint.fastResume;
            item->Silent = nativeBreakpoint.silent;
            item->BreakCondition = Helpers::FromUtf8OrNull(nativeBreakpoint.breakCondition);
            item->LogText = Helpers::FromUtf8OrNull(nativeBreakpoint.logText);
            item->LogCondition = Helpers::FromUtf8OrNull(nativeBreakpoint.logCondition);
            item->CommandText = Helpers::FromUtf8OrNull(nativeBreakpoint.commandText);
            item->CommandCondition = Helpers::FromUtf8OrNull(nativeBreakpoint.commandCondition);
            return item;
        }
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
            info->Links["attach_processes"] = Helpers::UriLink("x64dbg://attach/processes");
            info->Links["session_debuggee"] = Helpers::UriLink("x64dbg://session/debuggee");
            info->Links["threads"] = Helpers::UriLink("x64dbg://threads");
            info->Links["memory_maps"] = Helpers::UriLink("x64dbg://memory/maps");
            info->Links["modules"] = Helpers::UriLink("x64dbg://modules");
            info->Links["windows"] = Helpers::UriLink("x64dbg://windows");
            info->Links["handles"] = Helpers::UriLink("x64dbg://handles");
            info->Links["tcpconnections"] = Helpers::UriLink("x64dbg://tcpconnections");
            info->Links["breakpoints"] = Helpers::UriLink("x64dbg://breakpoints");
            info->Links["logging"] = Helpers::UriLink("x64dbg://logging");

            return MakeJson(info, "x64dbg://session");
        }

        [McpServerResource(UriTemplate = "x64dbg://logging", Name = "logging", MimeType = "text/plain")]
        [Description("Plain-text snapshot of the current x64dbg log window.")]
        static ResourceContents^ Logging()
        {
            String^ path = Path::GetTempFileName();
            auto context = new LogSaveContext();
            IntPtr utf8Path = Marshal::StringToCoTaskMemUTF8(path);
            context->path = static_cast<const char*>(utf8Path.ToPointer());
            Marshal::FreeCoTaskMem(utf8Path);

            std::future<void> completion = context->completion.get_future();
            // GuiLogSave must run on the GUI thread before the temporary file is read.
            GuiExecuteOnGuiThreadEx(SaveLogOnGuiThread, context);
            if (completion.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
                throw gcnew TimeoutException("Timed out while saving the x64dbg log window");

            String^ text = File::ReadAllText(path, gcnew UTF8Encoding(false, true));
            File::Delete(path);

            auto contents = gcnew TextResourceContents();
            contents->Text = text;
            contents->MimeType = "text/plain";
            contents->Uri = "x64dbg://logging";
            return contents;
        }

        [McpServerResource(UriTemplate = "x64dbg://session/debuggee", Name = "session-debuggee", MimeType = "application/json")]
        [Description("Information about the current session's debuggee: PID, path, command line, image base, thread info, and system structures.")]
        static ResourceContents^ Debuggee()
        {
            auto info = gcnew DebuggeeInfo();
			info->Elevated = BridgeIsProcessElevated();
            info->ProcessId = 0;
            info->ThreadId = 0;
            info->ImageBase = nullptr;
			info->EntryPoint = nullptr;
            info->PebAddress = nullptr;
            info->TebAddress = nullptr;
            info->Path = nullptr;
            info->CommandLine = nullptr;
            info->Links = gcnew Dictionary<String^, LinkRef^>();
            info->Links["self"] = Helpers::UriLink("x64dbg://session/debuggee");
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
				{
					info->PebAddress = Helpers::FormatAddress(value);

#if defined(_WIN64)
                    static_assert(offsetof(PEB, ProcessParameters) == 0x20);
                    static_assert(offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine) == 0x70);
#else
                    static_assert(offsetof(PEB, ProcessParameters) == 0x10);
                    static_assert(offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine) == 0x40);
#endif

                    duint processParametersAddress = 0;
                    if (DbgMemRead(
                            value + offsetof(PEB, ProcessParameters),
                            &processParametersAddress,
                            sizeof(processParametersAddress)) &&
                        processParametersAddress != 0)
                    {
                        UNICODE_STRING commandLine{};
                        if (DbgMemRead(
                                processParametersAddress + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine),
                                &commandLine,
                                sizeof(commandLine)))
                        {
                            if (commandLine.Length == 0)
                            {
                                info->CommandLine = String::Empty;
                            }
                            else if (commandLine.Length <= commandLine.MaximumLength &&
                                     commandLine.Buffer != nullptr &&
                                     commandLine.Length % sizeof(wchar_t) == 0)
                            {
                                int characterCount = commandLine.Length / sizeof(wchar_t);
                                std::vector<wchar_t> buffer(characterCount);
                                if (DbgMemRead(
                                        (duint)commandLine.Buffer,
                                        buffer.data(),
                                        commandLine.Length))
                                {
                                    info->CommandLine = gcnew String(buffer.data(), 0, characterCount);
                                }
                            }
                        }
                    }
				}

                // Get TEB address for current thread
                if (Script::Misc::ParseExpression("teb()", &value))
                    info->TebAddress = Helpers::FormatAddress(value);

				//// Get KUSER_SHARED_DATA address (always 0x7FFE0000 on Windows)
				//if (Script::Misc::ParseExpression("kusd()", &value))
				//	info->KUserSharedData = Helpers::FormatAddress(value);

                // Get main module info for path and image base
                Script::Module::ModuleInfo mod;
                if (Script::Module::GetMainModuleInfo(&mod))
                {
                    info->ImageBase = Helpers::FormatAddress(mod.base);
					info->EntryPoint = Helpers::FormatAddress(mod.entry);
                    info->Path = Helpers::FromCStr(mod.path);
                }

                info->Links["threads"] = Helpers::UriLink("x64dbg://threads");
                info->Links["memory_maps"] = Helpers::UriLink("x64dbg://memory/maps");
                info->Links["modules"] = Helpers::UriLink("x64dbg://modules");
                info->Links["windows"] = Helpers::UriLink("x64dbg://windows");
                info->Links["handles"] = Helpers::UriLink("x64dbg://handles");
                info->Links["tcpconnections"] = Helpers::UriLink("x64dbg://tcpconnections");
                info->Links["breakpoints"] = Helpers::UriLink("x64dbg://breakpoints");
            }

            return MakeJson(info, "x64dbg://session/debuggee");
        }

#pragma warning(push)
#pragma warning(disable: 4965)
        [McpServerResource(UriTemplate = "x64dbg://attach/processes{?offset,limit}", Name = "attach-processes", MimeType = "application/json")]
        [Description("Paged snapshot of the same filtered process candidates shown by x64dbg's Attach dialog.")]
        static ResourceContents^ AttachProcesses(RequestContext<ReadResourceRequestParams^>^ requestContext)
        {
            String^ requestUri = requestContext != nullptr && requestContext->Params != nullptr
                ? requestContext->Params->Uri
                : "x64dbg://attach/processes";
            int pageOffset = Math::Max(0, QueryInt(requestUri, "offset", 0));
            int pageLimit = Math::Min(Math::Max(1, QueryInt(requestUri, "limit", 100)), 100);

            auto payload = gcnew AttachProcessesPayload();
            payload->Data = gcnew List<AttachProcessInfo^>();
            payload->Page = gcnew PageInfo();
            payload->Page->Offset = pageOffset;
            payload->Page->Limit = pageLimit;
            payload->Links = gcnew Dictionary<String^, LinkRef^>();
            payload->Links["self"] = Helpers::UriLink(AttachProcessesPageUri(pageOffset, pageLimit));
            payload->Links["session"] = Helpers::UriLink("x64dbg://session");

            DBGPROCESSINFO* entries = nullptr;
            int count = 0;
            if (DbgFunctions()->GetProcessList(&entries, &count))
            {
                payload->Page->Total = count;
                try
                {
                    int start = Math::Min(pageOffset, count);
                    int end = Math::Min(count, start + pageLimit);
                    for (int i = start; i < end; i++)
                    {
                        auto item = gcnew AttachProcessInfo();
                        item->ProcessId = (int)entries[i].dwProcessId;
                        item->Path = Helpers::FromCStr(entries[i].szExeFile);
                        String^ fileName = Path::GetFileName(item->Path);
                        int firstDot = fileName->IndexOf('.');
                        // AttachDialog uses QFileInfo::baseName(), which stops at the first dot.
                        item->Name = firstDot >= 0 ? fileName->Substring(0, firstDot) : fileName;
                        item->Title = Helpers::FromCStr(entries[i].szExeMainWindowTitle);
                        item->CommandLineArguments = Helpers::FromCStr(entries[i].szExeArgs);
                        payload->Data->Add(item);
                    }
                }
                finally
                {
                    BridgeFree(entries);
                }
            }
            else if (entries)
            {
                BridgeFree(entries);
            }

            int returnedThrough = Math::Min(pageOffset, payload->Page->Total) + payload->Data->Count;
            payload->Page->HasMore = returnedThrough < payload->Page->Total;
            if (payload->Page->HasMore)
                payload->Links["next"] = Helpers::UriLink(AttachProcessesPageUri(pageOffset + pageLimit, pageLimit));
            if (pageOffset > 0)
                payload->Links["prev"] = Helpers::UriLink(AttachProcessesPageUri(Math::Max(0, pageOffset - pageLimit), pageLimit));

            return MakeJson(payload, requestUri);
        }
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable: 4965)
        [McpServerResource(UriTemplate = "x64dbg://modules{?offset,limit}", Name = "modules", MimeType = "application/json")]
        [Description("Paged list of loaded modules in the debugged process. Empty when not debugging.")]
        static ResourceContents^ Modules(RequestContext<ReadResourceRequestParams^>^ requestContext)
        {
            String^ requestUri = requestContext != nullptr && requestContext->Params != nullptr
                ? requestContext->Params->Uri
                : "x64dbg://modules";
            // C++/CLI does not emit CLR constants for optional parameters, so parse
            // URI-template query values directly instead of relying on SDK binding.
            int pageOffset = Math::Max(0, QueryInt(requestUri, "offset", 0));
            int pageLimit = Math::Min(Math::Max(1, QueryInt(requestUri, "limit", 100)), 100);

            auto payload = gcnew ModulesPayload();
            payload->Data = gcnew List<ModuleInfo^>();
            payload->Page = gcnew PageInfo();
            payload->Page->Offset = pageOffset;
            payload->Page->Limit = pageLimit;
            payload->Links = gcnew Dictionary<String^, LinkRef^>();
            payload->Links["self"] = Helpers::UriLink(ModulesPageUri(pageOffset, pageLimit));
            payload->Links["session"] = Helpers::UriLink("x64dbg://session");

            if (DbgIsDebugging())
            {
                BridgeList<Script::Module::ModuleInfo> list;
                if (Script::Module::GetList(&list))
                {
                    duint mainBase = Script::Module::GetMainModuleBase();
                    payload->Page->Total = list.Count();
                    int end = Math::Min(list.Count(), pageOffset + pageLimit);
                    for (int i = Math::Min(pageOffset, list.Count()); i < end; i++)
                    {
                        payload->Data->Add(MakeModuleInfo(list[i], mainBase, false));
                    }
                }
            }

            payload->Page->HasMore = pageOffset + payload->Data->Count < payload->Page->Total;
            if (payload->Page->HasMore)
                payload->Links["next"] = Helpers::UriLink(ModulesPageUri(pageOffset + pageLimit, pageLimit));
            if (pageOffset > 0)
                payload->Links["prev"] = Helpers::UriLink(ModulesPageUri(Math::Max(0, pageOffset - pageLimit), pageLimit));

            return MakeJson(payload, requestUri);
        }
#pragma warning(pop)

        [McpServerResource(UriTemplate = "x64dbg://modules/{name}", Name = "module", MimeType = "application/json")]
        [Description("Information and navigation links for one loaded module.")]
        static ResourceContents^ Module(
            [Description("Loaded module name including extension (e.g. \"kernel32.dll\")")]
            String^ name)
        {
            Script::Module::ModuleInfo nativeModule{};
            RequireModule(name, &nativeModule);
            auto info = MakeModuleInfo(nativeModule, Script::Module::GetMainModuleBase(), true);
            return MakeJson(info, ModuleUri(info->Name));
        }

        [McpServerResource(UriTemplate = "x64dbg://modules/{name}/sections", Name = "module-sections", MimeType = "application/json")]
        [Description("Section table for one loaded module.")]
        static ResourceContents^ ModuleSections(
            [Description("Loaded module name including extension (e.g. \"kernel32.dll\")")]
            String^ name)
        {
            Script::Module::ModuleInfo nativeModule{};
            RequireModule(name, &nativeModule);
            auto data = gcnew List<ModuleSection^>();
            BridgeList<Script::Module::ModuleSectionInfo> list;
            if (Script::Module::SectionListFromName(nativeModule.name, &list))
            {
                for (int i = 0; i < list.Count(); i++)
                {
                    auto item = gcnew ModuleSection();
                    item->Name = Helpers::FromCStr(list[i].name);
                    item->Address = Helpers::FormatAddress(list[i].addr);
                    item->Size = Helpers::FormatAddress(list[i].size);
                    data->Add(item);
                }
            }
            return MakeJson(data, ModuleChildUri(Helpers::FromCStr(nativeModule.name), "sections"));
        }

        [McpServerResource(UriTemplate = "x64dbg://modules/{name}/exports", Name = "module-exports", MimeType = "application/json")]
        [Description("Export table for one loaded module.")]
        static ResourceContents^ ModuleExports(
            [Description("Loaded module name including extension (e.g. \"kernel32.dll\")")]
            String^ name)
        {
            Script::Module::ModuleInfo nativeModule{};
            RequireModule(name, &nativeModule);
            auto data = gcnew List<ModuleExport^>();
            BridgeList<Script::Module::ModuleExport> list;
            if (Script::Module::GetExports(&nativeModule, &list))
            {
                for (int i = 0; i < list.Count(); i++)
                {
                    auto item = gcnew ModuleExport();
                    item->Name = Helpers::FromCStr(list[i].name);
                    item->UndecoratedName = Helpers::FromCStr(list[i].undecoratedName);
                    item->ForwardName = list[i].forwarded ? Helpers::FromCStrOrNull(list[i].forwardName) : nullptr;
                    item->Ordinal = (int)list[i].ordinal;
                    item->Rva = Helpers::FormatAddress(list[i].rva);
                    item->Va = Helpers::FormatAddress(list[i].va);
                    data->Add(item);
                }
            }
            return MakeJson(data, ModuleChildUri(Helpers::FromCStr(nativeModule.name), "exports"));
        }

        [McpServerResource(UriTemplate = "x64dbg://modules/{name}/imports", Name = "module-imports", MimeType = "application/json")]
        [Description("Import address table entries for one loaded module.")]
        static ResourceContents^ ModuleImports(
            [Description("Loaded module name including extension (e.g. \"kernel32.dll\")")]
            String^ name)
        {
            Script::Module::ModuleInfo nativeModule{};
            RequireModule(name, &nativeModule);
            auto data = gcnew List<ModuleImport^>();
            BridgeList<Script::Module::ModuleImport> list;
            if (Script::Module::GetImports(&nativeModule, &list))
            {
                for (int i = 0; i < list.Count(); i++)
                {
                    auto item = gcnew ModuleImport();
                    item->Name = Helpers::FromCStr(list[i].name);
                    item->UndecoratedName = Helpers::FromCStr(list[i].undecoratedName);
                    item->IatRva = Helpers::FormatAddress(list[i].iatRva);
                    item->IatVa = Helpers::FormatAddress(list[i].iatVa);
                    data->Add(item);
                }
            }
            return MakeJson(data, ModuleChildUri(Helpers::FromCStr(nativeModule.name), "imports"));
        }

        [McpServerResource(UriTemplate = "x64dbg://memory/maps", Name = "memory-maps", MimeType = "application/json")]
        [Description("Memory map for the debugged process with readable protection, state, and type values.")]
        static ResourceContents^ MemoryMaps()
        {
            auto payload = gcnew MemoryMapsPayload();
            payload->Data = gcnew List<MemoryRegion^>();
            payload->Links = gcnew Dictionary<String^, LinkRef^>();
            payload->Links["self"] = Helpers::UriLink("x64dbg://memory/maps");
            payload->Links["session"] = Helpers::UriLink("x64dbg://session");
            payload->Links["session_debuggee"] = Helpers::UriLink("x64dbg://session/debuggee");

            if (DbgIsDebugging())
            {
                MEMMAP maps{};
                if (DbgMemMap(&maps))
                {
                    for (int i = 0; i < maps.count; i++)
                    {
                        const auto& page = maps.page[i];
                        auto item = gcnew MemoryRegion();
                        item->Base = Helpers::FormatAddress((duint)page.mbi.BaseAddress);
                        item->AllocationBase = Helpers::FormatAddress((duint)page.mbi.AllocationBase);
                        item->Size = Helpers::FormatAddress((duint)page.mbi.RegionSize);
                        item->AllocationProtect = Helpers::FormatMemoryProtection(page.mbi.AllocationProtect);
                        item->Protect = Helpers::FormatMemoryProtection(page.mbi.Protect);
                        item->State = Helpers::MemoryStateName(page.mbi.State);
                        item->Type = Helpers::MemoryTypeName(page.mbi.Type);
                        item->Info = Helpers::FromCStrOrNull(page.info);
                        payload->Data->Add(item);
                    }
                }
                if (maps.page)
                    BridgeFree(maps.page);
            }

            return MakeJson(payload, "x64dbg://memory/maps");
        }

        [McpServerResource(UriTemplate = "x64dbg://threads", Name = "threads", MimeType = "application/json")]
        [Description("Thread list for the debugged process with execution, scheduling, timing, and active-thread details.")]
        static ResourceContents^ Threads()
        {
            auto payload = gcnew ThreadsPayload();
            payload->Data = gcnew List<ThreadInfo^>();
            payload->Links = gcnew Dictionary<String^, LinkRef^>();
            payload->Links["self"] = Helpers::UriLink("x64dbg://threads");
            payload->Links["session"] = Helpers::UriLink("x64dbg://session");
            payload->Links["session_debuggee"] = Helpers::UriLink("x64dbg://session/debuggee");

            if (DbgIsDebugging())
            {
                THREADLIST list{};
                DbgGetThreadList(&list);
                for (int i = 0; i < list.count; i++)
                {
                    const auto& nativeThread = list.list[i];
                    auto item = gcnew ThreadInfo();
					//item->Handle = Helpers::FormatAddress((duint)nativeThread.BasicInfo.ThreadHandle);
                    item->ThreadNumber = nativeThread.BasicInfo.ThreadNumber;
                    item->ThreadId = (int)nativeThread.BasicInfo.ThreadId;
                    item->Name = Helpers::FromCStrOrNull(nativeThread.BasicInfo.threadName);
                    item->Cip = Helpers::FormatAddress(nativeThread.ThreadCip);
                    item->EntryPoint = Helpers::FormatAddress(nativeThread.BasicInfo.ThreadStartAddress);
                    item->TebAddress = Helpers::FormatAddress(nativeThread.BasicInfo.ThreadLocalBase);
                    item->SuspendCount = nativeThread.SuspendCount;
                    item->Priority = Helpers::ThreadPriorityName(nativeThread.Priority);
                    item->WaitReason = Helpers::ThreadWaitReasonName(nativeThread.WaitReason);
                    item->LastError = nativeThread.LastError;
                    item->UserTime = Helpers::FormatFileTimeDuration(nativeThread.UserTime);
                    item->KernelTime = Helpers::FormatFileTimeDuration(nativeThread.KernelTime);
                    item->CreationTime = Helpers::FormatFileTimeUtc(nativeThread.CreationTime);
                    item->Cycles = nativeThread.Cycles;
                    item->IsActive = list.CurrentThread == i;
                    payload->Data->Add(item);
                }
                if (list.list)
                    BridgeFree(list.list);
            }

            return MakeJson(payload, "x64dbg://threads");
        }

#pragma warning(push)
#pragma warning(disable: 4965)
        [McpServerResource(UriTemplate = "x64dbg://breakpoints{?offset,limit}", Name = "breakpoints", MimeType = "application/json")]
        [Description("Paged snapshot of all software, hardware, memory, DLL, and exception breakpoints. Empty when not debugging.")]
        static ResourceContents^ Breakpoints(RequestContext<ReadResourceRequestParams^>^ requestContext)
        {
            String^ requestUri = requestContext != nullptr && requestContext->Params != nullptr
                ? requestContext->Params->Uri
                : "x64dbg://breakpoints";
            int pageOffset = Math::Max(0, QueryInt(requestUri, "offset", 0));
            int pageLimit = Math::Min(Math::Max(1, QueryInt(requestUri, "limit", 100)), 100);

            auto payload = gcnew BreakpointsPayload();
            payload->Data = gcnew List<BreakpointEntry^>();
            payload->Page = gcnew PageInfo();
            payload->Page->Offset = pageOffset;
            payload->Page->Limit = pageLimit;
            payload->Links = gcnew Dictionary<String^, LinkRef^>();
            payload->Links["self"] = Helpers::UriLink(BreakpointsPageUri(pageOffset, pageLimit));
            payload->Links["session"] = Helpers::UriLink("x64dbg://session");
            payload->Links["session_debuggee"] = Helpers::UriLink("x64dbg://session/debuggee");

            if (DbgIsDebugging())
            {
                auto snapshot = BreakpointSnapshots::ReadAll();
                payload->Page->Total = snapshot->Count;

                int end = Math::Min(snapshot->Count, pageOffset + pageLimit);
                for (int i = Math::Min(pageOffset, snapshot->Count); i < end; i++)
                    payload->Data->Add(snapshot[i]);
            }

            payload->Page->HasMore = pageOffset + payload->Data->Count < payload->Page->Total;
            if (payload->Page->HasMore)
                payload->Links["next"] = Helpers::UriLink(BreakpointsPageUri(pageOffset + pageLimit, pageLimit));
            if (pageOffset > 0)
                payload->Links["prev"] = Helpers::UriLink(BreakpointsPageUri(Math::Max(0, pageOffset - pageLimit), pageLimit));

            return MakeJson(payload, requestUri);
        }
#pragma warning(pop)

        [McpServerResource(UriTemplate = "x64dbg://windows", Name = "windows", MimeType = "application/json")]
        [Description("Window list for the debugged process, including window metadata and GWLP_USERDATA values.")]
        static ResourceContents^ Windows()
        {
            auto payload = gcnew WindowsPayload();
            payload->Data = gcnew List<WindowInfo^>();
            payload->Links = gcnew Dictionary<String^, LinkRef^>();
            payload->Links["self"] = Helpers::UriLink("x64dbg://windows");
            payload->Links["session"] = Helpers::UriLink("x64dbg://session");
            payload->Links["session_debuggee"] = Helpers::UriLink("x64dbg://session/debuggee");

            if (DbgIsDebugging())
            {
                BridgeList<WINDOW_INFO> windows;
                if (DbgFunctions()->EnumWindows(&windows))
                {
                    for (int i = 0; i < windows.Count(); i++)
                    {
                        const auto& nativeWindow = windows[i];
                        auto item = gcnew WindowInfo();
                        item->Procedure = Helpers::FormatAddress(nativeWindow.wndProc);
                        item->Handle = Helpers::FormatAddress(nativeWindow.handle);
                        item->Title = Helpers::FromCStr(nativeWindow.windowTitle);
                        item->ClassName = Helpers::FromCStr(nativeWindow.windowClass);
                        item->ThreadId = nativeWindow.threadId;
                        item->Style = Helpers::FormatAddress(nativeWindow.style);
                        item->StyleEx = Helpers::FormatAddress(nativeWindow.styleEx);
                        item->Parent = Helpers::FormatAddress(nativeWindow.parent);
                        item->Left = nativeWindow.position.left;
                        item->Top = nativeWindow.position.top;
                        item->Width = nativeWindow.position.right - nativeWindow.position.left;
                        item->Height = nativeWindow.position.bottom - nativeWindow.position.top;
                        item->Enabled = nativeWindow.enabled != FALSE;
                        item->UserData = Helpers::FormatAddress((duint)::GetWindowLongPtrW(
                            (HWND)(ULONG_PTR)nativeWindow.handle,
                            GWLP_USERDATA));
                        payload->Data->Add(item);
                    }
                }
            }

            return MakeJson(payload, "x64dbg://windows");
        }

        [McpServerResource(UriTemplate = "x64dbg://handles", Name = "handles", MimeType = "application/json")]
        [Description("Handle list for the debugged process, including type, access, and resolved object name.")]
        static ResourceContents^ Handles()
        {
            auto payload = gcnew HandlesPayload();
            payload->Data = gcnew List<HandleInfo^>();
            payload->Links = gcnew Dictionary<String^, LinkRef^>();
            payload->Links["self"] = Helpers::UriLink("x64dbg://handles");
            payload->Links["session"] = Helpers::UriLink("x64dbg://session");
            payload->Links["session_debuggee"] = Helpers::UriLink("x64dbg://session/debuggee");

            if (DbgIsDebugging())
            {
                BridgeList<HANDLEINFO> handles;
                if (DbgFunctions()->EnumHandles(&handles))
                {
                    for (int i = 0; i < handles.Count(); i++)
                    {
                        const auto& nativeHandle = handles[i];
                        char name[MAX_STRING_SIZE] = "";
                        char typeName[MAX_STRING_SIZE] = "";
                        DbgFunctions()->GetHandleName(
                            nativeHandle.Handle,
                            name,
                            sizeof(name),
                            typeName,
                            sizeof(typeName));

                        auto item = gcnew HandleInfo();
                        item->Type = Helpers::FromCStr(typeName);
                        item->TypeNumber = Helpers::FormatAddress(nativeHandle.TypeNumber);
                        item->Handle = Helpers::FormatAddress(nativeHandle.Handle);
                        item->GrantedAccess = Helpers::FormatAddress(nativeHandle.GrantedAccess);
                        item->Name = Helpers::FromCStr(name);
                        payload->Data->Add(item);
                    }
                }
            }

            return MakeJson(payload, "x64dbg://handles");
        }

        [McpServerResource(UriTemplate = "x64dbg://tcpconnections", Name = "tcpconnections", MimeType = "application/json")]
        [Description("TCP connection list for the debugged process, including local and remote endpoints and state.")]
        static ResourceContents^ TcpConnections()
        {
            auto payload = gcnew TcpConnectionsPayload();
            payload->Data = gcnew List<TcpConnectionInfo^>();
            payload->Links = gcnew Dictionary<String^, LinkRef^>();
            payload->Links["self"] = Helpers::UriLink("x64dbg://tcpconnections");
            payload->Links["session"] = Helpers::UriLink("x64dbg://session");
            payload->Links["session_debuggee"] = Helpers::UriLink("x64dbg://session/debuggee");

            if (DbgIsDebugging())
            {
                BridgeList<TCPCONNECTIONINFO> connections;
                if (DbgFunctions()->EnumTcpConnections(&connections))
                {
                    for (int i = 0; i < connections.Count(); i++)
                    {
                        const auto& nativeConnection = connections[i];
                        auto item = gcnew TcpConnectionInfo();
                        item->RemoteAddress = Helpers::FromCStr(nativeConnection.RemoteAddress);
                        item->RemotePort = nativeConnection.RemotePort;
                        item->LocalAddress = Helpers::FromCStr(nativeConnection.LocalAddress);
                        item->LocalPort = nativeConnection.LocalPort;
                        item->StateText = Helpers::FromCStr(nativeConnection.StateText);
                        item->State = nativeConnection.State;
                        payload->Data->Add(item);
                    }
                }
            }

            return MakeJson(payload, "x64dbg://tcpconnections");
        }

    private:
        static int QueryInt(String^ uri, String^ name, int fallback)
        {
            auto parsed = gcnew Uri(uri);
            String^ query = parsed->Query;
            if (String::IsNullOrEmpty(query))
                return fallback;

            for each (String^ pair in query->Substring(1)->Split(L'&'))
            {
                int separator = pair->IndexOf(L'=');
                String^ key = separator < 0 ? pair : pair->Substring(0, separator);
                if (Uri::UnescapeDataString(key) != name)
                    continue;

                String^ value = separator < 0 ? "" : pair->Substring(separator + 1);
                return Int32::Parse(
                    Uri::UnescapeDataString(value),
                    NumberStyles::Integer,
                    CultureInfo::InvariantCulture);
            }

            return fallback;
        }

        static String^ ModuleUri(String^ name)
        {
            return "x64dbg://modules/" + Uri::EscapeDataString(name);
        }

        static String^ BreakpointsPageUri(int offset, int limit)
        {
            return String::Format("x64dbg://breakpoints?offset={0}&limit={1}", offset, limit);
        }

        static String^ AttachProcessesPageUri(int offset, int limit)
        {
            return String::Format("x64dbg://attach/processes?offset={0}&limit={1}", offset, limit);
        }

        static String^ ModulesPageUri(int offset, int limit)
        {
            return String::Format("x64dbg://modules?offset={0}&limit={1}", offset, limit);
        }

        static String^ ModuleChildUri(String^ name, String^ child)
        {
            return ModuleUri(name) + "/" + child;
        }

        static void RequireModule(String^ name, Script::Module::ModuleInfo* module)
        {
            if (String::IsNullOrWhiteSpace(name))
                throw gcnew NotSupportedException("Unknown module: " + name);
            std::string nativeName = msclr::interop::marshal_as<std::string>(name);
            if (!Script::Module::InfoFromName(nativeName.c_str(), module))
                throw gcnew NotSupportedException("Unknown module: " + name);
        }

        static ModuleInfo^ MakeModuleInfo(
            const Script::Module::ModuleInfo& module,
            duint mainBase,
            bool includeNavigationLinks)
        {
            auto info = gcnew ModuleInfo();
            info->Name = Helpers::FromCStr(module.name);
            info->Path = Helpers::FromCStr(module.path);
            info->Base = Helpers::FormatAddress(module.base);
            info->Size = Helpers::FormatAddress(module.size);
            info->Entry = Helpers::FormatAddress(module.entry);
            info->SectionCount = module.sectionCount;
            info->IsMainModule = module.base == mainBase;
            info->Links = gcnew Dictionary<String^, LinkRef^>();
            info->Links["self"] = Helpers::UriLink(ModuleUri(info->Name));
            if (!includeNavigationLinks)
                return info;

            info->Links["modules"] = Helpers::UriLink("x64dbg://modules");
            info->Links["sections"] = Helpers::UriLink(ModuleChildUri(info->Name, "sections"));
            info->Links["exports"] = Helpers::UriLink(ModuleChildUri(info->Name, "exports"));
            info->Links["imports"] = Helpers::UriLink(ModuleChildUri(info->Name, "imports"));
            if (module.entry != 0)
            {
                auto args = gcnew Dictionary<String^, Object^>();
                args["addr"] = info->Entry;
                args["count"] = 30;
                info->Links["entry_disasm"] = Helpers::ToolLink("disassemble", args);
            }
            return info;
        }

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

            auto importNames = gcnew Dictionary<UInt64, String^>();
            auto indexedImportModules = gcnew HashSet<UInt64>();

            for (int i = 0; i < count; i++)
            {
                BASIC_INSTRUCTION_INFO bi;
                memset(&bi, 0, sizeof(bi));
                if (!DbgMemIsValidReadPtr(cur))
                {
                    r->Success = false;
                    r->Error = Helpers::MakeError(
                        "x64dbg_failed",
                        "address is not readable: " + Helpers::FormatAddress(cur));
                    return r;
                }

                DbgDisasmFastAt(cur, &bi);
                if (bi.size <= 0)
                {
                    r->Success = false;
                    r->Error = Helpers::MakeError(
                        "x64dbg_failed",
                        "DbgDisasmFastAt failed at " + Helpers::FormatAddress(cur));
                    return r;
                }
                int sz = bi.size;

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

                if ((bi.type & TYPE_MEMORY) != 0 && bi.memory.value != 0)
                {
                    duint moduleBase = Script::Module::BaseFromAddr(bi.memory.value);
                    if (moduleBase != 0 && indexedImportModules->Add((UInt64)moduleBase))
                    {
                        Script::Module::ModuleInfo module{};
                        BridgeList<Script::Module::ModuleImport> imports;
                        if (Script::Module::InfoFromAddr(moduleBase, &module) &&
                            Script::Module::GetImports(&module, &imports))
                        {
                            for (int j = 0; j < imports.Count(); j++)
                            {
                                const char* nativeName = imports[j].name;
                                if (nativeName[0] == '\0')
                                    nativeName = imports[j].undecoratedName;
                                if (nativeName[0] != '\0')
                                    importNames[(UInt64)imports[j].iatVa] = Helpers::FromCStr(nativeName);
                            }
                        }
                    }

                    UInt64 referenceAddress = (UInt64)bi.memory.value;
                    if (importNames->ContainsKey(referenceAddress))
                    {
                        String^ symbolName = importNames[referenceAddress];
                        int openBracket = e->Operands->IndexOf('[');
                        int closeBracket = e->Operands->LastIndexOf(']');
                        if (openBracket >= 0 && closeBracket > openBracket)
                        {
                            String^ symbolizedOperands =
                                e->Operands->Substring(0, openBracket + 1) +
                                "<&" + symbolName + ">" +
                                e->Operands->Substring(closeBracket);

                            e->Display = e->Mnemonic + " " + symbolizedOperands;
                            e->Reference = gcnew DisassembleReference();
                            e->Reference->Kind = "import";
                            e->Reference->Address = Helpers::FormatAddress(bi.memory.value);
                            e->Reference->Name = symbolName;
                        }
                    }
                }

                if (withBytes && sz > 0 && sz <= 16)
                {
                    array<unsigned char>^ bytes = gcnew array<unsigned char>(sz);
                    pin_ptr<unsigned char> p = &bytes[0];
                    if (!DbgMemRead(cur, p, sz))
                    {
                        r->Success = false;
                        r->Error = Helpers::MakeError(
                            "x64dbg_failed",
                            "DbgMemRead failed at " + Helpers::FormatAddress(cur));
                        return r;
                    }
                    auto sb = gcnew StringBuilder(sz * 2);
                    for (int j = 0; j < sz; j++) sb->AppendFormat("{0:X2}", bytes[j]);
                    e->Bytes = sb->ToString();
                }

                char comment[MAX_COMMENT_SIZE] = {};
                if (DbgGetCommentAt(cur, comment) && comment[0] != '\0')
                    e->Comment = Helpers::FromCStr(comment);

                r->Data->Add(e);
                cur += (duint)sz;
            }

            r->Success = true;
            return r;
        }

    };

    // ────────────────────────────────────────────────────────────────
    //  Unmanaged helpers for register contexts
    // ────────────────────────────────────────────────────────────────

#pragma unmanaged
    struct ThreadRegisterSnapshot
    {
        duint cax;
        duint cbx;
        duint ccx;
        duint cdx;
        duint csi;
        duint cdi;
        duint cbp;
        duint csp;
        duint cip;
#ifdef _WIN64
        duint r8;
        duint r9;
        duint r10;
        duint r11;
        duint r12;
        duint r13;
        duint r14;
        duint r15;
#endif
        duint eflags;
        unsigned short cs;
        unsigned short ds;
        unsigned short es;
        unsigned short fs;
        unsigned short gs;
        unsigned short ss;
        duint dr0;
        duint dr1;
        duint dr2;
        duint dr3;
        duint dr6;
        duint dr7;
    };

    static bool GetRegisterDumpUnmanaged(REGDUMP_AVX512* regdump)
    {
        return DbgGetRegDumpEx(regdump, sizeof(REGDUMP_AVX512));
    }

    static int GetThreadContextUnmanaged(DWORD threadId, ThreadRegisterSnapshot* snapshot)
    {
        THREADLIST list = {};
        DbgGetThreadList(&list);

        HANDLE threadHandle = nullptr;
        for (int i = 0; i < list.count; i++)
        {
            if (list.list[i].BasicInfo.ThreadId == threadId)
            {
                threadHandle = list.list[i].BasicInfo.Handle;
                break;
            }
        }

        if (list.list != nullptr)
            BridgeFree(list.list);
        if (threadHandle == nullptr)
            return 1;

        CONTEXT context = {};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS;
        if (!::GetThreadContext(threadHandle, &context))
            return 2;

#ifdef _WIN64
        snapshot->cax = context.Rax;
        snapshot->cbx = context.Rbx;
        snapshot->ccx = context.Rcx;
        snapshot->cdx = context.Rdx;
        snapshot->csi = context.Rsi;
        snapshot->cdi = context.Rdi;
        snapshot->cbp = context.Rbp;
        snapshot->csp = context.Rsp;
        snapshot->cip = context.Rip;
        snapshot->r8 = context.R8;
        snapshot->r9 = context.R9;
        snapshot->r10 = context.R10;
        snapshot->r11 = context.R11;
        snapshot->r12 = context.R12;
        snapshot->r13 = context.R13;
        snapshot->r14 = context.R14;
        snapshot->r15 = context.R15;
#else
        snapshot->cax = context.Eax;
        snapshot->cbx = context.Ebx;
        snapshot->ccx = context.Ecx;
        snapshot->cdx = context.Edx;
        snapshot->csi = context.Esi;
        snapshot->cdi = context.Edi;
        snapshot->cbp = context.Ebp;
        snapshot->csp = context.Esp;
        snapshot->cip = context.Eip;
#endif
        snapshot->eflags = context.EFlags;
        snapshot->cs = static_cast<unsigned short>(context.SegCs);
        snapshot->ds = static_cast<unsigned short>(context.SegDs);
        snapshot->es = static_cast<unsigned short>(context.SegEs);
        snapshot->fs = static_cast<unsigned short>(context.SegFs);
        snapshot->gs = static_cast<unsigned short>(context.SegGs);
        snapshot->ss = static_cast<unsigned short>(context.SegSs);
        snapshot->dr0 = context.Dr0;
        snapshot->dr1 = context.Dr1;
        snapshot->dr2 = context.Dr2;
        snapshot->dr3 = context.Dr3;
        snapshot->dr6 = context.Dr6;
        snapshot->dr7 = context.Dr7;
        return 0;
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
            "  attach      : { pid, detach2attach? } -- attach to a process; opt in to detaching an active debuggee\n"
            "  stop        : detach/terminate the debuggee\n"
            "  run         : continue execution (returns immediately, does not wait for next pause)\n"
            "  pause       : break into the debugger\n"
            "  StepInto    : single-step into\n"
            "  StepOver    : single-step over calls\n"
            "  StepOut     : run until current function returns\n"
            "  run_command : { command, wait? } -- raw x64dbg command (https://help.x64dbg.com/en/latest/commands/index.html); wait=true uses DbgCmdExecDirect\n"
        )]
        static Object^ DebugControl(
            [Description("Action: \"run\"|\"pause\"|\"stop\"|\"StepInto\"|\"StepOver\"|\"StepOut\"|\"init\"|\"attach\"|\"run_command\"")]
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
            [Description("Positive decimal Windows process ID (required for action=attach)")]
            [DefaultValue(0)]
            int pid,
            [Description("If true, detach the active debuggee before action=attach; defaults to false")]
            [DefaultValue(false)]
            bool detach2attach,
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
            else if (action == "attach")
            {
                return AttachAction(pid, detach2attach);
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
            "Precise breakpoint reads and mutations. Actions:\n"
            "  set             : { addr, breakCondition?, logText?, logCondition? } -> software breakpoint\n"
            "  set_hardware    : { addr, type?, size?, breakCondition?, logText?, logCondition? } -> hardware breakpoint\n"
            "  get             : { addr, kind? } -> software or hardware breakpoint\n"
            "  disable         : { addr, kind? } -> disabled software or hardware breakpoint\n"
            "  delete          : { addr, kind? } -> delete software or hardware breakpoint\n"
            "For get/disable/delete, kind is needed only when normal and hardware breakpoints coexist at addr.\n"
            "Use breakCondition=\"0\" with logText for a log-only breakpoint that does not pause."
        )]
        static BreakpointResult^ Breakpoints(
            [Description("Action: \"set\" | \"set_hardware\" | \"get\" | \"disable\" | \"delete\"")]
            String^ action,
            [Description("Address or x64dbg expression (required for every action)")]
            [DefaultValue("")]
            String^ addr,
            [Description("Breakpoint kind for get/disable/delete: \"normal\" | \"hardware\"; omit when exactly one kind exists at addr")]
            [DefaultValue("")]
            String^ kind,
            [Description("Hardware type for set_hardware: \"access\" | \"write\" | \"execute\"; defaults to execute")]
            [DefaultValue("execute")]
            String^ type,
            [Description("Hardware size for set_hardware: 1, 2, 4, or 8 (x64 only); defaults to 1 and requires matching address alignment")]
            [DefaultValue(1)]
            int size,
            [Description("Breakpoint-hit-time pause condition for set/set_hardware; use \"0\" for log-only behavior")]
            [DefaultValue("")]
            String^ breakCondition,
            [Description("Breakpoint-hit-time x64dbg format text for set/set_hardware (e.g. \"cip: {cip}\")")]
            [DefaultValue("")]
            String^ logText,
            [Description("Breakpoint-hit-time condition controlling logText for set/set_hardware")]
            [DefaultValue("")]
            String^ logCondition)
        {
            return BreakpointAction(
                action,
                addr,
                kind,
                type,
                size,
                breakCondition,
                logText,
                logCondition);
        }

        [McpServerTool]
        [Description(
            "Memory operations. Actions:\n"
            "  read : { addr, size, compress? } -> base64-encoded bytes; compress=true uses an lz4 block"
        )]
        static Object^ Memory(
            [Description("Action: \"read\"")]
            String^ action,
            [Description("Address or x64dbg expression (required for action=read; e.g. \"rax\", \"kernel32:CreateFileW\", \"cip+0x10\")")]
            [DefaultValue("")]
            String^ addr,
            [Description("Number of bytes to read (1-65536; required for action=read)")]
            [DefaultValue(0)]
            int size,
            [Description("Compress action=read payload with lz4 before base64 (recommended for size > ~4 KiB)")]
            [DefaultValue(false)]
            bool compress)
        {
            if (action == "read") return MemoryRead(addr, size, compress);

            auto r = gcnew MemoryReadResult();
            r->Success = false;
            r->Error = Helpers::MakeError(
                "invalid_argument",
                "unknown action: " + (action ? action : "<null>") + "; expected read");
            return r;
        }

        [McpServerTool]
        [Description(
            "Capture x64dbg GUI evidence and control CPU-pane focus or selections. Actions:\n"
            "  snapshot : { save_path? } -- capture the complete x64dbg main window as PNG\n"
            "  focus    : { window? } -- activate CPU, focus Disassembly/Dump/Stack, refresh, and flush GUI events\n"
            "  set      : { window, start, end? } -- navigate, select, focus, refresh, flush, and read back the actual range\n"
            "  get      : { window } -- read the pane's inclusive selection without changing it"
        )]
        static Object^ DebugGUI(
            [Description("Action: \"snapshot\" | \"focus\" | \"get\" | \"set\"")]
            String^ action,
            [Description("CPU pane: \"Disassembly\" | \"Dump\" | \"Stack\"; optional for focus, required for get/set")]
            [DefaultValue("")]
            String^ window,
            [Description("Start address or x64dbg expression (required for action=set)")]
            [DefaultValue("")]
            String^ start,
            [Description("Inclusive end address or x64dbg expression (action=set); omission means end=start")]
            [DefaultValue("")]
            String^ end,
            [Description("Absolute host path to a new .png file (action=snapshot); omission returns an inline image")]
            [DefaultValue("")]
            String^ save_path)
        {
            if (action == "snapshot")
                return SnapshotAction(save_path);

            if (action != "focus" && action != "get" && action != "set")
            {
                auto result = gcnew McpResult();
                result->Success = false;
                result->Error = Helpers::MakeError(
                    "invalid_argument",
                    "unknown action: " + (action ? action : "<null>") + "; expected snapshot|focus|get|set");
                return result;
            }

            if (!DbgIsDebugging())
                return DebugGUIError(action, "not_attached", "no active debug session");

            String^ canonicalWindow = window;
            if (action == "focus" && String::IsNullOrEmpty(canonicalWindow))
                canonicalWindow = "Disassembly";
            if (String::IsNullOrEmpty(canonicalWindow))
                return DebugGUIError(action, "invalid_argument", "window is required for action=" + action);

            GUISELECTIONTYPE selectionWindow;
            Script::Gui::Window scriptWindow;
            if (!TryMapDebugGUIWindow(canonicalWindow, &selectionWindow, &scriptWindow))
            {
                return DebugGUIError(
                    action,
                    "invalid_argument",
                    "window must be one of Disassembly|Dump|Stack");
            }

            duint requestedStart = 0;
            duint requestedEnd = 0;
            if (action == "set")
            {
                if (String::IsNullOrEmpty(start))
                    return DebugGUIError(action, "invalid_argument", "start is required for action=set");
                if (!Helpers::ResolveExpression(start, requestedStart))
                    return DebugGUIError(action, "not_found", "could not resolve start expression: " + start);

                if (String::IsNullOrEmpty(end))
                {
                    requestedEnd = requestedStart;
                }
                else if (!Helpers::ResolveExpression(end, requestedEnd))
                {
                    return DebugGUIError(action, "not_found", "could not resolve end expression: " + end);
                }
                if (requestedEnd < requestedStart)
                    return DebugGUIError(action, "invalid_argument", "end must resolve to an address greater than or equal to start");
            }

            auto context = new DebugGUIContext();
            context->action = action == "focus"
                ? DebugGUIWorkAction::Focus
                : action == "get" ? DebugGUIWorkAction::Get : DebugGUIWorkAction::Set;
            context->selectionWindow = selectionWindow;
            context->scriptWindow = scriptWindow;
            context->requestedStart = requestedStart;
            context->requestedEnd = requestedEnd;

            if (!RunDebugGUIContext(context))
            {
                context->Release();
                return DebugGUIError(action, "x64dbg_failed", "timed out waiting for the x64dbg GUI thread");
            }

            if (!context->success)
            {
                String^ code = DebugGUIFailureCode(context->failure);
                String^ message = gcnew String(context->error.c_str());
                context->Release();
                return DebugGUIError(action, code, message);
            }

            if (action == "focus")
            {
                context->Release();
                auto result = gcnew DebugGUIFocusResult();
                result->Success = true;
                result->Data = gcnew DebugGUIFocusData();
                result->Data->Action = "focus";
                result->Data->Window = canonicalWindow;
                result->Data->Refreshed = true;
                return result;
            }

            duint actualStart = context->actualStart;
            duint actualEnd = context->actualEnd;
            context->Release();
            if (action == "get")
            {
                auto result = gcnew DebugGUIGetResult();
                result->Success = true;
                result->Data = gcnew DebugGUIGetData();
                result->Data->Action = "get";
                result->Data->Window = canonicalWindow;
                result->Data->Selection = MakeDebugGUIRange(actualStart, actualEnd);
                return result;
            }

            auto result = gcnew DebugGUISetResult();
            result->Success = true;
            result->Data = gcnew DebugGUISetData();
            result->Data->Action = "set";
            result->Data->Window = canonicalWindow;
            result->Data->Requested = MakeDebugGUIRange(requestedStart, requestedEnd);
            result->Data->Actual = MakeDebugGUIRange(actualStart, actualEnd);
            result->Data->Refreshed = true;
            return result;
        }

        [McpServerTool]
        [Description(
            "Registers control. Actions:\n"
            "  get  : { name } -> { name, value }       — name is any x64dbg-known register/flag (rax, eip, zf, r8d, _zf...).\n"
            "  set  : { name, value } -> { name, value, previous } — value accepts any x64dbg expression.\n"
            "  dump : { threadId? } -> { registers, flags } — all GPRs (arch-agnostic) + flags for the active or specified thread."
        )]
        static Object^ Registers(
            [Description("Action: \"get\" | \"set\" | \"dump\"")]
            String^ action,
            [Description("Register/flag name (required for get/set; e.g. \"rax\", \"zf\")")]
            [DefaultValue("")]
            String^ name,
            [Description("Value or x64dbg expression (required for set; e.g. \"0x1000\", \"rax+8\")")]
            [DefaultValue("")]
            String^ value,
            [Description("Thread ID for action=dump; 0 selects the active thread")]
            [DefaultValue(0)]
            int threadId)
        {
            if (!DbgIsDebugging())
            {
                auto r = gcnew RegistersOpResult();
                r->Success = false;
                r->Error = Helpers::MakeError("not_attached", "no active debug session");
                return r;
            }

            if (action == "dump") return DumpAction(threadId);
            if (action == "get")  return GetAction(name);
            if (action == "set")  return SetAction(name, value);

            auto r = gcnew RegistersOpResult();
            r->Success = false;
            r->Error = Helpers::MakeError(
                "invalid_argument",
                "unknown action: " + (action ? action : "<null>") + "; expected get|set|dump");
            return r;
        }

        [McpServerTool]
        [Description(
            "Manage the x64dbg log window. Actions:\n"
            "  clear : clear the log window\n"
            "  put   : { text } -- append text as one line"
        )]
        static LoggingResult^ Logging(
            [Description("Action: \"clear\" | \"put\"")]
            String^ action,
            [Description("Text to append as a line (required for action=put)")]
            [DefaultValue("")]
            String^ text)
        {
            auto result = gcnew LoggingResult();

            if (action == "clear")
            {
                GuiLogClear();
            }
            else if (action == "put")
            {
                if (String::IsNullOrEmpty(text))
                {
                    result->Success = false;
                    result->Error = Helpers::MakeError(
                        "invalid_argument",
                        "text is required for action=put");
                    return result;
                }

                IntPtr utf8Text = Marshal::StringToCoTaskMemUTF8(text);
                _plugin_logputs(static_cast<const char*>(utf8Text.ToPointer()));
                Marshal::FreeCoTaskMem(utf8Text);
            }
            else
            {
                result->Success = false;
                result->Error = Helpers::MakeError(
                    "invalid_argument",
                    "unknown action: " + (action ? action : "<null>") + "; expected clear|put");
                return result;
            }

            result->Success = true;
            result->Data = gcnew LoggingActionData();
            result->Data->Action = action;
            return result;
        }

    private:
        static Object^ SnapshotAction(String^ savePath)
        {
            String^ normalizedPath = nullptr;
            String^ pathError = nullptr;
            if (!ValidateDebugGUISnapshotPath(savePath, normalizedPath, pathError))
            {
                auto result = gcnew DebugGUISnapshotResult();
                result->Success = false;
                result->Error = Helpers::MakeError("invalid_argument", pathError);
                return result;
            }

            auto context = new DebugGUIContext();
            context->action = DebugGUIWorkAction::Snapshot;
            if (!RunDebugGUIContext(context))
            {
                context->Release();
                auto result = gcnew DebugGUISnapshotResult();
                result->Success = false;
                result->Error = Helpers::MakeError("x64dbg_failed", "timed out waiting for the x64dbg GUI thread");
                return result;
            }
            if (!context->success)
            {
                String^ message = gcnew String(context->error.c_str());
                context->Release();
                auto result = gcnew DebugGUISnapshotResult();
                result->Success = false;
                result->Error = Helpers::MakeError("x64dbg_failed", message);
                return result;
            }

            if (context->png.size() > Int32::MaxValue)
            {
                context->Release();
                auto result = gcnew DebugGUISnapshotResult();
                result->Success = false;
                result->Error = Helpers::MakeError("x64dbg_failed", "captured PNG exceeds the supported result size");
                return result;
            }

            auto png = gcnew array<Byte>((int)context->png.size());
            if (png->Length > 0)
                Marshal::Copy(IntPtr(context->png.data()), png, 0, png->Length);
            int width = context->width;
            int height = context->height;
            int processId = (int)context->debuggeeProcessId;
            FILETIME capturedAt = context->capturedAtUtc;
            String^ windowTitle = gcnew String(context->windowTitle.c_str());
            context->Release();

            if (normalizedPath != nullptr)
            {
                try
                {
                    FileStream^ stream = gcnew FileStream(
                        normalizedPath,
                        FileMode::CreateNew,
                        FileAccess::Write,
                        FileShare::None);
                    try
                    {
                        stream->Write(png, 0, png->Length);
                        stream->Flush(true);
                    }
                    finally
                    {
                        delete stream;
                    }
                }
                catch (Exception^ exception)
                {
                    try
                    {
                        if (File::Exists(normalizedPath))
                            File::Delete(normalizedPath);
                    }
                    catch (...) {}

                    auto result = gcnew DebugGUISnapshotResult();
                    result->Success = false;
                    result->Error = Helpers::MakeError(
                        "io_failed",
                        "failed to write PNG file: " + exception->Message);
                    return result;
                }
            }

            auto result = gcnew DebugGUISnapshotResult();
            result->Success = true;
            result->Data = gcnew DebugGUISnapshotData();
            result->Data->Action = "snapshot";
            result->Data->Artifact = gcnew DebugGUIArtifact();
            result->Data->Artifact->Type = normalizedPath == nullptr ? "image" : "file";
            result->Data->Artifact->MimeType = "image/png";
            result->Data->Artifact->Path = normalizedPath;
            result->Data->CapturedAtUtc = Helpers::FormatFileTimeUtc(capturedAt);
            result->Data->Width = width;
            result->Data->Height = height;
            result->Data->Sha256 = Convert::ToHexString(SHA256::HashData(png));
            result->Data->WindowTitle = windowTitle;
            result->Data->DebuggeeProcessId = processId;

            if (normalizedPath != nullptr)
                return result;

            auto content = gcnew List<ContentBlock^>();
            auto textBlock = gcnew TextContentBlock();
            textBlock->Text = JsonSerializer::Serialize<DebugGUISnapshotResult^>(result);
            content->Add(textBlock);
            ReadOnlyMemory<Byte> imageData(png);
            content->Add(ImageContentBlock::FromBytes(imageData, "image/png"));

            auto callResult = gcnew CallToolResult();
            callResult->Content = content;
            return callResult;
        }

        static bool ValidateDebugGUISnapshotPath(
            String^ savePath,
            [Out] String^% normalizedPath,
            [Out] String^% error)
        {
            normalizedPath = nullptr;
            error = nullptr;
            if (String::IsNullOrEmpty(savePath))
                return true;

            try
            {
                if (!Path::IsPathFullyQualified(savePath))
                {
                    error = "save_path must be an absolute host path";
                    return false;
                }
                if (!String::Equals(Path::GetExtension(savePath), ".png", StringComparison::OrdinalIgnoreCase))
                {
                    error = "save_path must end with .png";
                    return false;
                }

                normalizedPath = Path::GetFullPath(savePath);
                String^ parent = Path::GetDirectoryName(normalizedPath);
                if (String::IsNullOrEmpty(parent) || !Directory::Exists(parent))
                {
                    error = "save_path parent directory must already exist";
                    return false;
                }
                if (File::Exists(normalizedPath) || Directory::Exists(normalizedPath))
                {
                    error = "save_path already exists and will not be overwritten";
                    return false;
                }
                return true;
            }
            catch (Exception^ exception)
            {
                normalizedPath = nullptr;
                error = "invalid save_path: " + exception->Message;
                return false;
            }
        }

        static bool TryMapDebugGUIWindow(
            String^ window,
            GUISELECTIONTYPE* selectionWindow,
            Script::Gui::Window* scriptWindow)
        {
            if (String::Equals(window, "Disassembly", StringComparison::Ordinal))
            {
                *selectionWindow = GUI_DISASSEMBLY;
                *scriptWindow = Script::Gui::DisassemblyWindow;
                return true;
            }
            if (String::Equals(window, "Dump", StringComparison::Ordinal))
            {
                *selectionWindow = GUI_DUMP;
                *scriptWindow = Script::Gui::DumpWindow;
                return true;
            }
            if (String::Equals(window, "Stack", StringComparison::Ordinal))
            {
                *selectionWindow = GUI_STACK;
                *scriptWindow = Script::Gui::StackWindow;
                return true;
            }
            return false;
        }

        static bool RunDebugGUIContext(DebugGUIContext* context)
        {
            std::future<void> completion = context->completion.get_future();
            GuiExecuteOnGuiThreadEx(ExecuteDebugGUIOnGuiThread, context);
            if (completion.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
                return false;
            return true;
        }

        static String^ DebugGUIFailureCode(DebugGUIFailure failure)
        {
            switch (failure)
            {
            case DebugGUIFailure::NotAttached: return "not_attached";
            case DebugGUIFailure::NotFound: return "not_found";
            default: return "x64dbg_failed";
            }
        }

        static Object^ DebugGUIError(String^ action, String^ code, String^ message)
        {
            McpResult^ result;
            if (action == "focus") result = gcnew DebugGUIFocusResult();
            else if (action == "get") result = gcnew DebugGUIGetResult();
            else result = gcnew DebugGUISetResult();
            result->Success = false;
            result->Error = Helpers::MakeError(code, message);
            return result;
        }

        static DebugGUIRange^ MakeDebugGUIRange(duint start, duint end)
        {
            auto range = gcnew DebugGUIRange();
            range->Start = Helpers::FormatAddress(start);
            range->End = Helpers::FormatAddress(end);
            return range;
        }

        static BreakpointResult^ BreakpointAction(
            String^ action,
            String^ addr,
            String^ kind,
            String^ hardwareType,
            int hardwareSize,
            String^ breakCondition,
            String^ logText,
            String^ logCondition)
        {
            bool isSet = action == "set";
            bool isSetHardware = action == "set_hardware";
            bool isGet = action == "get";
            bool isDisable = action == "disable";
            bool isDelete = action == "delete";
            if (!isGet && !isSet && !isSetHardware && !isDisable && !isDelete)
            {
                return BreakpointError(
                    "invalid_argument",
                    "unknown action: " + (action ? action : "<null>")
                    + "; expected get|set|set_hardware|disable|delete");
            }

            if (!DbgIsDebugging())
                return BreakpointError("not_attached", "no active debug session");

            if (String::IsNullOrEmpty(addr))
                return BreakpointError("invalid_argument", "addr is required");

            duint address = 0;
            if (!Helpers::ResolveExpression(addr, address))
                return BreakpointError("not_found", "could not resolve address: " + addr);

            if (isSet || isSetHardware)
            {
                String^ invalidText = ValidateBreakpointText("breakCondition", breakCondition, MAX_CONDITIONAL_EXPR_SIZE);
                if (invalidText != nullptr) return BreakpointError("invalid_argument", invalidText);
                invalidText = ValidateBreakpointText("logText", logText, MAX_CONDITIONAL_TEXT_SIZE);
                if (invalidText != nullptr) return BreakpointError("invalid_argument", invalidText);
                invalidText = ValidateBreakpointText("logCondition", logCondition, MAX_CONDITIONAL_EXPR_SIZE);
                if (invalidText != nullptr) return BreakpointError("invalid_argument", invalidText);
            }

            if (isSet)
                return SetSoftwareBreakpoint(address, breakCondition, logText, logCondition);
            if (isSetHardware)
                return SetHardwareBreakpoint(
                    address,
                    String::IsNullOrEmpty(hardwareType) ? "execute" : hardwareType,
                    hardwareSize,
                    breakCondition,
                    logText,
                    logCondition);

            BreakpointEntry^ existing = nullptr;
            auto selectionError = SelectBreakpoint(address, kind, existing);
            if (selectionError != nullptr)
                return selectionError;
            if (isGet)
            {
                auto result = gcnew BreakpointResult();
                result->Success = true;
                result->Data = existing;
                return result;
            }

            BPXTYPE selectedType = existing->Type == "hardware" ? bp_hardware : bp_normal;
            if (isDisable)
                return DisableBreakpoint(address, selectedType, existing);
            return DeleteBreakpoint(address, selectedType);
        }

        static BreakpointResult^ SelectBreakpoint(
            duint address,
            String^ kind,
            [Out] BreakpointEntry^% selected)
        {
            selected = nullptr;
            bool selectNormal = String::IsNullOrEmpty(kind) || kind == "normal";
            bool selectHardware = String::IsNullOrEmpty(kind) || kind == "hardware";
            if (!selectNormal && !selectHardware)
                return BreakpointError("invalid_argument", "kind must be one of normal|hardware");

            BreakpointEntry^ normal = nullptr;
            BreakpointEntry^ hardware = nullptr;
            BreakpointSnapshots::FindNormalAndHardware(address, normal, hardware);
            if (!selectNormal) normal = nullptr;
            if (!selectHardware) hardware = nullptr;
            if (String::IsNullOrEmpty(kind) && normal != nullptr && hardware != nullptr)
            {
                return BreakpointError(
                    "invalid_argument",
                    "both normal and hardware breakpoints exist at " + Helpers::FormatAddress(address)
                    + "; specify kind=normal or kind=hardware");
            }

            selected = normal != nullptr ? normal : hardware;
            if (selected == nullptr)
            {
                String^ requested = String::IsNullOrEmpty(kind) ? "normal or hardware" : kind;
                return BreakpointError(
                    "not_found",
                    requested + " breakpoint not found at " + Helpers::FormatAddress(address));
            }
            return nullptr;
        }

        static BreakpointResult^ SetSoftwareBreakpoint(
            duint address,
            String^ breakCondition,
            String^ logText,
            String^ logCondition)
        {
            bool existed = BreakpointSnapshots::Find(bp_normal, address) != nullptr;
            if (!Script::Debug::SetBreakpoint(address))
                return BreakpointError("x64dbg_failed", "failed to set software breakpoint at " + Helpers::FormatAddress(address));

            String^ optionError;
            if (!ApplyBreakpointOptions(false, address, breakCondition, logText, logCondition, optionError))
            {
                bool rolledBack = existed || Script::Debug::DeleteBreakpoint(address);
                return BreakpointError(
                    "x64dbg_failed",
                    optionError + (rolledBack ? "" : "; rollback failed"));
            }

            auto entry = BreakpointSnapshots::Find(bp_normal, address);
            String^ mismatch = ValidateBreakpointReadback(
                entry,
                nullptr,
                nullptr,
                breakCondition,
                logText,
                logCondition);
            if (mismatch != nullptr)
            {
                bool rolledBack = existed || Script::Debug::DeleteBreakpoint(address);
                return BreakpointError(
                    "x64dbg_failed",
                    mismatch + (rolledBack ? "" : "; rollback failed"));
            }

            auto result = gcnew BreakpointResult();
            result->Success = true;
            result->Data = entry;
            return result;
        }

        static BreakpointResult^ SetHardwareBreakpoint(
            duint address,
            String^ type,
            int size,
            String^ breakCondition,
            String^ logText,
            String^ logCondition)
        {
            String^ commandType;
            if (type == "access") commandType = "r";
            else if (type == "write") commandType = "w";
            else if (type == "execute") commandType = "x";
            else
                return BreakpointError(
                    "invalid_argument",
                    "type must be one of access|write|execute");

            if (size != 1 && size != 2 && size != 4 && size != 8)
                return BreakpointError("invalid_argument", "size must be one of 1|2|4|8");
#ifndef _WIN64
            if (size == 8)
                return BreakpointError("invalid_argument", "size=8 is supported only by x64dbg");
#endif
            if (address % (duint)size != 0)
            {
                return BreakpointError(
                    "invalid_argument",
                    "address " + Helpers::FormatAddress(address)
                    + " is not aligned to hardware size " + Convert::ToString(size, CultureInfo::InvariantCulture));
            }

            bool existed = BreakpointSnapshots::Find(bp_hardware, address) != nullptr;
            String^ command = "SetHardwareBreakpoint "
                + Helpers::FormatAddress(address)
                + ", " + commandType
                + ", " + Convert::ToString(size, CultureInfo::InvariantCulture);
            if (!ExecuteDirectUtf8(command))
                return BreakpointError("x64dbg_failed", "failed to set hardware breakpoint at " + Helpers::FormatAddress(address));

            String^ optionError;
            if (!ApplyBreakpointOptions(true, address, breakCondition, logText, logCondition, optionError))
            {
                bool rolledBack = existed || Script::Debug::DeleteHardwareBreakpoint(address);
                return BreakpointError(
                    "x64dbg_failed",
                    optionError + (rolledBack ? "" : "; rollback failed"));
            }

            auto entry = BreakpointSnapshots::Find(bp_hardware, address);
            String^ mismatch = ValidateBreakpointReadback(
                entry,
                type,
                HardwareSizeName(size),
                breakCondition,
                logText,
                logCondition);
            if (mismatch != nullptr)
            {
                bool rolledBack = existed || Script::Debug::DeleteHardwareBreakpoint(address);
                return BreakpointError(
                    "x64dbg_failed",
                    mismatch + (rolledBack ? "" : "; rollback failed"));
            }

            auto result = gcnew BreakpointResult();
            result->Success = true;
            result->Data = entry;
            return result;
        }

        static BreakpointResult^ DisableBreakpoint(
            duint address,
            BPXTYPE type,
            BreakpointEntry^ existing)
        {
            String^ kind = type == bp_hardware ? "hardware" : "normal";

            bool disabled = true;
            if (existing->Enabled)
            {
                disabled = type == bp_hardware
                    ? ExecuteDirectUtf8("DisableHardwareBreakpoint " + Helpers::FormatAddress(address))
                    : Script::Debug::DisableBreakpoint(address);
            }
            if (!disabled)
                return BreakpointError("x64dbg_failed", "failed to disable " + kind + " breakpoint at " + Helpers::FormatAddress(address));

            auto entry = BreakpointSnapshots::Find(type, address);
            if (entry == nullptr || entry->Enabled)
                return BreakpointError("x64dbg_failed", kind + " breakpoint disable readback mismatch at " + Helpers::FormatAddress(address));

            auto result = gcnew BreakpointResult();
            result->Success = true;
            result->Data = entry;
            return result;
        }

        static BreakpointResult^ DeleteBreakpoint(duint address, BPXTYPE type)
        {
            String^ kind = type == bp_hardware ? "hardware" : "software";
            if (BreakpointSnapshots::Find(type, address) == nullptr)
                return BreakpointError("not_found", kind + " breakpoint not found at " + Helpers::FormatAddress(address));

            bool deleted = type == bp_hardware
                ? Script::Debug::DeleteHardwareBreakpoint(address)
                : Script::Debug::DeleteBreakpoint(address);
            if (!deleted)
                return BreakpointError("x64dbg_failed", "failed to delete " + kind + " breakpoint at " + Helpers::FormatAddress(address));
            if (BreakpointSnapshots::Find(type, address) != nullptr)
                return BreakpointError("x64dbg_failed", kind + " breakpoint delete readback mismatch at " + Helpers::FormatAddress(address));

            auto result = gcnew BreakpointResult();
            result->Success = true;
            return result;
        }

        static bool ApplyBreakpointOptions(
            bool hardware,
            duint address,
            String^ breakCondition,
            String^ logText,
            String^ logCondition,
            [Out] String^% error)
        {
            error = nullptr;
            BP_REF reference = {};
            BPXTYPE type = hardware ? bp_hardware : bp_normal;
            if (!DbgFunctions()->BpRefVa(&reference, type, address)
                || !DbgFunctions()->BpRefExists(&reference))
            {
                error = "failed to create breakpoint SDK reference at " + Helpers::FormatAddress(address);
                return false;
            }

            if (!String::IsNullOrEmpty(breakCondition)
                && !SetBreakpointTextField(reference, bpf_breakcondition, breakCondition))
            {
                error = "BpSetFieldText failed for breakCondition at " + Helpers::FormatAddress(address);
                return false;
            }
            if (!String::IsNullOrEmpty(logText)
                && !SetBreakpointTextField(reference, bpf_logtext, logText))
            {
                error = "BpSetFieldText failed for logText at " + Helpers::FormatAddress(address);
                return false;
            }
            if (!String::IsNullOrEmpty(logCondition)
                && !SetBreakpointTextField(reference, bpf_logcondition, logCondition))
            {
                error = "BpSetFieldText failed for logCondition at " + Helpers::FormatAddress(address);
                return false;
            }

            if (!String::IsNullOrEmpty(logText)
                && !DbgFunctions()->BpSetFieldNumber(&reference, bpf_silent, 1))
            {
                error = "BpSetFieldNumber failed for silent at " + Helpers::FormatAddress(address);
                return false;
            }

            GuiUpdateAllViews();
            return true;
        }

        static bool SetBreakpointTextField(BP_REF reference, BP_FIELD field, String^ value)
        {
            IntPtr utf8Value = Marshal::StringToCoTaskMemUTF8(value);
            bool result = DbgFunctions()->BpSetFieldText(
                &reference,
                field,
                static_cast<const char*>(utf8Value.ToPointer()));
            Marshal::FreeCoTaskMem(utf8Value);
            return result;
        }

        static String^ ValidateBreakpointReadback(
            BreakpointEntry^ entry,
            String^ expectedHardwareType,
            String^ expectedHardwareSize,
            String^ breakCondition,
            String^ logText,
            String^ logCondition)
        {
            if (entry == nullptr)
                return "breakpoint was absent during post-mutation readback";
            if (!entry->Enabled)
                return "breakpoint was not enabled during post-mutation readback";
            if (expectedHardwareType != nullptr
                && !String::Equals(entry->Subtype, expectedHardwareType, StringComparison::Ordinal))
                return "hardware breakpoint type readback mismatch";
            if (expectedHardwareSize != nullptr
                && !String::Equals(entry->HardwareSize, expectedHardwareSize, StringComparison::Ordinal))
                return "hardware breakpoint size readback mismatch";
            if (!String::IsNullOrEmpty(breakCondition)
                && !String::Equals(entry->BreakCondition, breakCondition, StringComparison::Ordinal))
                return "breakCondition readback mismatch";
            if (!String::IsNullOrEmpty(logText)
                && !String::Equals(entry->LogText, logText, StringComparison::Ordinal))
                return "logText readback mismatch";
            if (!String::IsNullOrEmpty(logText) && !entry->Silent)
                return "non-empty logText did not enable silent breakpoint mode";
            if (!String::IsNullOrEmpty(logCondition)
                && !String::Equals(entry->LogCondition, logCondition, StringComparison::Ordinal))
                return "logCondition readback mismatch";
            return nullptr;
        }

        static String^ ValidateBreakpointText(String^ name, String^ value, int storageSize)
        {
            if (String::IsNullOrEmpty(value)) return nullptr;
            if (value->IndexOf(L'\0') >= 0)
                return name + " cannot contain a NUL character";

            int byteCount = Encoding::UTF8->GetByteCount(value);
            if (byteCount >= storageSize)
            {
                return name + " must be at most "
                    + Convert::ToString(storageSize - 1, CultureInfo::InvariantCulture)
                    + " UTF-8 bytes";
            }
            return nullptr;
        }

        static String^ HardwareSizeName(int size)
        {
            switch (size)
            {
            case 1: return "byte";
            case 2: return "word";
            case 4: return "dword";
            case 8: return "qword";
            default: return nullptr;
            }
        }

        static bool ExecuteDirectUtf8(String^ command)
        {
            IntPtr utf8Command = Marshal::StringToCoTaskMemUTF8(command);
            bool result = DbgCmdExecDirect(static_cast<const char*>(utf8Command.ToPointer()));
            Marshal::FreeCoTaskMem(utf8Command);
            return result;
        }

        static BreakpointResult^ BreakpointError(String^ code, String^ message)
        {
            auto result = gcnew BreakpointResult();
            result->Success = false;
            result->Error = Helpers::MakeError(code, message);
            return result;
        }

        static MemoryReadResult^ MemoryRead(String^ addr, int size, bool compress)
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

        static DebugControlResult^ AttachAction(int pid, bool detach2attach)
        {
            auto r = gcnew DebugControlResult();
            r->Action = "attach";

            if (pid <= 0)
            {
                r->Success = false;
                r->Error = Helpers::MakeError("invalid_argument", "pid must be a positive decimal process ID for action=attach");
                return r;
            }

            std::lock_guard<std::mutex> lock(g_attachMutex);
            bool wasDebugging = DbgIsDebugging();
            if (wasDebugging && !detach2attach)
            {
                r->Success = false;
                r->Error = Helpers::MakeError(
                    "invalid_argument",
                    "detach2attach must be true when action=attach is called during an active debug session");
                return r;
            }

            char previousDetachOnAttach[MAX_SETTING_SIZE] = {};
            bool hadPreviousSetting = false;
            if (wasDebugging)
            {
                hadPreviousSetting = BridgeSettingGet(
                    "Engine",
                    "DetachOnAttach",
                    previousDetachOnAttach);
                if (!BridgeSettingSetUint("Engine", "DetachOnAttach", 1))
                {
                    r->Success = false;
                    r->Error = Helpers::MakeError(
                        "x64dbg_failed",
                        "failed to enable Engine.DetachOnAttach for action=attach");
                    return r;
                }
            }

            auto cmd = String::Format(CultureInfo::InvariantCulture, "attach .{0}", pid);
            std::string nativeCommand = msclr::interop::marshal_as<std::string>(cmd);
            bool ok = DbgCmdExecDirect(nativeCommand.c_str());

            if (wasDebugging)
            {
                bool restored = hadPreviousSetting
                    ? BridgeSettingSet("Engine", "DetachOnAttach", previousDetachOnAttach)
                    : BridgeSettingSet("Engine", "DetachOnAttach", nullptr);
                if (!restored)
                {
                    r->Success = false;
                    r->Error = Helpers::MakeError(
                        "x64dbg_failed",
                        "attach command completed but Engine.DetachOnAttach could not be restored");
                    return r;
                }
            }

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

        static RegisterDumpResult^ DumpAction(int requestedThreadId)
        {
            auto r = gcnew RegisterDumpResult();
            r->Success = true;
            r->Registers = gcnew Dictionary<String^, String^>();
            r->Flags = gcnew Dictionary<String^, bool>();

            if (requestedThreadId < 0)
            {
                r->Success = false;
                r->Error = Helpers::MakeError("invalid_argument", "threadId must be non-negative");
                return r;
            }

            int activeThreadId = (int)DbgGetThreadId();
            r->ThreadId = requestedThreadId == 0 ? activeThreadId : requestedThreadId;

            if (r->ThreadId != activeThreadId)
            {
                if (DbgIsRunning())
                {
                    r->Success = false;
                    r->Error = Helpers::MakeError(
                        "not_paused",
                        "the debuggee must be paused to read an inactive thread context");
                    return r;
                }

                ThreadRegisterSnapshot* context = new ThreadRegisterSnapshot();
                memset(context, 0, sizeof(ThreadRegisterSnapshot));
                int contextResult = GetThreadContextUnmanaged((DWORD)r->ThreadId, context);
                if (contextResult != 0)
                {
                    delete context;
                    r->Success = false;
                    r->Error = contextResult == 1
                        ? Helpers::MakeError("not_found", "thread ID not found: " + r->ThreadId.ToString())
                        : Helpers::MakeError("x64dbg_failed", "GetThreadContext failed for thread: " + r->ThreadId.ToString());
                    return r;
                }

#ifdef _WIN64
                r->Registers["rax"] = Helpers::FormatAddress(context->cax);
                r->Registers["rbx"] = Helpers::FormatAddress(context->cbx);
                r->Registers["rcx"] = Helpers::FormatAddress(context->ccx);
                r->Registers["rdx"] = Helpers::FormatAddress(context->cdx);
                r->Registers["rsi"] = Helpers::FormatAddress(context->csi);
                r->Registers["rdi"] = Helpers::FormatAddress(context->cdi);
                r->Registers["rbp"] = Helpers::FormatAddress(context->cbp);
                r->Registers["rsp"] = Helpers::FormatAddress(context->csp);
                r->Registers["rip"] = Helpers::FormatAddress(context->cip);
                r->Registers["r8"] = Helpers::FormatAddress(context->r8);
                r->Registers["r9"] = Helpers::FormatAddress(context->r9);
                r->Registers["r10"] = Helpers::FormatAddress(context->r10);
                r->Registers["r11"] = Helpers::FormatAddress(context->r11);
                r->Registers["r12"] = Helpers::FormatAddress(context->r12);
                r->Registers["r13"] = Helpers::FormatAddress(context->r13);
                r->Registers["r14"] = Helpers::FormatAddress(context->r14);
                r->Registers["r15"] = Helpers::FormatAddress(context->r15);
#else
                r->Registers["eax"] = Helpers::FormatAddress(context->cax);
                r->Registers["ebx"] = Helpers::FormatAddress(context->cbx);
                r->Registers["ecx"] = Helpers::FormatAddress(context->ccx);
                r->Registers["edx"] = Helpers::FormatAddress(context->cdx);
                r->Registers["esi"] = Helpers::FormatAddress(context->csi);
                r->Registers["edi"] = Helpers::FormatAddress(context->cdi);
                r->Registers["ebp"] = Helpers::FormatAddress(context->cbp);
                r->Registers["esp"] = Helpers::FormatAddress(context->csp);
                r->Registers["eip"] = Helpers::FormatAddress(context->cip);
#endif
                r->Registers["cs"] = Helpers::FormatAddress(context->cs);
                r->Registers["ds"] = Helpers::FormatAddress(context->ds);
                r->Registers["es"] = Helpers::FormatAddress(context->es);
                r->Registers["fs"] = Helpers::FormatAddress(context->fs);
                r->Registers["gs"] = Helpers::FormatAddress(context->gs);
                r->Registers["ss"] = Helpers::FormatAddress(context->ss);
                r->Registers["dr0"] = Helpers::FormatAddress(context->dr0);
                r->Registers["dr1"] = Helpers::FormatAddress(context->dr1);
                r->Registers["dr2"] = Helpers::FormatAddress(context->dr2);
                r->Registers["dr3"] = Helpers::FormatAddress(context->dr3);
                r->Registers["dr6"] = Helpers::FormatAddress(context->dr6);
                r->Registers["dr7"] = Helpers::FormatAddress(context->dr7);
                PopulateFlags(r, context->eflags);
                delete context;
                return r;
            }

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

            PopulateFlags(r, ctx.eflags);

            // LastError and LastStatus from REGDUMP_AVX512
            if (regdump->lastError != 0)
                r->LastError = Helpers::FormatAddress(regdump->lastError);

            if (regdump->lastStatus != 0)
                r->LastStatus = Helpers::FormatAddress(regdump->lastStatus);

            delete regdump;
            return r;
        }

        static void PopulateFlags(RegisterDumpResult^ result, duint eflags)
        {
            result->Flags["cf"] = (eflags & 0x0001) != 0;
            result->Flags["pf"] = (eflags & 0x0004) != 0;
            result->Flags["af"] = (eflags & 0x0010) != 0;
            result->Flags["zf"] = (eflags & 0x0040) != 0;
            result->Flags["sf"] = (eflags & 0x0080) != 0;
            result->Flags["tf"] = (eflags & 0x0100) != 0;
            result->Flags["if"] = (eflags & 0x0200) != 0;
            result->Flags["df"] = (eflags & 0x0400) != 0;
            result->Flags["of"] = (eflags & 0x0800) != 0;
        }
    };
}
