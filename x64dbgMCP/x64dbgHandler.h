#pragma once

#include "plugintemplate/pluginmain.h"

namespace x64dbgMCP {

    using namespace System;
    using namespace System::Collections::Generic;
    using namespace System::ComponentModel;
    using namespace System::Runtime::InteropServices;
    using namespace ModelContextProtocol::Server;

    // ═══════════════════════════════════════════════════════════════
    //  Internal Helpers — not exposed as MCP tools
    // ═══════════════════════════════════════════════════════════════

    ref class Helpers abstract sealed
    {
    internal:

        // ── Address / Expression ──

        static String^ FormatAddress(duint addr)
        {
            return String::Format("0x{0:X}", (UInt64)addr);
        }

        /// Resolve any address-like string (hex, decimal, x64dbg expression,
        /// label, or API name) to a concrete address.
        static duint ResolveExpression(String^ expr)
        {
            if (String::IsNullOrWhiteSpace(expr))
                throw gcnew ArgumentException("Expression cannot be empty.");
            IntPtr ptr = Marshal::StringToHGlobalAnsi(expr);
            try {
                duint value = 0;
                if (!Script::Misc::ParseExpression(
                        static_cast<const char*>(ptr.ToPointer()), &value))
                    throw gcnew ArgumentException(
                        "Failed to resolve expression: " + expr);
                return value;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        // ── Flag name → enum ──

        static Script::Flag::FlagEnum FlagFromName(String^ name)
        {
            auto lower = name->ToLowerInvariant()->Trim();
            if (lower == "zf") return Script::Flag::ZF;
            if (lower == "of") return Script::Flag::OF;
            if (lower == "cf") return Script::Flag::CF;
            if (lower == "pf") return Script::Flag::PF;
            if (lower == "sf") return Script::Flag::SF;
            if (lower == "tf") return Script::Flag::TF;
            if (lower == "af") return Script::Flag::AF;
            if (lower == "df") return Script::Flag::DF;
            if (lower == "if") return Script::Flag::IF;
            throw gcnew ArgumentException(
                "Unknown flag: " + name +
                ". Valid names: zf, of, cf, pf, sf, tf, af, df, if");
        }

        // ── Register name → enum (case-insensitive, with aliases) ──

        static Script::Register::RegisterEnum RegisterFromName(String^ name)
        {
            auto lower = name->ToLowerInvariant()->Trim();

            // Debug registers
            if (lower == "dr0") return Script::Register::DR0;
            if (lower == "dr1") return Script::Register::DR1;
            if (lower == "dr2") return Script::Register::DR2;
            if (lower == "dr3") return Script::Register::DR3;
            if (lower == "dr6") return Script::Register::DR6;
            if (lower == "dr7") return Script::Register::DR7;

            // 32-bit general purpose
            if (lower == "eax") return Script::Register::EAX;
            if (lower == "ebx") return Script::Register::EBX;
            if (lower == "ecx") return Script::Register::ECX;
            if (lower == "edx") return Script::Register::EDX;
            if (lower == "esi") return Script::Register::ESI;
            if (lower == "edi") return Script::Register::EDI;
            if (lower == "ebp") return Script::Register::EBP;
            if (lower == "esp") return Script::Register::ESP;
            if (lower == "eip") return Script::Register::EIP;

            // 16-bit
            if (lower == "ax") return Script::Register::AX;
            if (lower == "bx") return Script::Register::BX;
            if (lower == "cx") return Script::Register::CX;
            if (lower == "dx") return Script::Register::DX;
            if (lower == "si") return Script::Register::SI;
            if (lower == "di") return Script::Register::DI;
            if (lower == "bp") return Script::Register::BP;
            if (lower == "sp") return Script::Register::SP;

            // 8-bit
            if (lower == "ah") return Script::Register::AH;
            if (lower == "al") return Script::Register::AL;
            if (lower == "bh") return Script::Register::BH;
            if (lower == "bl") return Script::Register::BL;
            if (lower == "ch") return Script::Register::CH;
            if (lower == "cl") return Script::Register::CL;
            if (lower == "dh") return Script::Register::DH;
            if (lower == "dl") return Script::Register::DL;

#ifdef _WIN64
            // 64-bit general purpose
            if (lower == "rax") return Script::Register::RAX;
            if (lower == "rbx") return Script::Register::RBX;
            if (lower == "rcx") return Script::Register::RCX;
            if (lower == "rdx") return Script::Register::RDX;
            if (lower == "rsi") return Script::Register::RSI;
            if (lower == "rdi") return Script::Register::RDI;
            if (lower == "rbp") return Script::Register::RBP;
            if (lower == "rsp") return Script::Register::RSP;
            if (lower == "rip") return Script::Register::RIP;
            if (lower == "sil") return Script::Register::SIL;
            if (lower == "dil") return Script::Register::DIL;
            if (lower == "bpl") return Script::Register::BPL;
            if (lower == "spl") return Script::Register::SPL;

            // R8–R15 and sub-registers
            if (lower == "r8")  return Script::Register::R8;
            if (lower == "r8d") return Script::Register::R8D;
            if (lower == "r8w") return Script::Register::R8W;
            if (lower == "r8b") return Script::Register::R8B;
            if (lower == "r9")  return Script::Register::R9;
            if (lower == "r9d") return Script::Register::R9D;
            if (lower == "r9w") return Script::Register::R9W;
            if (lower == "r9b") return Script::Register::R9B;
            if (lower == "r10")  return Script::Register::R10;
            if (lower == "r10d") return Script::Register::R10D;
            if (lower == "r10w") return Script::Register::R10W;
            if (lower == "r10b") return Script::Register::R10B;
            if (lower == "r11")  return Script::Register::R11;
            if (lower == "r11d") return Script::Register::R11D;
            if (lower == "r11w") return Script::Register::R11W;
            if (lower == "r11b") return Script::Register::R11B;
            if (lower == "r12")  return Script::Register::R12;
            if (lower == "r12d") return Script::Register::R12D;
            if (lower == "r12w") return Script::Register::R12W;
            if (lower == "r12b") return Script::Register::R12B;
            if (lower == "r13")  return Script::Register::R13;
            if (lower == "r13d") return Script::Register::R13D;
            if (lower == "r13w") return Script::Register::R13W;
            if (lower == "r13b") return Script::Register::R13B;
            if (lower == "r14")  return Script::Register::R14;
            if (lower == "r14d") return Script::Register::R14D;
            if (lower == "r14w") return Script::Register::R14W;
            if (lower == "r14b") return Script::Register::R14B;
            if (lower == "r15")  return Script::Register::R15;
            if (lower == "r15d") return Script::Register::R15D;
            if (lower == "r15w") return Script::Register::R15W;
            if (lower == "r15b") return Script::Register::R15B;
#endif

            // Architecture-agnostic (cip/csp/cax etc.)
            if (lower == "cip") return Script::Register::CIP;
            if (lower == "csp") return Script::Register::CSP;
            if (lower == "cax") return Script::Register::CAX;
            if (lower == "cbx") return Script::Register::CBX;
            if (lower == "ccx") return Script::Register::CCX;
            if (lower == "cdx") return Script::Register::CDX;
            if (lower == "csi") return Script::Register::CSI;
            if (lower == "cdi") return Script::Register::CDI;
            if (lower == "cbp") return Script::Register::CBP;
            if (lower == "cflags") return Script::Register::CFLAGS;

            throw gcnew ArgumentException(
                "Unknown register: " + name +
                ". Use names like rax, eax, cip, r8, zf, etc.");
        }

        // ── Breakpoint type string → BPXTYPE ──

        static BPXTYPE BpTypeFromName(String^ type)
        {
            auto lower = type->ToLowerInvariant()->Trim();
            if (lower == "all")                              return bp_none;
            if (lower == "normal"   || lower == "software")  return bp_normal;
            if (lower == "hardware" || lower == "hw")        return bp_hardware;
            if (lower == "memory"   || lower == "mem")       return bp_memory;
            throw gcnew ArgumentException(
                "Unknown breakpoint type: " + type +
                ". Valid: all, normal, hardware, memory");
        }

        static String^ BpTypeToString(int type)
        {
            switch (type) {
                case bp_normal:    return "normal";
                case bp_hardware:  return "hardware";
                case bp_memory:    return "memory";
                case bp_dll:       return "dll";
                case bp_exception: return "exception";
                default:           return "unknown";
            }
        }

        // ── Hardware breakpoint type string → enum ──

        static Script::Debug::HardwareType HwBpTypeFromName(String^ type)
        {
            auto lower = type->ToLowerInvariant()->Trim();
            if (lower == "access" || lower == "read")
                return Script::Debug::HardwareAccess;
            if (lower == "write")
                return Script::Debug::HardwareWrite;
            if (lower == "execute" || lower == "exec")
                return Script::Debug::HardwareExecute;
            throw gcnew ArgumentException(
                "Unknown hardware BP type: " + type +
                ". Valid: access, write, execute");
        }

        // ── Xref type int → readable string ──

        static String^ XrefTypeToString(int type)
        {
            switch (type) {
                case 0: return "none";
                case 1: return "data";
                case 2: return "jmp";
                case 3: return "call";
                default: return "unknown";
            }
        }

        // ── GUI window name → GUISELECTIONTYPE int ──

        static int GuiWindowFromName(String^ name)
        {
            auto lower = name->ToLowerInvariant()->Trim();
            if (lower == "disassembly" || lower == "disasm" || lower == "cpu")
                return 0;
            if (lower == "dump")    return 1;
            if (lower == "stack")   return 2;
            if (lower == "graph")   return 3;
            if (lower == "memmap" || lower == "memory") return 4;
            if (lower == "symmod" || lower == "symbols" || lower == "modules")
                return 5;
            throw gcnew ArgumentException(
                "Unknown window: " + name +
                ". Valid: disassembly, dump, stack, graph, memmap, symmod");
        }

        // ── Resolve module by name-or-address expression ──
        // Tries expression first, then falls back to module name lookup.

        static duint ResolveModuleBase(String^ moduleExpr)
        {
            // First try as an address expression
            IntPtr ptr = Marshal::StringToHGlobalAnsi(moduleExpr);
            try {
                const char* native = static_cast<const char*>(ptr.ToPointer());

                duint value = 0;
                if (Script::Misc::ParseExpression(native, &value)) {
                    duint base = Script::Module::BaseFromAddr(value);
                    if (base) return base;
                    return value;
                }
                // Fall back to module name
                duint base = Script::Module::BaseFromName(native);
                if (base) return base;

                throw gcnew ArgumentException(
                    "Cannot resolve module: " + moduleExpr);
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }
    };

    // ═══════════════════════════════════════════════════════════════
    //  Structured Result Types
    // ═══════════════════════════════════════════════════════════════

    public ref class ProjectInfoResult
    {
    public:
        [Description("Plugin Version")]
        property String^ Version
        {
            String^ get()
            {
                return (gcnew System::Version(
                    (PLUGIN_VERSION >> 16) & 0xFF,
                    (PLUGIN_VERSION >> 8) & 0xFF,
                    PLUGIN_VERSION & 0xFF))->ToString();
            }
        }
        [Description("Target Architecture")]
        property String^ Platform {
            String^ get()
            {
#ifdef _WIN64
                return BridgeIsARM64Emulated() ? "arm64" : "x64";
#else
                return "x86";
#endif
            }
        }
        [Description("x64dbg Directory")]
        property String^ X64dbg_dir {
            String^ get() {
                return gcnew String(BridgeUserDirectory());
            }
        }
    };

    public ref class DisassemblyInstruction
    {
    public:
        [Description("Instruction virtual address (hex)")]
        property String^ address;
        [Description("Full disassembly text")]
        property String^ text;
        [Description("Instruction size in bytes")]
        property int size;
        [Description("Raw instruction bytes (hex)")]
        property String^ bytes;
        [Description("True if this is a branch/jump instruction")]
        property bool is_branch;
        [Description("True if this is a call instruction")]
        property bool is_call;
        [Description("Branch/call target address (hex), empty if not a branch")]
        property String^ branch_target;
        [Description("Comment at this address (if any)")]
        property String^ comment;
        [Description("Label at this address (if any)")]
        property String^ label;
    };

    public ref class BreakpointItem
    {
    public:
        [Description("Breakpoint type: normal, hardware, memory, dll, exception")]
        property String^ type;
        [Description("Breakpoint address (hex)")]
        property String^ address;
        [Description("Whether the breakpoint is enabled")]
        property bool enabled;
        [Description("Whether this is a single-shot breakpoint (auto-deleted after first hit)")]
        property bool singleshoot;
        [Description("Whether the breakpoint is active")]
        property bool active;
        [Description("Breakpoint name")]
        property String^ name;
        [Description("Module name")]
        property String^ module;
        [Description("Hit count")]
        property unsigned int hitCount;
        [Description("Break condition expression")]
        property String^ breakCondition;
        [Description("Log text template")]
        property String^ logText;
        [Description("Command text to execute on hit")]
        property String^ commandText;
    };

    public ref class ModuleItem
    {
    public:
        [Description("Module base address (hex)")]
        property String^ base;
        [Description("Module size in bytes")]
        property UInt64 size;
        [Description("Module entry point address (hex)")]
        property String^ entry;
        [Description("Number of sections")]
        property int sectionCount;
        [Description("Module file name")]
        property String^ name;
        [Description("Full file path")]
        property String^ path;
    };

    public ref class SectionItem
    {
    public:
        [Description("Section virtual address (hex)")]
        property String^ address;
        [Description("Section size in bytes")]
        property UInt64 size;
        [Description("Section name")]
        property String^ name;
    };

    public ref class MemoryRegionItem
    {
    public:
        [Description("Region base address (hex)")]
        property String^ baseAddress;
        [Description("Allocation base address (hex)")]
        property String^ allocationBase;
        [Description("Region size in bytes")]
        property UInt64 regionSize;
        [Description("Memory protection flags")]
        property unsigned int protect;
        [Description("Memory state (commit/reserve/free)")]
        property unsigned int state;
        [Description("Memory type (image/mapped/private)")]
        property unsigned int type;
        [Description("Additional info (module name, etc.)")]
        property String^ info;
    };

    public ref class ThreadItem
    {
    public:
        [Description("Thread number (index)")]
        property int threadNumber;
        [Description("Thread ID")]
        property unsigned int threadId;
        [Description("Thread start address (hex)")]
        property String^ startAddress;
        [Description("Thread local base address (hex)")]
        property String^ localBase;
        [Description("Thread current instruction pointer (hex)")]
        property String^ cip;
        [Description("Suspend count")]
        property unsigned int suspendCount;
        [Description("Thread name")]
        property String^ name;
        [Description("Thread priority")]
        property int priority;
        [Description("Last Win32 error code")]
        property unsigned int lastError;
    };

    public ref class CallStackEntry
    {
    public:
        [Description("Stack frame address (hex)")]
        property String^ address;
        [Description("Call origin address (hex)")]
        property String^ from;
        [Description("Call target address (hex)")]
        property String^ to;
        [Description("Comment/symbol info")]
        property String^ comment;
    };

    public ref class LabelItem
    {
    public:
        [Description("Module name")]
        property String^ module;
        [Description("Relative virtual address (hex)")]
        property String^ rva;
        [Description("Label text")]
        property String^ text;
        [Description("Whether this is a user-defined label")]
        property bool manual;
    };

    public ref class CommentItem
    {
    public:
        [Description("Module name")]
        property String^ module;
        [Description("Relative virtual address (hex)")]
        property String^ rva;
        [Description("Comment text")]
        property String^ text;
        [Description("Whether this is a user-defined comment")]
        property bool manual;
    };

    public ref class BookmarkItem
    {
    public:
        [Description("Module name")]
        property String^ module;
        [Description("Relative virtual address (hex)")]
        property String^ rva;
        [Description("Whether this is a user-defined bookmark")]
        property bool manual;
    };

    public ref class FunctionItem
    {
    public:
        [Description("Module name")]
        property String^ module;
        [Description("Function start RVA (hex)")]
        property String^ rvaStart;
        [Description("Function end RVA (hex)")]
        property String^ rvaEnd;
        [Description("Whether this is a user-defined function")]
        property bool manual;
        [Description("Number of instructions")]
        property UInt64 instructionCount;
    };

    public ref class ArgumentItem
    {
    public:
        [Description("Module name")]
        property String^ module;
        [Description("Argument range start RVA (hex)")]
        property String^ rvaStart;
        [Description("Argument range end RVA (hex)")]
        property String^ rvaEnd;
        [Description("Whether this is user-defined")]
        property bool manual;
        [Description("Number of instructions")]
        property UInt64 instructionCount;
    };

    public ref class SymbolItem
    {
    public:
        [Description("Module name")]
        property String^ module;
        [Description("Relative virtual address (hex)")]
        property String^ rva;
        [Description("Symbol name")]
        property String^ name;
        [Description("Whether this is user-defined")]
        property bool manual;
        [Description("Symbol type: function, import, or export")]
        property String^ type;
    };

    public ref class ExportItem
    {
    public:
        [Description("Ordinal number")]
        property UInt64 ordinal;
        [Description("Relative virtual address (hex)")]
        property String^ rva;
        [Description("Virtual address (hex)")]
        property String^ va;
        [Description("Whether the export is forwarded")]
        property bool forwarded;
        [Description("Forward target name (if forwarded)")]
        property String^ forwardName;
        [Description("Export name")]
        property String^ name;
        [Description("Undecorated export name")]
        property String^ undecoratedName;
    };

    public ref class ImportItem
    {
    public:
        [Description("IAT relative virtual address (hex)")]
        property String^ iatRva;
        [Description("IAT virtual address (hex)")]
        property String^ iatVa;
        [Description("Ordinal (-1 if imported by name)")]
        property UInt64 ordinal;
        [Description("Import name")]
        property String^ name;
        [Description("Undecorated import name")]
        property String^ undecoratedName;
    };

    public ref class XrefItem
    {
    public:
        [Description("Cross-reference source address (hex)")]
        property String^ address;
        [Description("Cross-reference type: none, data, jmp, call")]
        property String^ type;
    };

    public ref class WatchItem
    {
    public:
        [Description("Watch entry name")]
        property String^ name;
        [Description("Watch expression")]
        property String^ expression;
        [Description("Window index")]
        property unsigned int window;
        [Description("Watch ID")]
        property unsigned int id;
        [Description("Current evaluated value (hex)")]
        property String^ value;
    };

    public ref class DebugStateResult
    {
    public:
        [Description("Whether the operation succeeded")]
        property bool success;
        [Description("Current debugger state: paused, running, terminated, inactive")]
        property String^ state;
        [Description("Address where execution paused (hex), if applicable")]
        property String^ paused_at;
        [Description("Additional message")]
        property String^ message;
    };

    // ═══════════════════════════════════════════════════════════════
    //  MCP Analysis Tools (read-only / annotation operations)
    // ═══════════════════════════════════════════════════════════════

    [McpServerToolType]
    public ref class McpAnalysisTools
    {
    public:

        // ── Project ──

        [McpServerTool(ReadOnly = true), Description(
            "Get project information: plugin version, target architecture, and x64dbg directory.")]
        static auto GetProjectInfo()
        {
            return gcnew ProjectInfoResult();
        }

        // ── Expression / Address Resolution ──

        [McpServerTool(ReadOnly = true), Description(
            "Evaluate an x64dbg expression and return the resolved address. "
            "Accepts hex (0x401000), decimal, x64dbg expressions (cip+5, mem.base(cip)), "
            "labels, or API names (kernel32:CreateFileW).")]
        static auto ParseExpression(
            [Description("Expression to evaluate")] String^ expression)
        {
            duint value = Helpers::ResolveExpression(expression);
            auto result = gcnew Dictionary<String^, Object^>();
            result["input"] = expression;
            result["resolved_address"] = Helpers::FormatAddress(value);
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Resolve a label or API name to its virtual address.")]
        static auto ResolveLabel(
            [Description("Label or API name (e.g. 'LoadLibraryA', 'main')")] String^ label)
        {
            IntPtr ptr = Marshal::StringToHGlobalAnsi(label);
            try {
                duint addr = Script::Misc::ResolveLabel(
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["input"] = label;
                result["resolved_address"] = Helpers::FormatAddress(addr);
                result["success"] = (addr != 0);
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the string (ASCII or Unicode) at the specified address, if any.")]
        static auto GetStringAt(
            [Description("Address expression to query")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            char text[MAX_STRING_SIZE] = "";
            bool found = DbgGetStringAt(addr, text);
            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["found"] = found;
            result["text"] = found ? gcnew String(text) : "";
            return result;
        }

        // ── Symbol ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the list of symbols in the debugged process. "
            "Returns structured symbol entries with module, name, RVA, and type.")]
        static auto GetSymbolList(
            [Description("Maximum number of symbols to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            BridgeList<Script::Symbol::SymbolInfo> nativeList;
            Script::Symbol::GetList(&nativeList);

            int total = nativeList.Count();
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<SymbolItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew SymbolItem();
                item->module = gcnew String(nativeList[i].mod);
                item->rva = Helpers::FormatAddress(nativeList[i].rva);
                item->name = gcnew String(nativeList[i].name);
                item->manual = nativeList[i].manual;
                switch (nativeList[i].type) {
                    case 0: item->type = "function"; break;
                    case 1: item->type = "import"; break;
                    case 2: item->type = "export"; break;
                    default: item->type = "unknown"; break;
                }
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get symbol information at a specific address.")]
        static auto GetSymbolAt(
            [Description("Address expression to query")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            SYMBOLINFO info = {};
            bool found = DbgGetSymbolInfoAt(addr, &info);

            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["found"] = found;
            if (found) {
                result["decoratedSymbol"] = info.decoratedSymbol
                    ? gcnew String(info.decoratedSymbol) : "";
                result["undecoratedSymbol"] = info.undecoratedSymbol
                    ? gcnew String(info.undecoratedSymbol) : "";
                result["ordinal"] = (int)info.ordinal;
                if (info.freeDecorated && info.decoratedSymbol)
                    BridgeFree(info.decoratedSymbol);
                if (info.freeUndecorated && info.undecoratedSymbol)
                    BridgeFree(info.undecoratedSymbol);
            }
            return result;
        }

        // ── Function ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the list of all recognized functions in the debugged process.")]
        static auto GetFunctionList(
            [Description("Maximum number of functions to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            BridgeList<Script::Function::FunctionInfo> nativeList;
            Script::Function::GetList(&nativeList);

            int total = nativeList.Count();
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<FunctionItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew FunctionItem();
                item->module = gcnew String(nativeList[i].mod);
                item->rvaStart = Helpers::FormatAddress(nativeList[i].rvaStart);
                item->rvaEnd = Helpers::FormatAddress(nativeList[i].rvaEnd);
                item->manual = nativeList[i].manual;
                item->instructionCount = nativeList[i].instructioncount;
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get function information at a specific address (start, end, instruction count).")]
        static auto GetFunctionAt(
            [Description("Address expression within the function")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            Script::Function::FunctionInfo f = {};
            bool found = Script::Function::GetInfo(addr, &f);

            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["found"] = found;
            if (found) {
                result["module"] = gcnew String(f.mod);
                result["rvaStart"] = Helpers::FormatAddress(f.rvaStart);
                result["rvaEnd"] = Helpers::FormatAddress(f.rvaEnd);
                result["manual"] = f.manual;
                result["instructionCount"] = (UInt64)f.instructioncount;
            }
            return result;
        }

        [McpServerTool, Description(
            "Add a function entry covering an address range.")]
        static auto AddFunction(
            [Description("Start address expression")] String^ start,
            [Description("End address expression")] String^ end,
            [Description("Whether this is a user-defined function")] bool manual,
            [Description("Number of instructions (0 if unknown)")] int instructionCount)
        {
            duint s = Helpers::ResolveExpression(start);
            duint e = Helpers::ResolveExpression(end);
            bool ok = Script::Function::Add(s, e, manual, instructionCount);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["start"] = Helpers::FormatAddress(s);
            result["end"] = Helpers::FormatAddress(e);
            return result;
        }

        [McpServerTool, Description(
            "Delete the function entry at the specified address.")]
        static auto DeleteFunction(
            [Description("Address expression within the function to delete")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Function::Delete(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        // ── Label ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the list of all labels in the debugged process.")]
        static auto GetLabelList(
            [Description("Maximum number of labels to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            BridgeList<Script::Label::LabelInfo> nativeList;
            Script::Label::GetList(&nativeList);

            int total = nativeList.Count();
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<LabelItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew LabelItem();
                item->module = gcnew String(nativeList[i].mod);
                item->rva = Helpers::FormatAddress(nativeList[i].rva);
                item->text = gcnew String(nativeList[i].text);
                item->manual = nativeList[i].manual;
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get label text at a specific address.")]
        static auto GetLabelAt(
            [Description("Address expression to query")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            char text[MAX_LABEL_SIZE] = "";
            bool found = DbgGetLabelAt(addr, SEG_DEFAULT, text);

            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["found"] = found;
            result["text"] = found ? gcnew String(text) : "";
            return result;
        }

        [McpServerTool, Description(
            "Set a label at the specified address.")]
        static auto SetLabel(
            [Description("Address expression")] String^ address,
            [Description("Label text")] String^ text,
            [Description("Whether this is a user-defined label")] bool manual,
            [Description("Whether this label is temporary")] bool temporary)
        {
            duint addr = Helpers::ResolveExpression(address);
            IntPtr ptr = Marshal::StringToHGlobalAnsi(text);
            try {
                bool ok = Script::Label::Set(addr,
                    static_cast<const char*>(ptr.ToPointer()), manual, temporary);
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = ok;
                result["address"] = Helpers::FormatAddress(addr);
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool, Description(
            "Delete the label at the specified address.")]
        static auto DeleteLabel(
            [Description("Address expression")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Label::Delete(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Resolve a label name to its virtual address.")]
        static auto LabelFromString(
            [Description("Label name to resolve")] String^ label)
        {
            IntPtr ptr = Marshal::StringToHGlobalAnsi(label);
            try {
                duint addr = 0;
                bool ok = Script::Label::FromString(
                    static_cast<const char*>(ptr.ToPointer()), &addr);
                auto result = gcnew Dictionary<String^, Object^>();
                result["input"] = label;
                result["found"] = ok;
                result["address"] = ok ? Helpers::FormatAddress(addr) : "";
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        // ── Comment ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the list of all comments in the debugged process.")]
        static auto GetCommentList(
            [Description("Maximum number of comments to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            BridgeList<Script::Comment::CommentInfo> nativeList;
            Script::Comment::GetList(&nativeList);

            int total = nativeList.Count();
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<CommentItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew CommentItem();
                item->module = gcnew String(nativeList[i].mod);
                item->rva = Helpers::FormatAddress(nativeList[i].rva);
                item->text = gcnew String(nativeList[i].text);
                item->manual = nativeList[i].manual;
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the comment text at a specific address.")]
        static auto GetCommentAt(
            [Description("Address expression to query")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            char text[MAX_COMMENT_SIZE] = "";
            bool found = DbgGetCommentAt(addr, text);

            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["found"] = found;
            result["text"] = found ? gcnew String(text) : "";
            return result;
        }

        [McpServerTool, Description(
            "Set a comment at the specified address.")]
        static auto SetComment(
            [Description("Address expression")] String^ address,
            [Description("Comment text")] String^ text,
            [Description("Whether this is a user-defined comment")] bool manual)
        {
            duint addr = Helpers::ResolveExpression(address);
            IntPtr ptr = Marshal::StringToHGlobalAnsi(text);
            try {
                bool ok = Script::Comment::Set(addr,
                    static_cast<const char*>(ptr.ToPointer()), manual);
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = ok;
                result["address"] = Helpers::FormatAddress(addr);
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool, Description(
            "Delete the comment at the specified address.")]
        static auto DeleteComment(
            [Description("Address expression")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Comment::Delete(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        // ── Bookmark ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the list of all bookmarks.")]
        static auto GetBookmarkList(
            [Description("Maximum number of bookmarks to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            BridgeList<Script::Bookmark::BookmarkInfo> nativeList;
            Script::Bookmark::GetList(&nativeList);

            int total = nativeList.Count();
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<BookmarkItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew BookmarkItem();
                item->module = gcnew String(nativeList[i].mod);
                item->rva = Helpers::FormatAddress(nativeList[i].rva);
                item->manual = nativeList[i].manual;
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Check whether there is a bookmark at the specified address.")]
        static auto GetBookmarkAt(
            [Description("Address expression to query")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool found = DbgGetBookmarkAt(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["found"] = found;
            return result;
        }

        [McpServerTool, Description(
            "Set a bookmark at the specified address.")]
        static auto SetBookmark(
            [Description("Address expression")] String^ address,
            [Description("Whether this is a user-defined bookmark")] bool manual)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Bookmark::Set(addr, manual);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        [McpServerTool, Description(
            "Delete the bookmark at the specified address.")]
        static auto DeleteBookmark(
            [Description("Address expression")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Bookmark::Delete(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        // ── Xref (Cross Reference) ──

        [McpServerTool(ReadOnly = true), Description(
            "Get all cross-references pointing to the specified address.")]
        static auto GetXrefs(
            [Description("Target address expression")] String^ address,
            [Description("Maximum number of xrefs to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;
            duint addr = Helpers::ResolveExpression(address);

            XREF_INFO xref = {};
            DbgXrefGet(addr, &xref);

            int total = (int)xref.refcount;
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<XrefItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew XrefItem();
                item->address = Helpers::FormatAddress(xref.references[i].addr);
                item->type = Helpers::XrefTypeToString(xref.references[i].type);
                items->Add(item);
            }

            if (xref.references)
                BridgeFree(xref.references);

            auto result = gcnew Dictionary<String^, Object^>();
            result["target"] = Helpers::FormatAddress(addr);
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool, Description(
            "Add a cross-reference from one address to a target address.")]
        static auto AddXref(
            [Description("Target address expression")] String^ target,
            [Description("Source address expression (where the reference originates)")] String^ from)
        {
            duint t = Helpers::ResolveExpression(target);
            duint f = Helpers::ResolveExpression(from);
            bool ok = DbgXrefAdd(t, f);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["target"] = Helpers::FormatAddress(t);
            result["from"] = Helpers::FormatAddress(f);
            return result;
        }

        [McpServerTool, Description(
            "Delete all cross-references to the specified address.")]
        static auto DeleteAllXrefs(
            [Description("Target address expression")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = DbgXrefDelAll(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the number of cross-references at the specified address.")]
        static auto GetXrefCountAt(
            [Description("Address expression to query")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            size_t count = DbgGetXrefCountAt(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["count"] = (int)count;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the type of cross-reference at the specified address "
            "(none, data, jmp, or call).")]
        static auto GetXrefTypeAt(
            [Description("Address expression to query")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            int type = DbgGetXrefTypeAt(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["type"] = Helpers::XrefTypeToString(type);
            return result;
        }

        // ── Argument ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the list of all argument ranges.")]
        static auto GetArgumentList(
            [Description("Maximum number of arguments to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            BridgeList<Script::Argument::ArgumentInfo> nativeList;
            Script::Argument::GetList(&nativeList);

            int total = nativeList.Count();
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<ArgumentItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew ArgumentItem();
                item->module = gcnew String(nativeList[i].mod);
                item->rvaStart = Helpers::FormatAddress(nativeList[i].rvaStart);
                item->rvaEnd = Helpers::FormatAddress(nativeList[i].rvaEnd);
                item->manual = nativeList[i].manual;
                item->instructionCount = nativeList[i].instructioncount;
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get argument range information at the specified address.")]
        static auto GetArgumentAt(
            [Description("Address expression to query")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            Script::Argument::ArgumentInfo a = {};
            bool found = Script::Argument::GetInfo(addr, &a);

            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["found"] = found;
            if (found) {
                result["module"] = gcnew String(a.mod);
                result["rvaStart"] = Helpers::FormatAddress(a.rvaStart);
                result["rvaEnd"] = Helpers::FormatAddress(a.rvaEnd);
                result["manual"] = a.manual;
                result["instructionCount"] = (UInt64)a.instructioncount;
            }
            return result;
        }

        [McpServerTool, Description(
            "Add an argument range.")]
        static auto AddArgument(
            [Description("Start address expression")] String^ start,
            [Description("End address expression")] String^ end,
            [Description("Whether this is user-defined")] bool manual,
            [Description("Number of instructions (0 if unknown)")] int instructionCount)
        {
            duint s = Helpers::ResolveExpression(start);
            duint e = Helpers::ResolveExpression(end);
            bool ok = Script::Argument::Add(s, e, manual, instructionCount);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["start"] = Helpers::FormatAddress(s);
            result["end"] = Helpers::FormatAddress(e);
            return result;
        }

        [McpServerTool, Description(
            "Delete the argument range at the specified address.")]
        static auto DeleteArgument(
            [Description("Address expression")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Argument::Delete(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        // ── Module ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the list of all loaded modules in the debugged process.")]
        static auto GetModuleList(
            [Description("Maximum number of modules to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            BridgeList<Script::Module::ModuleInfo> nativeList;
            Script::Module::GetList(&nativeList);

            int total = nativeList.Count();
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<ModuleItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew ModuleItem();
                item->base = Helpers::FormatAddress(nativeList[i].base);
                item->size = nativeList[i].size;
                item->entry = Helpers::FormatAddress(nativeList[i].entry);
                item->sectionCount = nativeList[i].sectionCount;
                item->name = gcnew String(nativeList[i].name);
                item->path = gcnew String(nativeList[i].path);
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get information about the main (debugged) module.")]
        static auto GetMainModuleInfo()
        {
            Script::Module::ModuleInfo m = {};
            Script::Module::GetMainModuleInfo(&m);
            auto item = gcnew ModuleItem();
            item->base = Helpers::FormatAddress(m.base);
            item->size = m.size;
            item->entry = Helpers::FormatAddress(m.entry);
            item->sectionCount = m.sectionCount;
            item->name = gcnew String(m.name);
            item->path = gcnew String(m.path);
            return item;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get module information by address or module name.")]
        static auto GetModuleInfo(
            [Description("Module name (e.g. 'kernel32.dll') or address expression within the module")] String^ module)
        {
            IntPtr ptr = Marshal::StringToHGlobalAnsi(module);
            try {
                const char* native = static_cast<const char*>(ptr.ToPointer());
                Script::Module::ModuleInfo m = {};

                // Try by name first, then by address
                bool found = Script::Module::InfoFromName(native, &m);
                if (!found) {
                    duint addr = 0;
                    if (Script::Misc::ParseExpression(native, &addr))
                        found = Script::Module::InfoFromAddr(addr, &m);
                }

                auto result = gcnew Dictionary<String^, Object^>();
                result["input"] = module;
                result["found"] = found;
                if (found) {
                    auto item = gcnew ModuleItem();
                    item->base = Helpers::FormatAddress(m.base);
                    item->size = m.size;
                    item->entry = Helpers::FormatAddress(m.entry);
                    item->sectionCount = m.sectionCount;
                    item->name = gcnew String(m.name);
                    item->path = gcnew String(m.path);
                    result["module"] = item;
                }
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the section list of a module by name or address.")]
        static auto GetSectionList(
            [Description("Module name (e.g. 'kernel32.dll') or address expression within the module. "
                         "Omit or pass empty string for the main module.")] String^ module,
            [Description("Maximum number of sections to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            BridgeList<Script::Module::ModuleSectionInfo> nativeList;
            bool ok;

            if (String::IsNullOrWhiteSpace(module)) {
                ok = Script::Module::GetMainModuleSectionList(&nativeList);
            } else {
                IntPtr ptr = Marshal::StringToHGlobalAnsi(module);
                try {
                    const char* native = static_cast<const char*>(ptr.ToPointer());
                    ok = Script::Module::SectionListFromName(native, &nativeList);
                    if (!ok) {
                        duint addr = 0;
                        if (Script::Misc::ParseExpression(native, &addr))
                            ok = Script::Module::SectionListFromAddr(addr, &nativeList);
                    }
                } finally {
                    Marshal::FreeHGlobal(ptr);
                }
            }

            int total = ok ? nativeList.Count() : 0;
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<SectionItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew SectionItem();
                item->address = Helpers::FormatAddress(nativeList[i].addr);
                item->size = nativeList[i].size;
                item->name = gcnew String(nativeList[i].name);
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the export table of a module.")]
        static auto GetExports(
            [Description("Module name (e.g. 'kernel32.dll') or address expression within the module")] String^ module,
            [Description("Maximum number of exports to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            duint base = Helpers::ResolveModuleBase(module);
            Script::Module::ModuleInfo m = {};
            m.base = base;

            BridgeList<Script::Module::ModuleExport> nativeList;
            Script::Module::GetExports(&m, &nativeList);

            int total = nativeList.Count();
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<ExportItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew ExportItem();
                item->ordinal = nativeList[i].ordinal;
                item->rva = Helpers::FormatAddress(nativeList[i].rva);
                item->va = Helpers::FormatAddress(nativeList[i].va);
                item->forwarded = nativeList[i].forwarded;
                item->forwardName = gcnew String(nativeList[i].forwardName);
                item->name = gcnew String(nativeList[i].name);
                item->undecoratedName = gcnew String(nativeList[i].undecoratedName);
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the import table of a module.")]
        static auto GetImports(
            [Description("Module name (e.g. 'kernel32.dll') or address expression within the module")] String^ module,
            [Description("Maximum number of imports to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            duint base = Helpers::ResolveModuleBase(module);
            Script::Module::ModuleInfo m = {};
            m.base = base;

            BridgeList<Script::Module::ModuleImport> nativeList;
            Script::Module::GetImports(&m, &nativeList);

            int total = nativeList.Count();
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<ImportItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew ImportItem();
                item->iatRva = Helpers::FormatAddress(nativeList[i].iatRva);
                item->iatVa = Helpers::FormatAddress(nativeList[i].iatVa);
                item->ordinal = nativeList[i].ordinal;
                item->name = gcnew String(nativeList[i].name);
                item->undecoratedName = gcnew String(nativeList[i].undecoratedName);
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        // ── Memory (read-only queries) ──

        [McpServerTool(ReadOnly = true), Description(
            "Check if the specified address is a valid readable pointer in the debugged process.")]
        static auto IsValidPtr(
            [Description("Address expression to check")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool valid = Script::Memory::IsValidPtr(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["valid"] = valid;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the memory map of the debugged process.")]
        static auto GetMemoryMaps(
            [Description("Maximum number of regions to return (default 50)")] int limit)
        {
            if (limit <= 0) limit = 50;

            MEMMAP maps = {};
            DbgMemMap(&maps);

            int total = maps.count;
            int count = (total < limit) ? total : limit;

            auto items = gcnew List<MemoryRegionItem^>(count);
            for (int i = 0; i < count; i++) {
                auto item = gcnew MemoryRegionItem();
                item->baseAddress = Helpers::FormatAddress((duint)maps.page[i].mbi.BaseAddress);
                item->allocationBase = Helpers::FormatAddress((duint)maps.page[i].mbi.AllocationBase);
                item->regionSize = maps.page[i].mbi.RegionSize;
                item->protect = maps.page[i].mbi.Protect;
                item->state = maps.page[i].mbi.State;
                item->type = maps.page[i].mbi.Type;
                item->info = gcnew String(maps.page[i].info);
                items->Add(item);
            }

            if (maps.page)
                BridgeFree(maps.page);

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = count;
            result["truncated"] = (total > limit);
            result["total"] = total;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the base address of the memory region containing the specified address.")]
        static auto GetMemoryBase(
            [Description("Address expression to query")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            duint base = Script::Memory::GetBase(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["base"] = Helpers::FormatAddress(base);
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the size of the memory region containing the specified address.")]
        static auto GetMemorySize(
            [Description("Address expression to query")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            duint size = Script::Memory::GetSize(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["size"] = (UInt64)size;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Read memory from the debugged process. Returns base64-encoded bytes. "
            "Maximum read size is 1 MB.")]
        static auto MemoryRead(
            [Description("Address expression to read from")] String^ address,
            [Description("Number of bytes to read (max 1048576)")] int size)
        {
            if (size <= 0 || size > 1048576)
                throw gcnew ArgumentException(
                    "Size must be between 1 and 1048576 bytes.");

            duint addr = Helpers::ResolveExpression(address);
            auto buffer = gcnew array<unsigned char>(size);
            pin_ptr<unsigned char> pinned = &buffer[0];
            duint bytesRead = 0;
            bool ok = Script::Memory::Read(addr, pinned, size, &bytesRead);

            auto result = gcnew Dictionary<String^, Object^>();
            result["address"] = Helpers::FormatAddress(addr);
            result["success"] = ok;
            result["size_requested"] = size;
            result["size_read"] = (int)bytesRead;
            if (ok && bytesRead > 0) {
                if ((int)bytesRead < size)
                    Array::Resize(buffer, (int)bytesRead);
                result["data"] = Convert::ToBase64String(buffer);
            } else {
                result["data"] = "";
            }
            return result;
        }

        // ── Thread (query only) ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the list of all threads in the debugged process.")]
        static auto GetThreadList()
        {
            THREADLIST list = {};
            DbgGetThreadList(&list);

            auto items = gcnew List<ThreadItem^>(list.count);
            for (int i = 0; i < list.count; i++) {
                auto item = gcnew ThreadItem();
                item->threadNumber = list.list[i].BasicInfo.ThreadNumber;
                item->threadId = list.list[i].BasicInfo.ThreadId;
                item->startAddress = Helpers::FormatAddress(
                    list.list[i].BasicInfo.ThreadStartAddress);
                item->localBase = Helpers::FormatAddress(
                    list.list[i].BasicInfo.ThreadLocalBase);
                item->cip = Helpers::FormatAddress(list.list[i].ThreadCip);
                item->suspendCount = list.list[i].SuspendCount;
                item->name = gcnew String(
                    list.list[i].BasicInfo.threadName);
                item->priority = list.list[i].Priority;
                item->lastError = list.list[i].LastError;
                items->Add(item);
            }

            int total = list.count;
            int currentThread = list.CurrentThread;
            if (list.list)
                BridgeFree(list.list);

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = total;
            result["total"] = total;
            result["truncated"] = false;
            result["currentThread"] = currentThread;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the thread ID of the first (main) thread.")]
        static auto GetFirstThreadId()
        {
            THREADLIST list = {};
            DbgGetThreadList(&list);

            unsigned int firstId = 0;
            for (int i = 0; i < list.count; i++) {
                if (list.list[i].BasicInfo.ThreadNumber == 0) {
                    firstId = list.list[i].BasicInfo.ThreadId;
                    break;
                }
            }
            if (list.list)
                BridgeFree(list.list);

            auto result = gcnew Dictionary<String^, Object^>();
            result["threadId"] = (int)firstId;
            return result;
        }

        // ── Disassemble ──

        [McpServerTool(ReadOnly = true), Description(
            "Disassemble instructions starting at the specified address. "
            "Returns a structured list of instructions with address, text, size, "
            "bytes, branch info, comments, and labels. "
            "Accepts any x64dbg expression as address (hex, label, cip+N, etc.).")]
        static auto Disassemble(
            [Description("Start address expression (e.g. 'cip', '0x401000', 'main')")] String^ address,
            [Description("Number of instructions to disassemble (1-200, default 20)")] int lines)
        {
            if (lines <= 0) lines = 20;
            if (lines > 200) lines = 200;

            duint addr = Helpers::ResolveExpression(address);
            auto items = gcnew List<DisassemblyInstruction^>(lines);

            duint currentAddr = addr;
            for (int i = 0; i < lines; i++) {
                BASIC_INSTRUCTION_INFO info = {};
                DbgDisasmFastAt(currentAddr, &info);

                if (info.size == 0) break; // invalid/unmapped

                auto instr = gcnew DisassemblyInstruction();
                instr->address = Helpers::FormatAddress(currentAddr);
                instr->text = gcnew String(info.instruction);
                instr->size = info.size;
                instr->is_branch = info.branch;
                instr->is_call = info.call;
                instr->branch_target = info.branch
                    ? Helpers::FormatAddress(info.addr) : "";

                // Read raw instruction bytes
                unsigned char buf[16] = {};
                DbgMemRead(currentAddr, buf, info.size);
                auto sb = gcnew System::Text::StringBuilder(info.size * 3);
                for (int b = 0; b < info.size; b++) {
                    if (b > 0) sb->Append(' ');
                    sb->AppendFormat("{0:X2}", buf[b]);
                }
                instr->bytes = sb->ToString();

                // Comment and label at this address
                char commentBuf[MAX_COMMENT_SIZE] = "";
                if (DbgGetCommentAt(currentAddr, commentBuf))
                    instr->comment = gcnew String(commentBuf);
                else
                    instr->comment = "";

                char labelBuf[MAX_LABEL_SIZE] = "";
                if (DbgGetLabelAt(currentAddr, SEG_DEFAULT, labelBuf))
                    instr->label = gcnew String(labelBuf);
                else
                    instr->label = "";

                items->Add(instr);
                currentAddr += info.size;
            }

            // TODO(design): Range-based disassembly (start + end) is not yet
            // implemented. Key open questions:
            //   - Whether `end` should be inclusive or exclusive
            //   - How to handle cross-page or cross-module boundaries
            //   - Whether a maximum return count cap should still apply
            //   - DbgDisasmFastAt iterates one instruction at a time; for
            //     large ranges this could be slow and produce huge output.
            // For now, the address+lines mode covers the primary MCP use case.
            // A range mode can be added later with clear boundary semantics.

            auto result = gcnew Dictionary<String^, Object^>();
            result["start"] = Helpers::FormatAddress(addr);
            result["items"] = items;
            result["returned"] = items->Count;
            return result;
        }

        // ── Pattern ──

        [McpServerTool(ReadOnly = true), Description(
            "Search for a byte pattern in the main module. "
            "Pattern format: 'AA BB ?? CC' where ?? is a wildcard byte.")]
        static auto FindPattern(
            [Description("Byte pattern with ?? as wildcard (e.g. '48 89 5C 24 ?? 57')")] String^ pattern)
        {
            IntPtr ptr = Marshal::StringToHGlobalAnsi(pattern);
            try {
                duint base = Script::Module::GetMainModuleBase();
                duint size = Script::Module::GetMainModuleSize();
                duint found = Script::Pattern::FindMem(base, size,
                    static_cast<const char*>(ptr.ToPointer()));

                auto result = gcnew Dictionary<String^, Object^>();
                result["pattern"] = pattern;
                result["found"] = (found != 0);
                result["address"] = (found != 0)
                    ? Helpers::FormatAddress(found) : "";
                result["search_base"] = Helpers::FormatAddress(base);
                result["search_size"] = (UInt64)size;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

    };

    // ═══════════════════════════════════════════════════════════════
    //  MCP Debugging Tools (state-changing operations)
    // ═══════════════════════════════════════════════════════════════

    [McpServerToolType]
    public ref class McpDebuggingTools
    {
    private:
        /// Build a DebugStateResult reflecting the current debugger state.
        static DebugStateResult^ MakeStateResult(bool success, String^ message)
        {
            auto r = gcnew DebugStateResult();
            r->success = success;
            r->message = message ? message : "";

            if (!DbgIsDebugging()) {
                r->state = "inactive";
                r->paused_at = "";
            } else if (DbgIsRunning()) {
                r->state = "running";
                r->paused_at = "";
            } else {
                r->state = "paused";
                r->paused_at = Helpers::FormatAddress(
                    Script::Register::Get(Script::Register::CIP));
            }
            return r;
        }

    public:

        // ── Debug State Queries ──

        [McpServerTool(ReadOnly = true), Description(
            "Check if the debugger is currently attached/debugging.")]
        static auto IsDebugging()
        {
            auto result = gcnew Dictionary<String^, Object^>();
            result["debugging"] = DbgIsDebugging();
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Check if the debugged process is currently running (not paused).")]
        static auto IsRunning()
        {
            auto result = gcnew Dictionary<String^, Object^>();
            result["debugging"] = DbgIsDebugging();
            result["running"] = DbgIsRunning();
            return result;
        }

        // ── Debug Control ──
        //
        // All control operations use synchronous semantics: they issue the
        // command and wait until the debugger pauses, the debuggee terminates,
        // or the action fails, before returning a structured result.

        [McpServerTool, Description(
            "Run/continue the debugged process. Waits until execution pauses "
            "(e.g. breakpoint hit) or the process terminates, then returns.")]
        static auto DebugRun()
        {
            if (!DbgIsDebugging())
                return MakeStateResult(false, "No active debug session.");
            Script::Debug::Run();
            Script::Debug::Wait();
            return MakeStateResult(true, "Execution completed.");
        }

        [McpServerTool, Description(
            "Pause the debugged process. Waits until the process is paused.")]
        static auto DebugPause()
        {
            if (!DbgIsDebugging())
                return MakeStateResult(false, "No active debug session.");
            Script::Debug::Pause();
            Script::Debug::Wait();
            return MakeStateResult(true, "Process paused.");
        }

        [McpServerTool, Description(
            "Stop debugging (terminate the debugged process).")]
        static auto DebugStop()
        {
            if (!DbgIsDebugging())
                return MakeStateResult(false, "No active debug session.");
            Script::Debug::Stop();
            return MakeStateResult(true, "Debug session stopped.");
        }

        [McpServerTool, Description(
            "Step into the next instruction. Waits until the step completes.")]
        static auto StepInto()
        {
            if (!DbgIsDebugging())
                return MakeStateResult(false, "No active debug session.");
            Script::Debug::StepIn();
            Script::Debug::Wait();
            return MakeStateResult(true, "Step into completed.");
        }

        [McpServerTool, Description(
            "Step over the next instruction (skip over calls). "
            "Waits until the step completes.")]
        static auto StepOver()
        {
            if (!DbgIsDebugging())
                return MakeStateResult(false, "No active debug session.");
            Script::Debug::StepOver();
            Script::Debug::Wait();
            return MakeStateResult(true, "Step over completed.");
        }

        [McpServerTool, Description(
            "Step out of the current function (run until return). "
            "Waits until the step completes.")]
        static auto StepOut()
        {
            if (!DbgIsDebugging())
                return MakeStateResult(false, "No active debug session.");
            Script::Debug::StepOut();
            Script::Debug::Wait();
            return MakeStateResult(true, "Step out completed.");
        }

        [McpServerTool, Description(
            "Restart the debugged process. Waits until execution pauses.")]
        static auto DebugRestart()
        {
            // TODO(source-check): "RestartDebug" is the x64dbg command for
            // restarting a debug session. It terminates the current process
            // and re-launches it. Need to verify edge cases: what if no
            // target is loaded? Does it preserve breakpoints? The command
            // is documented in x64dbg help under "RestartDebug".
            if (!DbgIsDebugging())
                return MakeStateResult(false, "No active debug session.");
            DbgCmdExecDirect("RestartDebug");
            Script::Debug::Wait();
            return MakeStateResult(true, "Debuggee restarted.");
        }

        [McpServerTool, Description(
            "Execute an x64dbg command string synchronously. "
            "Use for advanced operations not covered by dedicated tools.")]
        static auto RunCommand(
            [Description("x64dbg command (e.g. 'bp 0x401000', 'SetBPX ...', 'log ...')")] String^ command)
        {
            // TODO(behavior): DbgCmdExecDirect executes the command
            // synchronously with respect to the command processor, but
            // commands like "run" or "StepInto" will return before the
            // debuggee pauses again. We do NOT call Wait() here because
            // the semantics of arbitrary commands are unpredictable.
            // Callers should use dedicated tools (DebugRun, StepInto, etc.)
            // for synchronous execution control.
            IntPtr ptr = Marshal::StringToHGlobalAnsi(command);
            try {
                bool ok = DbgCmdExecDirect(
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = ok;
                result["command"] = command;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        // ── Breakpoint ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the list of breakpoints, optionally filtered by type.")]
        static auto GetBreakpointList(
            [Description("Breakpoint type filter: 'all', 'normal', 'hardware', or 'memory' (default 'all')")] String^ type)
        {
            BPXTYPE bpType = bp_none;
            if (!String::IsNullOrWhiteSpace(type))
                bpType = Helpers::BpTypeFromName(type);

            BPMAP bps = {};
            int count = DbgGetBpList(bpType, &bps);

            auto items = gcnew List<BreakpointItem^>(bps.count);
            for (int i = 0; i < bps.count; i++) {
                auto item = gcnew BreakpointItem();
                item->type = Helpers::BpTypeToString(bps.bp[i].type);
                item->address = Helpers::FormatAddress(bps.bp[i].addr);
                item->enabled = bps.bp[i].enabled;
                item->singleshoot = bps.bp[i].singleshoot;
                item->active = bps.bp[i].active;
                item->name = gcnew String(bps.bp[i].name);
                item->module = gcnew String(bps.bp[i].mod);
                item->hitCount = bps.bp[i].hitCount;
                item->breakCondition = gcnew String(bps.bp[i].breakCondition);
                item->logText = gcnew String(bps.bp[i].logText);
                item->commandText = gcnew String(bps.bp[i].commandText);
                items->Add(item);
            }

            if (bps.bp)
                BridgeFree(bps.bp);

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = items->Count;
            result["total"] = items->Count;
            result["truncated"] = false;
            result["filter"] = String::IsNullOrWhiteSpace(type) ? "all" : type;
            return result;
        }

        [McpServerTool, Description(
            "Set a software breakpoint at the specified address.")]
        static auto SetBreakpoint(
            [Description("Address expression (hex, label, expression)")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Debug::SetBreakpoint(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        [McpServerTool, Description(
            "Delete the software breakpoint at the specified address.")]
        static auto DeleteBreakpoint(
            [Description("Address expression")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Debug::DeleteBreakpoint(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        [McpServerTool, Description(
            "Disable the breakpoint at the specified address (keeps it but inactive).")]
        static auto DisableBreakpoint(
            [Description("Address expression")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Debug::DisableBreakpoint(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        [McpServerTool, Description(
            "Set a hardware breakpoint at the specified address.")]
        static auto SetHardwareBreakpoint(
            [Description("Address expression")] String^ address,
            [Description("Hardware breakpoint type: 'access', 'write', or 'execute' (default 'execute')")] String^ type)
        {
            duint addr = Helpers::ResolveExpression(address);
            auto hwType = String::IsNullOrWhiteSpace(type)
                ? Script::Debug::HardwareExecute
                : Helpers::HwBpTypeFromName(type);
            bool ok = Script::Debug::SetHardwareBreakpoint(addr, hwType);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            result["type"] = String::IsNullOrWhiteSpace(type) ? "execute" : type;
            return result;
        }

        [McpServerTool, Description(
            "Delete the hardware breakpoint at the specified address.")]
        static auto DeleteHardwareBreakpoint(
            [Description("Address expression")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Debug::DeleteHardwareBreakpoint(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        // ── CPU Flags ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the value of a CPU flag by name. "
            "Valid flag names: zf, of, cf, pf, sf, tf, af, df, if (case-insensitive).")]
        static auto GetFlag(
            [Description("Flag name (e.g. 'zf', 'cf', 'of')")] String^ flag)
        {
            auto flagEnum = Helpers::FlagFromName(flag);
            bool value = Script::Flag::Get(flagEnum);
            auto result = gcnew Dictionary<String^, Object^>();
            result["flag"] = flag->ToLowerInvariant()->Trim();
            result["value"] = value;
            return result;
        }

        [McpServerTool, Description(
            "Set the value of a CPU flag by name.")]
        static auto SetFlag(
            [Description("Flag name (e.g. 'zf', 'cf', 'of')")] String^ flag,
            [Description("New flag value")] bool value)
        {
            auto flagEnum = Helpers::FlagFromName(flag);
            bool ok = Script::Flag::Set(flagEnum, value);
            auto result = gcnew Dictionary<String^, Object^>();
            result["flag"] = flag->ToLowerInvariant()->Trim();
            result["value"] = value;
            result["success"] = ok;
            return result;
        }

        // ── Registers ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the value of a single CPU register by name. "
            "Supports all x86/x64 register names (rax, eax, ax, al, r8, cip, etc.) "
            "and architecture-agnostic aliases (cax, csp, cip). Case-insensitive.")]
        static auto GetRegister(
            [Description("Register name (e.g. 'rax', 'eip', 'cip', 'r8')")] String^ name)
        {
            auto regEnum = Helpers::RegisterFromName(name);
            duint value = Script::Register::Get(regEnum);
            auto result = gcnew Dictionary<String^, Object^>();
            result["register"] = name->ToLowerInvariant()->Trim();
            result["value"] = Helpers::FormatAddress(value);
            return result;
        }

        [McpServerTool, Description(
            "Set the value of a CPU register by name.")]
        static auto SetRegister(
            [Description("Register name (e.g. 'rax', 'eip', 'cip', 'r8')")] String^ name,
            [Description("Value expression (hex, decimal, or x64dbg expression)")] String^ value)
        {
            auto regEnum = Helpers::RegisterFromName(name);
            duint val = Helpers::ResolveExpression(value);
            bool ok = Script::Register::Set(regEnum, val);
            auto result = gcnew Dictionary<String^, Object^>();
            result["register"] = name->ToLowerInvariant()->Trim();
            result["value"] = Helpers::FormatAddress(val);
            result["success"] = ok;
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get a snapshot of all general-purpose registers, flags, and the "
            "instruction pointer. Returns a flat dictionary of register names "
            "to hex values — much more LLM-friendly than a raw register dump.")]
        static auto GetRegisters()
        {
            auto regs = gcnew Dictionary<String^, String^>();

            // Architecture-agnostic registers
            regs["cip"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::CIP));
            regs["csp"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::CSP));
            regs["cax"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::CAX));
            regs["cbx"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::CBX));
            regs["ccx"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::CCX));
            regs["cdx"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::CDX));
            regs["csi"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::CSI));
            regs["cdi"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::CDI));
            regs["cbp"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::CBP));
            regs["cflags"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::CFLAGS));

#ifdef _WIN64
            regs["rax"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::RAX));
            regs["rbx"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::RBX));
            regs["rcx"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::RCX));
            regs["rdx"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::RDX));
            regs["rsi"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::RSI));
            regs["rdi"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::RDI));
            regs["rbp"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::RBP));
            regs["rsp"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::RSP));
            regs["rip"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::RIP));
            regs["r8"]  = Helpers::FormatAddress(Script::Register::Get(Script::Register::R8));
            regs["r9"]  = Helpers::FormatAddress(Script::Register::Get(Script::Register::R9));
            regs["r10"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::R10));
            regs["r11"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::R11));
            regs["r12"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::R12));
            regs["r13"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::R13));
            regs["r14"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::R14));
            regs["r15"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::R15));
#else
            regs["eax"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::EAX));
            regs["ebx"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::EBX));
            regs["ecx"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::ECX));
            regs["edx"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::EDX));
            regs["esi"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::ESI));
            regs["edi"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::EDI));
            regs["ebp"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::EBP));
            regs["esp"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::ESP));
            regs["eip"] = Helpers::FormatAddress(Script::Register::Get(Script::Register::EIP));
#endif

            // Flags
            auto flags = gcnew Dictionary<String^, bool>();
            flags["zf"] = Script::Flag::Get(Script::Flag::ZF);
            flags["of"] = Script::Flag::Get(Script::Flag::OF);
            flags["cf"] = Script::Flag::Get(Script::Flag::CF);
            flags["pf"] = Script::Flag::Get(Script::Flag::PF);
            flags["sf"] = Script::Flag::Get(Script::Flag::SF);
            flags["tf"] = Script::Flag::Get(Script::Flag::TF);
            flags["af"] = Script::Flag::Get(Script::Flag::AF);
            flags["df"] = Script::Flag::Get(Script::Flag::DF);
            flags["if"] = Script::Flag::Get(Script::Flag::IF);

            auto result = gcnew Dictionary<String^, Object^>();
            result["registers"] = regs;
            result["flags"] = flags;
            return result;
        }

        // ── Memory (write / allocate / free) ──

        [McpServerTool, Description(
            "Write memory to the debugged process.")]
        static auto MemoryWrite(
            [Description("Address expression to write to")] String^ address,
            [Description("Base64-encoded bytes to write")] String^ base64Data)
        {
            duint addr = Helpers::ResolveExpression(address);
            auto data = Convert::FromBase64String(base64Data);
            pin_ptr<unsigned char> pinned = &data[0];
            duint written = 0;
            bool ok = Script::Memory::Write(addr, pinned, data->Length, &written);

            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            result["size_written"] = (int)written;
            return result;
        }

        [McpServerTool, Description(
            "Allocate memory in the debugged process.")]
        static auto MemoryAlloc(
            [Description("Desired size in bytes")] int size,
            [Description("Preferred address expression (use '0' for any)")] String^ address)
        {
            duint addr = 0;
            if (!String::IsNullOrWhiteSpace(address) && address != "0")
                addr = Helpers::ResolveExpression(address);
            duint allocated = Script::Memory::RemoteAlloc(addr, size);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = (allocated != 0);
            result["address"] = Helpers::FormatAddress(allocated);
            result["size"] = size;
            return result;
        }

        [McpServerTool, Description(
            "Free previously allocated memory in the debugged process.")]
        static auto MemoryFree(
            [Description("Address expression of the allocated memory")] String^ address)
        {
            duint addr = Helpers::ResolveExpression(address);
            bool ok = Script::Memory::RemoteFree(addr);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["address"] = Helpers::FormatAddress(addr);
            return result;
        }

        // ── Stack ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the call stack of a thread. Pass the thread ID from GetThreadList.")]
        static auto GetCallStack(
            [Description("Thread ID (from GetThreadList)")] int threadId)
        {
            // Look up thread handle from thread ID
            THREADLIST tlist = {};
            DbgGetThreadList(&tlist);
            HANDLE threadHandle = nullptr;
            for (int i = 0; i < tlist.count; i++) {
                if ((int)tlist.list[i].BasicInfo.ThreadId == threadId) {
                    threadHandle = tlist.list[i].BasicInfo.Handle;
                    break;
                }
            }
            if (tlist.list)
                BridgeFree(tlist.list);

            if (!threadHandle) {
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = false;
                result["message"] = "Thread ID not found: " + threadId.ToString();
                result["items"] = gcnew List<CallStackEntry^>();
                result["total"] = 0;
                return result;
            }

            DBGCALLSTACK callstack = {};
            auto funcs = DbgFunctions();
            if (funcs && funcs->GetCallStackByThread)
                funcs->GetCallStackByThread(threadHandle, &callstack);

            auto items = gcnew List<CallStackEntry^>((int)callstack.total);
            for (duint i = 0; i < callstack.total; i++) {
                auto entry = gcnew CallStackEntry();
                entry->address = Helpers::FormatAddress(callstack.entries[i].addr);
                entry->from = Helpers::FormatAddress(callstack.entries[i].from);
                entry->to = Helpers::FormatAddress(callstack.entries[i].to);
                entry->comment = gcnew String(callstack.entries[i].comment);
                items->Add(entry);
            }

            if (callstack.total && callstack.entries)
                BridgeFree(callstack.entries);

            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = true;
            result["items"] = items;
            result["total"] = items->Count;
            result["threadId"] = threadId;
            return result;
        }

        // ── Thread Control ──

        [McpServerTool, Description(
            "Set the name of a thread.")]
        static auto SetThreadName(
            [Description("Thread ID")] int threadId,
            [Description("New thread name")] String^ name)
        {
            auto cmd = String::Format("setthreadname {0:X},{1}",
                threadId, name);
            IntPtr ptr = Marshal::StringToHGlobalAnsi(cmd);
            try {
                bool ok = DbgCmdExecDirect(
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = ok;
                result["threadId"] = threadId;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool, Description(
            "Set the active thread for debugging.")]
        static auto SetActiveThread(
            [Description("Thread ID")] int threadId)
        {
            auto cmd = String::Format("switchthread {0:X}", threadId);
            IntPtr ptr = Marshal::StringToHGlobalAnsi(cmd);
            try {
                bool ok = DbgCmdExecDirect(
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = ok;
                result["threadId"] = threadId;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool, Description(
            "Suspend a thread by ID.")]
        static auto SuspendThread(
            [Description("Thread ID")] int threadId)
        {
            auto cmd = String::Format("suspendthread {0:X}", threadId);
            IntPtr ptr = Marshal::StringToHGlobalAnsi(cmd);
            try {
                bool ok = DbgCmdExecDirect(
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = ok;
                result["threadId"] = threadId;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool, Description(
            "Resume a suspended thread by ID.")]
        static auto ResumeThread(
            [Description("Thread ID")] int threadId)
        {
            auto cmd = String::Format("resumethread {0:X}", threadId);
            IntPtr ptr = Marshal::StringToHGlobalAnsi(cmd);
            try {
                bool ok = DbgCmdExecDirect(
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = ok;
                result["threadId"] = threadId;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool, Description(
            "Terminate a thread with the specified exit code.")]
        static auto KillThread(
            [Description("Thread ID")] int threadId,
            [Description("Exit code")] int exitCode)
        {
            auto cmd = String::Format("killthread {0:X},{1:X}",
                threadId, exitCode);
            IntPtr ptr = Marshal::StringToHGlobalAnsi(cmd);
            try {
                bool ok = DbgCmdExecDirect(
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = ok;
                result["threadId"] = threadId;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool, Description(
            "Create a new thread at the specified entry point.")]
        static auto CreateThread(
            [Description("Entry point address expression")] String^ entry,
            [Description("Argument address expression (use '0' for null)")] String^ argument)
        {
            duint entryAddr = Helpers::ResolveExpression(entry);
            duint argAddr = 0;
            if (!String::IsNullOrWhiteSpace(argument) && argument != "0")
                argAddr = Helpers::ResolveExpression(argument);

            auto cmd = String::Format("createthread {0:X},{1:X}",
                (UInt64)entryAddr, (UInt64)argAddr);
            IntPtr ptr = Marshal::StringToHGlobalAnsi(cmd);
            try {
                bool ok = DbgCmdExecDirect(
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = ok;
                result["entry"] = Helpers::FormatAddress(entryAddr);
                result["argument"] = Helpers::FormatAddress(argAddr);
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        // ── Assemble ──

        [McpServerTool, Description(
            "Assemble a single instruction at the specified address. "
            "The existing bytes at that address are overwritten.")]
        static auto Assemble(
            [Description("Address expression to assemble at")] String^ address,
            [Description("Assembly instruction (e.g. 'nop', 'mov eax, 1', 'jmp 0x401000')")] String^ instruction)
        {
            duint addr = Helpers::ResolveExpression(address);
            IntPtr ptr = Marshal::StringToHGlobalAnsi(instruction);
            try {
                bool ok = Script::Assembler::AssembleMem(addr,
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = ok;
                result["address"] = Helpers::FormatAddress(addr);
                result["instruction"] = instruction;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        // ── GUI ──

        [McpServerTool, Description(
            "Show a message box in x64dbg.")]
        static auto GuiMessage(
            [Description("Message text")] String^ message)
        {
            IntPtr ptr = Marshal::StringToHGlobalAnsi(message);
            try {
                Script::Gui::Message(
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = true;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool, Description(
            "Show a Yes/No dialog in x64dbg. Returns the user's choice.")]
        static auto GuiMessageYesNo(
            [Description("Question text")] String^ message)
        {
            IntPtr ptr = Marshal::StringToHGlobalAnsi(message);
            try {
                bool yes = Script::Gui::MessageYesNo(
                    static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["answer"] = yes ? "yes" : "no";
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool, Description(
            "Refresh all x64dbg GUI views (disassembly, dump, registers, etc.).")]
        static auto GuiRefresh()
        {
            Script::Gui::Refresh();
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = true;
            return result;
        }

        [McpServerTool, Description(
            "Focus a specific x64dbg window by name.")]
        static auto GuiFocusView(
            [Description("Window name: 'disassembly', 'dump', 'stack', 'graph', 'memmap', or 'symmod'")] String^ window)
        {
            int win = Helpers::GuiWindowFromName(window);
            ::GuiFocusView(win);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = true;
            result["window"] = window->ToLowerInvariant()->Trim();
            return result;
        }

        [McpServerTool, Description(
            "Set the selection range in a x64dbg window.")]
        static auto GuiSelectionSet(
            [Description("Window name: 'disassembly', 'dump', 'stack', 'graph', 'memmap', or 'symmod'")] String^ window,
            [Description("Start address expression")] String^ start,
            [Description("End address expression")] String^ end)
        {
            int win = Helpers::GuiWindowFromName(window);
            SELECTIONDATA sel = {};
            sel.start = Helpers::ResolveExpression(start);
            sel.end = Helpers::ResolveExpression(end);
            bool ok = ::GuiSelectionSet(win, &sel);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["window"] = window->ToLowerInvariant()->Trim();
            result["start"] = Helpers::FormatAddress(sel.start);
            result["end"] = Helpers::FormatAddress(sel.end);
            return result;
        }

        [McpServerTool(ReadOnly = true), Description(
            "Get the current selection range in a x64dbg window.")]
        static auto GuiSelectionGet(
            [Description("Window name: 'disassembly', 'dump', 'stack', 'graph', 'memmap', or 'symmod'")] String^ window)
        {
            int win = Helpers::GuiWindowFromName(window);
            SELECTIONDATA sel = {};
            bool ok = ::GuiSelectionGet(win, &sel);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = ok;
            result["window"] = window->ToLowerInvariant()->Trim();
            result["start"] = ok ? Helpers::FormatAddress(sel.start) : "";
            result["end"] = ok ? Helpers::FormatAddress(sel.end) : "";
            return result;
        }

        // ── Script ──

        [McpServerTool, Description(
            "Load a script file into the x64dbg script engine.")]
        static auto ScriptLoad(
            [Description("Path to the script file")] String^ filename)
        {
            IntPtr ptr = Marshal::StringToHGlobalAnsi(filename);
            try {
                DbgScriptLoad(static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = true;
                result["filename"] = filename;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        [McpServerTool, Description(
            "Unload the currently loaded script.")]
        static auto ScriptUnload()
        {
            DbgScriptUnload();
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = true;
            return result;
        }

        [McpServerTool, Description(
            "Run the loaded script from the specified line.")]
        static auto ScriptRun(
            [Description("Line number to start execution from")] int destLine)
        {
            DbgScriptRun(destLine);
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = true;
            result["startLine"] = destLine;
            return result;
        }

        [McpServerTool, Description(
            "Abort the currently running script.")]
        static auto ScriptAbort()
        {
            DbgScriptAbort();
            auto result = gcnew Dictionary<String^, Object^>();
            result["success"] = true;
            return result;
        }

        [McpServerTool, Description(
            "Execute a single command in the x64dbg script command processor.")]
        static auto ScriptCmdExec(
            [Description("Script command to execute")] String^ command)
        {
            IntPtr ptr = Marshal::StringToHGlobalAnsi(command);
            try {
                DbgScriptCmdExec(static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = true;
                result["command"] = command;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        // ── Logging ──

        [McpServerTool, Description(
            "Write a line to the x64dbg log window.")]
        static auto LogPuts(
            [Description("Text to log")] String^ text)
        {
            IntPtr ptr = Marshal::StringToHGlobalAnsi(text);
            try {
                _plugin_logputs(static_cast<const char*>(ptr.ToPointer()));
                auto result = gcnew Dictionary<String^, Object^>();
                result["success"] = true;
                return result;
            } finally {
                Marshal::FreeHGlobal(ptr);
            }
        }

        // ── Watch ──

        [McpServerTool(ReadOnly = true), Description(
            "Get the list of all watch expressions and their current values.")]
        static auto GetWatchList()
        {
            BridgeList<WATCHINFO> nativeList;
            DbgGetWatchList(&nativeList);

            int total = nativeList.Count();
            auto items = gcnew List<WatchItem^>(total);
            for (int i = 0; i < total; i++) {
                auto item = gcnew WatchItem();
                item->name = gcnew String(nativeList[i].WatchName);
                item->expression = gcnew String(nativeList[i].Expression);
                item->window = nativeList[i].window;
                item->id = nativeList[i].id;
                item->value = Helpers::FormatAddress(nativeList[i].value);
                items->Add(item);
            }

            auto result = gcnew Dictionary<String^, Object^>();
            result["items"] = items;
            result["returned"] = total;
            result["total"] = total;
            result["truncated"] = false;
            return result;
        }

    };
}
