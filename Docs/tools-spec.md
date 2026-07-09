# Tools & Resources Specification

This is the **contract baseline** for the MCP surface. Every tool and resource must conform to the shapes declared here. Adding/changing the surface requires updating this file *first*, then implementation.

> **Status legend**: `🟢 specified` — schema settled, ready to implement | `🟡 draft` — shape under discussion | `⚪ stub` — name reserved, contents TBD

> Cross-cutting rules (envelope, errors, addresses, pagination, links) live in [conventions.md](conventions.md). This file does not duplicate them; it only declares per-tool/per-resource specifics.

---

## 1. Result Envelope

```cpp
public ref class ErrorInfo
{
public:
    property String^ Code;       // closed set; see conventions.md §5
    property String^ Message;    // human-readable
    property Object^ Details;    // optional structured detail
};

public ref class LinkRef
{
public:
    property String^ Uri;        // for resource navigation; null if Tool/Args set
    property String^ Tool;       // for tool invocation hint
    property Dictionary<String^, Object^>^ Args;
};

public ref class PageInfo
{
public:
    property int Offset;
    property int Limit;
    property int Total;
    property bool HasMore;
};

public ref class McpResult
{
public:
    property bool Success;
    property ErrorInfo^ Error;                                // null when Success
    property Dictionary<String^, LinkRef^>^ Links;            // navigation roots only
};

generic <typename T>
public ref class McpResult : McpResult                        // pseudo-syntax; see note
{
public:
    property T Data;
    property PageInfo^ Page;                                  // list-shaped tools only
};
```

> **Implementation note**: C++/CLI generic ref classes are awkward. Practical pattern is to define a non-generic `McpResult` base and a concrete `<Domain>Result` per tool that adds typed `Data` (and `Page` if list-shaped). Examples below follow this pattern.

---

## 2. Resources

All resources use the URI scheme `x64dbg://`. Resources are defined on a single `[McpServerResourceType]` class (e.g. `McpResources`).

### `x64dbg://session` 🟢

Read-only snapshot of the plugin/x64dbg session.

```cpp
public ref class SessionInfo
{
public:
    property String^ PluginVersion;     // e.g. "0.1.0"
    property String^ Platform;          // "x86" | "x64" | "arm64"
    property String^ X64dbgDirectory;   // BridgeUserDirectory()
    property bool IsDebugging;
    property bool IsRunning;
    property Dictionary<String^, LinkRef^>^ Links;  // → process, modules, memory/map, threads
};
```

### `x64dbg://process` 🟢

Information about the currently debugged process. Empty/null fields when not debugging.

```cpp
public ref class ProcessInfo
{
public:
    // property String^ Handle;          // native process handle (hex)
    property int ProcessId;              // PID (0 when not debugging)
    property int ThreadId;               // current thread ID (0 when not debugging)
    property String^ ImageBase;          // base address of the main module (hex)
    property String^ EntryPoint;         // (hex)
    property String^ PebAddress;         // PEB address (hex)
    property String^ TebAddress;         // TEB address for current thread (hex)
    property String^ KUserSharedData;    // KUSER_SHARED_DATA address (hex)
    property String^ Path;               // full path to the executable
    property Dictionary<String^, LinkRef^>^ Links;  // → session, modules, threads
};
```

### `x64dbg://modules` 🟢

List of all loaded modules in the debugged process.

- Returns `List<ModuleInfo>` with `_links.self` set per item to `x64dbg://modules/{name}`.
- Empty list when not debugging (not an error).

### `x64dbg://modules/{name}` ⚪

```cpp
public ref class ModuleInfo
{
public:
    property String^ Name;
    property String^ Path;           // full path on disk
    property String^ Base;           // hex address
    property String^ Size;           // hex
    property String^ Entry;          // hex
    property bool IsMainModule;
    property Dictionary<String^, LinkRef^>^ Links;  // sections, exports, imports
};
```

### `x64dbg://modules/{name}/sections` ⚪

Returns `List<ModuleSection>`:

```cpp
public ref class ModuleSection
{
public:
    property String^ Name;
    property String^ Address;        // hex
    property String^ Size;           // hex
};
```

### `x64dbg://modules/{name}/exports` ⚪

Returns `List<ModuleExport>`:

```cpp
public ref class ModuleExport
{
public:
    property String^ Name;
    property String^ ForwardName;    // null if not a forwarder
    property int Ordinal;
    property String^ Rva;            // hex
    property String^ Va;             // hex
};
```

### `x64dbg://modules/{name}/imports` ⚪

Returns `List<ModuleImport>`:

```cpp
public ref class ModuleImport
{
public:
    property String^ Name;
    property String^ ModuleName;
    property String^ IatRva;         // hex
    property String^ IatVa;          // hex
};
```

### `x64dbg://memory/map` ⚪

Returns `List<MemoryRegion>` with `_links` at the top level:

```cpp
public ref class MemoryRegion
{
public:
    property String^ Base;           // hex
    property String^ Size;           // hex
    property String^ Protect;        // "RWX" | "RW-" | "R--" | ...
    property String^ Type;           // "image" | "private" | "mapped"
    property String^ Module;         // null if not in a module
    property String^ Section;        // null if not in a section
};
```

### `x64dbg://threads` 🟡

Returns `List<ThreadInfo>` (empty when not debugging):

```cpp
public ref class ThreadInfo
{
public:
    property int ThreadId;
    property String^ Name;
    property String^ Cip;            // hex
    property String^ EntryPoint;     // hex
    property String^ State;          // "running" | "suspended" | "terminated"
    property bool IsActive;
};
```

---

## 3. Rich-param Tools (Analysis, read-only — `McpAnalysisTools`)

### `Disassemble(addr, count, withBytes?)` 🟢

```cpp
[McpServerTool(ReadOnly = true),
 Description("Disassemble up to N instructions starting at the given address or expression.")]
DisassembleResult^ Disassemble(
    [Description("Address or x64dbg expression (e.g. \"rax\", \"kernel32:CreateFileW\")")]
    String^ addr,
    [Description("Number of instructions to disassemble (1–200)")]
    int count,
    [Description("Include raw byte sequence for each instruction (default false)")]
    bool withBytes
);

public ref class DisassembleEntry
{
public:
    property String^ Address;        // hex
    property String^ Mnemonic;       // "mov", "call", ...
    property String^ Operands;       // "rax, qword ptr [rcx+8]"
    property String^ Bytes;          // hex string, present iff withBytes=true
    property int Size;               // instruction size in bytes
    property String^ Comment;        // x64dbg comment if any
};

public ref class DisassembleResult : McpResult
{
public:
    property List<DisassembleEntry^>^ Data;
};
```

Errors: `not_attached`, `invalid_argument` (count out of range), `not_found` (addr unresolvable).

### `MemoryRead(addr, size, compress?)` 🟢

```cpp
[McpServerTool(ReadOnly = true),
 Description("Read memory from the debugged process. Returns base64-encoded bytes.")]
MemoryReadResult^ MemoryRead(
    [Description("Address or x64dbg expression")] String^ addr,
    [Description("Number of bytes to read (1–65536)")] int size,
    [Description("Compress payload with lz4 before base64 (recommended for size > ~4 KiB)")]
    bool compress
);

public ref class MemoryReadResult : McpResult
{
public:
    property String^ Address;        // resolved hex
    property int Size;               // original (uncompressed) byte count
    property String^ Encoding;       // "raw" | "lz4"
    property String^ Base64;
    property int CompressedSize;     // present iff Encoding == "lz4"
};
```

When `compress=true`, the client decodes base64 and then runs `LZ4_decompress_safe` (lz4 block format, no frame header) to recover `Size` bytes. The `compress` parameter exists because a single MCP response is bounded; lz4 typically halves typical instruction/data dumps and lets a single call return larger windows. The default is `false` so simple reads stay round-trip-cheap.

### `FindPattern(pattern, scope?, maxResults?)` 🟢

```cpp
[McpServerTool(ReadOnly = true),
 Description("Search for a byte pattern. Pattern format: \"AA BB ?? CC\" with ?? as wildcard.")]
FindPatternResult^ FindPattern(
    [Description("Byte pattern (e.g. \"48 89 5C 24 ?? 57\")")] String^ pattern,
    [Description("Search scope: \"main\" (default) | \"all\" | module name | address expression for region")]
    String^ scope,
    [Description("Maximum number of matches to return (1–256, default 64)")]
    int maxResults
);

public ref class PatternMatch
{
public:
    property String^ Address;
    property String^ Module;         // containing module if any
};

public ref class FindPatternResult : McpResult
{
public:
    property List<PatternMatch^>^ Data;
    property bool Truncated;         // true if maxResults limit was reached
};
```

### `ParseExpression(expr)` 🟢

```cpp
[McpServerTool(ReadOnly = true),
 Description("Evaluate an x64dbg expression and return the resolved address.")]
ParseExpressionResult^ ParseExpression(
    [Description("Expression (e.g. \"kernel32:CreateFileW\", \"peb()\", \"mem.base(cip)\", \"rax+0x10\")")]
    String^ expr
);

public ref class ParseExpressionResult : McpResult
{
public:
    property String^ Expression;
    property String^ Address;        // hex
    property String^ Module;         // containing module if any
    property String^ Section;        // containing section if any
};
```

### `GetStringAt(addr)` 🟢

```cpp
[McpServerTool(ReadOnly = true),
 Description("Detect and return a string (ASCII / UTF-16) at the given address, if any.")]
GetStringAtResult^ GetStringAt(
    [Description("Address or x64dbg expression")] String^ addr
);

public ref class GetStringAtResult : McpResult
{
public:
    property String^ Address;
    property String^ Encoding;       // "ascii" | "utf16" | null if no string
    property String^ Value;
    property int Length;
};
```

### `GetCallStack(threadId?)` 🟡

```cpp
[McpServerTool(ReadOnly = true),
 Description("Get the call stack of a thread. Defaults to active thread.")]
GetCallStackResult^ GetCallStack(
    [Description("Thread ID (omit for active thread)")] int threadId
);

public ref class CallStackFrame
{
public:
    property int Index;
    property String^ Address;        // CIP / return address (hex)
    property String^ Symbol;
    property String^ Module;
};

public ref class GetCallStackResult : McpResult
{
public:
    property int ThreadId;
    property List<CallStackFrame^>^ Data;
};
```

### `GetRegisterDump(threadId?)` 🟢

Returns all GPRs, segment registers, debug registers, flags, and error status for the active or specified thread.

```cpp
[McpServerTool(ReadOnly = true),
 Description("Dump all registers, flags, and error status for the active or specified thread.")]
RegisterDumpResult^ GetRegisterDump(
    [Description("Thread ID (omit for active thread)")] int threadId
);

public ref class RegisterDumpResult : McpResult
{
public:
    property int ThreadId;
    property Dictionary<String^, String^>^ Registers;  // name → hex value (GPRs, segments, debug)
    property Dictionary<String^, bool>^ Flags;         // "zf" → true, "of" → false, ...
    property String^ LastError;                        // hex (from TEB)
    property String^ LastStatus;                       // hex (from TEB)
};
```

Registers includes:
- **x64**: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, r8-r15
- **x86**: eax, ebx, ecx, edx, esi, edi, ebp, esp, eip
- **Segments**: cs, ds, es, fs, gs, ss
- **Debug**: dr0, dr1, dr2, dr3, dr6, dr7

Flags includes: zf, of, cf, pf, sf, tf, af, df, if

---

## 4. Mega-tools (CRUD Families — `McpAnalysisTools`)

Each mega-tool dispatches on `action`. Closed set per tool. The `params` parameter object varies by action; document each variant. Returned `Data` shape varies by action — declare per-action result classes.

### `Symbols{list, get}` 🟡

Read-only. Symbols are sourced from PDB / PE export tables / x64dbg user data.

| Action | Params | Returns |
|---|---|---|
| `list` | `{ module?: string, offset?: int, limit?: int }` | `List<SymbolEntry>` + `Page` |
| `get` | `{ addr: string }` | `SymbolEntry?` |

### `Functions{list, get, set, delete}` ⚪

| Action | Params | Returns |
|---|---|---|
| `list` | `{ module?: string, offset?: int, limit?: int }` | `List<FunctionEntry>` + `Page` |
| `get` | `{ addr: string }` | `FunctionEntry?` |
| `set` | `{ start: string, end: string, manual?: bool }` | `FunctionEntry` (created/updated) |
| `delete` | `{ addr: string }` | `{ deleted: bool }` |

```cpp
public ref class FunctionEntry
{
public:
    property String^ Start;
    property String^ End;
    property bool Manual;
    property int InstructionCount;
};
```

### `Labels{list, get, set, delete, set_batch, delete_batch}` 🟡

| Action | Params | Returns |
|---|---|---|
| `list` | `{ module?: string, offset?: int, limit?: int }` | `List<LabelEntry>` + `Page` |
| `get` | `{ addr: string }` | `LabelEntry?` |
| `set` | `{ addr: string, text: string, manual?: bool, temporary?: bool }` | `LabelEntry` |
| `delete` | `{ addr: string }` | `{ deleted: bool }` |
| `set_batch` | `{ items: [{addr, text, manual?, temporary?}] }` | `{ succeeded: int, failed: [{addr, error}] }` |
| `delete_batch` | `{ addrs: string[] }` | `{ succeeded: int, failed: [{addr, error}] }` |

```cpp
public ref class LabelEntry
{
public:
    property String^ Address;
    property String^ Text;
    property bool Manual;
    property bool Temporary;
};
```

### `Comments{list, get, set, delete, set_batch, delete_batch}` ⚪

Same shape pattern as `Labels` (without `temporary`). `CommentEntry { Address, Text, Manual }`.

### `Bookmarks{list, get, set, delete}` ⚪

`BookmarkEntry { Address, Manual }`.

### `Xrefs{list_at, add, count_at, type_at}` ⚪

| Action | Params | Returns |
|---|---|---|
| `list_at` | `{ addr: string }` | `List<XrefEntry>` |
| `add` | `{ from: string, to: string }` | `XrefEntry` |
| `count_at` | `{ addr: string }` | `{ count: int }` |
| `type_at` | `{ addr: string }` | `{ type: "none" \| "data" \| "jmp" \| "call" }` |

```cpp
public ref class XrefEntry
{
public:
    property String^ From;
    property String^ To;
    property String^ Type;
};
```

---

## 5. Debug-mode Tools (state-mutating — `McpDebuggingTools`)

These tools are registered only when `McpServerHost::Start(..., enableDebugging: true)`.

### `DebugControl{init, stop, run, pause, Step*, run_command}` 🟡

| Action | Params | Notes |
|---|---|---|
| `stop` | — | Detach/terminate |
| `run` | — | Returns immediately; does not wait for next pause |
| `pause` | — | |
| `StepInto` | — | |
| `StepOver` | — | |
| `StepOut` | — | |
| `init` | `{ exePath: string, cmdLine?: string, curFolder?: string }` | Loads target executable |
| `run_command` | `{ command: string, wait?: bool }` | Raw x64dbg command; `wait` uses `DbgCmdExecDirect` |

Returns: `{ success: bool, isDebugging?: bool, isRunning?: bool }` envelope per action.

### `Breakpoints{list, get, set, delete, disable, set_hardware, delete_hardware, set_batch, delete_batch}` 🟡

```cpp
public ref class BreakpointEntry
{
public:
    property String^ Address;
    property String^ Type;           // "normal" | "hardware" | "memory" | "dll" | "exception"
    property String^ HwType;         // "access" | "write" | "execute" | null
    property bool Enabled;
    property int HitCount;
    property String^ Module;
    property String^ Condition;      // x64dbg conditional expression if any
};
```

### `Registers{get, set, dump}` 🟢

| Action | Params | Returns |
|---|---|---|
| `get` | `{ name: string }` | `{ name, value }` — `name` accepts any x64dbg-known register/flag name (rax, eip, zf, r8d…) |
| `set` | `{ name: string, value: string }` | `{ name, value, previous }` |
| `dump` | `{ threadId?: int }` | same as `GetRegisterDump` result |

`name` is resolved by x64dbg; we do not maintain an enum mirror. See [adr/002-resolve-via-x64dbg-expression.md](adr/002-resolve-via-x64dbg-expression.md).

### `Memory{write, alloc, free}` 🟡

| Action | Params | Returns |
|---|---|---|
| `write` | `{ addr: string, base64: string }` | `{ written: int }` |
| `alloc` | `{ size: int, addr?: string }` | `{ address: string, size: int }` |
| `free` | `{ addr: string }` | `{ freed: bool }` |

### `Threads{list, get, set_name, set_active, suspend, resume, create_at}` 🟡

`list` shape mirrors `x64dbg://threads`. State-mutating actions are here so analysis-only mode does not expose them.

### `Assemble(addr, instruction, fillNops?)` 🟡

```cpp
[McpServerTool,
 Description("Assemble a single instruction at the given address. Optionally fill remaining bytes with NOPs.")]
AssembleResult^ Assemble(
    [Description("Address or x64dbg expression")] String^ addr,
    [Description("Assembly source (e.g. \"mov eax, 1\", \"jmp 0x140001000\")")] String^ instruction,
    [Description("If true, fill leftover bytes within the original instruction span with NOPs")] bool fillNops
);

public ref class AssembleResult : McpResult
{
public:
    property String^ Address;
    property String^ Bytes;           // hex
    property int Size;
};
```

### `LogPuts(text)` 🟢

```cpp
[McpServerTool,
 Description("Write a line to the x64dbg log window.")]
LogPutsResult^ LogPuts([Description("Text to log")] String^ text);
```

Trivial wrapper; useful for AI to leave breadcrumbs in the debugger UI.

---

## 6. Reserved Resources (specified but not yet implemented)

The following resources are **reserved** in the URI namespace and specified here for completeness. They are not yet implemented; attempts to access them will return an error or empty response until implementation is complete.

### `x64dbg://symbols` ⚪

Returns `List<SymbolEntry>` across all modules. Pagination via `?offset=&limit=` query params.

```cpp
public ref class SymbolEntry
{
public:
    property String^ Name;
    property String^ DecoratedName;  // null if not C++ mangled
    property String^ Address;        // hex
    property String^ Module;         // containing module
    property String^ Type;           // "import" | "export" | "user" | "auto"
};
```

### `x64dbg://labels` ⚪

Returns `List<LabelEntry>` across all modules. User-defined and automatic labels.

```cpp
public ref class LabelEntry
{
public:
    property String^ Address;        // hex
    property String^ Text;
    property String^ Module;         // containing module
    property bool Manual;
    property bool Temporary;
};
```

### `x64dbg://comments` ⚪

Returns `List<CommentEntry>` across all modules.

```cpp
public ref class CommentEntry
{
public:
    property String^ Address;        // hex
    property String^ Text;
    property String^ Module;         // containing module
    property bool Manual;
};
```

### `x64dbg://bookmarks` ⚪

Returns `List<BookmarkEntry>` across all modules.

```cpp
public ref class BookmarkEntry
{
public:
    property String^ Address;        // hex
    property String^ Module;         // containing module
    property bool Manual;
};
```

### `x64dbg://breakpoints` ⚪

Returns `List<BreakpointEntry>` across all modules. All breakpoint types.

```cpp
public ref class BreakpointEntry
{
public:
    property String^ Address;        // hex
    property String^ Type;           // "normal" | "hardware" | "memory" | "dll" | "exception"
    property String^ HwType;         // "access" | "write" | "execute" | null
    property bool Enabled;
    property int HitCount;
    property String^ Module;
    property String^ Condition;      // x64dbg conditional expression if any
};
```

---

## 7. Out of Scope (deliberately not exposed)

The following PoC-era tools are intentionally **not** exposed in the v0 baseline:

- `Gui*` (GuiMessage, GuiMessageYesNo, GuiSelectionGet/Set, GuiFocusView, GuiRefresh) — UX-coupling, low automation value
- `Script*` (ScriptLoad, ScriptRun, ScriptAbort, ScriptCmdExec) — superseded by `DebugControl{action:"run_command"}`
- `Watch*` — niche; revisit if user-driven need emerges
- Per-flag `GetFlag` / `SetFlag` / per-register `GetRegister` / `SetRegister` — covered by `Registers{get,set,dump}` with name-based addressing

If a future need arises, propose an ADR before adding back.

---

## 8. Mapping to PoC

Per-PoC-tool migration table for review. PoC reference: `copilot/refine-x64dbg-handler-todos` branch.

| PoC tool | New form | Note |
|---|---|---|
| `GetProjectInfo` | resource `x64dbg://session` | Promoted to navigation root |
| `GetSymbolList`, `GetSymbolAt` | `Symbols{list, get}` | |
| `GetFunctionList`, `GetFunctionAt`, `AddFunction`, `DeleteFunction` | `Functions{list, get, set, delete}` | |
| `GetLabelList`, `GetLabelAt`, `SetLabel`, `DeleteLabel`, `IsLabelTemporary`, `LabelFromString` | `Labels{...}` | `LabelFromString` collapses into `ParseExpression` |
| `GetCommentList`, `GetCommentAt`, `SetComment`, `DeleteComment` | `Comments{...}` | |
| `GetBookmarkList`, `GetBookmarkAt`, `SetBookmark`, `DeleteBookmark` | `Bookmarks{...}` | |
| `GetXrefs`, `AddXref`, `GetXrefCountAt`, `GetXrefTypeAt` | `Xrefs{...}` | |
| `GetModuleList`, `GetMainModuleInfo`, `GetModuleByAddr`, `GetModuleByName`, `GetMainModuleSectionList`, `GetSectionListByAddr`, `GetSectionListByName`, `GetExports`, `GetImports` | resources `x64dbg://modules/...` | All become URI-addressable |
| `IsValidPtr`, `GetMemoryMaps`, `GetMemoryBase`, `GetMemorySize` | resource `x64dbg://memory/map` + tool `ParseExpression` | Most queries reduce to expression resolution |
| `MemoryRead` | tool `MemoryRead` | Added optional `compress` (lz4) for large reads |
| `GetThreadList` | resource `x64dbg://threads` | |
| `Disassemble` | tool `Disassemble` | Same name, raised `count` ceiling |
| `FindPattern` | tool `FindPattern` | Added `scope`, `maxResults` |
| `InitDebug` | `DebugControl{action:"init"}` | |
| `ParseExpression`, `ResolveLabel`, `GetStringAt` | tools `ParseExpression`, `GetStringAt` | `ResolveLabel` collapses into `ParseExpression` |
| `IsDebugging`, `IsRunning`, ..., `RunCommand` | `DebugControl{...}` | |
| `GetBreakpointList`, `SetBreakpoint`, `DeleteBreakpoint`, `DisableBreakpoint`, `SetHardwareBreakpoint`, `DeleteHardwareBreakpoint` | `Breakpoints{...}` | |
| `GetFlag`, `SetFlag`, `GetRegister`, `SetRegister`, `GetRegisterDump` | `Registers{...}` + tool `GetRegisterDump` | Name-based, no enum mirror |
| `MemoryWrite`, `MemoryAlloc`, `MemoryFree` | `Memory{...}` | |
| `GetCallStack` | tool `GetCallStack` | |
| `SetThreadName`, `SetActiveThread`, `SuspendThread`, `ResumeThread`, `CreateThread` | `Threads{...}` | |
| `Assemble` | tool `Assemble` | Added `fillNops` |
| `LogPuts` | tool `LogPuts` | |
| `Gui*`, `Script*`, `*Watch*` | (excluded) | See §6 |

Net surface estimate: **~7 resources + ~7 rich-param tools + ~9 mega-tools ≈ 23 entries** (PoC was ~50+).
