# Tools & Resources Specification

This is the **contract baseline** for the MCP surface. Every tool and resource must conform to the shapes declared here. Adding/changing the surface requires updating this file *first*, then implementation.

> **Contract-maturity legend**: `🟢 stable` — schema settled | `🟡 draft` — shape under discussion | `⚪ stub` — name reserved, contents TBD. These markers never mean “implemented”; current code coverage lives only in [implementation-status.md](implementation-status.md).

> Cross-cutting rules (envelope, errors, addresses, pagination, links) live in [conventions.md](conventions.md). This file does not duplicate them; it only declares per-tool/per-resource specifics.

Tool headings use the exact MCP-visible `snake_case` name returned by `tools/list`. C++/CLI method signatures remain `PascalCase`; MCP C# SDK 2.1.0 derives the wire name when `[McpServerTool(Name=...)]` is not set.

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
    property PageInfo^ Page;                                  // list-shaped payloads only
};
```

> **Implementation note**: C++/CLI generic ref classes are awkward. Practical pattern is to define a non-generic `McpResult` base and a concrete `<Domain>Result` per tool that adds typed `Data` (and `Page` if list-shaped). Examples below follow this pattern.

---

## 2. Resources

All resources use the URI scheme `x64dbg://`. Resources are defined on a single `[McpServerResourceType]` class (e.g. `McpResources`).

Resources are the read-only bulk surface: they return compact snapshots or collections that an agent can scan quickly. A Tool may exist for the same domain when it performs a precise item read or update; the Resource and Tool must not duplicate an equivalent operation.

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
    property Dictionary<String^, LinkRef^>^ Links;  // → debuggee, attach/processes, modules, memory/maps, threads, windows, handles, tcpconnections, breakpoints, logging
};
```

### `x64dbg://logging` 🟢

Plain-text snapshot of the current x64dbg Log view. The Resource uses MIME type
`text/plain`, does not require an active debug session, and returns the rendered log text
without a JSON envelope or `_links`.

The implementation calls `GuiLogSave` on the GUI thread, reads the resulting UTF-8 file,
and immediately deletes the unique temporary file after a successful read. `GuiLogSave`'s
own status message is suppressed so reading the Resource does not append a breadcrumb to
the log being observed.
Messages that x64dbg still holds in its private LogView buffer while the Log tab is hidden
are outside this rendered snapshot until upstream displays the tab and flushes that buffer.

### `x64dbg://session/debuggee` 🟢

Information about the current session's debuggee. Empty/null fields when not debugging.

```cpp
public ref class DebuggeeInfo
{
public:
    // property String^ Handle;          // native process handle (hex)
    property bool Elevated;              // 
    property int ProcessId;              // PID (0 when not debugging)
    property int ThreadId;               // current thread ID (0 when not debugging)
    property String^ ImageBase;          // base address of the main module (hex)
    property String^ EntryPoint;         // (hex)
    property String^ PebAddress;         // PEB address (hex)
    property String^ TebAddress;         // TEB address for current thread (hex)
    // property String^ KUserSharedData;    // KUSER_SHARED_DATA address (hex)
    property String^ Path;               // full path to the executable
    property String^ CommandLine;        // full Unicode command line; null when unavailable
    property Dictionary<String^, LinkRef^>^ Links;  // → session, modules, memory/maps, threads, windows, handles, tcpconnections, breakpoints
};
```

This Resource replaces the former `x64dbg://process` URI. The old URI is not retained as an
alias because two equivalent Resources would violate ADR-003's no-duplicate-operation rule.

### `x64dbg://attach/processes{?offset,limit}` 🟢

Paged snapshot of the processes offered by x64dbg's Attach dialog. It is available without an
active debug session. `offset` defaults to `0`; `limit` defaults to `100` and is clamped to
`1–100`. Pagination is applied to one `DbgFunctions()->GetProcessList` snapshot; process creation
and exit can change subsequent pages.

The native list is already filtered by x64dbg: it excludes the debugger itself, PID 0/4,
processes that cannot be opened for query and memory read, and processes whose architecture does
not match the current x32dbg/x64dbg instance. Consequently the collection represents attach
candidates, not every process in Windows and not a guarantee that a later attach will succeed.

```cpp
public ref class AttachProcessInfo
{
public:
    property int ProcessId;
    property String^ Name;                  // file name without extension, matching AttachDialog
    property String^ Title;                 // main-window title or class name; empty when unavailable
    property String^ Path;                  // full executable path
    property String^ CommandLineArguments;  // x64dbg's best-effort parsed arguments
};

public ref class AttachProcessesPayload
{
public:
    property List<AttachProcessInfo^>^ Data;
    property PageInfo^ Page;
    property Dictionary<String^, LinkRef^>^ Links;  // self/next/prev/session
};
```

`GetProcessList` allocates its contiguous `DBGPROCESSINFO` array with `BridgeAlloc`; the Resource
materializes the managed page and releases that allocation exactly once with `BridgeFree`. The
SDK returns `false` both when enumeration fails and when it finds no candidates, so both states
are exposed as an empty page.

`CommandLineArguments` preserves `DBGPROCESSINFO::szExeArgs`, the same value rendered by
x64dbg's Attach dialog. Upstream normally attempts to remove the executable from the full command
line, but the matching is best-effort and case-sensitive. The value can therefore contain an
`ARG_GET_ERROR` diagnostic or a partial executable prefix when the image path/name does not match
the command line exactly. The Resource does not independently re-read or normalize every
candidate's remote command line.

### `x64dbg://modules` 🟢

Paged list of loaded modules in the debugged process. The URI template is
`x64dbg://modules{?offset,limit}`; `offset` defaults to `0`, `limit` defaults to `100`,
and the server clamps `limit` to `1–100`. The collection is wrapped in `ModulesPayload`
so pagination and navigation metadata are not repeated on every item.

- `Data` contains `ModuleInfo` entries with `_links.self` set per item to `x64dbg://modules/{name}`.
- `Page` follows [conventions.md §7](conventions.md#7-pagination--bulk-parameters).
- Empty list when not debugging (not an error).

### `x64dbg://modules/{name}` 🟢

```cpp
public ref class ModuleInfo
{
public:
    property String^ Name;
    property String^ Path;           // full path on disk
    property String^ Base;           // hex address
    property String^ Size;           // hex
    property String^ Entry;          // hex
    property int SectionCount;
    property bool IsMainModule;
    property Dictionary<String^, LinkRef^>^ Links;  // self, modules, sections, exports, imports, entry_disasm
};

public ref class ModulesPayload
{
public:
    property List<ModuleInfo^>^ Data;
    property PageInfo^ Page;
    property Dictionary<String^, LinkRef^>^ Links;  // self, next?, prev?, session
};
```

Unknown module names fail the resource request. The URI-template parameter is the loaded
module name including its extension (for example, `kernel32.dll`).

### `x64dbg://modules/{name}/sections` 🟢

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

### `x64dbg://modules/{name}/exports` 🟢

Returns `List<ModuleExport>`:

```cpp
public ref class ModuleExport
{
public:
    property String^ Name;
    property String^ UndecoratedName;
    property String^ ForwardName;    // null if not a forwarder
    property int Ordinal;
    property String^ Rva;            // hex
    property String^ Va;             // hex
};
```

### `x64dbg://modules/{name}/imports` 🟢

Returns `List<ModuleImport>`:

```cpp
public ref class ModuleImport
{
public:
    property String^ Name;
    property String^ UndecoratedName;
    property String^ IatRva;         // hex
    property String^ IatVa;          // hex
};
```

`ModuleName` is intentionally absent: `Script::Module::ModuleImport` does not expose the
source DLL name. The resource reports only fields that the public x64dbg Script API can
provide truthfully.

### `x64dbg://memory/maps` 🟢

Returns `MemoryMapsPayload` with `_links` at the top level. Protection values use
x64dbg's fixed `ERWCG` display order (`Execute`, `Read`, `Write`, `Copy-on-write`,
`Guard`) as produced by `DbgFunctions()->PageRightsToString`; state and type are also
display strings. Addresses and sizes remain unambiguous hexadecimal strings. `Data` is
empty when not debugging.

```cpp
public ref class MemoryRegion
{
public:
    property String^ Base;           // hex
    property String^ AllocationBase; // hex
    property String^ Size;           // hex
    property String^ AllocationProtect; // "-R---" | "-RW--" | "ERWC-" | ...
    property String^ Protect;        // "-R---" | "-RW--" | "ERWC-" | ...
    property String^ State;          // "commit" | "reserve" | "free" | "unknown"
    property String^ Type;           // "image" | "private" | "mapped" | "unknown"
    property String^ Info;           // x64dbg memory-map annotation; null when empty
};

public ref class MemoryMapsPayload
{
public:
    property List<MemoryRegion^>^ Data;
    property Dictionary<String^, LinkRef^>^ Links;  // self, session, debuggee
};
```

### `x64dbg://threads` 🟢

Returns `ThreadsPayload` (empty `Data` when not debugging). Fields mirror the useful
facts exposed by `THREADALLINFO`; priority and wait reason are rendered with the same
names used by x64dbg's Threads view.

```cpp
public ref class ThreadInfo
{
public:
    property int ThreadNumber;       // 0 is the main thread
    // property String^ Handle;       // native handle, currently not exposed
    property int ThreadId;
    property String^ Name;
    property String^ Cip;            // serialized as "pc"; program counter, hex
    property String^ EntryPoint;     // hex
    property String^ TebAddress;     // hex
    property unsigned int SuspendCount;
    property String^ Priority;
    property String^ WaitReason;
    property unsigned int LastError;
    property String^ UserTime;                   // CPU duration: "hh:mm:ss.fffffff" or "d:hh:mm:ss.fffffff"
    property String^ KernelTime;                 // CPU duration: "hh:mm:ss.fffffff" or "d:hh:mm:ss.fffffff"
    property String^ CreationTime;               // UTC ISO 8601
    property unsigned long long Cycles;
    property bool IsActive;
};

public ref class ThreadsPayload
{
public:
    property List<ThreadInfo^>^ Data;
    property Dictionary<String^, LinkRef^>^ Links;  // self, session, debuggee
};
```

`CreationTime` is an absolute timestamp. `UserTime` and `KernelTime` are cumulative CPU
durations, not timestamps; all three are serialized as strings, while the two durations
use the same representation as x64dbg's Threads view.

### `x64dbg://breakpoints{?offset,limit}` 🟢

Paged snapshot of all breakpoint types returned by `DbgGetBpList(bp_none, ...)`. `offset`
defaults to `0`; `limit` defaults to `100` and is clamped to `1–100`. The response is an empty
page when there is no active debug session. The native `BPMAP.bp` allocation is released with
`BridgeFree` after the managed snapshot has been materialized.

`BRIDGEBP.addr` is type-dependent. For normal, hardware, and memory breakpoints it is exposed
as `Address`. For exception breakpoints it is an exception code and is exposed separately as
`ExceptionCode`. A DLL breakpoint stores a module-name hash in `addr`; that internal lookup key
is not an address and is intentionally omitted. `Module` identifies the DLL breakpoint instead.

`Subtype` normalizes `BRIDGEBP.typeEx` according to `Type`:

- hardware: `"access" | "write" | "execute"`
- memory: `"access" | "read" | "write" | "execute"`
- DLL: `"load" | "unload" | "all"`
- exception: `"first_chance" | "second_chance" | "all"`
- normal: `null`

```cpp
public ref class BreakpointEntry
{
public:
    property String^ Type;              // "normal" | "hardware" | "memory" | "dll" | "exception"
    property String^ Subtype;           // normalized typeEx value; null for normal
    property String^ Address;           // hex VA/native location for normal, hardware, or memory; otherwise null
    property String^ ExceptionCode;     // hex exception code for exception; otherwise null
    property String^ HardwareSize;      // "byte" | "word" | "dword" | "qword" for hardware; otherwise null
    property Nullable<int> HardwareSlot; // 0..3 for hardware; otherwise null
    property bool Enabled;
    property bool SingleShoot;
    property bool Active;
    property String^ Name;
    property String^ Module;
    property unsigned int HitCount;
    property bool FastResume;
    property bool Silent;
    property String^ BreakCondition;
    property String^ LogText;
    property String^ LogCondition;
    property String^ CommandText;
    property String^ CommandCondition;
};

public ref class BreakpointsPayload
{
public:
    property List<BreakpointEntry^>^ Data;
    property PageInfo^ Page;
    property Dictionary<String^, LinkRef^>^ Links;  // self, session, debuggee, next?, prev?
};
```

Empty optional native text fields are omitted from the JSON payload. `Address`,
`ExceptionCode`, `HardwareSize`, and `HardwareSlot` are mutually constrained by `Type`; the
resource never exposes the DLL breakpoint's internal module hash as an address. As a navigation
root, the Resource links back to session/debuggee and supplies page-local self/next/prev links.

### `x64dbg://windows` 🟢

List of windows returned by x64dbg's `DbgFunctions()->EnumWindows`. `Data` is empty when
there is no active debug session or the underlying enumeration fails. Pointer-like fields
are hexadecimal strings. `UserData` is read from the window handle with
`GetWindowLongPtrW(hwnd, GWLP_USERDATA)` and is returned as a hexadecimal string; `0x0`
is the API's ambiguous zero result: the stored value may be zero, or the call may have
failed. This resource intentionally exposes only the raw value and no separate error field.

```cpp
public ref class WindowInfo
{
public:
    property String^ Procedure;       // window procedure address, hex
    property String^ Handle;           // HWND, hex
    property String^ Title;
    property String^ ClassName;
    property unsigned int ThreadId;
    property String^ Style;            // hex
    property String^ StyleEx;          // hex
    property String^ Parent;           // parent HWND, hex
    property int Left;
    property int Top;
    property int Width;
    property int Height;
    property bool Enabled;
    property String^ UserData;         // GWLP_USERDATA, hex
};

public ref class WindowsPayload
{
public:
    property List<WindowInfo^>^ Data;
    property Dictionary<String^, LinkRef^>^ Links;  // self, session, debuggee
};
```

### `x64dbg://handles` 🟢

List of handles returned by x64dbg's `DbgFunctions()->EnumHandles`, with the display name
and type resolved through `DbgFunctions()->GetHandleName`. `Data` is empty when there is no
active debug session or the underlying enumeration fails.

```cpp
public ref class HandleInfo
{
public:
    property String^ Type;
    property String^ TypeNumber;       // hex
    property String^ Handle;           // hex
    property String^ GrantedAccess;    // hex
    property String^ Name;
};

public ref class HandlesPayload
{
public:
    property List<HandleInfo^>^ Data;
    property Dictionary<String^, LinkRef^>^ Links;  // self, session, debuggee
};
```

### `x64dbg://tcpconnections` 🟢

List of TCP connections returned by x64dbg's `DbgFunctions()->EnumTcpConnections`.
`Data` is empty when there is no active debug session or the underlying enumeration fails.
Addresses are display strings supplied by x64dbg; ports and the numeric state are returned
as integers, while `StateText` mirrors x64dbg's Handles view.

```cpp
public ref class TcpConnectionInfo
{
public:
    property String^ RemoteAddress;
    property unsigned short RemotePort;
    property String^ LocalAddress;
    property unsigned short LocalPort;
    property String^ StateText;
    property unsigned int State;
};

public ref class TcpConnectionsPayload
{
public:
    property List<TcpConnectionInfo^>^ Data;
    property Dictionary<String^, LinkRef^>^ Links;  // self, session, debuggee
};
```

---

## 3. Rich-param Tools (always-registered analysis, read-only — `McpAnalysisTools`)

This section covers the five always-registered analysis queries. The debugger-domain `assemble` Tool uses the same rich-param form but is documented in §5 because it belongs behind the `enableDebugging` catalog gate.

### `disassemble(addr, count, withBytes?)` 🟢

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

public ref class DisassembleReference
{
public:
    property String^ Kind;           // currently "import"
    property String^ Address;        // referenced IAT slot, hex
    property String^ Name;           // imported symbol name
};

public ref class DisassembleEntry
{
public:
    property String^ Address;        // hex
    property String^ Mnemonic;       // "mov", "call", ...
    property String^ Operands;       // canonical fast-disasm text, e.g. "rax, qword ptr [rcx+8]"
    property String^ Display;        // optional symbolized instruction text
    property DisassembleReference^ Reference; // optional exact reference metadata
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

`operands` remains the canonical text returned by x64dbg's fast disassembler and is never
rewritten. When the instruction has a memory operand whose effective address exactly matches
an IAT entry in the loaded module's import table, `display` presents the same instruction with
that operand rendered as `<&Name>`, and `reference` identifies the import and its IAT slot. For
example:

```json
{
  "mnemonic": "call",
  "operands": "qword ptr ds:[0x00007FF709D12D58]",
  "display": "call qword ptr ds:[<&RaiseException>]",
  "reference": {
    "kind": "import",
    "address": "0x7FF709D12D58",
    "name": "RaiseException"
  }
}
```

The reference address is the IAT slot named by the instruction, not the pointer currently
stored in that slot and not the final implementation address. Both optional fields are absent
when exact import resolution is unavailable; ordinary memory operands must not be labelled as
imports. The symbolized display is a stable Tool representation constructed from fast-disasm
metadata and the debugger symbol table, rather than the GUI's setting-dependent rendered line.

Errors: `not_attached`, `invalid_argument` (count out of range), `not_found` (addr unresolvable), `x64dbg_failed` (unreadable address, disassembly failure, or byte-read failure).

### `find_pattern(pattern, scope?, maxResults?)` 🟢

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

### `parse_expression(expr)` 🟢

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

### `get_string_at(addr)` 🟢

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

### `get_call_stack(threadId?)` 🟡

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

---

## 4. Analysis Mega-tools (fine-grained CRUD — `McpAnalysisTools`)

Each mega-tool dispatches on `action`. Closed set per tool. The `params` parameter object varies by action; document each variant. Returned `Data` shape varies by action — declare per-action result classes.

These analysis-domain tools are always registered. Their catalog may update x64dbg analysis metadata; `enableDebugging` is not a generic write gate. Bulk collection reads live in Resources, while these Tools address or change individual items.

### `symbols{get}` 🟡

Read-only precise lookup. Symbols are sourced from PDB / PE export tables / x64dbg user data. Bulk enumeration uses `x64dbg://symbols`.

| Action | Params | Returns |
|---|---|---|
| `get` | `{ addr: string }` | `SymbolEntry?` |

### `functions{get, set, delete}` ⚪

Bulk enumeration uses `x64dbg://functions`.

| Action | Params | Returns |
|---|---|---|
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

### `labels{get, set, delete, set_batch, delete_batch}` 🟡

Bulk enumeration uses `x64dbg://labels`.

| Action | Params | Returns |
|---|---|---|
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

### `comments{get, set, delete, set_batch, delete_batch}` ⚪

Same precise-operation pattern as `labels` (without `temporary`). Bulk enumeration uses `x64dbg://comments`. `CommentEntry { Address, Text, Manual }`.

### `bookmarks{get, set, delete}` ⚪

Bulk enumeration uses `x64dbg://bookmarks`. `BookmarkEntry { Address, Manual }`.

### `xrefs{list_at, add, count_at, type_at}` ⚪

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

## 5. Debugger-domain Tools (conditionally registered — `McpDebuggingTools`)

These tools are registered only when `McpServerHost::Start(..., enableDebugging: true)`. The flag limits debugger-domain tool-schema growth; it is not a generic read/write or authorization boundary.

### `debug_control{init, attach, stop, run, pause, Step*, run_command}` 🟢

| Action | Params | Notes |
|---|---|---|
| `attach` | `{ pid: int, detach2attach?: bool = false }` | Attaches to a positive decimal Windows PID. If a debug session is already active, the call fails before side effects unless `detach2attach=true`; the opt-in path detaches the current debuggee, leaves it running, and then attaches to `pid`. |
| `stop` | — | Detach/terminate |
| `run` | — | Returns immediately; does not wait for next pause |
| `pause` | — | |
| `StepInto` | — | |
| `StepOver` | — | |
| `StepOut` | — | |
| `init` | `{ exePath: string, cmdLine?: string, curFolder?: string }` | Loads target executable |
| `run_command` | `{ command: string, wait?: bool }` | Raw x64dbg command; `wait` uses `DbgCmdExecDirect` |

`attach` dispatches x64dbg's `attach .<pid>` command, where the leading dot preserves decimal PID semantics. It uses direct command execution so a `detach2attach=true` call can temporarily force x64dbg's `Engine/DetachOnAttach` behavior for that dispatch and restore the prior setting before returning. The option is call-local and does not persistently change the user's debugger configuration. A successful return means the attach command handler accepted the target and started the attach debug loop; it does not wait for the system breakpoint. Clients should confirm the resulting PID through `x64dbg://session/debuggee`.

Returns a `DebugControlResult` envelope with the echoed `action` and post-dispatch `isDebugging` / `isRunning` snapshot. `commandOutput` is reserved in the current result class but is not populated by the implementation; `run_command` reports command acceptance, not captured console output.

Errors: `invalid_argument` (unknown action, missing/zero `pid`, missing action-specific parameter, or `attach` attempted during an active session without `detach2attach=true`), `not_attached` (session action without a debuggee), `x64dbg_failed` (x64dbg rejected the dispatched command or the temporary detach-on-attach setting could not be applied/restored).

### `breakpoints{get, set, set_hardware, disable, delete}` 🟢

Bulk enumeration and the shared `BreakpointEntry` wire vocabulary are defined by
`x64dbg://breakpoints`. The Tool supplies precise per-item reads and mutations and must not add an
equivalent unfiltered bulk-list action. `set_batch` and `delete_batch` remain reserved actions from
ADR-003; they are not exposed by the current Tool schema until their contracts are defined.

| Action | Params | Returns |
|---|---|---|
| `get` | `{ addr: string, kind?: "normal" \| "hardware" }` | Matching software or hardware `BreakpointEntry` |
| `set` | `{ addr: string, breakCondition?: string, logText?: string, logCondition?: string }` | Post-mutation software `BreakpointEntry` |
| `set_hardware` | `{ addr: string, type?: "access" \| "write" \| "execute", size?: 1 \| 2 \| 4 \| 8, breakCondition?: string, logText?: string, logCondition?: string }` | Post-mutation hardware `BreakpointEntry` |
| `disable` | `{ addr: string, kind?: "normal" \| "hardware" }` | Matching post-mutation `BreakpointEntry` with `enabled:false` |
| `delete` | `{ addr: string, kind?: "normal" \| "hardware" }` | Success-only envelope after deleting the matching breakpoint |

`addr` is resolved through the x64dbg expression engine and every native operation uses the
resulting canonical address. For `get`, `disable`, and `delete`, `kind` reuses the
`BreakpointEntry.type` values `"normal"` and `"hardware"`. When omitted, the Tool scans both
families: zero matches returns `not_found`, one match is selected automatically, and two matches
returns `invalid_argument` before mutation because x64dbg permits software and hardware
breakpoints to coexist at one address. The caller must then provide `kind`; the Tool never picks
by enumeration order or silently mutates both breakpoints.

`set_hardware.type` defaults to `"execute"`, matching x64dbg's official command and Script API.
`"access"` means read/write and is intentionally opt-in because its broader hit surface can
generate substantially more debug events and log output. `size` defaults to `1`; valid values are
`1`, `2`, and `4` on x86, plus `8` on x64. The address must be aligned to the selected size. The
four debug-register slots remain an upstream hardware limit.

`breakCondition`, `logText`, and `logCondition` are stored for breakpoint-hit time rather than
pre-evaluated by the Tool. Each non-empty value is limited to 255 UTF-8 bytes, matching the
`BRIDGEBP` readback fields. The Script API has no named setter for these fields, but the vendored
Plugin SDK exposes the generic `BP_REF` + `BpSetFieldText` interface with
`bpf_breakcondition`, `bpf_logtext`, and `bpf_logcondition`. The Tool uses that interface with
UTF-8 values, and explicitly sets `bpf_silent` when `logText` is non-empty. Consequently log text
does not pass through x64dbg's command parser: commas, semicolons, significant spaces, embedded
quotes, backslashes, and hit-time formatting such as `{rcx}` are stored verbatim. The only raw
commands in this implementation are `SetHardwareBreakpoint <address>,<type>,<size>`, because the
Script API cannot express hardware size, and `DisableHardwareBreakpoint <address>`, because the
Script API has no hardware-disable wrapper. After every mutation, the Tool rereads
`DbgGetBpList` and verifies the exact breakpoint type, canonical address, requested condition/log
values, and action-specific state before returning success.

A log-only breakpoint is represented without another action kind:

```json
{
  "action": "set_hardware",
  "addr": "target expression",
  "type": "access",
  "size": 8,
  "breakCondition": "0",
  "logText": "cip: {cip}  address: {$breakpointexceptionaddress}"
}
```

This is the supported x64dbg form for “record but do not pause”. A non-empty `logText` also makes
the breakpoint silent, suppressing the standard hit message while retaining the custom log.
`fastResume` must not be enabled for this use case because a false break condition with fast
resume skips logging, commands, plugin callbacks, and GUI work. Invalid hit-time conditions follow
x64dbg semantics and evaluate as triggered, so `"0"` is clearer and safer than an incidental
always-false register comparison such as `cip == 0`.

```cpp
public ref class BreakpointResult : McpResult
{
public:
    property BreakpointEntry^ Data;  // omitted for delete
};
```

Errors: `not_attached`; `invalid_argument` (unknown action, missing `addr`, invalid `kind`, both
normal and hardware breakpoints present without `kind`, invalid hardware type/size/alignment, x86
size 8, or condition/log value too long); `not_found` (unresolvable `addr` or requested breakpoint
absent); `x64dbg_failed` (native/command mutation failure, occupied hardware slots, or
post-readback mismatch).

### `registers{get, set, dump}` 🟢

| Action | Params | Returns |
|---|---|---|
| `get` | `{ name: string }` | `{ name, value }` — `name` accepts any x64dbg-known register/flag name (rax, eip, zf, r8d…) |
| `set` | `{ name: string, value: string }` | `{ name, value, previous }` |
| `dump` | `{ threadId?: int }` | `RegisterDumpResult` |

`name` is resolved by x64dbg; we do not maintain an enum mirror. See [adr/002-resolve-via-x64dbg-expression.md](adr/002-resolve-via-x64dbg-expression.md).
For an inactive thread, register values come from its native thread context and require the debuggee to be paused; a running target returns `not_paused`. `lastError` and `lastStatus` may be null when x64dbg does not expose the TEB-derived values for that context.

`registers{action:"dump"}` is the only register-dump Tool; there is no separate `get_register_dump` Tool because it would duplicate the same operation.

```cpp
public ref class RegisterDumpResult : McpResult
{
public:
    property int ThreadId;
    property Dictionary<String^, String^>^ Registers;  // name → hex value (GPRs, segments, debug)
    property Dictionary<String^, bool>^ Flags;         // "zf" → true, "of" → false, ...
    property String^ LastError;                        // hex (from TEB), nullable for inactive contexts
    property String^ LastStatus;                       // hex (from TEB), nullable for inactive contexts
};
```

Registers includes:
- **x64**: rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, r8-r15
- **x86**: eax, ebx, ecx, edx, esi, edi, ebp, esp, eip
- **Segments**: cs, ds, es, fs, gs, ss
- **Debug**: dr0, dr1, dr2, dr3, dr6, dr7

Flags includes: zf, of, cf, pf, sf, tf, af, df, if

Errors: `invalid_argument` (unknown action, missing name/value, invalid value, or negative `threadId`), `not_attached`, `not_found` (unknown register/flag or thread), `not_paused` (inactive-thread dump while running), `x64dbg_failed` (write or native thread-context failure).

### `memory{read, write, alloc, free}` 🟡

| Action | Params | Returns |
|---|---|---|
| `read` | `{ addr: string, size: int, compress?: bool }` | `MemoryReadResult` |
| `write` | `{ addr: string, base64: string }` | `{ written: int }` |
| `alloc` | `{ size: int, addr?: string }` | `{ address: string, size: int }` |
| `free` | `{ addr: string }` | `{ freed: bool }` |

The `read` action preserves the earlier standalone `memory_read(addr, size, compress?)` contract; only the MCP-visible entry point and debugger-catalog membership change. Its flattened Tool arguments are `{ action: "read", addr, size, compress? }`, with no nested `params` object. `size` remains bounded to `1–65536`, and `compress` defaults to `false`.

```cpp
[McpServerTool,
 Description("Memory operations. The currently implemented action is read.")]
Object^ Memory(
    [Description("Action: \"read\"")] String^ action,
    [Description("Address or x64dbg expression (required for action=read)")] String^ addr,
    [Description("Number of bytes to read (1–65536; required for action=read)")] int size,
    [Description("Compress action=read payload with lz4 before base64")]
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

When `compress=true`, the client decodes base64 and then runs `LZ4_decompress_safe` (lz4 block format, no frame header) to recover `Size` bytes. The option can reduce compressible memory windows but does not guarantee a smaller payload; the response reports `CompressedSize` so the client can account for the actual result. The default is `false` so simple reads stay round-trip-cheap.

The family is not marked `ReadOnly=true` because later actions mutate the debuggee. The current implementation exposes only `read`; `write`, `alloc`, and `free` remain target actions and must not be advertised as implemented in the live Tool description until their dispatch paths exist.

Read errors: `not_attached`, `invalid_argument` (unknown action or size out of range), `not_found` (addr unresolvable), `x64dbg_failed` (memory read failure), `internal` (unexpected lz4 failure).

### `threads{get, set_name, set_active, suspend, resume, create_at}` 🟡

Bulk enumeration uses `x64dbg://threads`. Precise thread lookup and debugger control actions live here so they can be omitted from the default tool catalog.

### `assemble(addr, instruction, fillNops?)` 🟡

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

<a id="debug-gui"></a>

### `debug_gui{snapshot, focus, get, set}` 🟢

The managed method is named `DebugGUI`; MCP C# SDK 2.1.0 derives the wire name `debug_gui`. This debugger-domain action-mega Tool composes GUI primitives into evidence-oriented operations rather than exposing `GuiSelectionGet/Set`, `GuiFocusView`, or `GuiRefresh` as separate Tools. It is registered only when `enableDebugging=true`.

| Action | Params | Returns |
|---|---|---|
| `snapshot` | `{ save_path?: string }` | `DebugGUISnapshotResult` metadata plus an inline MCP image when `save_path` is omitted; file metadata/path only when supplied |
| `focus` | `{ window?: "Disassembly" \| "Dump" \| "Stack" = "Disassembly" }` | `DebugGUIFocusResult` after CPU activation, focus, refresh, and GUI event flush |
| `get` | `{ window: "Disassembly" \| "Dump" \| "Stack" }` | `DebugGUIGetResult` with the pane's current inclusive selection |
| `set` | `{ window: "Disassembly" \| "Dump" \| "Stack", start: string, end?: string }` | `DebugGUISetResult` with resolved requested and GUI-read-back actual ranges |

Arguments remain flat, consistent with the other action-mega Tools:

```cpp
[McpServerTool,
 Description("Capture x64dbg GUI evidence and control CPU-pane focus or selections.")]
Object^ DebugGUI(
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
    String^ save_path
);
```

`window` uses the canonical case-sensitive values above and maps only to `GUI_DISASSEMBLY`, `GUI_DUMP`, and `GUI_STACK`. For `focus`, an empty/omitted `window` is normalized to `Disassembly`; `get` and `set` require it explicitly. `focus`, `get`, and `set` require an active debug session. `snapshot` can capture the x64dbg main window while detached.

#### Result models

```cpp
public ref class DebugGUIRange
{
public:
    property String^ Start;           // resolved/formatted hex; inclusive
    property String^ End;             // resolved/formatted hex; inclusive
};

public ref class DebugGUIArtifact
{
public:
    property String^ Type;            // "image" | "file"
    property String^ MimeType;        // "image/png"
    property String^ Path;            // normalized absolute host path for Type == "file"; otherwise null
};

public ref class DebugGUISnapshotData
{
public:
    property String^ Action;          // "snapshot"
    property DebugGUIArtifact^ Artifact;
    property String^ CapturedAtUtc;   // ISO 8601 UTC
    property int Width;
    property int Height;
    property String^ Sha256;          // 64 uppercase hex characters over the exact PNG bytes
    property String^ WindowTitle;
    property int DebuggeeProcessId;   // 0 when detached
};

public ref class DebugGUISnapshotResult : McpResult
{
public:
    property DebugGUISnapshotData^ Data;
};

public ref class DebugGUIFocusData
{
public:
    property String^ Action;          // "focus"
    property String^ Window;          // canonical window value
    property bool Refreshed;          // true only after Refresh + GUI event flush
};

public ref class DebugGUIFocusResult : McpResult
{
public:
    property DebugGUIFocusData^ Data;
};

public ref class DebugGUIGetData
{
public:
    property String^ Action;          // "get"
    property String^ Window;
    property DebugGUIRange^ Selection;
};

public ref class DebugGUIGetResult : McpResult
{
public:
    property DebugGUIGetData^ Data;
};

public ref class DebugGUISetData
{
public:
    property String^ Action;          // "set"
    property String^ Window;
    property DebugGUIRange^ Requested;
    property DebugGUIRange^ Actual;
    property bool Refreshed;
};

public ref class DebugGUISetResult : McpResult
{
public:
    property DebugGUISetData^ Data;
};
```

For `snapshot`, `artifact` is the delivery discriminator:

- If `save_path` is omitted, `artifact.type="image"`, `artifact.mimeType="image/png"`, and `artifact.path=null`. The Tool returns a `CallToolResult` whose first text block is the serialized `DebugGUISnapshotResult` envelope and whose second block is one `ImageContentBlock` containing the PNG. The PNG is not duplicated as base64 inside the JSON metadata.
- If `save_path` is supplied, `artifact.type="file"`, `artifact.mimeType="image/png"`, and `artifact.path` is the normalized path. The exact PNG bytes used for the reported hash are written to that path; the result contains only the serialized typed envelope and no inline image block.

`save_path` must be an absolute `.png` filename on the machine running x64dbg. The parent directory must already exist, and an existing target is rejected rather than overwritten. Success requires a complete write; file creation/write failure returns `io_failed`, and the implementation removes any partial file when possible. The Tool never silently switches delivery modes. A host path is not a claim that a remote MCP client can open that path.

The capture boundary is the complete x64dbg main window returned by `GuiGetWindowHandle`, not the desktop and not only one CPU pane. `width`, `height`, title, UTC timestamp, debuggee PID, and SHA-256 describe the same PNG bytes delivered inline or saved. SHA-256 establishes byte identity only; it is not authenticated provenance or a trusted timestamp.

#### Focus and selection sequencing

`focus` activates the CPU page, focuses the selected pane, invokes `Script::Gui::Refresh()`, and processes pending GUI events before returning `refreshed=true`.

`get` reads the selected pane through `Script::Gui::SelectionGet` on the GUI thread and does not change focus, navigation, or selection.

`set` is self-contained; callers do not need a preceding `focus`. It performs the following ordered operation on the GUI thread:

1. Resolve `start` and any supplied `end` before changing GUI state.
2. Activate the CPU page and navigate the selected pane to the resolved `start`.
3. Apply the inclusive selection and focus that pane.
4. Call `Script::Gui::Refresh()` and process pending GUI events.
5. Read back the actual selection and return it with the resolved requested range.

An omitted `end` is resolved as `end = start`; neither `-1` nor `0` is used as a sentinel. For `Disassembly`, x64dbg expands that request to the complete instruction containing `start`. For `Dump` and `Stack`, the shared `HexDump` implementation retains a one-byte selection. Supplied ranges must resolve with `end >= start` and fit the view's addressable memory page. Because the view may normalize boundaries, a caller that needs visual evidence must rely on `actual` before calling `snapshot`.

Errors: `invalid_argument` (unknown action/window, missing action-specific input, reversed range, non-absolute/non-PNG `save_path`, missing parent directory, or existing destination); `not_attached` (`focus/get/set` without a debug session); `not_found` (unresolvable expression or range outside the pane's address space); `x64dbg_failed` (window handle, capture, navigation, selection, refresh, or readback failure); `io_failed` (validated file target could not be completely created/written).

### `logging{clear, put}` 🟢

```cpp
public ref class LoggingActionData
{
public:
    property String^ Action;
};

public ref class LoggingResult : McpResult
{
public:
    property LoggingActionData^ Data;
};

[McpServerTool,
 Description("Manage the x64dbg log window.")]
LoggingResult^ Logging(
    [Description("Action: \"clear\" | \"put\"")] String^ action,
    [Description("Text to append as a line (required for action=put)")] String^ text
);
```

| Action | Params | Native API | Notes |
|---|---|---|---|
| `clear` | — | `GuiLogClear()` | Direct call; does not require a debug session. |
| `put` | `{ text: string }` | `_plugin_logputs()` | Appends `text` as one line; `text` is required. |

Errors: `invalid_argument` (unknown action or missing `text` for `put`).

---

## 6. Reserved Resources (not yet implemented)

The following five Resource names are **reserved** in the URI namespace. Their current ⚪ entries are target sketches rather than implementation-ready schemas, and none is registered by the current server. Their corresponding Tools perform precise item operations, so this cross-layer pairing follows ADR-003 rather than duplicating the bulk read.

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

### `x64dbg://functions` ⚪

Returns `List<FunctionEntry>` across all modules. Pagination via `?offset=&limit=` query params. The entry shape is defined by `functions{get,set,delete}`.

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

---

## 7. Out of Scope (deliberately not exposed)

The following PoC-era tools are intentionally **not** exposed in the v0 baseline:

- `GuiMessage` / `GuiMessageYesNo` — interactive modal UX is unsuitable for unattended MCP automation
- 1:1 `GuiSelectionGet/Set`, `GuiFocusView`, and `GuiRefresh` Tools — the supported evidence workflow composes them behind `debug_gui`; see [ADR-006](adr/006-debug-gui-evidence-capture.md)
- `Script*` (ScriptLoad, ScriptRun, ScriptAbort, ScriptCmdExec) — superseded by `debug_control{action:"run_command"}`
- `Watch*` — niche; revisit if user-driven need emerges
- Per-flag `GetFlag` / `SetFlag` / per-register `GetRegister` / `SetRegister` — covered by `registers{get,set,dump}` with name-based addressing

If a future need arises, propose an ADR before adding back.

---

## 8. Mapping to PoC

Per-PoC-tool migration table for review. PoC reference: `copilot/refine-x64dbg-handler-todos` branch.

| PoC tool | New form | Note |
|---|---|---|
| `GetProjectInfo` | resource `x64dbg://session` | Promoted to navigation root |
| `GetSymbolList`, `GetSymbolAt` | resource `x64dbg://symbols` + `symbols{get}` | Bulk list vs precise lookup |
| `GetFunctionList`, `GetFunctionAt`, `AddFunction`, `DeleteFunction` | resource `x64dbg://functions` + `functions{get, set, delete}` | Bulk list vs precise CRUD |
| `GetLabelList`, `GetLabelAt`, `SetLabel`, `DeleteLabel`, `IsLabelTemporary`, `LabelFromString` | resource `x64dbg://labels` + `labels{...}` | Bulk list vs precise CRUD; `LabelFromString` collapses into `parse_expression` |
| `GetCommentList`, `GetCommentAt`, `SetComment`, `DeleteComment` | resource `x64dbg://comments` + `comments{...}` | Bulk list vs precise CRUD |
| `GetBookmarkList`, `GetBookmarkAt`, `SetBookmark`, `DeleteBookmark` | resource `x64dbg://bookmarks` + `bookmarks{...}` | Bulk list vs precise CRUD |
| `GetXrefs`, `AddXref`, `GetXrefCountAt`, `GetXrefTypeAt` | `xrefs{...}` | |
| `GetModuleList`, `GetMainModuleInfo`, `GetModuleByAddr`, `GetModuleByName`, `GetMainModuleSectionList`, `GetSectionListByAddr`, `GetSectionListByName`, `GetExports`, `GetImports` | resources `x64dbg://modules/...` | All become URI-addressable |
| `IsValidPtr`, `GetMemoryMaps`, `GetMemoryBase`, `GetMemorySize` | resource `x64dbg://memory/maps` + tool `parse_expression` | Most queries reduce to expression resolution |
| `MemoryRead` | `memory{action:"read"}` | Preserves `addr`, `size`, and optional `compress` (lz4); standalone Tool removed |
| `GetThreadList` | resource `x64dbg://threads` | |
| `Disassemble` | tool `disassemble` | Same operation, raised `count` ceiling |
| `FindPattern` | tool `find_pattern` | Added `scope`, `maxResults` |
| `InitDebug` | `debug_control{action:"init"}` | |
| `ParseExpression`, `ResolveLabel`, `GetStringAt` | tools `parse_expression`, `get_string_at` | `ResolveLabel` collapses into `parse_expression` |
| `IsDebugging`, `IsRunning`, ..., `RunCommand` | `debug_control{...}` | |
| `GetBreakpointList`, `SetBreakpoint`, `DeleteBreakpoint`, `DisableBreakpoint`, `SetHardwareBreakpoint`, `DeleteHardwareBreakpoint` | resource `x64dbg://breakpoints` + `breakpoints{...}` | Bulk list vs precise control |
| `GetFlag`, `SetFlag`, `GetRegister`, `SetRegister`, `GetRegisterDump` | `registers{get,set,dump}` | Name-based, no enum mirror; register dump has one Tool surface only |
| `MemoryWrite`, `MemoryAlloc`, `MemoryFree` | `memory{...}` | |
| `GetCallStack` | tool `get_call_stack` | |
| `SetThreadName`, `SetActiveThread`, `SuspendThread`, `ResumeThread`, `CreateThread` | `threads{...}` | |
| `Assemble` | tool `assemble` | Added `fillNops` |
| `LogPuts` | `logging{action:"put"}` | `x64dbg://logging` supplies the read snapshot; `logging{action:"clear"}` adds the matching clear action |
| `GuiSelectionGet/Set`, `GuiFocusView`, `GuiRefresh` | `debug_gui{focus,get,set}` | Composed GUI-thread workflow; screenshot capture is a new `snapshot` action |
| `GuiMessage*`, `Script*`, `*Watch*` | (excluded) | See §7 |

Target surface: **20 Resources + 6 rich-param Tools (including gated `assemble`) + 13 action-mega Tools = 39 entries**. Only the 19 Tool definitions consume the AI tool-schema budget; with the debugger-domain catalog disabled, the default Tool catalog is 11 definitions (PoC was 50+).
