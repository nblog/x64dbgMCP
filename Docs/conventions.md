# Conventions

This document encodes the **non-negotiable rules** for shaping MCP tools, resources, parameters, returns, and errors in x64dbgMCP. These rules exist to keep the surface coherent across many tools and to keep AI agents productive (predictable shapes, low cognitive load).

> When in doubt: rule of thumb is *if a future agent reading only the JSON Schema would be confused, the rule is wrong* — open an issue or new ADR rather than ad-hoc deviating.

---

## 1. Naming

| Element | Rule | Example |
|---|---|---|
| Tool method (managed) | `PascalCase`, verb-first | `Disassemble`, `GetMemoryMap`, `FindPattern` |
| Tool `Name` (MCP-visible) | Defaults to method name; override only if the method name conflicts or hurts discoverability | — |
| Action-mega tool | Plural noun for the family; the `action` parameter is `snake_case` | `Breakpoints{action:"list"\|"set"\|"delete"\|"set_batch"}` |
| Resource URI scheme | `x64dbg://` (single scheme for the whole project) | — |
| Resource URI template | `lowercase`, hyphenated, hierarchical, plural collections | `x64dbg://modules`, `x64dbg://modules/{name}/sections` |
| Helper class | `Helpers`, `internal` access only | — |
| Result class | `<Domain><Verb>Result` or `<Domain>Info` | `DisassembleResult`, `ModuleInfo`, `BreakpointEntry` |

Action names: prefer `list`, `get`, `set`, `delete`, `set_batch`, `delete_batch`. For control clusters use the natural verb: `init`, `stop`, `run`, `pause`, `StepInto`, `StepOver`, `StepOut`.

---

## 2. Address & Expression Inputs

**Rule**: Every parameter that names a memory location, a register, a flag, a label, an export, or an arithmetic combination of these accepts a **x64dbg expression string**, resolved via `Script::Misc::ParseExpression` (wrapped by `Helpers::ResolveExpression`). See [adr/002-resolve-via-x64dbg-expression.md](adr/002-resolve-via-x64dbg-expression.md).

Accepted forms (all valid for the same parameter):

```
0x140001000              ; hex literal
140001000                ; numeric (still hex in x64dbg semantics, but accept it)
rax                      ; register
cip                      ; architecture-agnostic register
zf                       ; flag
kernel32:CreateFileW     ; module:export
LoadLibraryA             ; api name (resolved against loaded modules)
mem.base(cip)            ; expression
peb()                    ; built-in function
rax + 0x10               ; arithmetic
```

Parameter type: always `String^` for address-like inputs. Never `duint` / `int` at the MCP boundary — that would force the client to format upfront and lose expression power.

Parameter description: `[Description("Address or x64dbg expression (e.g. \"rax\", \"kernel32:CreateFileW\", \"cip+0x10\")")]`.

---

## 3. Address Outputs

**Rule**: Addresses in returned data are formatted as `0x` + uppercase hex, no padding, no width assumption.

```cpp
Helpers::FormatAddress(duint addr)  // → "0x140001000"
```

Do **not** return raw `UInt64` / `duint` for address fields. The string form survives JSON roundtrips, prints correctly in MCP client UIs, and is unambiguous between 32/64-bit targets.

---

## 4. Result Envelope

All tool returns are wrapped in a typed result class derived from `McpResult` (defined in [tools-spec.md](tools-spec.md#返回-envelope)):

```
McpResult
├── Success     : bool
├── Error       : ErrorInfo?     // null when Success
├── Data        : <typed payload>
└── Links?      : Dictionary<String, LinkRef>?  // see §6, only on navigation roots
```

Concrete result classes inherit `McpResult` and add a typed `Data` property:

```cpp
public ref class DisassembleResult : McpResult
{
public:
    property List<DisassembleEntry^>^ Data;
};
```

Tools return the envelope object directly; the MCP framework serialises it to JSON via `System.Text.Json`. See [adr/004-typed-result-with-envelope.md](adr/004-typed-result-with-envelope.md).

Resources are different: they return raw text or `ResourceContents` per MCP spec; the envelope rule does not apply to them.

---

## 5. Error Semantics

| Error class | Where | How |
|---|---|---|
| **Caller error** (bad arg, unknown name, out-of-range) | Inside the tool method, before any side effect | Construct envelope with `Success=false`, `Error.Code="invalid_argument"`, descriptive `Error.Message`. Return the envelope; do **not** `throw`. |
| **Operational error** (debugger not attached, target not paused, x64dbg API returned false) | After validation, during execution | Same envelope shape with appropriate `Error.Code` (see table below). |
| **Programmer error** (null deref, unexpected state) | Anywhere | Let it propagate; the MCP framework converts unhandled exceptions to JSON-RPC `internal_error`. Do not swallow. |

`Error.Code` taxonomy (closed set):

- `invalid_argument` — caller-provided value rejected
- `not_found` — referenced address/name/symbol does not exist
- `not_attached` — no active debug session when one is required
- `not_paused` — target is running and the operation requires pause
- `unsupported` — operation not supported on current arch / build
- `x64dbg_failed` — underlying SDK call returned failure with no further info
- `internal` — fallback for genuinely unexpected conditions (prefer `throw` instead)

> Rationale for envelope-over-throw on caller/operational errors: see [adr/004-typed-result-with-envelope.md](adr/004-typed-result-with-envelope.md). Unhandled exceptions remain reserved for true bugs.

---

## 6. HATEOAS `_links` (Navigation Roots Only)

`_links` is a structured map of "where to go next" hints. It appears **only on navigation-root responses** — top-level entry points an agent uses to orient itself. Detail/leaf items do not carry `_links` (it would dwarf the payload).

Navigation roots (carry `_links`):

- `GetProjectInfo` / `x64dbg://session`
- `x64dbg://modules` / `GetMainModuleInfo`
- `x64dbg://memory/maps`
- Top-level `Breakpoints{action:"list"}`, `Threads{action:"list"}`

Leaves (no `_links`):

- Each `DisassembleEntry`, `MemoryReadResult`, `BreakpointEntry`, `ModuleSection`, etc.

Link shape:

```jsonc
{
  "_links": {
    "self":     { "uri": "x64dbg://modules/target.exe" },
    "sections": { "uri": "x64dbg://modules/target.exe/sections" },
    "imports":  { "uri": "x64dbg://modules/target.exe/imports" },
    "entry_disasm": {
      "tool": "Disassemble",
      "args": { "addr": "0x140001000", "count": 30 }
    }
  }
}
```

A `LinkRef` is one of: `{ uri: "x64dbg://..." }` (resource navigation) or `{ tool: "<ToolName>", args: { ... } }` (tool invocation hint). Never both.

See [adr/005-hateoas-links-on-navigation-roots.md](adr/005-hateoas-links-on-navigation-roots.md).

---

## 7. Pagination & Bulk Parameters

List-shaped operations (`list` action of mega-tools, `x64dbg://modules`, `Breakpoints{action:"list"}`) accept:

- `offset : int = 0` — index of first item
- `limit : int = 100` — max items to return; clamped server-side to a per-tool ceiling

The response includes:

```jsonc
{
  "data": [ ... ],
  "page": { "offset": 0, "limit": 100, "total": 247, "hasMore": true },
  "_links": { "next": { ... }, "prev": { ... } }
}
```

Hot-path single-target tools (`Disassemble`, `MemoryRead`, `FindPattern`) use bulk parameters instead of pagination:

- `Disassemble(addr, count)` — `count` ≤ 200 (per-call ceiling)
- `MemoryRead(addr, size)` — `size` ≤ 64 KiB
- `FindPattern(pattern, maxResults)` — `maxResults` ≤ 256

These ceilings exist to bound a single MCP response; clients that need more issue follow-up calls.

---

## 8. `[Description]` on Parameters

Every tool parameter must have `[Description("...")]`. Conventions:

- Lead with what the value **is**, not what it **does**
- Include 1–3 concrete examples for non-obvious formats
- Mention units / ranges / closed sets

```cpp
[Description("Address or x64dbg expression (e.g. \"rax\", \"kernel32:CreateFileW\")")]
String^ addr,

[Description("Number of instructions to disassemble (1–200)")]
int count,

[Description("Hardware breakpoint type: \"access\" | \"write\" | \"execute\"")]
String^ type
```

Closed-set parameters: enumerate values inside the description. The MCP tool schema does not currently enforce string enums, so the description is the contract.

---

## 9. Threading

Tools execute on ASP.NET Core thread-pool threads. Most `Script::*` APIs are safe from any thread; specific exceptions:

- `Script::Gui::*` — must be marshalled to the GUI thread. Use `GuiExecuteOnGuiThread` or queue via `DbgCmdExec` if a x64dbg command equivalent exists.
- `DbgCmdExec` — fire-and-forget; use `DbgCmdExecDirect` if you need to wait for completion.
- Do **not** call `Script::Debug::Run` / `StepInto` / etc. from a tool that itself blocks waiting for a pause — that deadlocks the request thread. Either return immediately or expose the wait as a separate poll-based tool.

When marshalling is required, document it on the tool method with a one-line comment, e.g. `// Requires GUI thread; marshalled via GuiExecuteOnGuiThread`.

---

## 10. Comments in Code

Default: write **no** comments. Names already describe behaviour.

Add a comment only when:

- The code is genuinely surprising (a workaround for a SDK quirk, an x64dbg-specific gotcha)
- A non-obvious invariant must hold (e.g. "must run before debugger attach")
- The convention itself diverges from the surrounding code intentionally — link the ADR

Never add comments that:

- Restate the method name in English
- Document the current task ("Added for the Disassemble feature")
- Reference issue numbers or PR descriptions (those rot)

---

## 11. Cross-Reference Discipline

Within Docs and ADRs:

- Reference another file by relative link (`[conventions.md](conventions.md)`)
- Reference a code symbol by `file:line` markdown (`[x64dbgMCP.h:79](../x64dbgMCP/x64dbgMCP.h#L79)`)
- Reference an x64dbg SDK symbol by namespace-qualified name (`Script::Misc::ParseExpression`) — no need to link unless the call site is unusual

When introducing a new convention here, also update the *Reading paths* table in [README.md](README.md) so AI agents know where to look.
