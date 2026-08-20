# ADR-003: Three-layer surface — Resources + rich-param Tools + action-mega Tools

- **Status**: Accepted
- **Date**: 2026-05-24
- **Amended**: 2026-08-20
- **Deciders**: @nblog

## Context

The naive translation of x64dbg pluginsdk to MCP is 1:1 — every SDK function becomes a tool. The PoC follows this shape and reaches ~50 tools.

Two costs follow from 1:1 mapping:

1. **Tool-list bloat**: Anthropic measures tool definitions consuming 20–40%+ of an agent's context window in real deployments, with one 5-server config hitting ~55k tokens of pure tool schemas ([Writing tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents); [Code execution with MCP](https://anthropic.com/engineering/code-execution-with-mcp)). 50 tools × ~150 tokens of schema each ≈ 7.5k tokens just for our surface.
2. **Round-trip amplification**: 1:1 forces narrow returns. Disassembling 30 instructions becomes 30 tool calls if `disassemble(addr)` returns one line. Each call is a request/response pair in the agent's context. The user explicitly raised this concern.

Survey of prior art (see [research notes](../references.md#4-prior-art-mcp-servers-for-reverse-engineering)):

| Project | Tools | Pattern | Notable |
|---|---|---|---|
| LaurieWired/GhidraMCP | 27 | Fine-grained 1:1 | Pagination via `offset/limit` |
| MxIris/ida-mcp-server | 19 | 1:1 + paired `*_MULTI_*` batch variants | Batch as escape hatch |
| GhydraMCP | 51 | Compound family + **HATEOAS `_links`** | Hypertext-driven navigation |
| MCPPhalanx/binaryninja-mcp | ~10 tools + ~8 resources | **Resource + Tool hybrid** | Static data as URI resources |
| DNLINYJ/better-x64dbg-mcp | 21 mega-tools (~148 ops) | **Action-enum dispatch** | Closest to our domain |
| bethington/ghidra-mcp | 245 | Anti-pattern | Catalog bloat dominates context |

The MCP specification distinguishes Resources (read-only, URI-addressable, **application-driven** access) from Tools (model-driven actions). Most prior art treats this as a stylistic choice; we treat it as a design lever.

## Decision

**The MCP surface is split into three forms based on access pattern**, not by mechanical SDK mapping.

### Layer A — Resources (`[McpServerResource]`)

For **read-only data that is most useful as a bulk snapshot or collection** and that an agent typically scans before selecting an individual target:

- Modules list, per-module sections/exports/imports
- Memory map
- Threads list
- Symbols, functions, labels, comments, bookmarks, and breakpoints lists
- Project/session/debuggee info and attach-process candidates
- x64dbg Log view snapshot

Resources are not required to be immutable or permanently cacheable: their contents may change between reads as the debug session changes. The invariant is that reading a Resource does not alter debugger-domain state. Benefits: URI-addressable, compact for bulk retrieval, absent from the AI tool-definition budget, and naturally navigable via `_links`.

`x64dbg://logging` has one documented transient host-filesystem exception: x64dbg exposes the rendered Log view through `GuiLogSave(filename)`, so each read materializes a unique temporary file, reads it as UTF-8, and immediately deletes it after the successful read. The save notification is suppressed and the Log view itself remains unchanged.

### Layer B — Rich-param Tools (`[McpServerTool]`)

For **single-purpose focused operations** over one target or a bounded hot-path window:

- `disassemble(addr, count, withBytes?)` — `count` ≤ 200
- `find_pattern(pattern, scope?, maxResults?)` — `maxResults` ≤ 256
- `parse_expression(expr)`, `get_string_at(addr)`, `get_call_stack(threadId?)`
- Debugger-domain focused operation `assemble(addr, instruction, fillNops?)`, registered only behind the debugger catalog gate

Benefits: clear contract, minimal action enum noise, AI agents discover them by name.

### Layer C — Action-mega Tools (`[McpServerTool]` with `action` enum)

For **fine-grained per-item CRUD families** and **debug control clusters** that share parameter shapes:

- `labels{get, set, delete, set_batch, delete_batch}`; bulk reads use `x64dbg://labels`
- `comments{...}`, `bookmarks{...}`, `functions{...}`, `xrefs{...}`
- `debug_control{run, pause, stop, StepInto, StepOver, StepOut, init, attach, run_command}`
- `breakpoints{get, set, delete, disable, set_hardware, set_batch, delete_batch}`; bulk reads use `x64dbg://breakpoints`
- `registers{get, set, dump}`, `memory{read, write, alloc, free}`, `threads{get, set_name, set_active, suspend, resume, create_at}`, `logging{clear, put}`

Benefits: tool count compression, symmetric ops live next to each other, batch variants come for free in the same dispatch.

For breakpoints, `get`, `disable`, and `delete` are type-neutral public actions over the
normal/hardware breakpoint families. They accept an optional `kind` discriminator only for the
valid x64dbg state where both types coexist at the same address: omitting `kind` auto-selects the
sole match, while two matches fail before mutation and require `kind="normal"` or
`kind="hardware"`. `set` and `set_hardware` remain separate because hardware creation has distinct
trigger-type, size, alignment, and debug-register-slot constraints. This 2026-08-17 refinement
supersedes the earlier reserved `delete_hardware` action rather than exposing two deletion names
for one conceptual operation.

`debug_control{action:"attach"}` remains in the existing control cluster rather than becoming a
separate Tool. Its `detach2attach=false` default rejects an active debug session before side
effects. An explicit `true` detaches the current debuggee and leaves it running before attaching
the requested PID. The option is scoped to one invocation: the implementation temporarily
overrides x64dbg's global `Engine/DetachOnAttach` setting only while synchronously dispatching the
attach command, then restores the previous setting.

### Estimated surface

The current target catalog is 20 Resources + 6 rich-param Tools (including the gated `assemble`) + 12 action-mega Tools, for 18 Tools in total. Only Tool definitions consume the AI tool-schema budget. With debugger-domain Tools gated off, an agent loads 11 Tool definitions instead of the full 18 (PoC: 50+).

`memory{action:"read"}` preserves the earlier `memory_read(addr, size, compress?)` parameter and result design. The standalone Tool was implemented before the symmetric memory family was consolidated; the 2026-08-14 amendment supersedes that original Layer B classification so read/write/alloc/free share one MCP-visible family without duplicating the read operation.

`registers{action:"dump"}` is the sole register-dump Tool surface. A separate `get_register_dump` rich-param Tool would be an equivalent duplicate and is therefore excluded from the target catalog.

### Debugger-domain catalog gate

`McpAnalysisTools` is always registered and may contain both precise reads and updates to analysis metadata such as labels, comments, bookmarks, functions, and xrefs. `McpDebuggingTools` is registered only when `enableDebugging=true` and contains the large debugger-operation catalog: execution control, breakpoints, registers, memory operations, thread control, assembly, and logging.

This classification is by **debugger domain and schema cost**, not by whether an operation writes state. `enableDebugging` is therefore a tool-catalog gate, not an authorization or read-only safety boundary.

## Consequences

**Positive**

- Tool-list size roughly halved vs PoC
- Disassembly / memory read / pattern search return bounded windows in one call
- Bulk collections become free to browse via Resources rather than tool calls
- Action mega-tools naturally accommodate batch operations (key for AI agents iterating over many addresses)

**Negative**

- Mega-tool schemas are bigger; per-action documentation must live in the JSON Schema's `description` strings, not as separate tool entries. Mitigation: each mega-tool's schema enumerates valid actions and per-action required params explicitly ([conventions.md §1](../conventions.md#1-naming) for naming; [tools-spec.md](../tools-spec.md) for full schemas).
- Resources require a working understanding of MCP's resource model in the C# SDK — but the SDK supports it cleanly via `[McpServerResource(UriTemplate=...)]` ([sample code](https://github.com/modelcontextprotocol/csharp-sdk/blob/main/samples/EverythingServer/Resources/SimpleResourceType.cs)).
- Result types per action vary; tool method signatures will return `Object^` and use polymorphic typed result classes underneath. See [ADR-004](004-typed-result-with-envelope.md).

**Constraints on future work**

- New functionality must be triaged into one of the three layers before implementation. The triage criteria (in order):
  1. Is it a read-only bulk snapshot or collection scan? → **Resource**
  2. Is it a focused query/action over one target or bounded window, with no symmetric siblings? → **rich-param Tool**
  3. Is it fine-grained per-item CRUD or part of a control cluster? → **action-mega Tool**
- A concept may span Resource and Tool layers when the Resource supplies a bulk read view and the Tool supplies precise item reads or changes. The exact same operation must not be duplicated across layers.
- `enableDebugging` membership follows debugger-domain ownership and schema-budget impact, not a generic mutation test.
- Adding a tool that doesn't fit any layer requires an ADR.

## Alternatives Considered

1. **Pure 1:1 (PoC shape)** — rejected. Density and tool-list bloat are the original problem.
2. **Pure mega-tool (better-x64dbg-mcp shape, 21 tools / 148 ops)** — rejected as too aggressive. Single-purpose hot queries such as `disassemble` lose discoverability when buried under an `action` enum, and big schemas make every read of the tool list expensive. The bounded memory read is deliberately grouped because it now has symmetric write/alloc/free siblings; this does not generalize to unrelated hot-path queries.
3. **HATEOAS-only with one query tool (GraphQL-ish)** — rejected. Maximum client autonomy but maximum schema cost; the AI must learn the entire query language to do anything. Better suited to client SDK code than to chat-driven agents.
4. **Pure Resources + a single `execute` tool** — rejected. Hides precise operations behind one oversized schema and discards the discoverability of focused tools.
5. **One layer per concept** — superseded by the 2026-08-08 amendment. It prevented the useful combination of a compact bulk-read Resource with precise per-item Tools.

## References

- [Anthropic — Writing tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents)
- [Anthropic — Code execution with MCP](https://anthropic.com/engineering/code-execution-with-mcp)
- [MCP — Tools vs Resources vs Prompts](https://rapidevelopers.com/mcp-tutorial/mcp-tools-vs-resources-vs-prompts)
- [MCP C# SDK — Resource sample](https://github.com/modelcontextprotocol/csharp-sdk/blob/main/samples/EverythingServer/Resources/SimpleResourceType.cs)
- Prior art (full survey in [references.md](../references.md))
- Related: [ADR-004](004-typed-result-with-envelope.md), [ADR-005](005-hateoas-links-on-navigation-roots.md), [tools-spec.md](../tools-spec.md)
