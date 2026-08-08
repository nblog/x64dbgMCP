# ADR-003: Three-layer surface — Resources + rich-param Tools + action-mega Tools

- **Status**: Accepted
- **Date**: 2026-05-24
- **Deciders**: @nblog

## Context

The naive translation of x64dbg pluginsdk to MCP is 1:1 — every SDK function becomes a tool. The PoC follows this shape and reaches ~50 tools.

Two costs follow from 1:1 mapping:

1. **Tool-list bloat**: Anthropic measures tool definitions consuming 20–40%+ of an agent's context window in real deployments, with one 5-server config hitting ~55k tokens of pure tool schemas ([Writing tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents); [Code execution with MCP](https://anthropic.com/engineering/code-execution-with-mcp)). 50 tools × ~150 tokens of schema each ≈ 7.5k tokens just for our surface.
2. **Round-trip amplification**: 1:1 forces narrow returns. Disassembling 30 instructions becomes 30 tool calls if `Disassemble(addr)` returns one line. Each call is a request/response pair in the agent's context. The user explicitly raised this concern.

Survey of prior art (see [research notes](../references.md#prior-art-mcp-servers-for-reverse-engineering)):

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

For data that is **static while the debuggee is paused** and that an agent typically explores rather than acts on:

- Modules list, per-module sections/exports/imports
- Memory map
- Threads list
- Project/session info

Benefits: URI-addressable (cacheable by clients), does not contribute to the tool list (free in tool schema budget), supports natural hierarchical navigation via `_links`.

### Layer B — Rich-param Tools (`[McpServerTool]`)

For **single-purpose hot-path queries** with bulk parameters that minimise round-trips:

- `Disassemble(addr, count, withBytes?)` — `count` ≤ 200
- `MemoryRead(addr, size)` — `size` ≤ 64 KiB
- `FindPattern(pattern, scope?, maxResults?)` — `maxResults` ≤ 256
- `ParseExpression(expr)`, `GetStringAt(addr)`, `GetCallStack(threadId?)`, `GetRegisterDump(threadId?)`

Benefits: clear contract, minimal action enum noise, AI agents discover them by name.

### Layer C — Action-mega Tools (`[McpServerTool]` with `action` enum)

For **symmetric CRUD families** and **debug control clusters** that share parameter shapes:

- `Labels{list, get, set, delete, set_batch, delete_batch}`
- `Comments{...}`, `Bookmarks{...}`, `Functions{...}`, `Xrefs{...}`
- `DebugControl{run, pause, stop, restart, step_into, step_over, step_out, init, run_command}`
- `Breakpoints{list, get, set, delete, disable, set_hardware, delete_hardware, set_batch, delete_batch}`
- `Registers{get, set, dump}`, `Memory{write, alloc, free}`, `Threads{...}`

Benefits: tool count compression, symmetric ops live next to each other, batch variants come for free in the same dispatch.

### Estimated surface

~10 resources + ~7 rich-param tools + ~9 mega-tools ≈ **26 entries** (PoC: 50+). Each mega-tool's schema is larger than a single-purpose tool's, but the net token cost is lower because we collapsed many siblings.

## Consequences

**Positive**

- Tool-list size roughly halved vs PoC
- Disassembly / memory read / pattern search return bulk in one call
- Modules and memory map become free to browse via Resources, not tools
- Action mega-tools naturally accommodate batch operations (key for AI agents iterating over many addresses)

**Negative**

- Mega-tool schemas are bigger; per-action documentation must live in the JSON Schema's `description` strings, not as separate tool entries. Mitigation: each mega-tool's schema enumerates valid actions and per-action required params explicitly ([conventions.md §1](../conventions.md#1-naming) for naming; [tools-spec.md](../tools-spec.md) for full schemas).
- Resources require a working understanding of MCP's resource model in the C# SDK — but the SDK supports it cleanly via `[McpServerResource(UriTemplate=...)]` ([sample code](https://github.com/modelcontextprotocol/csharp-sdk/blob/main/samples/EverythingServer/Resources/SimpleResourceType.cs)).
- Result types per action vary; tool method signatures will return `Object^` and use polymorphic typed result classes underneath. See [ADR-004](004-typed-result-with-envelope.md).

**Constraints on future work**

- New functionality must be triaged into one of the three layers before implementation. The triage criteria (in order):
  1. Is it static while paused and naturally hierarchical? → **Resource**
  2. Is it a single-purpose query / action with no symmetric siblings? → **rich-param Tool**
  3. Is it part of a CRUD family or a control cluster? → **action-mega Tool**
- We do **not** mix layers within one concept. E.g. `Breakpoints` is exclusively a mega-tool; we do not also expose `x64dbg://breakpoints` (state-mutating, frequent change → a poor resource fit).
- Adding a tool that doesn't fit any layer requires an ADR.

## Alternatives Considered

1. **Pure 1:1 (PoC shape)** — rejected. Density and tool-list bloat are the original problem.
2. **Pure mega-tool (better-x64dbg-mcp shape, 21 tools / 148 ops)** — rejected as too aggressive. Single-purpose hot queries (`Disassemble`, `MemoryRead`) lose discoverability when buried under an `action` enum, and big schemas make every read of the tool list expensive.
3. **HATEOAS-only with one query tool (GraphQL-ish)** — rejected. Maximum client autonomy but maximum schema cost; the AI must learn the entire query language to do anything. Better suited to client SDK code than to chat-driven agents.
4. **Pure Resources + a single `execute` tool** — rejected. Conflates state-mutating with read-only; loses MCP's built-in safety semantics (`ReadOnly = true`).

## References

- [Anthropic — Writing tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents)
- [Anthropic — Code execution with MCP](https://anthropic.com/engineering/code-execution-with-mcp)
- [MCP — Tools vs Resources vs Prompts](https://rapidevelopers.com/mcp-tutorial/mcp-tools-vs-resources-vs-prompts)
- [MCP C# SDK — Resource sample](https://github.com/modelcontextprotocol/csharp-sdk/blob/main/samples/EverythingServer/Resources/SimpleResourceType.cs)
- Prior art (full survey in [references.md](../references.md))
- Related: [ADR-004](004-typed-result-with-envelope.md), [ADR-005](005-hateoas-links-on-navigation-roots.md), [tools-spec.md](../tools-spec.md)
