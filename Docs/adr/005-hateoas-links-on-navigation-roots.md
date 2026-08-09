# ADR-005: HATEOAS `_links` on navigation roots only, not on every leaf

- **Status**: Accepted
- **Date**: 2026-05-24
- **Deciders**: @nblog

## Context

A core idea borrowed from [GhydraMCP](https://github.com/starsong-consulting/GhydraMCP) is **hypertext-driven navigation**: each response carries `_links` pointing at related resources/tools, so the client/agent follows links rather than memorising the API. This boosts client autonomy — exactly what the user identified as missing in 1:1 wrappers ("Client 缺少了很多自主性").

GhydraMCP applies this universally: every list response carries `_links.next/prev/self`, every entity carries pointers to related entities. This is consistent but expensive — every leaf entry in a list pays a `_links` overhead, and pagination links accompany every page response.

For our domain, leaves are typically high-cardinality:

- Disassembly results: 30–200 instructions per call, each with `Address`, `Mnemonic`, `Operands`, `Bytes`, `Size`, `Comment`
- Memory map: hundreds of regions
- Symbols: thousands per module

Putting `_links` on every disassembly entry would inflate response size by ~30% with information the agent rarely uses (when does an agent want a link from one disassembly line to another tool call? almost never).

## Decision

**`_links` appears only on navigation-root responses**, not on leaves. A "navigation root" is a top-level entry point an agent uses to orient itself across the surface.

### Carry `_links`

- `x64dbg://session` (and `GetProjectInfo` if exposed as tool) — points to process/modules/memory/threads/system snapshots/logging
- `x64dbg://modules` (top-level) and `x64dbg://modules/{name}` (per-module entry) — point to sections/exports/imports, and to `Disassemble` for the entry point; list items carry only `_links.self`
- `x64dbg://memory/maps` (top-level) — points to per-region details if expanded
- `x64dbg://windows` (top-level) — snapshot of debuggee windows
- `x64dbg://handles` (top-level) — snapshot of debuggee handles
- `x64dbg://tcpconnections` (top-level) — snapshot of debuggee TCP connections
- `x64dbg://breakpoints`, `x64dbg://threads` — top-level bulk list Resources
- Pagination wrappers (`Page` field is present) — the envelope-level `_links.next/prev/self` for paginated tools

### Do **not** carry `_links`

- `x64dbg://logging` — the complete plain-text Log view is a leaf
- Per-instruction entries in `DisassembleResult.Data`
- Per-region entries in memory map results
- Per-symbol/export/import entries in module child resources
- Per-frame entries in call stack
- Any item that's a "leaf" — the agent reaches it through a parent that already linked them

### `LinkRef` shape

```jsonc
{
  "_links": {
    "self":     { "uri": "x64dbg://modules/target.exe" },
    "sections": { "uri": "x64dbg://modules/target.exe/sections" },
    "entry_disasm": {
      "tool": "Disassemble",
      "args": { "addr": "0x140001000", "count": 30 }
    }
  }
}
```

A `LinkRef` is **either** `{uri}` (resource navigation) or `{tool, args}` (tool invocation hint), never both. The `args` field is a suggestion — the agent may modify it.

## Consequences

**Positive**

- Top-level returns advertise the surface; agents can self-discover without reading our schema bible
- Leaves stay compact; bulk responses (disassembly, memory map) don't pay link overhead
- Tool-invocation links unify resources and tools under one navigation idiom — agents follow `{uri}` for resource fetches and `{tool, args}` for actions, with no protocol switch

**Negative**

- Inconsistency: a `ModuleInfo` from `x64dbg://modules/{name}` carries `_links`, but the same `ModuleInfo` embedded as a `BreakpointEntry.Module` field does not. Mitigation: `_links` is part of the **response envelope** semantically, not part of the entity. When `ModuleInfo` is embedded, only its data fields appear; the parent's `_links` covers navigation.
- Agents calibrated to GhydraMCP-style universal `_links` may not look for navigation hints on leaf items. Acceptable: our leaves are domain-uniform (disassembly entries, memory regions) and don't need per-item navigation in practice.

**Constraints on future work**

- Adding `_links` to a new leaf type requires evidence (e.g. analytics showing agents repeatedly fetching the same parent to navigate from a leaf) and an ADR.
- The closed set of navigation-root types is enumerated above. Adding a new root requires updating this ADR or superseding it.
- Tool-invocation hints (`{tool, args}` in `_links`) must reference tools that exist in [tools-spec.md](../tools-spec.md). Stale links (pointing at removed tools) fail loudly via schema validation in tests.

## Alternatives Considered

1. **Universal `_links` (GhydraMCP shape)** — rejected. Per-leaf overhead too high for our high-cardinality leaves; agents rarely benefit from leaf-to-leaf links in this domain.
2. **No `_links` at all (PoC shape)** — rejected. Loses self-describing navigation; forces the agent to memorise the surface from schema reads.
3. **`_links` only on resources, not on tools** — rejected. Tool returns like `GetMainModuleInfo` (if it remains a tool) and mega-tool list returns benefit equally from navigation hints; the resource/tool distinction shouldn't gate this.
4. **Use Link header equivalents (HTTP-style)** — rejected. Out of band from the JSON-RPC payload; MCP clients don't surface HTTP headers to agents.

## References

- [GhydraMCP](https://github.com/starsong-consulting/GhydraMCP) and its [HTTP API doc](https://github.com/starsong-consulting/GhydraMCP/blob/main/GHIDRA_HTTP_API.md) for the universal-`_links` reference design
- [HAL — Hypertext Application Language](https://stateless.group/hal_specification.html) for the broader HATEOAS pattern in REST
- Related: [ADR-003](003-tool-resource-action-three-layer.md) (the surface that defines what counts as a navigation root), [conventions.md §6](../conventions.md#6-hateoas-_links-navigation-roots-only)
