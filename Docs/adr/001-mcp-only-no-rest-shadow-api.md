# ADR-001: MCP-only transport; no REST shadow API

- **Status**: Accepted
- **Date**: 2026-05-24
- **Deciders**: @nblog

## Context

The project is built on `WebApplication.CreateSlimBuilder` ([x64dbgMCP.h:79](../../x64dbgMCP/x64dbgMCP.h#L79)) so ASP.NET Core is already in the host. A natural question is whether to additionally expose plain REST/OpenAPI endpoints next to the MCP transport — to support clients that are not MCP-aware (curl, Postman, web dashboards).

The user's deeper concern was not about *protocol* per se but about **information density per request** — too many fine-grained tools force AI clients into many round-trips. We separated those concerns: density is an API-shape problem (addressed by [ADR-003](003-tool-resource-action-three-layer.md)), not a protocol problem.

Industry signal: established MCP servers in the reverse-engineering domain (LaurieWired/GhidraMCP, MCPPhalanx/binaryninja-mcp, MxIris/ida-mcp-server, DNLINYJ/better-x64dbg-mcp) all expose **one** transport. Anthropic's own guidance frames MCP servers as the canonical AI-facing surface, and warns that schema bloat across multiple surfaces compounds context costs ([Writing tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents)).

## Decision

**MCP is the only externally exposed transport.** The plugin's HTTP server hosts:

- Streamable HTTP at `POST /` (preferred)
- Legacy SSE at `GET /sse`, `POST /message` (compatibility)

We do **not** add a parallel `/api/*` REST surface. If a future need for non-MCP-aware clients emerges, we will revisit this ADR — but the same data exposed by REST would suffer the same density problem unless redesigned at the API-shape level, so the right next step would be to first fix the shape, then optionally re-expose.

## Consequences

**Positive**

- Single source of truth for the surface; one schema set to maintain
- Lower context cost on AI clients (no duplicated definitions)
- Forces us to address density at the right layer (tool/resource design, not protocol)

**Negative**

- No drop-in for curl/Postman exploration. Mitigation: MCP Inspector ([modelcontextprotocol.io](https://modelcontextprotocol.io)) provides equivalent dev-time exploration.
- Non-MCP clients (e.g. internal dashboards) cannot consume directly. Mitigation: write a thin MCP-to-REST adapter outside this plugin if/when needed.

**Constraints on future work**

- All new functionality must be designed as MCP Tools or Resources first.
- Any proposal to add a parallel transport requires an ADR that supersedes this one.

## Alternatives Considered

1. **Dual MCP + REST** — rejected. Doubles schema maintenance, doubles testing surface, doesn't solve density (the user's actual concern), and creates two ways to call the same operation with potentially divergent behaviour over time.
2. **REST-only with an external MCP adapter** — rejected. MCP's first-class type/description metadata is the main value-add for AI agents; routing through a generic REST adapter loses the tool semantics and would force re-decoration in the adapter.
3. **gRPC or other binary transport** — rejected. No reverse-engineering MCP server in the surveyed prior art uses one; would fragment client compatibility.

## References

- [Anthropic — Writing tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents)
- [Anthropic — Code execution with MCP](https://anthropic.com/engineering/code-execution-with-mcp)
- [MCP specification](https://modelcontextprotocol.io)
- Prior art surveyed: [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP), [starsong-consulting/GhydraMCP](https://github.com/starsong-consulting/GhydraMCP), [MCPPhalanx/binaryninja-mcp](https://github.com/MCPPhalanx/binaryninja-mcp), [MxIris/ida-mcp-server](https://github.com/MxIris-Reverse-Engineering/ida-mcp-server), [DNLINYJ/better-x64dbg-mcp](https://github.com/DNLINYJ/better-x64dbg-mcp)
- Related: [ADR-003](003-tool-resource-action-three-layer.md) (where the density concern is actually addressed)
