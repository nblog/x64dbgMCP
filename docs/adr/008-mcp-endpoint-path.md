# ADR-008: Use `/mcp` as the single Streamable HTTP endpoint

- **Status**: Accepted
- **Date**: 2026-08-21
- **Deciders**: @nblog

## Context

The plugin listens on a host and port, then separately maps the MCP transport to an
ASP.NET Core route prefix. The previous implementation used `MapMcp(app, "")`, so
the listener `http://localhost:3001` and the MCP endpoint `http://localhost:3001/`
were the same URL. The MCP protocol permits any single endpoint path, but its
current Streamable HTTP specification uses `/mcp` as the canonical example, and
the official Python and TypeScript SDK serving guides use `/mcp` in their client
and curl examples.

The root path is protocol-valid, but it is not self-describing and leaves no clear
namespace for future non-MCP operational endpoints. The project already has an
MCP-only transport decision in [ADR-001](001-mcp-only-no-rest-shadow-api.md); this
ADR decides the path of that one transport and does not add a REST API.

## Decision

The plugin exposes exactly one MCP Streamable HTTP endpoint at `/mcp`.

```text
Listener:       http://localhost:3001
MCP endpoint:   http://localhost:3001/mcp
```

The host must map the SDK transport with `MapMcp(app, "/mcp")`. The root path is
not an MCP alias and must not be mapped to a second MCP endpoint.

The default transport profile is explicit rather than dependent on SDK defaults:

- Streamable HTTP is enabled.
- Stateless mode is enabled.
- Legacy HTTP+SSE is disabled.
- The server remains loopback-only by default.
- Any future compatibility profile for legacy SSE must be separately documented;
  if enabled, its routes are the SDK-scoped `/mcp/sse` and `/mcp/message` paths.

Requests carrying an `Origin` header are accepted only when the origin is a
loopback HTTP(S) origin. This protects the local default against browser DNS
rebinding while preserving non-browser MCP clients, which normally omit `Origin`.
Non-loopback binding remains an explicit escape hatch and is not an authentication
boundary.

## Consequences

**Positive**

- Client configuration is self-describing and matches the dominant MCP examples.
- There is one canonical endpoint, so routing, logging, and security policy do not
  diverge between aliases.
- A future `/healthz` or similar operational endpoint can coexist without sharing
  the MCP root path.
- Explicit stateless/legacy settings make SDK upgrades less likely to change the
  product profile silently.

**Negative**

- Existing clients configured with `http://localhost:3001` must change to
  `http://localhost:3001/mcp`.
- The plugin currently does not provide a general authentication system. Clients
  that use non-loopback binding remain responsible for running behind an
  authenticated, trusted boundary.

## Alternatives Considered

1. **Keep `/`** — protocol-valid and migration-free, but less discoverable and
   less suitable as the application grows.
2. **Serve both `/` and `/mcp`** — easy migration, but violates the one-canonical-
   endpoint intent and creates duplicate routing/security/test surfaces.
3. **Use `/api/mcp` or a configurable path** — technically valid, but adds a
   project-specific convention or configuration dimension without a demonstrated
   second deployment need.

## References

- [MCP Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [MCP Python SDK README](https://github.com/modelcontextprotocol/python-sdk/blob/main/README.md)
- [MCP TypeScript SDK Express serving guide](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/serving/express.md)
- [MCP C# SDK `MapMcp` implementation](https://github.com/modelcontextprotocol/csharp-sdk/blob/v2.1.0/src/ModelContextProtocol.AspNetCore/McpEndpointRouteBuilderExtensions.cs)
- [ADR-001](001-mcp-only-no-rest-shadow-api.md)
