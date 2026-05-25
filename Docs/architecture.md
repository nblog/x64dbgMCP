# Architecture

This document describes the runtime structure, component layering, and lifecycle of the x64dbgMCP plugin. It is the source of truth for how the pieces fit together; specific contract details live in [conventions.md](conventions.md) and [tools-spec.md](tools-spec.md).

---

## 1. Process & Loading Model

```
┌─────────────────────────────────────────────────────────────┐
│  x64dbg.exe (host process)                                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  x64dbgMCP.dp32 / .dp64  (this plugin, C++/CLI DLL)   │  │
│  │                                                       │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │ Native plugin entry (plugintemplate)            │  │  │
│  │  │  - DllMain, plugininit, pluginstart             │  │  │
│  │  │  - Registers x64dbg command "mcp.start"         │  │  │
│  │  └────────────────────┬────────────────────────────┘  │  │
│  │                       │ /clr:netcore                  │  │
│  │  ┌────────────────────▼────────────────────────────┐  │  │
│  │  │ Managed CLR side (.NET 10+)                     │  │  │
│  │  │  ┌─────────────────────────────────────────┐    │  │  │
│  │  │  │ McpServerHost (x64dbgMCP.h)             │    │  │  │
│  │  │  │  - WebApplication.CreateSlimBuilder     │    │  │  │
│  │  │  │  - AddMcpServer + WithHttpTransport     │    │  │  │
│  │  │  │  - Background Task hosting Kestrel      │    │  │  │
│  │  │  └────────────┬────────────────────────────┘    │  │  │
│  │  │               │                                 │  │  │
│  │  │  ┌────────────▼────────────────────────────┐    │  │  │
│  │  │  │ Tool / Resource surface                 │    │  │  │
│  │  │  │  [McpServerToolType]   McpAnalysisTools │    │  │  │
│  │  │  │  [McpServerToolType]   McpDebuggingTools│    │  │  │
│  │  │  │  [McpServerResourceType] McpResources    │   │  │  │
│  │  │  └────────────┬────────────────────────────┘    │  │  │
│  │  └───────────────┼─────────────────────────────────┘  │  │
│  │                  │ Script::*, Dbg*, Bridge*           │  │
│  │  ┌───────────────▼─────────────────────────────────┐  │  │
│  │  │ x64dbg pluginsdk (native)                       │  │  │
│  │  │  _scriptapi_*.h, bridgemain.h, _dbgfunctions.h  │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │ HTTP (loopback only)
                            │
                  ┌─────────┴─────────┐
                  │   MCP Client      │
                  │  (Claude Code,    │
                  │   Codex, …)       │
                  └───────────────────┘
```

The plugin is a **single in-process DLL**. The native side handles x64dbg's plugin contract; the CLR side hosts an embedded ASP.NET Core `WebApplication` running the MCP HTTP transport. There is no out-of-process server, no IPC across process boundaries.

---

## 2. Lifecycle

| Phase | Trigger | Effect |
|---|---|---|
| Load | x64dbg loads `*.dp32`/`*.dp64` at startup or via `Plugins → Load` | Native `pluginit` registers x64dbg command `mcp.start`. CLR is initialised lazily on first managed call. |
| Activate | User issues `mcp.start [port=3001],[host=localhost]` in x64dbg command line | Calls `McpServerHost::Start(port, ...)`. A background `Task` is launched which constructs `WebApplication` and runs `RunAsync` until `StopAsync`. |
| Serve | MCP client connects via Streamable HTTP (`POST /`) or Legacy SSE (`GET /sse` + `POST /message`) | Tool/resource methods are dispatched on ASP.NET Core thread-pool threads. Each method calls into x64dbg pluginsdk synchronously. |
| Deactivate | x64dbg shuts down, plugin unloads, or explicit stop command | `McpServerHost::Stop` calls `app.StopAsync` and waits up to 5 s for the background task. |

---

## 3. Component Layers

```
 Layer                          Responsibility                       Owner File(s)
─────────────────────────────────────────────────────────────────────────────────────
 1. Native plugin entry         x64dbg plugin contract,              clr-dllmain.cpp,
                                command registration                  plugintemplate/*

 2. Managed host                Construct/start/stop                 x64dbgMCP.h
                                WebApplication; transport
                                wiring; lifetime

 3. Tool & resource surface     [McpServerTool] /                    x64dbgHandler.h
                                [McpServerResource] methods;          (planned: split
                                input validation; result               into multiple
                                envelope construction                  partial files)

 4. Helpers                     Address parsing, x64dbg expression   x64dbgHandler.h
                                resolution, naming conventions,       (Helpers class)
                                result envelope factories

 5. x64dbg pluginsdk bridge     Direct calls into Script::*,         (consumed by 3 & 4)
                                Dbg*, Bridge* native APIs
```

**Layering rule**: layer N may call layer N-1 only. Tool methods must not call ASP.NET Core APIs directly; helpers must not call MCP framework types. This keeps each layer testable in isolation and makes the boundary with x64dbg SDK explicit.

---

## 4. Threading

- The MCP server runs on a single background `Task` started from `Task::Run`. ASP.NET Core then dispatches incoming requests onto thread-pool threads.
- **All x64dbg pluginsdk calls happen on those request threads, not on x64dbg's main/GUI thread.** Most `Script::*` APIs are documented as safe from any thread (they internally marshal to the debugger's threads where needed). When a specific API is not thread-safe, the tool must marshal explicitly — see [conventions.md](conventions.md#threading) for the pattern.
- Long-running operations (e.g. `FindPattern` on large modules) are not currently cancellable. If this becomes an issue, plumb `CancellationToken` from the MCP request context — see [adr/](adr/) for any future decision.

---

## 5. Tool / Resource Surface (high-level)

The MCP-visible surface is split into three forms based on access pattern. Detailed catalog and per-item schemas live in [tools-spec.md](tools-spec.md); the reasoning is in [adr/003-tool-resource-action-three-layer.md](adr/003-tool-resource-action-three-layer.md).

| Form | When | Examples |
|---|---|---|
| **Resource** (`[McpServerResource]`) | Static-while-paused metadata, exploratory navigation | `x64dbg://modules`, `x64dbg://modules/{name}/sections`, `x64dbg://memory/map` |
| **Rich-param Tool** (`[McpServerTool]`) | Hot-path queries with bulk parameters | `Disassemble(addr, count)`, `MemoryRead(addr, size)`, `FindPattern(pattern, maxResults)` |
| **Action-mega Tool** (`[McpServerTool]` with `action` enum) | Symmetric CRUD families and debug control clusters | `DebugControl{init/run/pause/Step*}`, `Breakpoints{list/get/set/delete + batch}` |

The `enableDebugging` flag on `McpServerHost::Start` controls whether `McpDebuggingTools` (state-mutating) is registered. Read-only analysis tools are always registered.

---

## 6. Build / Output

- Project: `x64dbgMCP/x64dbgMCP.vcxproj`, `CLRSupport=NetCore`, `TargetFramework=net10.0`, `LanguageStandard=stdcpp17`, `PlatformToolset=v145`
- Output: `out/bin/<platform>-<config>/x64dbgMCP.dp{32,64}` (extension switches by platform via `TargetExt`)
- Dependencies pulled by NuGet (PackageReference): `ModelContextProtocol`, `ModelContextProtocol.AspNetCore` (1.1.0); FrameworkReference: `Microsoft.AspNetCore.App`
- x64dbg pluginsdk is vendored under `x64dbgMCP/plugintemplate/pluginsdk/` and linked via `AdditionalLibraryDirectories=$(ProjectDir)plugintemplate`

The build produces a self-contained mixed-mode DLL. No additional runtime files need to be copied alongside it as long as the host machine has the .NET 10 runtime available.
