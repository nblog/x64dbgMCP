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
                            │ HTTP (loopback by default)
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
| Activate | User issues `mcp.start [port=3001],[host=localhost],[enableDebugging]` in x64dbg command line | A background `Task` constructs and starts `WebApplication`, then waits until `StopAsync`. The command reports success only after Kestrel has bound the configured URL. |
| Serve | MCP client connects via Streamable HTTP (`POST /`) or Legacy SSE (`GET /sse` + `POST /message`) | Tool/resource methods are dispatched on ASP.NET Core thread-pool threads. Each method calls into x64dbg pluginsdk synchronously. |
| Deactivate | x64dbg shuts down, plugin unloads, or explicit stop command | `McpServerHost::Stop` calls `app.StopAsync` and waits up to 5 s for the background task. A timeout leaves the host marked active until the background task actually exits, preventing an overlapping restart. |

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
| **Resource** (`[McpServerResource]`) | Read-only bulk snapshots and collection navigation | `x64dbg://logging`, `x64dbg://modules`, `x64dbg://modules/{name}/sections`, `x64dbg://memory/maps`, `x64dbg://windows`, `x64dbg://handles`, `x64dbg://tcpconnections` |
| **Rich-param Tool** (`[McpServerTool]`) | Focused queries over one target or a bounded hot-path window | `Disassemble(addr, count)`, `MemoryRead(addr, size)`, `FindPattern(pattern, maxResults)` |
| **Action-mega Tool** (`[McpServerTool]` with `action` enum) | Fine-grained per-item reads/updates and debugger control clusters | `Labels{get/set/delete + batch}`, `DebugControl{init/run/pause/Step*}`, `Breakpoints{get/set/delete + batch}` |

A Resource and Tool may cover the same domain when their access patterns differ: the Resource is the compact bulk-read surface, while the Tool addresses or changes individual items. They must not duplicate the same operation with equivalent inputs and outputs.

`x64dbg://logging` is backed by `GuiLogSave`, the upstream API for snapshotting the rendered Log view. Because that API accepts only a filename, each read marshals the save to the GUI thread, materializes a unique host temporary file, reads it as UTF-8, and immediately deletes it after the successful read. x64dbg stops the LogView flush timer while the Log tab is hidden, so messages still in its private pending buffer are not part of the rendered document until upstream displays the tab and flushes them.

The `enableDebugging` flag on `McpServerHost::Start` controls whether the debugger-domain `McpDebuggingTools` catalog is registered. Its purpose is to keep execution control, breakpoints, registers, memory mutation, thread control, assembly, and logging from inflating every agent's tool schema. It is **not** a general read/write or authorization boundary: analysis-domain tools may update x64dbg analysis metadata while remaining in the always-registered `McpAnalysisTools` catalog.

---

## 6. Build / Output

- Project: `x64dbgMCP/x64dbgMCP.vcxproj`, `CLRSupport=NetCore`, `TargetFramework=net10.0`, `LanguageStandard=stdcpp17`, `PlatformToolset=v145`
- Output: `out/bin/<platform>-<config>/x64dbgMCP.dp{32,64}` (extension switches by platform via `TargetExt`)
- Dependencies pulled by NuGet (PackageReference): `ModelContextProtocol`, `ModelContextProtocol.AspNetCore` (1.1.0); FrameworkReference: `Microsoft.AspNetCore.App`
- x64dbg pluginsdk is vendored under `x64dbgMCP/plugintemplate/pluginsdk/` and linked via `AdditionalLibraryDirectories=$(ProjectDir)plugintemplate`

The build produces a self-contained mixed-mode DLL. No additional runtime files need to be copied alongside it as long as the host machine has the .NET 10 runtime available.
