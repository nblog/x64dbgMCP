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
│  │  │  - Registers x64dbg commands: mcp.start          │  │  │
│  │  │    and mcp.stop                                  │  │  │
│  │  └────────────────────┬────────────────────────────┘  │  │
│  │                       │ /clr:netcore                  │  │
│  │  ┌────────────────────▼────────────────────────────┐  │  │
│  │  │ Managed CLR side (.NET 10)                      │  │  │
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

The plugin executes as a **single in-process mixed-mode DLL**. The native side handles x64dbg's plugin contract; the CLR side hosts an embedded ASP.NET Core `WebApplication` running the MCP HTTP transport. There is no out-of-process server and no IPC across process boundaries. This describes the runtime process boundary, not the deployment file set: the mixed-mode DLL still loads the managed assemblies and runtime metadata copied beside it from the build output.

Kestrel's listener URL and the MCP route are separate contracts. The default listener is `http://localhost:3001`, while [ADR-008](adr/008-mcp-endpoint-path.md) fixes the one MCP endpoint at `http://localhost:3001/mcp`; the root path is not an MCP alias. The default listener is loopback-only. A non-loopback `host` is an explicit deployment escape hatch, not authentication.

---

## 2. Lifecycle

| Phase | Trigger | Effect |
|---|---|---|
| Load | x64dbg loads `*.dp32`/`*.dp64` at startup or via `Plugins → Load` | Native `pluginit` registers x64dbg commands `mcp.start` and `mcp.stop`. CLR is initialised lazily on first managed call. |
| Activate | User issues `mcp.start [port=3001],[host=localhost],[enableDebugging]` in x64dbg command line | A background `Task` constructs and starts `WebApplication`, then waits until `StopAsync`. The command reports success only after Kestrel has bound the configured URL. |
| Serve | MCP client connects to the single Streamable HTTP endpoint `POST /mcp`; stateless mode is explicit and Legacy SSE is disabled | Requests carrying an `Origin` header are limited to loopback HTTP(S) origins before Tool/resource dispatch. Methods then run on ASP.NET Core thread-pool threads and call the x64dbg pluginsdk. Calls that intentionally use x64dbg fire-and-forget semantics (for example `debug_control{action:"run"}`) return without waiting for the next debugger stop. |
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
                                [McpServerResource] methods;
                                input validation; result
                                envelope construction

 4. Helpers                     Address parsing, x64dbg expression   x64dbgHandler.h
                                resolution, naming conventions,       (Helpers class)
                                result envelope factories

 5. x64dbg pluginsdk bridge     Direct calls into Script::*,         (consumed by 3 & 4)
                                Dbg*, Bridge* native APIs
```

**Layering rule**: dependency flow follows the table from the entry/host surface toward helpers and the x64dbg SDK. Tool and Resource methods may call `Helpers` and the native SDK bridge; `Helpers` may call the native SDK but must not depend on MCP framework types; neither surface nor helper code calls ASP.NET Core APIs directly. The host owns transport and registration only. This matches the current direct SDK calls in `x64dbgHandler.h` while keeping transport concerns out of debugger-domain code.

---

## 4. Threading

- The MCP server runs on a single background `Task` started from `Task::Run`. ASP.NET Core then dispatches incoming requests onto thread-pool threads.
- **Most x64dbg pluginsdk calls happen on those request threads.** `Script::*` APIs are generally documented as safe from any thread (they internally marshal to debugger threads where needed), while GUI-only calls are explicit exceptions: `x64dbg://logging` marshals `GuiLogSave` to the x64dbg GUI thread, and `debug_gui` executes each composed navigation/selection/refresh/readback or capture sequence on that thread. When a specific API is not thread-safe, the tool must marshal explicitly — see [conventions.md](conventions.md#9-threading) for the pattern.
- Current Tool methods do not accept `CancellationToken`. Before implementing a potentially long-running operation such as `find_pattern` over all modules, decide and document how MCP cancellation propagates to the underlying x64dbg work.

---

## 5. Tool / Resource Surface (high-level)

The MCP-visible surface is split into three forms based on access pattern. Detailed catalog and per-item schemas live in [tools-spec.md](tools-spec.md); the reasoning is in [adr/003-tool-resource-action-three-layer.md](adr/003-tool-resource-action-three-layer.md).

| Form | When | Examples |
|---|---|---|
| **Resource** (`[McpServerResource]`) | Read-only bulk snapshots and collection navigation | `x64dbg://logging`, `x64dbg://modules`, `x64dbg://modules/{name}/sections`, `x64dbg://memory/maps`, `x64dbg://windows`, `x64dbg://handles`, `x64dbg://tcpconnections` |
| **Rich-param Tool** (`[McpServerTool]`) | Focused operations over one target or a bounded hot-path window | `disassemble(addr, count)`, `find_pattern(pattern, maxResults)`, `assemble(addr, instruction)` |
| **Action-mega Tool** (`[McpServerTool]` with `action` enum) | Fine-grained per-item reads/updates and debugger control clusters | `labels{get/set/delete + batch}`, `debug_control{init/attach/run/pause/Step*}`, `breakpoints{get/set/delete + batch}`, `memory{read/write/alloc/free}`, `debug_gui{snapshot/focus/get/set}` |

A Resource and Tool may cover the same domain when their access patterns differ: the Resource is the compact bulk-read surface, while the Tool addresses or changes individual items. They must not duplicate the same operation with equivalent inputs and outputs.

`x64dbg://logging` is backed by `GuiLogSave`, the upstream API for snapshotting the rendered Log view. Because that API accepts only a filename, each read marshals the save to the GUI thread, materializes a unique host temporary file, reads it as UTF-8, and immediately deletes it after the successful read. x64dbg stops the LogView flush timer while the Log tab is hidden, so messages still in its private pending buffer are not part of the rendered document until upstream displays the tab and flushes them.

The `enableDebugging` flag on `McpServerHost::Start` controls whether the debugger-domain `McpDebuggingTools` catalog is registered. Its purpose is to keep execution control, breakpoints, registers, memory operations, thread control, assembly, logging, and GUI evidence operations from inflating every agent's tool schema. It is **not** a general read/write or authorization boundary: analysis-domain tools may update x64dbg analysis metadata while remaining in the always-registered `McpAnalysisTools` catalog.

`debug_gui{action:"snapshot"}` is the sole mixed-content Tool in the target catalog. Inline delivery returns the normal typed JSON envelope as text plus one MCP `ImageContentBlock(image/png)`. When `save_path` is supplied, it instead creates a PNG on the x64dbg host and returns only typed metadata and the normalized path. The Tool captures the complete x64dbg main window, not the desktop or only the selected CPU pane; detailed selection, path, and evidence semantics live in [ADR-006](adr/006-debug-gui-evidence-capture.md).

---

## 6. Build / Output

- Project: `x64dbgMCP/x64dbgMCP.vcxproj`, `CLRSupport=NetCore`, `TargetFramework=net10.0`, `LanguageStandard=stdcpp17`, `PlatformToolset=v145`
- Output: `out/bin/<platform>-<config>/x64dbgMCP.dp{32,64}` (extension switches by platform via `TargetExt`)
- Dependencies pulled by NuGet (PackageReference): `ModelContextProtocol`, `ModelContextProtocol.AspNetCore` (2.1.0); FrameworkReference: `Microsoft.AspNetCore.App`
- x64dbg pluginsdk is vendored under `x64dbgMCP/plugintemplate/pluginsdk/` and linked via `AdditionalLibraryDirectories=$(ProjectDir)plugintemplate`

The build is framework-dependent on the .NET 10 runtime and produces a mixed-mode plugin plus runtime metadata and managed dependencies in the MSBuild `OutputPath`. Deploying only `x64dbgMCP.dp32` / `x64dbgMCP.dp64` is insufficient on a clean target. The repository's `deploy_x64dbg_plugin` target therefore copies the complete `out/bin/<platform>-<config>/` directory into the matching x64dbg `plugins/` directory; runtime-relevant files include `Ijwhost.dll`, `x64dbgMCP.deps.json`, `x64dbgMCP.runtimeconfig.json`, and the MCP/AI managed assemblies.
