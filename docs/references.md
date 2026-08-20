# References

External resources used as authoritative sources for design and implementation. Citations here are referenced by ADRs and conventions; please add new entries here rather than inlining URLs into multiple files.

---

## 1. MCP (Model Context Protocol)

### Specification & official docs

- [modelcontextprotocol.io](https://modelcontextprotocol.io) — protocol overview, transport bindings, capability negotiation
- [MCP specification](https://spec.modelcontextprotocol.io) — formal spec
- [MCP — Tools vs Resources vs Prompts (community guide)](https://rapidevelopers.com/mcp-tutorial/mcp-tools-vs-resources-vs-prompts) — practical guidance on when to expose what

### MCP C# SDK

- [modelcontextprotocol/csharp-sdk](https://github.com/modelcontextprotocol/csharp-sdk) — repo root
- [EverythingServer sample](https://github.com/modelcontextprotocol/csharp-sdk/tree/main/samples/EverythingServer) — comprehensive sample exercising tools, resources, prompts
- [SimpleResourceType.cs](https://github.com/modelcontextprotocol/csharp-sdk/blob/main/samples/EverythingServer/Resources/SimpleResourceType.cs) — `[McpServerResource(UriTemplate=...)]` reference for our resource layer
- [`AIFunctionMcpServerTool.DeriveName` in v2.1.0](https://github.com/modelcontextprotocol/csharp-sdk/blob/v2.1.0/src/ModelContextProtocol.Core/Server/AIFunctionMcpServerTool.cs#L337-L383) — default MCP-visible Tool names are derived with `JsonNamingPolicy.SnakeCaseLower`
- [`McpServerToolAttribute` in v2.1.0](https://github.com/modelcontextprotocol/csharp-sdk/blob/v2.1.0/src/ModelContextProtocol.Core/Server/McpServerToolAttribute.cs) — exception-to-failed-result behavior and the opt-in `UseStructuredContent` / `OutputSchemaType` boundary
- NuGet packages used by this project (2.1.0):
  - `ModelContextProtocol`
  - `ModelContextProtocol.AspNetCore`

### MCP transport in ASP.NET Core

- `HttpMcpServerBuilderExtensions::WithHttpTransport` — enables Streamable HTTP + Legacy SSE
- `McpEndpointRouteBuilderExtensions::MapMcp(app, "")` — maps MCP endpoints to the app's root path
- See [x64dbgMCP.h](../x64dbgMCP/x64dbgMCP.h) for our wiring

---

## 2. Anthropic engineering on agent tool design

Foundational reading for tool/resource design decisions in this project.

- [Writing tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents) — schema budget, naming, parameter design; cited by ADR-001 and ADR-003 for tool-list bloat data
- [Code execution with MCP](https://anthropic.com/engineering/code-execution-with-mcp) — discusses minimising context cost across many MCP servers

---

## 3. x64dbg

### Plugin SDK (vendored)

The pluginsdk headers are vendored under [`x64dbgMCP/plugintemplate/pluginsdk/`](../x64dbgMCP/plugintemplate/pluginsdk/). Key files:

| Header | Use |
|---|---|
| `bridgemain.h` | `Bridge*` core APIs, `DbgValFromString`, `DbgValToString`, `DbgGetRegDumpEx`, `GuiLogSave`, `GuiLogClear`, `GuiExecuteOnGuiThreadEx`, `GuiDisableLogScope` |
| `_dbgfunctions.h` | Extended debugger function table |
| `_plugins.h` | Plugin lifecycle hooks and `_plugin_logputs` |
| `_scriptapi.h` | Top-level Script API namespace |
| `_scriptapi_argument.h` | `Script::Argument::*` (function arg analysis) |
| `_scriptapi_assembler.h` | `Script::Assembler::*` |
| `_scriptapi_bookmark.h` | `Script::Bookmark::*` |
| `_scriptapi_comment.h` | `Script::Comment::*` |
| `_scriptapi_debug.h` | `Script::Debug::Run/Pause/Step*`, `HardwareType` |
| `_scriptapi_flag.h` | `Script::Flag::Get/Set`, `FlagEnum` |
| `_scriptapi_function.h` | `Script::Function::*` |
| `_scriptapi_gui.h` | `Script::Gui::*` (requires GUI thread marshalling) |
| `_scriptapi_label.h` | `Script::Label::*` |
| `_scriptapi_memory.h` | `Script::Memory::*` |
| `_scriptapi_misc.h` | `Script::Misc::ParseExpression`, etc. |
| `_scriptapi_module.h` | `Script::Module::*` (modules, sections, exports, imports) |
| `_scriptapi_pattern.h` | `Script::Pattern::*` |
| `_scriptapi_register.h` | `Script::Register::Get/Set`, `RegisterEnum` |
| `_scriptapi_stack.h` | `Script::Stack::*` |
| `_scriptapi_symbol.h` | `Script::Symbol::*` |

### x64dbg documentation

- [x64dbg help — Expressions](https://help.x64dbg.com/en/latest/introduction/Expressions.html) — expression syntax cited by ADR-002
- [x64dbg help — Plugins](https://help.x64dbg.com/en/latest/developers/plugins/index.html) — plugin SDK reference
- [x64dbg help — Commands](https://help.x64dbg.com/en/latest/commands/index.html) — full x64dbg command catalog (relevant to `debug_control{action:"run_command"}`)

#### x64dbg command groups (cited by `debug_control` and other mega-tools)

When implementing a `debug_control` action that maps onto a raw command, consult the matching group page first. Names and argument shapes occasionally change between x64dbg releases.

| Group | URL | Used by |
|---|---|---|
| Debug control | [help.x64dbg.com/.../debug-control/index.html](https://help.x64dbg.com/en/latest/commands/debug-control/index.html) | `debug_control{init, attach, stop, run, pause, Step*}` |
| Breakpoints | [help.x64dbg.com/.../breakpoint-control/index.html](https://help.x64dbg.com/en/latest/commands/breakpoint-control/index.html) | `breakpoints{...}` |
| Conditional breakpoints | [help.x64dbg.com/.../conditional-breakpoint-control/index.html](https://help.x64dbg.com/en/latest/commands/conditional-breakpoint-control/index.html) | `breakpoints{set,set_hardware}` condition/log fields |
| Memory operations | [help.x64dbg.com/.../memory-operations/index.html](https://help.x64dbg.com/en/latest/commands/memory-operations/index.html) | `memory{write, alloc, free}` |
| Threads | [help.x64dbg.com/.../thread-control/index.html](https://help.x64dbg.com/en/latest/commands/thread-control/index.html) | `threads{...}` |
| Variables / Expressions | [help.x64dbg.com/.../variables/index.html](https://help.x64dbg.com/en/latest/commands/variables/index.html) | `registers`, `parse_expression` (when arithmetic is involved) |

### Repository

- [x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) — main repository
- [x64dbg pluginsdk source](https://github.com/x64dbg/x64dbg/tree/development/src/dbg/pluginsdk) — authoritative source for pluginsdk headers (compare against vendored copies during SDK upgrades)
- [Attach dialog at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/gui/Src/Gui/AttachDialog.cpp#L151-L218) — GUI precedent for decimal `attach .<pid>` command construction and detach-on-attach selection
- [Attach dialog process snapshot at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/gui/Src/Gui/AttachDialog.cpp#L63-L83) — maps `DBGPROCESSINFO` to PID, derived name, title, path, and command-line-arguments columns
- [Qt 5 `QFileInfo::baseName`](https://doc.qt.io/qt-5/qfileinfo.html#baseName) — the Attach dialog's process name stops at the first dot, unlike last-extension-only path helpers
- [`GetProcessList` at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/_dbgfunctions.cpp#L246-L269) — returns the filtered attach candidates as a `BridgeAlloc`-allocated `DBGPROCESSINFO` array
- [`dbglistprocesses` at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/debugger.cpp#L2352-L2513) — filters same-bitness attach candidates and best-effort derives `szExeArgs`; its case-sensitive executable matching can leave parser artifacts that the Attach dialog and Resource preserve
- [Attach command handler at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/commands/cmd-debug-control.cpp#L246-L334) — reads `Engine/DetachOnAttach`, waits for the old debug loop after detaching, validates access/architecture, and starts the new attach loop
- [x64dbg help — AttachDebugger/attach](https://help.x64dbg.com/en/latest/commands/debug-control/AttachDebugger.html) — official PID argument and attach-command result semantics
- [`_dbg_getbplist` at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/_exports.cpp#L749-L804) — `DbgGetBpList(bp_none, ...)` enumerates every breakpoint type and allocates the returned `BPMAP.bp` with `BridgeAlloc`
- [`BpGetList` at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/breakpoint.cpp#L102-L126) — breakpoint address normalization used by `x64dbg://breakpoints`
- [`BpToBridgeTypeEx` / `BpToBridge` at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/breakpoint.cpp#L750-L881) — `BRIDGEBP` field and subtype semantics used by `x64dbg://breakpoints`
- [`BpNew` and its typed `BreakpointKey` at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/breakpoint.cpp#L129-L183) — breakpoint type participates in identity, so normal and hardware breakpoints can coexist at one address and type-neutral actions must reject ambiguous targets
- [`BP_FIELD`, `BP_REF`, and generic breakpoint field functions at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/_dbgfunctions.h#L141-L191) — public Plugin SDK interface used for condition/log text without command parsing; [`DBGFUNCTIONS` entries](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/_dbgfunctions.h#L276-L285)
- [`BpSetFieldText` implementation at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/breakpoint.cpp#L1372-L1407) — generic text-field storage; unlike `SetBreakpointLog`, it does not automatically set silent mode, so the Tool also writes `bpf_silent`
- [`SetHardwareBreakpoint` implementation at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/commands/cmd-breakpoint-control.cpp#L393-L482) — type/size/alignment/slot behavior used by `breakpoints{action:"set_hardware"}`
- [Software and hardware disable handlers at the vendored `2026.05.27` release commit](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/commands/cmd-breakpoint-control.cpp#L266-L328) / [hardware handler](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/commands/cmd-breakpoint-control.cpp#L588-L630) — the engine uses type-specific disable paths; the Tool selects one only after `kind`/snapshot resolution
- [Official conditional-breakpoint execution order](https://help.x64dbg.com/en/latest/introduction/ConditionalBreakpoint.html) — hit counter, break/log/command conditions, fast-resume boundary, and log-only `breakCondition=0` semantics
- [`disasm_fast.cpp` at `37e8d517`](https://github.com/x64dbg/x64dbg/blob/37e8d517b8cac411c926f49095b8938bff228a8f/src/dbg/disasm_fast.cpp#L11-L79) — `DbgDisasmFastAt` instruction text and `BASIC_INSTRUCTION_INFO::memory.value` semantics, including RIP-relative effective-address calculation
- [`SymbolFromAddressExact` at `37e8d517`](https://github.com/x64dbg/x64dbg/blob/37e8d517b8cac411c926f49095b8938bff228a8f/src/dbg/symbolinfo.cpp#L497-L528) — exact symbol lookup order: loaded symbols precede module imports, so `SYMBOLINFO.type` alone is not a stable IAT classifier while symbols are loading
- [LogView.cpp — save](https://github.com/x64dbg/x64dbg/blob/749bd554c58f0e3fa2091e67373d949845ef073e/src/gui/Src/Gui/LogView.cpp#L471-L484) — `GuiLogSave` handling: append-mode `QFile`, rendered UTF-8 log contents, and save-status message
- [LogView.cpp — visibility and flush](https://github.com/x64dbg/x64dbg/blob/749bd554c58f0e3fa2091e67373d949845ef073e/src/gui/Src/Gui/LogView.cpp#L164-L175) — the Log tab starts/stops its flush timer on show/hide; [`flushTimerSlot`](https://github.com/x64dbg/x64dbg/blob/749bd554c58f0e3fa2091e67373d949845ef073e/src/gui/Src/Gui/LogView.cpp#L574-L606) moves the private buffer into the rendered document
- [HandlesView.cpp](https://github.com/x64dbg/x64dbg/blob/development/src/gui/Src/Gui/HandlesView.cpp) — x64dbg GUI's handle, window, and TCP-connection enumeration and display fields

### Bundled compression (lz4)

x64dbg ships architecture-specific lz4 import libraries and headers in the pluginsdk ([`pluginsdk/lz4/`](../x64dbgMCP/plugintemplate/pluginsdk/lz4/)), with the runtime implementation provided by `lz4.dll` in each x64dbg release architecture directory. The plugin imports the legacy block API (`LZ4_compress` and `LZ4_compressBound`); clients may use `LZ4_decompress_safe` to decode an opted-in `memory{action:"read"}` response.

- [lz4 reference](https://github.com/lz4/lz4/blob/dev/lib/lz4.h) — upstream API; the bundled headers are an older snapshot, so prefer the bundled signatures over upstream-only additions
- Bundled headers: [`lz4.h`](../x64dbgMCP/plugintemplate/pluginsdk/lz4/lz4.h) (block), [`lz4hc.h`](../x64dbgMCP/plugintemplate/pluginsdk/lz4/lz4hc.h) (high-compression), [`lz4file.h`](../x64dbgMCP/plugintemplate/pluginsdk/lz4/lz4file.h) (file IO — unused by us)
- Wire format used by `memory{action:"read", compress:true}`: lz4 block bytes (no frame header, no length prefix). Decompressors must know the original size — the response exposes it as `size`. Reference: [x64dbgpy3 — RequestBuffer::Serialize](https://github.com/nblog/x64dbgpy3/blob/main/x64dbgpy3svr/x64dbghandler.hpp#L25-L144) (uses a 4-byte big-endian length header *plus* the lz4 bytes; this project omits the header because the JSON envelope already carries `size`)

---

## 4. Prior art: MCP servers for reverse engineering

Surveyed during ADR-003 design. Detailed comparison table lives in [ADR-003](adr/003-tool-resource-action-three-layer.md).

| Project | URL | Pattern | Tool count |
|---|---|---|---|
| LaurieWired/GhidraMCP | [github](https://github.com/LaurieWired/GhidraMCP) | Fine-grained 1:1 | 27 |
| starsong-consulting/GhydraMCP | [github](https://github.com/starsong-consulting/GhydraMCP) | Compound family + HATEOAS `_links` | 51 |
| MxIris-Reverse-Engineering/ida-mcp-server | [github](https://github.com/MxIris-Reverse-Engineering/ida-mcp-server) | 1:1 + paired batch variants | 19 |
| MCPPhalanx/binaryninja-mcp | [github](https://github.com/MCPPhalanx/binaryninja-mcp) | **Resource + Tool hybrid** | ~10 tools + ~8 resources |
| DNLINYJ/better-x64dbg-mcp | [github](https://github.com/DNLINYJ/better-x64dbg-mcp) | Action-mega dispatch | 21 mega (~148 ops) |
| blacktop/ida-mcp-rs | [github](https://github.com/blacktop/ida-mcp-rs) | Categorised + filter | 14 categories |
| bethington/ghidra-mcp | [github](https://github.com/bethington/ghidra-mcp) | Anti-pattern (catalog bloat) | 245 |

Key files referenced for design:

- [GhydraMCP — GHIDRA_HTTP_API.md](https://github.com/starsong-consulting/GhydraMCP/blob/main/GHIDRA_HTTP_API.md) — HATEOAS link shape we partially adopted
- [better-x64dbg-mcp — c_mcp_tools.cpp](https://github.com/DNLINYJ/better-x64dbg-mcp/blob/main/src/mcp/c_mcp_tools.cpp) — `make_mega_tool` / `make_action` action dispatch pattern, validated on the same x64dbg domain

---

## 5. ASP.NET Core / .NET

- [ASP.NET Core minimal APIs](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/minimal-apis) — `WebApplication.CreateSlimBuilder` is the slim variant
- [System.Text.Json](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/overview) — default serializer used by MCP C# SDK
- [System.Text.Json polymorphism](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/polymorphism) — relevant if we ever need `oneOf`-style result unions ([ADR-004](adr/004-typed-result-with-envelope.md) alternatives)

---

## 6. C++/CLI

- [C++/CLI Language Reference (MS Learn)](https://learn.microsoft.com/en-us/cpp/extensions/component-extensions-for-runtime-platforms) — managed extensions used throughout
- [`/clr:netcore` in MSBuild](https://learn.microsoft.com/en-us/cpp/build/reference/clr-common-language-runtime-compilation) — required for .NET 10 interop
- See [x64dbgMCP.vcxproj](../x64dbgMCP/x64dbgMCP.vcxproj) for our specific configuration (`CLRSupport=NetCore`, `TargetFramework=net10.0`, `LanguageStandard=stdcpp17`, `PlatformToolset=v145`)

---

## 7. Hypermedia / API design background

- [HAL — Hypertext Application Language](https://stateless.group/hal_specification.html) — canonical `_links` shape that informed [ADR-005](adr/005-hateoas-links-on-navigation-roots.md)
- [Architecture Decision Records (Michael Nygard)](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) — ADR template origin

---

## How to add a reference

When citing a new external source from an ADR or convention, add the entry here first (or move an inline citation here once it's referenced ≥2 places). Group by section above. Prefer permanent URLs (specific commit / version) over `main` for source files we depend on for behaviour.
