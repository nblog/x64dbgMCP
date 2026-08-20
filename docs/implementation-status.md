# Implementation Status

本文件是开发完成度与验证边界的唯一来源。根级 [`README.md`](../README.md) 按最终产品能力描述；目标契约以 [`tools-spec.md`](tools-spec.md) 为准；本文件只回答“代码现在实现了什么、验证到了哪一步、还差什么”。`tools-spec.md` 中的 🟢/🟡/⚪ 表示契约成熟度，不表示代码完成度。

> Snapshot: 2026-08-20，base HEAD `652610e`；最近一次双架构 live MCP 验收完成于 2026-08-09，`disassemble` import 符号化、breakpoints Resource 与 `memory{action:"read"}` 迁移的 x64 专项验收完成于 2026-08-14；breakpoints Tool 的首批 mutation 与统一 `get/disable/delete` 于 2026-08-17 完成 x64 live MCP 专项验收和 x86 build-only 验证；`debug_control{action:"attach"}`、Resource namespace migration 与 attach candidates 于 2026-08-20 分别完成 x64 live MCP + NtObjectManager 闭环和 x86 build-only 验证。`DebugGUI` 已实现并完成 x64 live MCP 验收，x86 已完成构建与部署检查；三类 CPU pane 的 x86 GUI 行为仍待 live 验收。统计先以实时 MCP `tools/list`、`resources/list`、`resources/templates/list` 为准，再与 `x64dbgMCP/x64dbgHandler.h` 中的注册和实现交叉核对；不是从根级 README 的产品清单反推。

## Coverage

| Surface | Contract target | Implemented / registered | Remaining |
|---|---:|---:|---:|
| Fixed Resources | 8 | 8 | 0 |
| Resource Templates | 7 | 7 | 0 |
| Reserved Resources | 5 | 0 | 5 |
| **All Resources** | **20** | **15** | **5** |
| Always-registered rich-param Tools | 5 | 1 | 4 |
| Analysis action-mega Tools | 6 | 0 | 6 |
| Debugger-domain Tools | 8 | 6 | 2 |
| **All Tools** | **19** | **7** | **12** |

### Runtime catalog

实时 `resources/list` 返回 8 个固定 Resources：`x64dbg://session`、`x64dbg://logging`、`x64dbg://session/debuggee`、`x64dbg://memory/maps`、`x64dbg://threads`、`x64dbg://windows`、`x64dbg://handles`、`x64dbg://tcpconnections`。旧 `x64dbg://process` 不再注册，直接读取返回 `Unknown resource URI`。

实时 `resources/templates/list` 返回 7 个 Resource Templates：`x64dbg://modules{?offset,limit}`、`x64dbg://modules/{name}`、`x64dbg://modules/{name}/sections`、`x64dbg://modules/{name}/exports`、`x64dbg://modules/{name}/imports`、`x64dbg://breakpoints{?offset,limit}`、`x64dbg://attach/processes{?offset,limit}`。因此当前共有 15 个可读取 Resource 端点，但只有前 8 个出现在固定 Resource 列表中。

尚未注册的 5 个 reserved Resources 为：`x64dbg://symbols`、`x64dbg://functions`、`x64dbg://labels`、`x64dbg://comments`、`x64dbg://bookmarks`。

实时 `tools/list` 返回 7 个 MCP-visible Tools：常驻的 `disassemble`，以及由调试领域目录门控的 `debug_control`、`breakpoints`、`registers`、`memory`、`logging`、`debug_gui`。`debug_control` 当前在既有 control cluster 中公开 `attach`，平铺参数为 `pid:int` 与 `detach2attach:bool=false`。`breakpoints` 当前公开 `get`、`set`、`set_hardware`、`disable`、`delete`；`get/disable/delete` 以可选 `kind=normal|hardware` 处理同址双断点歧义，旧 `delete_hardware` 已移除。独立 `memory_read` 已从目录移除，`memory` 当前只公开 `read` action。action-mega Tool 的输入 Schema 均直接保留各 action 的平铺参数，没有嵌套 `params`。C++/CLI 方法使用 `PascalCase`，MCP C# SDK 2.1.0 默认把它们派生为上述 `snake_case` wire names。

其余 12 个目标 Tool definitions 尚未实现：常驻 rich-param 的 `find_pattern`、`parse_expression`、`get_string_at`、`get_call_stack`；分析 action-mega 的 `symbols`、`functions`、`labels`、`comments`、`bookmarks`、`xrefs`；调试领域的 `threads`、`assemble`。`debug_gui` 的 managed 方法名为 `DebugGUI`，SDK 派生的 MCP wire name 为 `debug_gui`；其 `snapshot/focus/get/set` 已在 `x64dbgHandler.h` 实现并受 `enableDebugging` 门控。`breakpoints` 的 `set_batch`、`delete_batch` 与 `memory` 的 `write`、`alloc`、`free` 仍是 action 级缺口，不重复计为缺失 Tool definitions。寄存器批量读取已由 `registers{action:"dump"}` 实现，契约不再重复保留 `get_register_dump`。

## Current milestone

当前里程碑实现 [ADR-006](adr/006-debug-gui-evidence-capture.md) 的 `debug_gui{snapshot,focus,get,set}`。`snapshot` 在 x64dbg GUI thread 刷新并捕获完整主窗口，通过 WIC 编码为 PNG；省略 `save_path` 时返回 typed JSON text + MCP image block，提供绝对新 `.png` 路径时只创建文件并返回 metadata/path。`focus/get/set` 把 CPU pane 导航、选区、聚焦、刷新、event flush 与回读组合成单个 GUI-thread transaction；`set` 同时返回 resolved requested 和 GUI actual range。截图摘要是 PNG byte-identity anchor，不是签名 provenance 或可信时间戳。

此前里程碑把会话内目标从旧 `x64dbg://process` breaking rename 为 `x64dbg://session/debuggee`，新增分页 `x64dbg://attach/processes{?offset,limit}`，并为 `debug_control` 增加 `attach` action。候选集合直接来自 `DbgFunctions()->GetProcessList`，与 x64dbg Attach dialog 使用同一过滤快照；`attach` 的 success 只表示命令 handler 已接受并启动 attach，最终目标身份由 `x64dbg://session` 与 `x64dbg://session/debuggee` 确认。更早的里程碑包括 `breakpoints{get,set,set_hardware,disable,delete}`、`memory_read` → `memory{action:"read"}` 迁移和分页 `x64dbg://breakpoints` Resource。

`enableDebugging` 的正式含义是“调试领域 Tool catalog / schema-budget 门控”，不是通用写权限。Resource 的正式边界是只读批量快照，Tool 的正式边界是单项精细读取、修改与控制；同一领域可以同时存在两种表面，但不得重复等价操作。见 [ADR-003](adr/003-tool-resource-action-three-layer.md)。

## Verification boundary

当前 namespace / attach-candidates 专项验收使用最终部署物 attach Windows Notepad 11.2606.15.0 x64 PID 10316，并以 `x64dbg://session/debuggee` 与 NtObjectManager 双重确认目标身份、完整命令行、位数、Session、创建时间与存活状态；此前 attach Tool 专项验收还使用两个独立 Notepad 覆盖 active-session switching。此前 memory 迁移与 breakpoints Resource/Tool 专项验收均使用 x64dbg 调试 Electron 32.2.8 x64；完整双架构基线还包括 x32dbg 调试 `%SystemRoot%\SysWOW64\notepad.exe`。所有 breakpoints Tool 状态变更均在 Tool 返回后用 `x64dbg://breakpoints` 二次确认。

| Check | Status | Evidence / limit |
|---|---|---|
| Debug x64 build | Verified | `out/bin/x64-Debug/x64dbgMCP.dp64`, SHA-256 `89E6D67742C8E2AE0B4FD05354B7F117E4F61AC9B133CDA51BEEE25E8D1BEC46`; 2026-08-20 CMake/MSBuild run succeeded with 0 errors and 8 known C4945 duplicate-import warnings |
| Debug Win32 build | Verified | `out/bin/win32-Debug/x64dbgMCP.dp32`, SHA-256 `7EC5C80B99D58769F872BD8EB55539B4B4EE2DF8F3DCAB7BD6C26A4B4CB3EE32`; the same run succeeded with 0 errors and 8 known C4945 warnings; DebugGUI remains live-unverified on x86 |
| Full plugin deployment | Verified | Complete 11-file x64 and x86 `OutputPath` sets were deployed to the matching x64dbg `plugins` directories; every source/deployed filename, size, and SHA-256 matched. Deployed plugin hashes are the `.dp64` / `.dp32` hashes recorded above, and both sets include `Ijwhost.dll`, `.deps.json`, `.runtimeconfig.json`, `ModelContextProtocol*.dll`, and `Microsoft.Extensions.AI.Abstractions.dll` |
| MCP catalog | Verified on current x64 | Returned exactly `debug_control`, `breakpoints`, `registers`, `disassemble`, `debug_gui`, `memory`, `logging`; `debug_gui` exposed the flat `action/window/start/end/save_path` schema with only `action` required. Existing fixed Resources and templates remained available; `x64dbg://modules/notepad.exe` emitted `_links.entry_disasm.tool="disassemble"` |
| Existing Resources | Previous baseline retained | The previous 13 endpoints and modules pagination passed on x64/x86. This milestone reran the complete catalogs plus `session`, renamed `session/debuggee`, and new `attach/processes`; the unrelated pre-existing Resource payload matrix was not fully rerun |
| `x64dbg://attach/processes` | Verified on current x64 | Final deployed binary's detached default read returned `offset=0`, `limit=100`, `total=201`, `hasMore=true`; tracked Notepad PID 10316 was present with exact name/path and the upstream case-sensitive-parser artifact `:\Windows\notepad.exe" C:\Windows\win.ini`, matching NtObjectManager on PID/path. A copied x64 `PING.EXE` fixture named `x64dbg.attach.fixture.exe` returned `name="x64dbg"`, proving exact Qt `QFileInfo::baseName()` first-dot semantics; the tracked fixture and its single-file temporary directory were then removed. Earlier in the same task, pages at `0/5` and `5/5` returned 5 entries with correct next/prev links; `offset=-5,limit=0` normalized to `0/1`, `limit=500` clamped to 100, and total varied from 197 to 203 across per-request snapshots as helper processes came and went |
| `x64dbg://breakpoints` | Verified on x64 | Electron database returned the expected 11 normal + 1 execute-hardware breakpoints with exact addresses, one-shot/enabled state, names, hit counts, break/log/command fields, and `hardwareSize/Slot`; joining each address to `disassemble(count=1)` reproduced all 12 instruction rows. Temporary execute-memory, DLL-load, and first-chance exception breakpoints proved all five type/subtype mappings and were precisely deleted; total returned from 15 to 12. Pages `5/5/2`, next/prev links, negative-offset normalization, and `limit=500` clamping to 100 passed |
| `breakpoints` Tool | Verified on current x64 | Against the specified Electron 32.2.8 target (single-type paths on PID 26048; same-address paths on PID 9120), omitted `kind` completed normal and hardware `get → disable → delete`, including hardware readback `enabled:false`, and each final `get` returned `not_found`. At `electron:$30`, normal and hardware breakpoints coexisted: omitted-kind `get/disable/delete` all returned `invalid_argument`; typed reads returned both entries; `kind=hardware` disabled only hardware while normal remained enabled; `kind=normal` deleted only normal; omitted-kind `get/delete` then auto-selected the sole disabled hardware entry. Deprecated `delete_hardware` returned unknown-action `invalid_argument`. The final Resource snapshot returned to the original 10 normal and 0 hardware entries. Earlier condition/log/type/size/slot/error and UTF-8/special-text evidence remains valid for the same implementation family |
| Module children | Verified on x64 and x86 | Electron: 15 sections, 3163 exports, 652 imports; Notepad: 6 sections, empty exports, 312 imports |
| `disassemble` | Previous x64/x86 baseline retained | Electron `electron:$47E98D2`: 15 instruction boundaries and all bytes matched the supplied 65-byte sequence; the IAT call retained raw absolute operands and returned `RaiseException` display/reference across repeated calls before/after symbol loading; a non-IAT RIP-relative data reference remained unsymbolized; `count=201` returned contracted `invalid_argument` |
| `memory{action:"read"}` | Verified on current x64; build-only on x86 | Live Schema required only `action` and exposed direct optional `addr/size/compress`. Reading `electron:$0,size=256` resolved to `0x7FF7159D0000`; the raw bytes SHA-256 `065CC4CE27F8E70FA81149B80824FBCCB6319943A72F09B98168B8D2E7EC20DD` exactly matched an independent Win32 `ReadProcessMemory` read from Electron PID 45300. `action=write` and `size=65537` returned `invalid_argument`; an invalid expression returned `not_found` |
| LZ4 memory payload | Verified on current x64 | The same 256-byte window compressed to 187 bytes; `LZ4_decompress_safe` returned 256 and the decompressed SHA-256 exactly matched the raw payload |
| `registers` | Verified on x64 and x86 | Active dump, get, set-to-same-value, architecture-specific register sets, paused inactive-thread dump, missing thread, and running-target `not_paused` paths passed |
| `debug_control` | Verified on current x64 | Final deployed binary's detached attach to Notepad PID 10316 returned provisional `success:true` with `isDebugging:false`; the first Resource poll converged to `session.isDebugging=true` and `session/debuggee.processId=10316`, with exact path and full command line matching NtObjectManager (x64, non-WOW64, Session 10, unchanged creation time). Earlier attach validation proved `pid=0` rejection, active-session false/omitted rejection, explicit `detach2attach=true` switching between PIDs 11064/36760 while restoring `Engine/DetachOnAttach=0`, and the then-current process Resource retained the old target until a permitted switch. Previous `init/run/pause/stop/StepInto/StepOver/StepOut/run_command(wait=true)` and x32 lifecycle evidence is retained |
| `logging` | Verified on x64 and x86 | After displaying the Log tab, `clear` → `put` → Resource read preserved exact Chinese UTF-8 text; empty `put` returned `invalid_argument` |
| `debug_gui` | Implemented; x64 live verified | Against the final deployed x64 plugin, detached inline snapshot returned exactly typed JSON text + one `image/png` block; the 2586×1530 decoded PNG had matching magic, dimensions, non-uniform pixels, and SHA-256. File mode returned one text block, wrote no-overwrite PNG metadata/path, and rejected existing, relative, non-PNG, and missing-parent paths. A real Notepad debug session proved default `focus=Disassembly`; Disassembly single-selection expanded resolved `start=end=0x7FFA8BF1D78E` to the complete 2-byte `EB00` instruction ending at `0x7FFA8BF1D78F`; Dump/Stack retained one byte; an explicit 16-byte Dump range round-tripped exactly. Bad window case, reversed range, unresolved expression, detached focus/get/set, final Resource detachment, and process cleanup passed. Evidence PNG: `out/debug-gui-e2e/x64-live-disassembly-2248.png`, SHA-256 `52DC1AFC9329F65C9C2038FED4E17103E88C19CDAD4CE0AD0B9E5457EB902428`. x86 build/deployment passed; x86 live GUI semantics remain unverified |
| Tool output schema | Known SDK boundary | Current `[McpServerTool]` annotations do not set `UseStructuredContent`; typed results are returned as JSON text content and are not advertised as `outputSchema` in `tools/list` |
| Logging snapshot boundary | Upstream-defined | `GuiLogSave` serializes the rendered `QTextDocument`; while the Log tab is hidden, x64dbg may retain newer messages in its private `logBuffer` until the tab is displayed and its flush timer runs |
| Electron PDB | Partially observable | Waited more than two minutes and x64dbg resource use stabilized, but the current MCP surface has no symbols Resource/Tool, so PDB symbol enumeration was not and cannot be claimed as verified |
| Release builds | Not rerun for this milestone | Current namespace and attach-candidates Resource changes were validated in Debug builds; the previous Release result is not treated as current evidence |
| Server stop / cleanup | Verified for current DebugGUI run | Final `debug_control{stop}` was followed by `x64dbg://session.isDebugging=false` and `x64dbg://session/debuggee.processId=0`; tracked Notepad PID 52100 exited. Gracefully closing tracked x64dbg PID 2248 removed its `[::1]:3001` listener; neither tracked process remained. At the time of this run the Windows IPv4/IPv6 excluded-port lists no longer covered 3001, so the formal default port was used. Occupied-port failure propagation was not rerun |

## Known conformance gaps

1. The five reserved Resources and twelve target Tool definitions listed under Coverage are not registered. Their presence in the root README describes the intended product surface, not current implementation.
2. The registered `memory` Tool currently implements only `read`; target actions `write`, `alloc`, and `free` remain undispatched and are deliberately excluded from its live description.
3. General Symbol/PDB enumeration has no MCP-observable Resource/Tool contract yet. `disassemble` exposes only exact module-import/IAT references; large-PDB process stability is evidence about the host session only, not evidence that arbitrary symbols can be queried through MCP.

## Temporary experiment deviations

以下两项是用户确认保留的临时实验门控，不代表目标契约，也不应被后续实现当作默认行为：

- `plugintemplate/plugin.cpp` 中裸 `mcp.start` 当前令 `enableDebugging=true`；实验结束后恢复为正式默认值。
- `_DEBUG` 构建在插件初始化时自动调用 `mcp.start`；实验结束后移除。

## Next implementation order

1. 对 [ADR-006](adr/006-debug-gui-evidence-capture.md) 做 x86 GUI 专项验收：复用已通过的 x64 PNG/selection matrix，补齐三类 CPU pane 的 x86 focus/get/set 与清理证据。
2. 补齐常驻 rich-param 查询：`parse_expression` → `get_string_at` → `find_pattern` → `get_call_stack`。
3. 成对实现批量 Resource 与单项 Tool：symbols → labels → comments → bookmarks → functions；`xrefs` 只保留目标地址上的精细 Tool。Symbols 应包含可验证的 PDB 加载/枚举状态，使 Electron 大型 PDB 场景第一次具备 MCP 语义验收面。
4. 扩展其余调试领域目录：`memory{write,alloc,free}` → `threads` → `assemble`；breakpoints 的批量 Resource 与五个首批 mutation actions、`memory{read}` 已完成。
5. 重验双架构 Release、`mcp.stop` → restart 和端口占用失败传播；在行为稳定后，为单测/集成测试策略新增 ADR，并把 live smoke cases 固化为可重复测试入口。

每一批继续遵守 Docs-first：先把 🟡/⚪ 契约收敛为可实施 schema，再改代码；若实现证据与基线冲突，按根级 `AGENTS.md` 要求先停止并对齐文档。
