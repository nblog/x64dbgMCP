# Implementation Status

本文件是开发完成度与验证边界的唯一来源。根级 [`README.md`](../README.md) 按最终产品能力描述；目标契约以 [`tools-spec.md`](tools-spec.md) 为准；本文件只回答“代码现在实现了什么、验证到了哪一步、还差什么”。`tools-spec.md` 中的 🟢/🟡/⚪ 表示契约成熟度，不表示代码完成度。

> Snapshot: 2026-08-14，base HEAD `f3f5a2d`；最近一次双架构 live MCP 验收完成于 2026-08-09，`disassemble` import 符号化的 x64 专项验收完成于 2026-08-14。统计先以实时 MCP `tools/list`、`resources/list`、`resources/templates/list` 为准，再与 `x64dbgMCP/x64dbgHandler.h` 中的注册和实现交叉核对；不是从根级 README 的产品清单反推。

## Coverage

| Surface | Contract target | Implemented / registered | Remaining |
|---|---:|---:|---:|
| Fixed Resources | 8 | 8 | 0 |
| Resource Templates | 5 | 5 | 0 |
| Reserved Resources | 6 | 0 | 6 |
| **All Resources** | **19** | **13** | **6** |
| Always-registered rich-param Tools | 6 | 2 | 4 |
| Analysis action-mega Tools | 6 | 0 | 6 |
| Debugger-domain Tools | 7 | 3 | 4 |
| **All Tools** | **19** | **5** | **14** |

### Runtime catalog

实时 `resources/list` 返回 8 个固定 Resources：`x64dbg://session`、`x64dbg://logging`、`x64dbg://process`、`x64dbg://memory/maps`、`x64dbg://threads`、`x64dbg://windows`、`x64dbg://handles`、`x64dbg://tcpconnections`。

实时 `resources/templates/list` 返回 5 个 Resource Templates：`x64dbg://modules{?offset,limit}`、`x64dbg://modules/{name}`、`x64dbg://modules/{name}/sections`、`x64dbg://modules/{name}/exports`、`x64dbg://modules/{name}/imports`。因此当前共有 13 个可读取 Resource 端点，但只有前 8 个出现在固定 Resource 列表中。

尚未注册的 6 个 reserved Resources 为：`x64dbg://symbols`、`x64dbg://functions`、`x64dbg://labels`、`x64dbg://comments`、`x64dbg://bookmarks`、`x64dbg://breakpoints`。

实时 `tools/list` 返回 5 个 MCP-visible Tools：常驻的 `disassemble`、`memory_read`，以及由调试领域目录门控的 `debug_control`、`registers`、`logging`。C++/CLI 方法使用 `PascalCase`，MCP C# SDK 2.1.0 默认把它们派生为上述 `snake_case` wire names。

其余 14 个目标 Tools 尚未实现：常驻 rich-param 的 `find_pattern`、`parse_expression`、`get_string_at`、`get_call_stack`；分析 action-mega 的 `symbols`、`functions`、`labels`、`comments`、`bookmarks`、`xrefs`；调试领域的 `breakpoints`、`memory`、`threads`、`assemble`。寄存器批量读取已由 `registers{action:"dump"}` 实现，契约不再重复保留 `get_register_dump`。

## Current milestone

当前里程碑实现了日志读写闭环：`x64dbg://logging` 在 GUI 线程调用 `GuiLogSave` 生成 UTF-8 临时快照，读取成功后删除；`logging{clear,put}` 分别调用 `GuiLogClear` 与 `_plugin_logputs`。相邻实现还包括：Process JSON 字段使用契约 wire names；modules Resource 支持 `offset/limit` 分页并区分列表项与详情链接；modules 从请求 URI 解析可选 query，绕开 C++/CLI 可选参数没有 CLR default constant 时的 `Missing.Value` 转换问题；`disassemble` 对不可读地址、反汇编失败和字节读取失败返回真实错误并带回 x64dbg comment，同时保留 canonical `operands`，对精确匹配模块 IAT 的内存引用增加可选 symbolized `display` 与 typed `reference`；`registers{dump}` 支持指定 `threadId`；MCP Server 只有在 Kestrel 成功绑定后才报告启动成功。

`enableDebugging` 的正式含义是“调试领域 Tool catalog / schema-budget 门控”，不是通用写权限。Resource 的正式边界是只读批量快照，Tool 的正式边界是单项精细读取、修改与控制；同一领域可以同时存在两种表面，但不得重复等价操作。见 [ADR-003](adr/003-tool-resource-action-three-layer.md)。

## Verification boundary

本轮使用以下真实目标完成双架构验收：x64dbg 调试带大型 PDB 的 Electron 32.2.8 x64，x32dbg 调试 `%SystemRoot%\SysWOW64\notepad.exe`。所有状态变更均在 Tool 返回后用相关 Resource 二次确认。

| Check | Status | Evidence / limit |
|---|---|---|
| Debug x64 build | Verified | `out/bin/x64-Debug/x64dbgMCP.dp64`, SHA-256 `BE1865A949213D17455C8F77D34CCDD367237F6BED57BC5D6164A6F1A7673DEF`, 2026-08-14 build succeeded with 0 errors |
| Debug Win32 build | Verified | `out/bin/win32-Debug/x64dbgMCP.dp32`, SHA-256 `B593046DE672394A3532F8F48F49F903727F5268A3D47BDD6B2EBC45FCDDCF89`, build succeeded with 0 errors |
| Full plugin deployment | Verified | Current x64 complete 11-file `OutputPath` set deployed with every source/deployed SHA-256 pair matched; x86 retains the 2026-08-09 equivalent result and was not rerun for the x64-only symbolization change |
| MCP catalog | Verified on x64 and x86 | Both returned the same 5 Tools, 8 fixed Resources, and 5 Resource Templates listed above |
| All current Resources | Verified on x64 and x86 | All 13 endpoints read successfully; modules default page and explicit `offset/limit` pagination passed on both architectures |
| Module children | Verified on x64 and x86 | Electron: 15 sections, 3163 exports, 652 imports; Notepad: 6 sections, empty exports, 312 imports |
| `disassemble` / `memory_read` | Verified on x64; previous baseline verified on x86 | Electron `electron:$47E98D2`: 15 instruction boundaries and all bytes matched the supplied 65-byte sequence; `memory_read(size=65)` matched continuously; the IAT call retained raw absolute operands and returned `RaiseException` display/reference across repeated calls before/after symbol loading; a non-IAT RIP-relative data reference remained unsymbolized; `count=201` returned contracted `invalid_argument` |
| LZ4 memory payload | Verified on x64 | A 256-byte raw read and compressed read were compared after `LZ4_decompress_safe`; decompressed bytes matched the raw payload exactly |
| `registers` | Verified on x64 and x86 | Active dump, get, set-to-same-value, architecture-specific register sets, paused inactive-thread dump, missing thread, and running-target `not_paused` paths passed |
| `debug_control` | Verified | `init`, `run`, `pause`, `stop`, `StepInto`, `StepOver`, `StepOut`, `run_command(wait=true)`, and invalid action covered; x32 `init` completed detached → attached → detached lifecycle |
| `logging` | Verified on x64 and x86 | After displaying the Log tab, `clear` → `put` → Resource read preserved exact Chinese UTF-8 text; empty `put` returned `invalid_argument` |
| Tool output schema | Known SDK boundary | Current `[McpServerTool]` annotations do not set `UseStructuredContent`; typed results are returned as JSON text content and are not advertised as `outputSchema` in `tools/list` |
| Logging snapshot boundary | Upstream-defined | `GuiLogSave` serializes the rendered `QTextDocument`; while the Log tab is hidden, x64dbg may retain newer messages in its private `logBuffer` until the tab is displayed and its flush timer runs |
| Electron PDB | Partially observable | Waited more than two minutes and x64dbg resource use stabilized, but the current MCP surface has no symbols Resource/Tool, so PDB symbol enumeration was not and cannot be claimed as verified |
| Release builds | Not rerun for this milestone | Current logging/pagination changes were validated in Debug builds; the previous Release result is not treated as current evidence |
| Server stop/restart and bind failure | Not rerun in this acceptance pass | `mcp.stop` → restart and occupied-port startup failure propagation remain outside the latest Tools/Resources acceptance matrix |

## Known conformance gaps

1. Per-module `_links.entry_disasm.tool` is currently emitted as the managed method name `Disassemble`, while MCP C# SDK 2.1.0 registers the wire name `disassemble`. The Resource payload is readable, but a case-sensitive client cannot invoke that link verbatim. Code must emit the wire name defined by [conventions.md](conventions.md#1-naming).
2. The six reserved Resources and fourteen target Tools listed under Coverage are not registered. Their presence in the root README describes the intended product surface, not current implementation.
3. General Symbol/PDB enumeration has no MCP-observable Resource/Tool contract yet. `disassemble` exposes only exact module-import/IAT references; large-PDB process stability is evidence about the host session only, not evidence that arbitrary symbols can be queried through MCP.

## Temporary experiment deviations

以下两项是用户确认保留的临时实验门控，不代表目标契约，也不应被后续实现当作默认行为：

- `plugintemplate/plugin.cpp` 中裸 `mcp.start` 当前令 `enableDebugging=true`；实验结束后恢复为正式默认值。
- `_DEBUG` 构建在插件初始化时自动调用 `mcp.start`；实验结束后移除。

## Next implementation order

1. 先修复现有 `_links.entry_disasm.tool` 的 wire-name 漂移，并增加目录/链接一致性检查，避免 Resource 导航指向不存在的 Tool。
2. 补齐常驻 rich-param 查询：`parse_expression` → `get_string_at` → `find_pattern` → `get_call_stack`。
3. 成对实现批量 Resource 与单项 Tool：symbols → labels → comments → bookmarks → functions；`xrefs` 只保留目标地址上的精细 Tool。Symbols 应包含可验证的 PDB 加载/枚举状态，使 Electron 大型 PDB 场景第一次具备 MCP 语义验收面。
4. 扩展调试领域目录：breakpoints Resource + `breakpoints` Tool → `memory` → `threads` → `assemble`。
5. 重验双架构 Release、`mcp.stop` → restart 和端口占用失败传播；在行为稳定后，为单测/集成测试策略新增 ADR，并把 live smoke cases 固化为可重复测试入口。

每一批继续遵守 Docs-first：先把 🟡/⚪ 契约收敛为可实施 schema，再改代码；若实现证据与基线冲突，按根级 `AGENTS.md` 要求先停止并对齐文档。
