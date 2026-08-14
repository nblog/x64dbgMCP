# Implementation Status

本文件是开发完成度与验证边界的唯一来源。根级 [`README.md`](../README.md) 按最终产品能力描述；目标契约以 [`tools-spec.md`](tools-spec.md) 为准；本文件只回答“代码现在实现了什么、验证到了哪一步、还差什么”。`tools-spec.md` 中的 🟢/🟡/⚪ 表示契约成熟度，不表示代码完成度。

> Snapshot: 2026-08-14，base HEAD `857d7af`；最近一次双架构 live MCP 验收完成于 2026-08-09，`disassemble` import 符号化、breakpoints Resource 与 `memory{action:"read"}` 迁移的 x64 专项验收完成于 2026-08-14。统计先以实时 MCP `tools/list`、`resources/list`、`resources/templates/list` 为准，再与 `x64dbgMCP/x64dbgHandler.h` 中的注册和实现交叉核对；不是从根级 README 的产品清单反推。

## Coverage

| Surface | Contract target | Implemented / registered | Remaining |
|---|---:|---:|---:|
| Fixed Resources | 8 | 8 | 0 |
| Resource Templates | 6 | 6 | 0 |
| Reserved Resources | 5 | 0 | 5 |
| **All Resources** | **19** | **14** | **5** |
| Always-registered rich-param Tools | 5 | 1 | 4 |
| Analysis action-mega Tools | 6 | 0 | 6 |
| Debugger-domain Tools | 7 | 4 | 3 |
| **All Tools** | **18** | **5** | **13** |

### Runtime catalog

实时 `resources/list` 返回 8 个固定 Resources：`x64dbg://session`、`x64dbg://logging`、`x64dbg://process`、`x64dbg://memory/maps`、`x64dbg://threads`、`x64dbg://windows`、`x64dbg://handles`、`x64dbg://tcpconnections`。

实时 `resources/templates/list` 返回 6 个 Resource Templates：`x64dbg://modules{?offset,limit}`、`x64dbg://modules/{name}`、`x64dbg://modules/{name}/sections`、`x64dbg://modules/{name}/exports`、`x64dbg://modules/{name}/imports`、`x64dbg://breakpoints{?offset,limit}`。因此当前共有 14 个可读取 Resource 端点，但只有前 8 个出现在固定 Resource 列表中。

尚未注册的 5 个 reserved Resources 为：`x64dbg://symbols`、`x64dbg://functions`、`x64dbg://labels`、`x64dbg://comments`、`x64dbg://bookmarks`。

实时 `tools/list` 返回 5 个 MCP-visible Tools：常驻的 `disassemble`，以及由调试领域目录门控的 `debug_control`、`registers`、`memory`、`logging`。独立 `memory_read` 已从目录移除；`memory` 当前只公开 `read` action，其输入 Schema 直接保留 `addr`、`size`、`compress`，没有嵌套 `params`。C++/CLI 方法使用 `PascalCase`，MCP C# SDK 2.1.0 默认把它们派生为上述 `snake_case` wire names。

其余 13 个目标 Tool definitions 尚未实现：常驻 rich-param 的 `find_pattern`、`parse_expression`、`get_string_at`、`get_call_stack`；分析 action-mega 的 `symbols`、`functions`、`labels`、`comments`、`bookmarks`、`xrefs`；调试领域的 `breakpoints`、`threads`、`assemble`。`memory` definition 已注册，但 `write`、`alloc`、`free` 仍是 action 级缺口，不重复计为缺失 Tool definitions。寄存器批量读取已由 `registers{action:"dump"}` 实现，契约不再重复保留 `get_register_dump`。

## Current milestone

当前里程碑把早期独立实现的 `memory_read(addr,size,compress?)` 迁入统一的 `memory{action:"read"}`：MCP 参数、64 KiB 上限、base64/LZ4 wire shape 与 `MemoryReadResult` 保持不变，独立 Tool definition 被删除，读取入口随 memory family 进入 `enableDebugging` 目录。此前同一里程碑还新增了分页 `x64dbg://breakpoints`：通过 `DbgGetBpList(bp_none, ...)` 一次枚举 normal、hardware、memory、DLL、exception 五类断点，在 managed snapshot 形成后释放 `BPMAP.bp`；`typeEx` 按主类型归一化为稳定字符串，DLL 内部模块哈希不伪装成地址，exception code 使用独立字段。session/process 导航根已增加 breakpoints 链接。相邻实现还包括：`x64dbg://logging` 与 `logging{clear,put}` 的日志读写闭环；Process JSON wire names；modules `offset/limit` 分页与查询解析；`disassemble` 的真实错误、canonical `operands` 及稳定 IAT import display/reference；`registers{dump}` 指定线程；Kestrel 成功绑定后才报告 MCP Server 启动成功。

`enableDebugging` 的正式含义是“调试领域 Tool catalog / schema-budget 门控”，不是通用写权限。Resource 的正式边界是只读批量快照，Tool 的正式边界是单项精细读取、修改与控制；同一领域可以同时存在两种表面，但不得重复等价操作。见 [ADR-003](adr/003-tool-resource-action-three-layer.md)。

## Verification boundary

当前 memory 迁移与 breakpoints 专项验收均使用 x64dbg 调试 Electron 32.2.8 x64；此前的完整双架构基线还包括 x32dbg 调试 `%SystemRoot%\SysWOW64\notepad.exe`。所有状态变更均在 Tool 返回后用相关 Resource 二次确认。

| Check | Status | Evidence / limit |
|---|---|---|
| Debug x64 build | Verified | `out/bin/x64-Debug/x64dbgMCP.dp64`, SHA-256 `2BB92D949215F79CB33B0A4D3CD5573370666BBA65ACB717B4DE165693F34B7F`, 2026-08-14 CMake/MSBuild build succeeded with 0 errors |
| Debug Win32 build | Verified | `out/bin/win32-Debug/x64dbgMCP.dp32`, SHA-256 `A9BE3A386901AB04EFD5ABDD32BEE3C55B288DDCF9D857E89387B3DABC2EE146`, CMake/MSBuild build succeeded with 0 errors; memory migration and breakpoints live behavior were not rerun on x86 |
| Full plugin deployment | Verified | Current x64 complete 11-file `OutputPath` set deployed with every source/deployed SHA-256 pair matched; x86 was build-only in this milestone |
| MCP catalog | Verified on current x64 | Returned exactly `debug_control`, `registers`, `disassemble`, `memory`, `logging`; `memory_read` was absent and a direct legacy invocation returned `Unknown tool` with mcporter exit code 1. Resources remained at 8 fixed plus the 6 templates listed above |
| Existing Resources | Previous baseline retained | The previous 13 endpoints and modules pagination passed on x64/x86; this milestone reran session/process plus the new breakpoints Resource rather than the full pre-existing Resource matrix |
| `x64dbg://breakpoints` | Verified on x64 | Electron database returned the expected 11 normal + 1 execute-hardware breakpoints with exact addresses, one-shot/enabled state, names, hit counts, break/log/command fields, and `hardwareSize/Slot`; joining each address to `disassemble(count=1)` reproduced all 12 instruction rows. Temporary execute-memory, DLL-load, and first-chance exception breakpoints proved all five type/subtype mappings and were precisely deleted; total returned from 15 to 12. Pages `5/5/2`, next/prev links, negative-offset normalization, and `limit=500` clamping to 100 passed |
| Module children | Verified on x64 and x86 | Electron: 15 sections, 3163 exports, 652 imports; Notepad: 6 sections, empty exports, 312 imports |
| `disassemble` | Previous x64/x86 baseline retained | Electron `electron:$47E98D2`: 15 instruction boundaries and all bytes matched the supplied 65-byte sequence; the IAT call retained raw absolute operands and returned `RaiseException` display/reference across repeated calls before/after symbol loading; a non-IAT RIP-relative data reference remained unsymbolized; `count=201` returned contracted `invalid_argument` |
| `memory{action:"read"}` | Verified on current x64; build-only on x86 | Live Schema required only `action` and exposed direct optional `addr/size/compress`. Reading `electron:$0,size=256` resolved to `0x7FF7159D0000`; the raw bytes SHA-256 `065CC4CE27F8E70FA81149B80824FBCCB6319943A72F09B98168B8D2E7EC20DD` exactly matched an independent Win32 `ReadProcessMemory` read from Electron PID 45300. `action=write` and `size=65537` returned `invalid_argument`; an invalid expression returned `not_found` |
| LZ4 memory payload | Verified on current x64 | The same 256-byte window compressed to 187 bytes; `LZ4_decompress_safe` returned 256 and the decompressed SHA-256 exactly matched the raw payload |
| `registers` | Verified on x64 and x86 | Active dump, get, set-to-same-value, architecture-specific register sets, paused inactive-thread dump, missing thread, and running-target `not_paused` paths passed |
| `debug_control` | Verified | `init`, `run`, `pause`, `stop`, `StepInto`, `StepOver`, `StepOut`, `run_command(wait=true)`, and invalid action covered; x32 `init` completed detached → attached → detached lifecycle |
| `logging` | Verified on x64 and x86 | After displaying the Log tab, `clear` → `put` → Resource read preserved exact Chinese UTF-8 text; empty `put` returned `invalid_argument` |
| Tool output schema | Known SDK boundary | Current `[McpServerTool]` annotations do not set `UseStructuredContent`; typed results are returned as JSON text content and are not advertised as `outputSchema` in `tools/list` |
| Logging snapshot boundary | Upstream-defined | `GuiLogSave` serializes the rendered `QTextDocument`; while the Log tab is hidden, x64dbg may retain newer messages in its private `logBuffer` until the tab is displayed and its flush timer runs |
| Electron PDB | Partially observable | Waited more than two minutes and x64dbg resource use stabilized, but the current MCP surface has no symbols Resource/Tool, so PDB symbol enumeration was not and cannot be claimed as verified |
| Release builds | Not rerun for this milestone | Current logging/pagination changes were validated in Debug builds; the previous Release result is not treated as current evidence |
| Server stop / cleanup | Partially verified | `debug_control{stop}` was followed by `x64dbg://session.isDebugging=false` and Electron PID 45300 exit; `run_command("mcp.stop")` removed the PID-owned 3001 listener. Restart and occupied-port failure propagation were not rerun |

## Known conformance gaps

1. Per-module `_links.entry_disasm.tool` is currently emitted as the managed method name `Disassemble`, while MCP C# SDK 2.1.0 registers the wire name `disassemble`. The Resource payload is readable, but a case-sensitive client cannot invoke that link verbatim. Code must emit the wire name defined by [conventions.md](conventions.md#1-naming).
2. The five reserved Resources and thirteen target Tool definitions listed under Coverage are not registered. Their presence in the root README describes the intended product surface, not current implementation.
3. The registered `memory` Tool currently implements only `read`; target actions `write`, `alloc`, and `free` remain undispatched and are deliberately excluded from its live description.
4. General Symbol/PDB enumeration has no MCP-observable Resource/Tool contract yet. `disassemble` exposes only exact module-import/IAT references; large-PDB process stability is evidence about the host session only, not evidence that arbitrary symbols can be queried through MCP.

## Temporary experiment deviations

以下两项是用户确认保留的临时实验门控，不代表目标契约，也不应被后续实现当作默认行为：

- `plugintemplate/plugin.cpp` 中裸 `mcp.start` 当前令 `enableDebugging=true`；实验结束后恢复为正式默认值。
- `_DEBUG` 构建在插件初始化时自动调用 `mcp.start`；实验结束后移除。

## Next implementation order

1. 先修复现有 `_links.entry_disasm.tool` 的 wire-name 漂移，并增加目录/链接一致性检查，避免 Resource 导航指向不存在的 Tool。
2. 补齐常驻 rich-param 查询：`parse_expression` → `get_string_at` → `find_pattern` → `get_call_stack`。
3. 成对实现批量 Resource 与单项 Tool：symbols → labels → comments → bookmarks → functions；`xrefs` 只保留目标地址上的精细 Tool。Symbols 应包含可验证的 PDB 加载/枚举状态，使 Electron 大型 PDB 场景第一次具备 MCP 语义验收面。
4. 扩展调试领域目录：`breakpoints` Tool → `memory{write,alloc,free}` → `threads` → `assemble`；breakpoints 的批量 Resource 与 `memory{read}` 已完成。
5. 重验双架构 Release、`mcp.stop` → restart 和端口占用失败传播；在行为稳定后，为单测/集成测试策略新增 ADR，并把 live smoke cases 固化为可重复测试入口。

每一批继续遵守 Docs-first：先把 🟡/⚪ 契约收敛为可实施 schema，再改代码；若实现证据与基线冲突，按根级 `AGENTS.md` 要求先停止并对齐文档。
