# Implementation Status

本文件是开发完成度与验证边界的唯一来源。根级 [`README.md`](../README.md) 按最终产品能力描述；目标契约以 [`tools-spec.md`](tools-spec.md) 为准；本文件只回答“代码现在实现了什么、验证到了哪一步、还差什么”。`tools-spec.md` 中的 🟢/🟡/⚪ 表示契约成熟度，不表示代码完成度。

> Snapshot: 2026-08-17，base HEAD `060be7e`；最近一次双架构 live MCP 验收完成于 2026-08-09，`disassemble` import 符号化、breakpoints Resource 与 `memory{action:"read"}` 迁移的 x64 专项验收完成于 2026-08-14；breakpoints Tool 的首批 mutation 与统一 `get/disable/delete` 于 2026-08-17 完成 x64 live MCP 专项验收和 x86 build-only 验证。统计先以实时 MCP `tools/list`、`resources/list`、`resources/templates/list` 为准，再与 `x64dbgMCP/x64dbgHandler.h` 中的注册和实现交叉核对；不是从根级 README 的产品清单反推。

## Coverage

| Surface | Contract target | Implemented / registered | Remaining |
|---|---:|---:|---:|
| Fixed Resources | 8 | 8 | 0 |
| Resource Templates | 6 | 6 | 0 |
| Reserved Resources | 5 | 0 | 5 |
| **All Resources** | **19** | **14** | **5** |
| Always-registered rich-param Tools | 5 | 1 | 4 |
| Analysis action-mega Tools | 6 | 0 | 6 |
| Debugger-domain Tools | 7 | 5 | 2 |
| **All Tools** | **18** | **6** | **12** |

### Runtime catalog

实时 `resources/list` 返回 8 个固定 Resources：`x64dbg://session`、`x64dbg://logging`、`x64dbg://process`、`x64dbg://memory/maps`、`x64dbg://threads`、`x64dbg://windows`、`x64dbg://handles`、`x64dbg://tcpconnections`。

实时 `resources/templates/list` 返回 6 个 Resource Templates：`x64dbg://modules{?offset,limit}`、`x64dbg://modules/{name}`、`x64dbg://modules/{name}/sections`、`x64dbg://modules/{name}/exports`、`x64dbg://modules/{name}/imports`、`x64dbg://breakpoints{?offset,limit}`。因此当前共有 14 个可读取 Resource 端点，但只有前 8 个出现在固定 Resource 列表中。

尚未注册的 5 个 reserved Resources 为：`x64dbg://symbols`、`x64dbg://functions`、`x64dbg://labels`、`x64dbg://comments`、`x64dbg://bookmarks`。

实时 `tools/list` 返回 6 个 MCP-visible Tools：常驻的 `disassemble`，以及由调试领域目录门控的 `debug_control`、`breakpoints`、`registers`、`memory`、`logging`。`breakpoints` 当前公开 `get`、`set`、`set_hardware`、`disable`、`delete`；`get/disable/delete` 以可选 `kind=normal|hardware` 处理同址双断点歧义，旧 `delete_hardware` 已移除。独立 `memory_read` 已从目录移除，`memory` 当前只公开 `read` action。两个 action-mega Tool 的输入 Schema 均直接保留各 action 的平铺参数，没有嵌套 `params`。C++/CLI 方法使用 `PascalCase`，MCP C# SDK 2.1.0 默认把它们派生为上述 `snake_case` wire names。

其余 12 个目标 Tool definitions 尚未实现：常驻 rich-param 的 `find_pattern`、`parse_expression`、`get_string_at`、`get_call_stack`；分析 action-mega 的 `symbols`、`functions`、`labels`、`comments`、`bookmarks`、`xrefs`；调试领域的 `threads`、`assemble`。`breakpoints` 的 `set_batch`、`delete_batch` 与 `memory` 的 `write`、`alloc`、`free` 仍是 action 级缺口，不重复计为缺失 Tool definitions。寄存器批量读取已由 `registers{action:"dump"}` 实现，契约不再重复保留 `get_register_dump`。

## Current milestone

当前里程碑将 Breakpoints 收敛为 `breakpoints{get,set,set_hardware,disable,delete}`。`get/disable/delete` 在单次共享 `DbgGetBpList` snapshot 中查找 normal/hardware：唯一匹配时自动选择；同地址两类并存且未传 `kind` 时，在 side effect 前返回 `invalid_argument`；显式 `kind` 只操作目标类型。软件 mutation 使用 Script API；带 size 的硬件设置与硬件禁用分别使用同步官方 `SetHardwareBreakpoint` / `DisableHardwareBreakpoint` 命令；`breakCondition`、`logText`、`logCondition` 则使用 vendored Plugin SDK 的通用 `BP_REF` / `BpSetFieldText`，不经过 command parser，并在非空日志文本时显式写 `bpf_silent`。所有 mutation 都按选定类型和 canonical address 精确读回；删除只返回成功包络，但仍验证目标已不存在。硬件默认保持官方 `execute/size=1`，`access`/`write` 显式 opt-in，size/alignment/x86 qword/四槽限制在 side effect 前或失败结果中显式表达。此前里程碑还包括 `memory_read` → `memory{action:"read"}` 迁移和分页 `x64dbg://breakpoints` Resource；Resource 与 Tool 现共用一套 `BRIDGEBP` → `BreakpointEntry` 映射。

`enableDebugging` 的正式含义是“调试领域 Tool catalog / schema-budget 门控”，不是通用写权限。Resource 的正式边界是只读批量快照，Tool 的正式边界是单项精细读取、修改与控制；同一领域可以同时存在两种表面，但不得重复等价操作。见 [ADR-003](adr/003-tool-resource-action-three-layer.md)。

## Verification boundary

当前 memory 迁移与 breakpoints Resource/Tool 专项验收均使用 x64dbg 调试 Electron 32.2.8 x64；此前的完整双架构基线还包括 x32dbg 调试 `%SystemRoot%\SysWOW64\notepad.exe`。所有 breakpoints Tool 状态变更均在 Tool 返回后用 `x64dbg://breakpoints` 二次确认。

| Check | Status | Evidence / limit |
|---|---|---|
| Debug x64 build | Verified | `out/bin/x64-Debug/x64dbgMCP.dp64`, SHA-256 `E87643F24A80CA906DD65E52D62FA8C4D3DDD23FAB01FDB5EB4671C481F711D0`, 2026-08-17 CMake/MSBuild build succeeded with 0 errors (8 pre-existing C4945 reference warnings) |
| Debug Win32 build | Verified | `out/bin/win32-Debug/x64dbgMCP.dp32`, SHA-256 `D984AB79EDE180576611C8A5A1A73C6B3EAECDE9C55349229AE71355268C072A`, CMake/MSBuild build succeeded with 0 errors (same 8 C4945 warnings); current unified breakpoint behavior is build-only on x86 |
| Full plugin deployment | Verified | Current x64 complete 11-file `OutputPath` set deployed with every source/deployed SHA-256 pair matched; x86 was build-only in this milestone |
| MCP catalog | Verified on current x64 | Returned exactly `debug_control`, `breakpoints`, `registers`, `disassemble`, `memory`, `logging`. Live `breakpoints` Schema required only `action`, advertised exactly `get/set/set_hardware/disable/delete`, exposed direct optional `addr/kind/type/size/breakCondition/logText/logCondition`, and retained `type:"execute"` plus `size:1` defaults. `delete_hardware` was absent. Resources remained at 8 fixed plus 6 templates |
| Existing Resources | Previous baseline retained | The previous 13 endpoints and modules pagination passed on x64/x86; this milestone reran session/process plus the new breakpoints Resource rather than the full pre-existing Resource matrix |
| `x64dbg://breakpoints` | Verified on x64 | Electron database returned the expected 11 normal + 1 execute-hardware breakpoints with exact addresses, one-shot/enabled state, names, hit counts, break/log/command fields, and `hardwareSize/Slot`; joining each address to `disassemble(count=1)` reproduced all 12 instruction rows. Temporary execute-memory, DLL-load, and first-chance exception breakpoints proved all five type/subtype mappings and were precisely deleted; total returned from 15 to 12. Pages `5/5/2`, next/prev links, negative-offset normalization, and `limit=500` clamping to 100 passed |
| `breakpoints` Tool | Verified on current x64 | Against the specified Electron 32.2.8 target (single-type paths on PID 26048; same-address paths on PID 9120), omitted `kind` completed normal and hardware `get → disable → delete`, including hardware readback `enabled:false`, and each final `get` returned `not_found`. At `electron:$30`, normal and hardware breakpoints coexisted: omitted-kind `get/disable/delete` all returned `invalid_argument`; typed reads returned both entries; `kind=hardware` disabled only hardware while normal remained enabled; `kind=normal` deleted only normal; omitted-kind `get/delete` then auto-selected the sole disabled hardware entry. Deprecated `delete_hardware` returned unknown-action `invalid_argument`. The final Resource snapshot returned to the original 10 normal and 0 hardware entries. Earlier condition/log/type/size/slot/error and UTF-8/special-text evidence remains valid for the same implementation family |
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
| Release builds | Not rerun for this milestone | Current breakpoints Tool changes were validated in Debug builds; the previous Release result is not treated as current evidence |
| Server stop / cleanup | Partially verified | Final `debug_control{stop}` was followed by `x64dbg://session.isDebugging=false` and tracked Electron PID 9008 exit; graceful close of tracked x64dbg PID 13296 ran `pluginStop` and removed its 3001 listener without a forced kill. Plugin/server restart was exercised during redeployment; occupied-port failure propagation was not rerun |

## Known conformance gaps

1. Per-module `_links.entry_disasm.tool` is currently emitted as the managed method name `Disassemble`, while MCP C# SDK 2.1.0 registers the wire name `disassemble`. The Resource payload is readable, but a case-sensitive client cannot invoke that link verbatim. Code must emit the wire name defined by [conventions.md](conventions.md#1-naming).
2. The five reserved Resources and twelve target Tool definitions listed under Coverage are not registered. Their presence in the root README describes the intended product surface, not current implementation.
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
4. 扩展调试领域目录：`memory{write,alloc,free}` → `threads` → `assemble`；breakpoints 的批量 Resource 与五个首批 mutation actions、`memory{read}` 已完成。
5. 重验双架构 Release、`mcp.stop` → restart 和端口占用失败传播；在行为稳定后，为单测/集成测试策略新增 ADR，并把 live smoke cases 固化为可重复测试入口。

每一批继续遵守 Docs-first：先把 🟡/⚪ 契约收敛为可实施 schema，再改代码；若实现证据与基线冲突，按根级 `AGENTS.md` 要求先停止并对齐文档。
