# Implementation Status

本文件是开发完成度与验证边界的唯一来源。根级 [`README.md`](../README.md) 按最终产品能力描述；目标契约以 [`tools-spec.md`](tools-spec.md) 为准；本文件只回答“代码现在实现了什么、验证到了哪一步、下一批做什么”。`tools-spec.md` 中的 🟢/🟡/⚪ 表示契约成熟度，不表示代码完成度。

> Snapshot: 2026-08-09. 统计依据为 `x64dbgMCP/x64dbgHandler.h` 中实际注册的 `[McpServerResource]` 与 `[McpServerTool]`，不是 README 功能清单。

## Coverage

| Surface | Contract target | Implemented | Remaining |
|---|---:|---:|---:|
| Resources | 19 | 13 | 6 |
| Rich-param Tools | 7 | 2 | 5 |
| Analysis mega-tools | 6 | 0 | 6 |
| Debugger-domain mega-tools | 7 | 3 | 4 |
| **All Tools** | **20** | **5** | **15** |

当前实现的 13 个 Resources 为：`x64dbg://session`、`x64dbg://logging`、`x64dbg://process`、`x64dbg://modules`、`x64dbg://modules/{name}`、`x64dbg://modules/{name}/sections`、`x64dbg://modules/{name}/exports`、`x64dbg://modules/{name}/imports`、`x64dbg://memory/maps`、`x64dbg://threads`、`x64dbg://windows`、`x64dbg://handles`、`x64dbg://tcpconnections`。

尚未实现的 6 个 reserved Resources 为：`x64dbg://symbols`、`x64dbg://functions`、`x64dbg://labels`、`x64dbg://comments`、`x64dbg://bookmarks`、`x64dbg://breakpoints`。

当前实现的 5 个 Tools 为：常驻的 `Disassemble`、`MemoryRead`，以及由调试领域目录门控的 `DebugControl`、`Registers`、`Logging`。其余 15 个目标 Tools 尚未实现：`FindPattern`、`ParseExpression`、`GetStringAt`、`GetCallStack`、`GetRegisterDump`；`Symbols`、`Functions`、`Labels`、`Comments`、`Bookmarks`、`Xrefs`；`Breakpoints`、`Memory`、`Threads`、`Assemble`。

## Current milestone

本里程碑在既有能力对齐的基础上实现了日志读写闭环：`x64dbg://logging` 通过 GUI 线程上的 `GuiLogSave` 生成 UTF-8 临时文件，读取成功后立即删除，`Logging{clear,put}` 分别直接调用 `GuiLogClear` 与 `_plugin_logputs`。已完成的相邻契约修复包括：Process JSON 字段采用契约命名；modules Resource 支持 `offset/limit` 分页并区分列表项与详情链接；由于 C++/CLI 不会为原可选参数生成 CLR default constant，modules 从请求 URI 解析可选 query，避免 MCP SDK 在启动或读取默认页时把 `Missing.Value` 转换为 `Int32`；`Disassemble` 对不可读地址、反汇编失败和字节读取失败返回真实错误，并填充 x64dbg comment；`Registers{dump}` 支持指定 `threadId`；MCP Server 只有在 Kestrel 成功绑定后才报告启动成功。

`enableDebugging` 的正式含义已经对齐为“调试领域 Tool catalog / schema-budget 门控”，不是通用写权限。Resource 的正式边界是只读批量快照，Tool 的正式边界是单项精细读取、修改与控制；同一领域可以同时存在两种表面，但不得重复等价操作。见 [ADR-003](adr/003-tool-resource-action-three-layer.md)。

## Verification boundary

| Check | Status | Evidence / limit |
|---|---|---|
| Debug x64 build | Verified | `out/bin/x64-Debug/x64dbgMCP.dp64`, SHA-256 `0AB0028DE673B82B0436FC5487173B2C3F8D27349CAC3167778F346E10BF6B66`, 0 errors / 8 known warnings |
| Debug Win32 build | Verified | `out/bin/win32-Debug/x64dbgMCP.dp32`, SHA-256 `6AE87ED155AE84A50379AF8D756D17EE30568D2C9D2F2580ECF7ED0DA898DB4C`, 0 errors / 8 known warnings |
| Full plugin deployment | Verified | x64 and x86 complete 11-file `OutputPath` sets deployed; every source/deployed SHA-256 pair matched |
| MCP startup / catalog | Verified on x64 and x86 | Debug auto-start reached a live `localhost:3001` listener; mcporter discovered `logging`; the previous `System.Int32` schema-generation failure no longer occurs |
| Modules optional query routing | Verified on x64 and x86 | `x64dbg://modules` returned defaults `offset=0,limit=100`; `?offset=0&limit=1` passed on both architectures; x64 additionally passed `?limit=1` and `?offset=2` |
| Logging live round trip | Verified on x64 and x86 | mcporter `logging action=put` preserved Chinese UTF-8 text in `x64dbg://logging`; `action=clear` returned success and the following snapshot was empty |
| Logging temporary-file behavior | Verified on x64 and x86 | File-system events observed `tmpa53asj.tmp` (x64) and `tmpe5eme1.tmp` (x86) being created and then deleted during successful Resource reads; `%TEMP%\\tmp*.tmp` remained at the pre-existing count of 24 after each call, with no new snapshot left behind |
| Logging snapshot boundary | Upstream-defined | `GuiLogSave` serializes the rendered `QTextDocument`; while the Log tab is hidden, x64dbg may retain newer messages in its private `logBuffer` until the tab is displayed and its flush timer runs |
| Release builds | Not rerun for this milestone | The prior milestone passed x64/Win32 Release, but the new logging implementation was validated only in Debug builds |

当前编译仍有仓库已知的 .NET 10 `C4945` 重复类型导入警告；本里程碑的双架构 Debug 构建各为 0 errors / 8 warnings。尚未在本轮重验的既有行为包括：端口占用失败传播；`Disassemble` 的可读/不可读地址、comment 与 `withBytes`；`Registers{dump}` 的活动线程、暂停时的非活动线程以及运行时的 `not_paused`；`mcp.stop` 后重启。

## Temporary experiment deviations

以下两项是用户确认保留的临时实验门控，不代表目标契约，也不应被后续实现当作默认行为：

- `plugintemplate/plugin.cpp` 中裸 `mcp.start` 当前令 `enableDebugging=true`；实验结束后恢复为正式默认值。
- `_DEBUG` 构建在插件初始化时自动调用 `mcp.start`；实验结束后移除。

## Next implementation order

下一批优先完成当前里程碑的 live MCP 验收，因为它能直接验证启动失败传播、SDK URI-template 路由和 Win32 thread-context 边界。随后按最小可验证批次实施：

1. 补齐常驻 rich-param 查询：`ParseExpression` → `GetStringAt` → `FindPattern` → `GetCallStack` → `GetRegisterDump`。
2. 成对实现批量 Resource 与单项 Tool：symbols → labels → comments → bookmarks → functions；`Xrefs` 只保留目标地址上的精细 Tool。
3. 扩展调试领域目录：breakpoints Resource + `Breakpoints` Tool → `Memory` → `Threads` → `Assemble`。
4. 在行为稳定后，为单测/集成测试策略新增 ADR，并把 live smoke cases 固化为可重复测试入口。

每一批继续遵守 Docs-first：先把 🟡/⚪ 契约收敛为可实施 schema，再改代码；若实现证据与基线冲突，按根级 `AGENTS.md` 要求先停止并对齐文档。
