# 2026-10-26 — Electron 27.3.0 / mcpc 全表面闭环验证

验收时间：2026-10-26T14:53:10+08:00。结果：**部分通过**。当前 8 个 Tool 的所有已实现动作、8 个固定 Resource 和 9 个 Resource Template 均已实际触达；明确选择 Electron 主线程后的 20 轮 run/pause 与 Resource 交叉验证通过。未指定活动线程的暂停失败场景、flag 输入示例差异和可见日志页验证限制均保留，不声明无条件全绿。

本次使用 HEAD `41654f59afab128329ee45413feffdfed8bb2910`，未修改生产代码。CMake 的 `deploy_x64dbg_plugin` 构建并部署 x64 Release，0 错误、28 条 C4945 警告，11 个输出文件与部署文件的大小和 SHA-256 一致。插件 SHA-256 为 `F6F4C6C1ED4DB27FEEF788E0371F5A0DEFA1E85C7EEA03A3AAD0E3E2316F3BDD`。样本为用户指定路径的 Electron 27.3.0，SHA-256 为 `2D6D281AB0974DE5B8D88DA1B258D04807E423FFD4DB1A977D7F4CB9960038D5`。

验证通过的范围包括干净 init、3 轮 stop/reinit、attach 与显式双进程切换、三种单步、断点全部现有动作与 Resource 回读、寄存器/非活动线程、raw/lz4 内存与原生独立读取、反汇编机器码与 IAT 符号化、三种 xref 命中、三面板 GUI 操作和截图、全部 Resource 领域与分页、9 项路由/Origin 检查，以及关闭调试目录后的分析能力。生命周期收尾验证通过 `mcp.stop` 端口释放、测试进程退出和原有三份 Electron 数据库文件的 SHA-256 精确恢复。

需保留的边界：普通 `pause` 的 queued success 曾未在 20 秒内收敛为暂停，直接 pause 返回失败；恢复线程并选定 `CrBrowserMain` 后 20 轮通过。文档输入示例 `zf` 返回 `not_found`，原生 `_zf` get/set/dump 通过。字符串 URI 的查询参数按发布模板顺序展开时通过，反序被 SDK 路由拒绝。原有数据库恢复的命令行会覆盖新 init 参数，干净实例复验通过。日志 clear/put 与文本 Resource 基础操作通过，但显示 Log 页后的新增行回读因 Computer Use native pipe 不可用而 BLOCKED。本次没有执行 x86 live 验证。

完整证据位于 [本轮报告](../../.codex-tracking/research/2026-10-26-electron-validation/report.md)，包括 [统计与清理结果](../../.codex-tracking/research/2026-10-26-electron-validation/summary.json)、[构建部署证据](../../.codex-tracking/research/2026-10-26-electron-validation/deployment.json)、[原生内存交叉验证](../../.codex-tracking/research/2026-10-26-electron-validation/native-memory-verification.json) 和 [CMake 重放入口](../../.codex-tracking/research/2026-10-26-electron-validation/README.md)。原始记录包含 1465 次编号 mcpc 交互，其中 session 读取 352 次、session/debuggee 读取 329 次；收尾请求另存 `lifecycle.json`。探索夹具的错误假设与对应修正复验也保留在报告中，未作为生产故障累计。
