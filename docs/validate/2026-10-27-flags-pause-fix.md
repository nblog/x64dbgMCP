# 2026-10-27 — 公开 flag 名称与 pause 拒绝回归

验收时间：2026-10-27T09:45:51+08:00。分支 `fix/register-flags-validation`，基线 HEAD `41654f59afab128329ee45413feffdfed8bb2910` 加本轮工作区变更。结果：**27 个用例通过，0 个失败，1 个日志可见页用例因环境受阻**；另外 9 项 HTTP 路由/Origin 检查、原生内存比对、生命周期与数据库恢复通过。

公开 flag 名称适配已通过九项 get/set/dump 与独立 EFLAGS 位值交叉、大小写、兼容输入的 canonical 输出、非零写入实际 boolean 回读及原值恢复。`zf` 输入返回 `name:"zf"`，客户端无需在名称参数上使用原生 `_zf`。一般寄存器/表达式保持既有路径。

pause 的已暂停目标拒绝与明确挂起的活动线程拒绝均返回 `x64dbg_failed`，分发后的错误状态快照与 session/debuggee 一致；测试恢复同一线程后正常暂停通过。明确选定主线程后的 20 轮 run/pause 与领域 Resources 交叉全部通过。现有 8 Tool、8 固定 Resource、9 Template 已复验，含单步、实际断点命中、IAT/xrefs、内存/字符串、GUI、3 轮 stop/reinit、attach 与显式双进程切换及未附加行为。

CMake x64 Release 构建并完整部署 11 个文件，大小与 SHA-256 一致；Win32 Release 构建检查通过。最终构建均 0 错误、8 条 C4945 警告。插件 SHA-256 为 x64 `7C13CDE63AA136A4FC8AE2A3A1BDE9699F235BF26CC3B1B5A288815F327B7F0A`，Win32 `4F0D3E51F267FD9A261D8CD92871F9CB8D7C18AB1CD156D4377CBA6B08547CCC`。样本为指定路径的 Electron 27.3.0 x64。

日志 clear/put 与 Resource 基础读取通过，Log 可见页新增文本回读因 Computer Use native pipe 不可用而 BLOCKED。Win32 没有本轮 live 验证。测试宿主、样本和 mcpc 会话已退出，3001 无监听；原有三份 Electron 数据库文件的恢复哈希与本轮备份一致。

完整证据见 [本轮报告](../../.codex-tracking/research/2026-10-27-flags-pause-fix/report.md)、[汇总与用例范围](../../.codex-tracking/research/2026-10-27-flags-pause-fix/summary.json)、[具体 wire 返回](../../.codex-tracking/research/2026-10-27-flags-pause-fix/regression-examples.json)、[原生内存交叉](../../.codex-tracking/research/2026-10-27-flags-pause-fix/native-memory-verification.json) 和 [CMake 入口](../../.codex-tracking/research/2026-10-27-flags-pause-fix/README.md)。本轮保存 965 次编号 mcpc 交互（session 204 次，debuggee 182 次），收尾请求另存 lifecycle.json。
