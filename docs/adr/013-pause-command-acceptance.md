# ADR-013: 回传原生 pause 命令拒绝

- **Status**: Accepted
- **Date**: 2026-10-27
- **Deciders**: @nblog

## 背景

2026-10-26 的 Electron 验证发现 `pause` 入队成功后，目标仍持续运行；直接调用原生命令则返回失败。原生 [`cbDebugPause`](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/commands/cmd-debug-control.cpp#L390-L448) 会拒绝已挂起的活动线程，也可能在内部断点设置时失败。只报告入队成功会隐藏这些错误。用户已授权实施验证后续修复，并继续用 Resource 确认最终状态。

## 决策

`debug_control{action:"pause"}` 通过 `DbgCmdExecDirect` 调用原生 pause 命令，在 handler 拒绝时返回 `x64dbg_failed`。成功表示原生 handler 已接受暂停请求，不承诺暂停事件已经到达；客户端仍需读取 session 的 `isRunning` 和 debuggee 身份。已暂停目标上的重复 pause 遵循原生拒绝语义。命令分发后的状态快照在成功或失败时都描述实际会话。

Tool 不等待下一个调试事件，不自动切换活动线程，也不自动恢复线程。其它控制动作的调度策略保持原状：run/init/stop/Step* 入队，attach 使用既有直接路径，run_command 由 wait 参数决定。因此仍遵守 conventions §9 禁止请求线程等待暂停事件的边界。

## 后果

可复现的原生命令拒绝通过已有 envelope 暴露，不增加参数、错误码或返回模型。客户端分别处理原生拒绝和最终状态超时。回归必须明确挂起所选测试线程，验证 pause 返回失败且目标身份未变，再恢复同一线程，通过 Resource 验证正常暂停；不把测试恢复动作变成生产 Tool 的静默行为。

## 考虑过的替代方案

1. 继续只报告入队成功：会隐藏已复现的运行错误。
2. Tool 内等待最终暂停：存在阻塞/死锁风险，且需要不同的取消和超时契约。
3. 自动选择或恢复其它线程：会修改用户控制的调试状态，掩盖失败条件。

## 参考

- [2026-10-26 验收](../validate/2026-10-26-electron27-mcpc.md)
- [Conventions §9](../conventions.md#9-threading)
- [DebugControl 契约](../tools-spec.md#debug_controlinit-attach-stop-run-pause-step-run_command-)
