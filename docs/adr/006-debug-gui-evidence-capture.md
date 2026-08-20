# ADR-006: `DebugGUI` GUI 取证与 CPU 子窗口选区控制

- **Status**: Accepted
- **Date**: 2026-08-20
- **Deciders**: @nblog

## Context

x64dbgMCP 已能用结构化 Tool / Resource 返回调试器状态，但还不能保留调查者在 x64dbg GUI 中实际看到的画面。一个典型取证流程是：先根据分析结果找到可疑地址范围，让 CPU 页面显示并选中该范围，再截取 x64dbg 窗口。结构化数据仍是语义来源，截图则增加一份可供人工复核、留存并计算摘要的可视化证据。

v0 基线曾有意排除 PoC 阶段的 `GuiSelectionGet/Set`、`GuiFocusView` 和 `GuiRefresh` Tool，因为把每个 GUI 原语 1:1 暴露会让 Agent 承担脆弱的 UI 编排。当前需求是完整取证流程，而不是恢复这些低层 Tool。MCP 支持原生图像内容，固定使用的 C# SDK 也能让 `CallToolResult` 同时携带 typed JSON text 与 `ImageContentBlock`。vendored x64dbg SDK 则提供主窗口句柄、CPU 视图导航、子窗口聚焦、刷新、事件处理与选区 API，可以组合出所需工作流。

## Decision

新增一个调试领域 action-mega Tool：managed 方法名为 `DebugGUI`，MCP-visible wire name 为 `debug_gui`。它与现有调试领域目录一致，仅在 `enableDebugging=true` 时注册。`DebugGUI` 包含四个 action：

| Action | 契约 |
|---|---|
| `snapshot` | 把完整 x64dbg 主窗口捕获为 PNG。可选 `save_path` 选择文件交付；省略时返回 MCP 图像块。 |
| `focus` | 激活 CPU 页面，聚焦一个受支持的子窗口，调用 `Script::Gui::Refresh()`，再清空待处理 GUI 事件。`window` 缺省为 `Disassembly`。 |
| `get` | 在不改变选区的前提下，读取指定 CPU 子窗口的当前闭区间选区。 |
| `set` | 解析并导航到闭区间地址范围，设置并聚焦子窗口，刷新和处理 GUI 事件，然后回读实际选区。 |

第一版只支持三个规范化 `window` 值：`Disassembly`、`Dump`、`Stack`，分别映射到 `GUI_DISASSEMBLY`、`GUI_DUMP`、`GUI_STACK`。不接受任意 x64dbg window enum。

### Snapshot artifact variants

`snapshot` 在两种模式下都返回 typed metadata，其中 `artifact` 是 discriminated union：

- 未传 `save_path`：`artifact.type="image"`、`artifact.mimeType="image/png"`，Tool result 另外包含一个承载 PNG bytes 的 MCP `ImageContentBlock`。
- 传入 `save_path`：`artifact.type="file"`、`artifact.mimeType="image/png"`，`artifact.path` 为规范化后的主机路径。Tool 把 PNG 写入该路径，**不再**附带 inline image data。

MIME type 描述 artifact 的媒体格式，所以两种模式都是 `image/png`；交付形式由独立的 `type` discriminator 表达，不能只靠 MIME 区分。

`save_path` 必须是运行 x64dbg 的主机上的绝对 `.png` 文件路径，父目录必须已经存在。Tool 以新文件方式创建，拒绝覆盖已有路径。只有完整写入才返回成功；失败时实现应尽可能移除残留的部分文件，并且不能静默回退到 inline 交付。远程 MCP 客户端不一定能直接访问这个主机路径。

metadata 包含 UTC 捕获时间、尺寸、x64dbg 窗口标题、当前 debuggee PID（detached 时为 0）、PNG 原始 bytes 的 SHA-256，以及 artifact discriminator。摘要只能证明后续文件或 inline payload 与本次捕获逐字节一致；它不能认证调试器、画面内容或生成它的机器，也不是可信时间戳。

### Selection semantics

`start` 与 `end` 都是 x64dbg expression string。`set` 必须在改变 GUI 状态前解析完所有输入；范围为闭区间，显式 `end` 解析后必须大于或等于 `start`。

省略 `end` 时，requested end 使用解析后的 `start`。不向 x64dbg 传数值 sentinel：`-1` 在无符号地址处理中会发生 wrap 或越界，`0` 则是真实地址并且通常小于 `start`。

实际选区取决于视图，因此 `set` 必须回读，并把 `actual` 与 `requested` 一起返回：

- `Disassembly`：x64dbg 的 `setSingleSelection(start)` 会扩展到包含 `start` 的完整指令，所以 `start == end` 表示一条反汇编指令行。
- `Dump` / `Stack`：共享的 `HexDump` 选区实现会把 `start == end` 保留为 1 byte，而不是整条视觉行或一个指针宽度的 cell。

对显式 range，x64dbg 仍可能按照视图边界规范化实际选区。调用方在把后续截图声明为某段范围的证据前，必须使用 `actual`，不能假设它与 `requested` 完全相同。

### GUI-thread transaction

四个 action 都会读取或操作 GUI-owned state，其 GUI 工作必须在 x64dbg GUI thread 执行。`set` 是自包含操作，调用方无需先执行 `focus`；它的导航、选区、聚焦、刷新、event flush 与选区回读构成一个有序 GUI 操作，不能在可见窗口仍停留于请求前状态时返回成功。`focus`、`get`、`set` 需要 active debug session；`snapshot` 在 detached 状态下也可以捕获 x64dbg 窗口。

原生截图与文件 I/O 的具体机制属于实现细节。对外有约束力的是：捕获窗口边界、PNG 编码、交付 discriminator、禁止覆盖、metadata，以及上述 action 顺序。

## Consequences

**Positive**

- Agent 可以把 `0x401000..0x401020` 一类语义发现转化为可复现 GUI 选区与可供人工复核的证据 artifact。
- `set` 封装易错的 UI 编排，并返回 x64dbg 的实际选区，不虚构 requested range 已原样呈现。
- Inline 交付适合远程客户端；明确选择文件交付时不再重复传输 base64 image data。
- PNG metadata 与 SHA-256 为报告和后续传输提供稳定的 byte-identity anchor。

**Negative**

- GUI automation 依赖 x64dbg GUI thread 与受支持的 CPU 子窗口，因此除了 build check，还必须进行真实 x32dbg / x64dbg 验收。
- 截图比纯文本断言更适合展示证据，但不是可信时间戳、签名 provenance，也不能证明捕获期间 debuggee state 不变。
- 文件交付会写入 debugger host，引入路径、权限、磁盘空间与清理责任。
- `snapshot` 是常规 direct typed-envelope 返回路径的一个窄例外：image 交付使用 `CallToolResult`，其 text content 仍包含 typed envelope。

## Alternatives Considered

1. **把每个 `Gui*` 原语恢复成独立 Tool** — 拒绝。它会重现 PoC 的工具数量与编排问题，也允许调用方在刷新/回读完成前截图。
2. **拆成四个独立 Tool** — 拒绝。四个 action 共享同一小型 window 闭集与 GUI-thread 顺序契约；一个 gated control family 更容易发现和演进。
3. **始终同时返回 inline image 与保存文件** — 拒绝。选择文件交付就是为了避免重复图像传输，此时只返回主机路径与 metadata。
4. **只用 `mimeType` 区分交付形式** — 拒绝。两种 artifact 都是 PNG，所以 MIME 都是 `image/png`；必须另外使用 `type` discriminator。
5. **用 `-1` 或 `0` 作为缺省 `end` sentinel** — 拒绝。两者都是会产生错误范围行为的地址值；`end = start` 无需 sentinel，并符合 x64dbg 的原生 single-selection 路径。
6. **`set` 只返回 requested range** — 拒绝。反汇编与 HexDump 的最小选区粒度不同，只返回 requested 会夸大 GUI 实际选中的内容。

## References

- [Tool content 与 mixed-content 返回参考](../references.md#mcp-c-sdk)
- [vendored x64dbg GUI API 与固定 upstream 选区参考](../references.md#x64dbg-gui-evidence-apis)
- [ADR-003](003-tool-resource-action-three-layer.md) — Tool / Resource / action-mega 分类及调试领域目录门控
- [ADR-004](004-typed-result-with-envelope.md) — typed result 与 actionable error 基线
- [tools-spec.md — `debug_gui`](../tools-spec.md#debug-gui)
