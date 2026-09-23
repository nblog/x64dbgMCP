# Project Instructions for AI Coding Agents

> 在为本仓库生成代码、设计、变更或回答之前，**先阅读 [docs/README.md](docs/README.md)**。
> 该文档是本项目的开发实施中心，承载架构、契约、约定、决策记录。
> 这里只放最小化入口，避免上下文堆积。

## 项目一句话

C++/CLI 编写的 [x64dbg](https://github.com/x64dbg/x64dbg) 插件，通过 [Model Context Protocol](https://modelcontextprotocol.io) 把调试器能力暴露给 AI 生态。

## 操作前必读

1. **[docs/README.md](docs/README.md)** — 文档索引与按任务类型的阅读路径
2. 命中下列任一情形，**追加阅读对应文件**：
   - 新增/修改 MCP Tool 或 Resource → [docs/tools-spec.md](docs/tools-spec.md) + [docs/conventions.md](docs/conventions.md)
   - 修改服务器启动、传输层、生命周期 → [docs/architecture.md](docs/architecture.md)
   - 做出会影响后续所有实施的设计选择 → 先看 [docs/adr/](docs/adr/) 是否已有相关 ADR；若无，提议新增
   - 涉及 x64dbg SDK / MCP C# SDK 用法 → [docs/references.md](docs/references.md)
   - 复盘历史验收或踩坑 → [docs/validate/](docs/validate/) 或 [docs/notes/](docs/notes/)

## 文档落盘纪律

`docs/` 按职责落盘，不要混写：

- 设计文档（architecture / conventions / tools-spec）记录稳定约束（架构、配置、契约、运行）；实现、测试和部署必须与这些约束保持一致
- [docs/adr/](docs/adr/) 只记录决策：背景、选择、后果，以及后续工作必须遵守的约束；新增或更新 ADR 时，同步更新 [docs/adr/README.md](docs/adr/README.md) 索引
- [docs/notes/](docs/notes/) 只记录闭环后的问题调查与踩坑记录：现象、根因、结论与规避方式，标注日期，用于回溯
- [docs/validate/](docs/validate/) 只记录带时间的验收：每次推进完成后的闭环验证，标注验收时间，用于回溯

[docs/notes/](docs/notes/) 与 [docs/validate/](docs/validate/) 都是追加式、按时间累积的 CHANGELOG：只追加带 ISO 8601 日期的条目，不回改历史条目；区别于设计文档、ADR 与 [implementation-status](docs/implementation-status.md) 这类持续维护、可整体改写的“活文档”。

不要把未闭环的排查、实验或实现过程草稿直接写入 `docs/`。稳定下来的约束进入设计文档或 ADR；完成闭环验证的推进进入 [docs/validate/](docs/validate/)；闭环后的排查与踩坑进入 [docs/notes/](docs/notes/)。验收记录必须带 ISO 8601 日期，写清验证范围、结果和回溯所需的最小证据；不要把决策理由写进验收记录，也不要用验收记录替代 ADR。

## 不做什么

- 不要在不读 Docs 的情况下"凭直觉"生成 MCP 工具 — 工具粒度、返回结构、错误语义在 [docs/conventions.md](docs/conventions.md) 有强约束
- 不要为 PoC 分支 (`copilot/refine-x64dbg-handler-todos`) 的 1:1 工具形态背书 — 已被 [docs/adr/003-tool-resource-action-three-layer.md](docs/adr/003-tool-resource-action-three-layer.md) 取代
- 不要把决策直接写进代码注释 — 决策走 ADR，代码注释只解释"为什么这里反直觉"

## 偏离基线时：先 ABORT，再对齐

只要在任务过程中**发现拟采取的实施方案与 Docs 基线**（[architecture.md](docs/architecture.md) / [conventions.md](docs/conventions.md) / [tools-spec.md](docs/tools-spec.md) / [adr/](docs/adr/)）**存在偏差、冲突或缺口**，立即按以下流程处理，不要继续推进实施：

1. **停下，不要"先写了再说"**，也不要单方面在代码里打补丁绕开冲突
2. **明确指出偏差点**：是哪份文档的哪一条规约 / 哪个 ADR，与当前任务或拟实施思路不一致
3. **提出对齐方案，二选一**：
   - 调整实施回到基线（默认首选），或
   - 提议修订基线 — 改约定/ADR，必要时**先新增 ADR** 再动代码
4. **等待用户确认**后再继续；用户的口头同意不替代基线变更，文档落地后才算

理由：项目原则 [Schema-as-constraint](docs/README.md#文档原则) 要求 Docs 是约束性的**事前契约**而非事后描述。沉默地实施"偏离方案"会让代码与 Docs 分叉，后续 AI 协作的信息源失真，回头修复成本远高于当下停下来对齐。

## 弃用标记

任何属性/功能/类/模块/文档被明确“已弃用”时，必须在定义处添加所属语言的 Deprecated 标识（C++17 `[[deprecated]]`、C# `[Obsolete]` 等），并在标识中注明弃用原因、替代方案与迁移指引。

仅在 `docs/` 中追加一段记录不视为完成弃用：决策背景进入 ADR；Deprecated 标识负责让弃用在定义处与调用点持续可见，并可被 IDE、lint、静态检查等工具识别。弃用状态变化时，两边同步更新。

## 模型聚合

当共性可以由 base model 聚合管理时，必须先将其沉淀到 base model 统一维护，再派生出仅包含差异的 derived model，通过继承/组合/扩展点表达变化。

禁止复制既有 model 或功能代码后各自修改来满足相似需求，避免数据模型与功能代码散乱扩张。触及既有的重复模型时，应顺手收敛为 base + derived 结构；确实无法立即收敛的，先在相关设计文档或 ADR 记录待收敛项与原因。
