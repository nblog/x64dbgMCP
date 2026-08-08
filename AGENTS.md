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

## 不做什么

- 不要在不读 Docs 的情况下"凭直觉"生成 MCP 工具 — 工具粒度、返回结构、错误语义在 [docs/conventions.md](docs/conventions.md) 有强约束
- 不要为 PoC 分支 (`copilot/refine-x64dbg-handler-todos`) 的 1:1 工具形态背书 — 已被 [docs/adr/003-tool-resource-action-three-layer.md](docs/adr/003-tool-resource-action-three-layer.md) 取代
- 不要把决策直接写进代码注释 — 决策走 ADR，代码注释只解释"为什么这里反直觉"

## 偏离基线时：先 abort，再对齐

只要在任务过程中**发现拟采取的实施方案与 Docs 基线**（[architecture.md](docs/architecture.md) / [conventions.md](docs/conventions.md) / [tools-spec.md](docs/tools-spec.md) / [adr/](docs/adr/)）**存在偏差、冲突或缺口**，立即按以下流程处理，不要继续推进实施：

1. **停下，不要"先写了再说"**，也不要单方面在代码里打补丁绕开冲突
2. **明确指出偏差点**：是哪份文档的哪一条规约 / 哪个 ADR，与当前任务或拟实施思路不一致
3. **提出对齐方案，二选一**：
   - 调整实施回到基线（默认首选），或
   - 提议修订基线 — 改约定/ADR，必要时**先新增 ADR** 再动代码
4. **等待用户确认**后再继续；用户的口头同意不替代基线变更，文档落地后才算

理由：项目原则 [Schema-as-constraint](docs/README.md#文档原则) 要求 Docs 是约束性的**事前契约**而非事后描述。沉默地实施"偏离方案"会让代码与 Docs 分叉，后续 AI 协作的信息源失真，回头修复成本远高于当下停下来对齐。
