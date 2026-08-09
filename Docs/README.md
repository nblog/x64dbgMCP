# x64dbgMCP — 开发实施中心

本目录是 x64dbgMCP 项目的**开发基线**。所有 AI 协作的设计/实施变更，须先阅读本文件，按任务类型加载对应章节，避免漂移。

> 信息渐进加载原则：根级 [`AGENTS.md`](../AGENTS.md) 只放最小入口；本文件提供导航；具体规约/契约/决策按需深入。

---

## 项目定位

x64dbgMCP 是一款 [x64dbg](https://github.com/x64dbg/x64dbg) 插件，通过 [Model Context Protocol](https://modelcontextprotocol.io) 把动态调试能力以"AI 友好"的形态暴露给 MCP 客户端（Claude Code、Codex 等）。

- **运行形态**: x64dbg 插件 (`.dp32`/`.dp64`)，通过 x64dbg 命令 `mcp.start [port=3001],[host=localhost],[enableDebugging]` 启动嵌入式 MCP HTTP server
- **技术栈**: C++/CLI (`CLRSupport=NetCore`) + ASP.NET Core (`WebApplication.CreateSlimBuilder`) + [ModelContextProtocol](https://github.com/modelcontextprotocol/csharp-sdk)
- **目标客户端**: 任何遵守 MCP 规范的 Agent；默认 loopback only，安全边界由本机约束

---

## 进程闭环验证

当一项变更需要在真实 x64dbg 与被调试进程中完成闭环验证时，可按 [mcporter Quick start](https://github.com/openclaw/mcporter#quick-start) 将 mcporter 用作本地 x64dbgMCP 客户端。先用 `list` 确认服务与目录可发现，再用 `call` 执行 Tool、用 `resource` 枚举并读取 Resource；工具调用成功只证明请求已受理，仍应以 Resource 返回的调试会话、进程状态和待测领域数据确认行为实际生效。

---

## 阅读路径（按任务类型）

| 你要做的事 | 必读文件 |
|---|---|
| 新增/修改 MCP Tool | [conventions.md](conventions.md) → [tools-spec.md](tools-spec.md) → [adr/003](adr/003-tool-resource-action-three-layer.md) |
| 新增/修改 MCP Resource | [conventions.md](conventions.md) → [tools-spec.md](tools-spec.md#资源-resources) → [adr/003](adr/003-tool-resource-action-three-layer.md) |
| 设计返回结构 / 错误处理 | [conventions.md](conventions.md#返回结构) + [adr/004](adr/004-typed-result-with-envelope.md) |
| 处理寄存器/标志位/表达式输入 | [adr/002](adr/002-resolve-via-x64dbg-expression.md) |
| 修改 server 启动 / 生命周期 / 端口 / 命令注册 | [architecture.md](architecture.md) |
| 引入大型设计变更 | 先查 [adr/](adr/) 是否已存在；若无，**先提议新增 ADR**，再实施 |
| 查 x64dbg SDK / MCP C# SDK 具体 API | [references.md](references.md) |

---

## 文档目录

| 文件 | 用途 |
|---|---|
| [README.md](README.md) | （本文件）开发实施中心，导航与原则 |
| [architecture.md](architecture.md) | 架构总览：进程/线程模型、组件分层、数据流、生命周期 |
| [conventions.md](conventions.md) | 编码与契约约定：命名、地址格式、错误语义、返回 envelope、HATEOAS |
| [tools-spec.md](tools-spec.md) | MCP Tool 与 Resource 契约骨架（输入/输出 schema、错误条件） |
| [implementation-status.md](implementation-status.md) | 当前实现覆盖率、验证边界、临时实验偏离与下一批实施顺序 |
| [adr/](adr/) | Architecture Decision Records — 关键设计决策的可追溯快照 |
| [references.md](references.md) | 外部参考索引：x64dbg SDK 头、MCP 规范、ASP.NET Core 配置 |

---

## 文档原则

1. **Schema-as-constraint** — 文档不是描述性的"事后总结"，而是约束性的"事前契约"。代码与文档冲突时，先讨论修哪边，再改。
2. **Source-anchored** — 任何技术声明须挂可验证来源（SDK 头路径、官方文档 URL、ADR 编号）。无来源的判断要标注 *unverified inference*。
3. **One authoritative source** — 同一信息只在一处定义，其它地方用链接引用。例如返回 envelope 形态在 [conventions.md](conventions.md#返回结构) 定义，[tools-spec.md](tools-spec.md) 只引用不重复。
4. **Decisions are first-class** — 设计选择走 [ADR](adr/)。代码注释只解释"为什么这里反直觉"，不承载决策本体。
5. **语言混合**: README/ADR 用中文（讨论密度高）；conventions/tools-spec 用英文（贴近代码）。
