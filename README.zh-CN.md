[English](README.md) | 中文版

# x64dbgMCP

x64dbgMCP 是一个 C++/CLI 编写的 x64dbg 插件，启动一个嵌入式 MCP server。所有调试器原语——反汇编、内存读写、断点、寄存器、符号/标签/注释、调用栈——都以 MCP Tool / Resource 的形式直接对 Agent 可用。

---

### Resources — `x64dbg://...`

适合探索式导航。Agent 可以用 URI 直接寻址。

| URI | 用途 |
|---|---|
| `x64dbg://attach/processes{?offset,limit}` | x64dbg 提供的可附加候选进程 |
| `x64dbg://session` | 会话快照（平台、是否在调试、是否运行、x64dbg 目录），导航根 |
| `x64dbg://session/debuggee` | 当前会话的被调试进程信息 |
| `x64dbg://logging` | 日志窗口信息 |
| `x64dbg://threads` | 线程列表 |
| `x64dbg://memory/maps` | 内存映射 |
| `x64dbg://modules` | 加载模块列表 |
| `x64dbg://windows` | 调试进程窗口列表 |
| `x64dbg://handles` | 调试进程句柄列表 |
| `x64dbg://tcpconnections` | 调试进程 TCP 连接列表 |
| `x64dbg://modules/{name}` | 单模块基本信息（基址、大小、入口） |
| `x64dbg://modules/{name}/sections` | 模块节表 |
| `x64dbg://modules/{name}/exports` | 导出表 |
| `x64dbg://modules/{name}/imports` | 导入表 |
| `x64dbg://functions` | 函数信息 |
| `x64dbg://symbols` | 符号信息 |
| `x64dbg://labels` | 标签信息 |
| `x64dbg://comments` | 注释信息 |
| `x64dbg://bookmarks` | 书签信息 |
| `x64dbg://breakpoints` | 断点信息 |

### Rich-param Tools — 热路径查询

参数较多但语义单一，按工具维度暴露。所有地址参数接受 x64dbg 表达式（`rax`、`kernel32:CreateFileW`、`cip+0x10`、`peb()`），不必预先解析。

| Tool | 作用 |
|---|---|
| `ParseExpression(expr)` | 把任意表达式解析为地址 + 所属模块/节 |
| `Disassemble(addr, count, withBytes?)` | 反汇编 N 条指令，可选返回原始字节 |

### Action-mega Tools — CRUD 家族 / 控制簇

形态对称的家族用 `action` 字段分派，避免工具数量爆炸。Resource 负责批量只读快照，Tool (`enableDebugging=true`) 负责单条读取与调整。

分析与标注（始终注册）：

- `Symbols { get }`
- `Functions { get, set, delete }`
- `Labels { get, set, delete, set_batch, delete_batch }`
- `Comments { get, set, delete, set_batch, delete_batch }`
- `Bookmarks { get, set, delete }`
- `Xrefs { list_at, add, count_at, type_at }`

仅在 `enableDebugging=true` 时加载，避免默认 tool schema 膨胀：

- `Logging { clear, put }` — 清空日志窗口或追加一行
- `DebugControl { run_command, init, attach, run, stop, pause, StepInto, StepOver, StepOut }`
- `Registers { get, set, dump }` — 名称由 x64dbg 解析，覆盖任意寄存器/标志
- `Assemble(addr, instruction, fillNops?)`
- `Memory { read(addr, size, compress?), write, alloc }` — `read` 以 base64 返回；`compress=true` 使用 lz4
- `Threads { suspend, resume, create_at, set_name, set_active }`
- `Breakpoints { set, delete, disable, set_hardware }`
- `DebugGUI { snapshot, focus, set, get }` — 操作 x64dbg 主窗口作为可视化源，聚焦 CPU 子窗口，并读取或设置 GUI 选区

---

## Quick Start

### 1. 装载插件

把构建产物放进 x64dbg 的 `plugins/` 目录：

- 32 位：`x64dbgMCP.dp32` → `x32dbg/plugins/`
- 64 位：`x64dbgMCP.dp64` → `x64dbg/plugins/`

启动服务：

```
mcp.start                    ; 默认 port=3001, host=localhost
mcp.start 3001               ; 指定端口
mcp.start 3001,0.0.0.0       ; 显式非 loopback 绑定；应放在可信且有认证的边界后
```

默认 listener 是 `http://localhost:3001`；客户端应配置的唯一 MCP endpoint 是 `http://localhost:3001/mcp`。

### 2. 接到 MCP 客户端

Claude Code 配置示例：

```bash
claude mcp add --transport http x64dbg http://localhost:3001/mcp
```

或在客户端配置文件中：

```json
{
  "mcpServers": {
		"x64dbgmcp": {
			"url": "http://localhost:3001/mcp",
		}
  }
}
```

连上后让 Agent 试一句：「读 `x64dbg://session`，告诉我现在是不是在调试」——能拿到 `isDebugging` 字段就跑通了。

---

## License

基于 x64dbg pluginsdk，遵循 x64dbg 项目的许可条款。
