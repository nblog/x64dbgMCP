# x64dbgMCP

x64dbgMCP 是一个 C++/CLI 编写的 x64dbg 插件，启动一个嵌入式 MCP HTTP server。所有调试器原语——反汇编、内存读写、断点、寄存器、符号/标签/注释、调用栈——都以 MCP Tool / Resource 的形式直接对 Agent 可用，无需中间脚本桥接。

---

### Resources — `x64dbg://...`

只读快照，适合探索式导航。Agent 可以用 URI 直接寻址，不需要先调 list 再调 get。

| URI | 用途 |
|---|---|
| `x64dbg://session` | 会话快照（平台、是否在调试、是否运行、x64dbg 目录），导航根 |
| `x64dbg://modules` | 已加载模块列表 |
| `x64dbg://modules/{name}` | 单模块基本信息（基址、大小、入口） |
| `x64dbg://modules/{name}/sections` | 模块节表 |
| `x64dbg://modules/{name}/exports` | 导出表 |
| `x64dbg://modules/{name}/imports` | 导入表 |
| `x64dbg://modules/{name}/symbols` | 符号（PDB / 导出 / 用户标记） |
| `x64dbg://memory/map` | 内存映射 |
| `x64dbg://threads` | 线程列表 |

### Rich-param Tools — 热路径查询

参数较多但语义单一，按工具维度暴露。所有地址参数接受 x64dbg 表达式（`rax`、`kernel32:CreateFileW`、`cip+0x10`、`peb()`），不必预先解析。

| Tool | 作用 |
|---|---|
| `Disassemble(addr, count, withBytes?)` | 反汇编 N 条指令，可选返回原始字节 |
| `MemoryRead(addr, size, compress?)` | 读内存，base64 返回；`compress=true` 用 lz4 压缩以放大单次返回窗口 |
| `ParseExpression(expr)` | 把任意表达式解析为地址 + 所属模块/节 |

### Action-mega Tools — CRUD 家族 / 控制簇

形态对称的家族用 `action` 字段分派，避免工具数量爆炸。状态变更类工具仅在 `enableDebugging=true` 时注册。

只读：

- `Symbols { list, get }`
- `Functions { list, get, set, delete }`
- `Labels { list, get, set, delete, set_batch, delete_batch }`
- `Comments { list, get, set, delete, set_batch, delete_batch }`
- `Bookmarks { list, get, set, delete }`
- `Xrefs { list_at, add, count_at, type_at }`

调试态（mutating）：

- `DebugControl { run, stop, pause, StepInto, StepOver, StepOut, init, run_command }`
- `Registers { get, set, dump }` — 名称由 x64dbg 解析，覆盖任意寄存器/标志
- `Breakpoints { list, get, set, delete, disable, set_hardware, delete_hardware, set_batch, delete_batch }`
- `Memory { write, alloc, free }`
- `Threads { list, get, set_name, set_active, suspend, resume, create_at }`
- `Assemble(addr, instruction, fillNops?)`
- `LogPuts(text)` — 在 x64dbg 日志窗口留痕

---

## Quick Start

### 1. 装载插件

把构建产物放进 x64dbg 的 `plugins/` 目录：

- 32 位：`x64dbgMCP.dp32` → `x32dbg/plugins/`
- 64 位：`x64dbgMCP.dp64` → `x64dbg/plugins/`

启动 x64dbg，或在已运行的实例里 `Plugins → Load`。命令 `mcp.start` 应已注册。

启动服务：

```
mcp.start                    ; 默认 port=3001, host=localhost, 仅注册只读工具
mcp.start 3001               ; 指定端口
mcp.start 3001,0.0.0.0       ; 暴露给非 loopback 客户端 (host=0.0.0.0)
```

### 2. 接到 MCP 客户端

Claude Code 配置示例：

```bash
claude mcp add --transport http x64dbg http://localhost:3001
```

或在客户端配置文件中：

```json
{
  "mcpServers": {
		"x64dbgmcp": {
			"url": "http://localhost:3001",
		}
  }
}
```

连上后让 Agent 试一句：「读 `x64dbg://session`，告诉我现在是不是在调试」——能拿到 `IsDebugging` 字段就跑通了。

---

## License

基于 x64dbg pluginsdk，遵循 x64dbg 项目的许可条款。
