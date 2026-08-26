[中文版](README.zh-CN.md) | English

# x64dbgMCP

x64dbgMCP is a C++/CLI x64dbg plugin that starts an embedded MCP server. All debugger primitives, disassembly, memory read/write, breakpoints, registers, symbols/labels/comments, call stacks, are exposed directly to agents as MCP Tools / Resources.

---

### Resources — `x64dbg://...`

Suited for exploratory navigation. Agents can address these directly by URI.

| URI | Purpose |
|---|---|
| `x64dbg://attach/processes{?offset,limit}` | Processes offered by x64dbg for attach |
| `x64dbg://session` | Session snapshot (platform, debugging state, running state, x64dbg directory), navigation root |
| `x64dbg://session/debuggee` | Current session debuggee information |
| `x64dbg://logging` | Log window info |
| `x64dbg://threads` | Thread list |
| `x64dbg://memory/maps` | Memory map |
| `x64dbg://memory/{address}/strings{?offset,limit,length}` | Paged string-reference scan for the containing memory region |
| `x64dbg://modules` | Loaded module list |
| `x64dbg://windows` | Debuggee window list |
| `x64dbg://handles` | Debuggee handle list |
| `x64dbg://tcpconnections` | Debuggee TCP connection list |
| `x64dbg://modules/{name}` | Single module basic info (base address, size, entry point) |
| `x64dbg://modules/{name}/sections` | Module section table |
| `x64dbg://modules/{name}/exports` | Export table |
| `x64dbg://modules/{name}/imports` | Import table |
| `x64dbg://modules/{name}/strings{?offset,limit,length}` | Paged string-reference scan for the module |
| `x64dbg://functions` | Function info |
| `x64dbg://symbols` | Symbol info |
| `x64dbg://labels` | Label info |
| `x64dbg://comments` | Comment info |
| `x64dbg://bookmarks` | Bookmark info |
| `x64dbg://breakpoints` | Breakpoint info |

`.../strings` follows x64dbg `strref` semantics: it scans the module's instructions,
resolves static value/memory operands, and returns the referencing instruction, target string
address, disassembly, decoded string, encoding, and character length.

### Rich-param Tools — Hot Path Queries

Tools with many parameters but a single semantic purpose, exposed per tool. All address parameters accept x64dbg expressions (`rax`, `kernel32:CreateFileW`, `cip+0x10`, `peb()`) and don't need to be pre-resolved.

| Tool | Purpose |
|---|---|
| `ParseExpression(expr)` | Resolve any expression to an address plus its owning module/section |
| `Disassemble(addr, count, withBytes?)` | Disassemble N instructions, optionally returning raw bytes |

### Action-mega Tools — CRUD Families / Control Clusters

Symmetric families dispatch on an `action` field to avoid a proliferation of tools. Resources handle bulk read-only snapshots, while tools (`enableDebugging=true`) handle single-item reads and adjustments.

Analysis and annotation (always registered):

- `Symbols { get }`
- `Functions { get, set, delete }`
- `Labels { get, set, delete, set_batch, delete_batch }`
- `Comments { get, set, delete, set_batch, delete_batch }`
- `Bookmarks { get, set, delete }`
- `Xrefs { list_at, add, count_at, type_at }`

Loaded only when `enableDebugging=true`, to avoid bloating the default tool schema:

- `Logging { clear, put }` — Clear the log window or append a line
- `DebugControl { run_command, init, attach, run, stop, pause, StepInto, StepOver, StepOut }`
- `Registers { get, set, dump }` — Names are resolved by x64dbg, covering any register/flag
- `Assemble(addr, instruction, fillNops?)`
- `Memory { read(addr, size, compress?), write, alloc }` — `read` returns base64; `compress=true` uses lz4
- `Threads { suspend, resume, create_at, set_name, set_active }`
- `Breakpoints { set, delete, disable, set_hardware }`
- `DebugGUI { snapshot, focus, set, get }` — Operate the x64dbg main window as a visual source, focus the CPU pane, and read or set GUI selections

---

## Quick Start

### 1. Load the Plugin

Place the build artifacts into x64dbg's `plugins/` directory:

- 32-bit: `x64dbgMCP.dp32` → `x32dbg/plugins/`
- 64-bit: `x64dbgMCP.dp64` → `x64dbg/plugins/`

Start the server:

```
mcp.start                    ; default port=3001, host=localhost
mcp.start 3001               ; specify a port
mcp.start 3001,0.0.0.0       ; explicit non-loopback bind; place behind a trusted authenticated boundary
```

The default listener is `http://localhost:3001`; the single MCP endpoint clients configure is `http://localhost:3001/mcp`.

### 2. Connect an MCP Client

Claude Code configuration example:

```bash
claude mcp add --transport http x64dbg http://localhost:3001/mcp
```

Or in your client's config file:

```json
{
  "mcpServers": {
		"x64dbgmcp": {
			"url": "http://localhost:3001/mcp",
		}
  }
}
```

Once connected, ask the agent to try: "Read `x64dbg://session` and tell me if it's currently debugging", if it gets an `isDebugging` field back, you're set.

---

## License

Built on the x64dbg pluginsdk, and follows the x64dbg project's license terms.
