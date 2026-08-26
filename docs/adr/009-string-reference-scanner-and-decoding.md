# ADR-009：字符串引用扫描与三阶段解码

## 状态

Accepted — 2026-08-25

## 背景

x64dbg 的 GUI “Find Strings” (`strref`) 是字符串引用搜索：它扫描指令、解析立即数或有效内存操作数，再尝试把目标地址解释为字符串。它不是一个可直接复用的公共 Plugin SDK 范围枚举接口，`RefFind` 和 `cbRefStr` 仍属于 debugger 内部实现；公开的 `DbgGetStringAt` 只提供单地址点查询，并且只返回 x64dbg 自己格式化的文本。

MCP 需要可重复的结构化 Resource 结果，不能依赖 GUI Reference View 的全局状态。因此本项目为模块与 memory Resource 共享一个按地址范围工作的扫描抽象。模块 Resource 以模块 `base/size` 为范围；memory Resource 只负责把地址表达式解析为所在 region，再复用同一抽象。

## 决策

### 1. Resource 语义是“字符串引用”，不是直接字符串表

`modules/{name}/strings` 扫描模块地址范围内的指令，并返回指令地址、反汇编、字符串目标地址和解码后的字符串。这与 x64dbg Reference View 的四列语义一致：

```text
address        = 引用字符串的指令地址
disassembly    = 该指令的 fast-disasm 文本
stringAddress  = 指令操作数解析出的目标地址
string         = 目标地址处的字符串内容
```

该 Resource 不调用 `strref` 命令，也不读取 GUI Reference View；这样避免共享 GUI 状态、异步命令完成边界和不可分页的表格读取问题。

### 2. 扫描抽象只接收地址范围和字符串筛选选项

共享扫描器的核心输入是：

```text
start       : 扫描起始地址
rangeSize   : 扫描字节数
minLength   : 最小解码字符数，默认 4，允许值为 3..512
maxResults  : 内部保护上限，默认 5000
```

`rangeSize` 与 `minLength` 是两个不同维度。模块 Resource 默认把模块 `base/size` 作为扫描范围；其 URI 的 `length` 参数表示 `minLength`，而不是只读取模块前 4 个字节。memory Resource 先把地址表达式解析到所属 region，再把该 region 的 base/size 作为扫描范围。解码器会从目标字符串地址读取至 NUL 或内部最大探测长度（512 字节），因此不会把默认值 4 误用成字符串截断长度；`rangeSize` 保持为 scanner 内部参数，不作为 MCP query 暴露。

小于 3 的最小长度对 MCP 模块扫描没有足够筛选价值，作为 caller error 拒绝；大于 512 的值也拒绝，避免把一次 Resource 请求变成无界扫描。x64dbg 底层识别器可以接受长度为 2 的字符串，但 Resource 契约有意提高这一过滤阈值以降低噪声。

### 3. 解码优先级固定为 UTF-16LE、UTF-8、系统 ANSI

每个候选目标地址按以下顺序尝试：

1. Windows 默认小端 UTF-16 (`UTF-16LE`)；
2. 严格 UTF-8（解码错误即失败，不使用替换字符）；
3. 当前 Windows 系统 ANSI code page (`GetACP()`)，同样拒绝无法转换的字节序列。

候选必须以 NUL 结束（或达到内部探测上限），字符数至少达到 `minLength`，并且不包含不可接受的控制字符。UTF-16 尝试阶段还会检查候选是否实际上在更早的单字节 NUL 处形成了严格 UTF-8；这是为了避免 ASCII/UTF-8 字符串末尾的填充零字节被误判为 UTF-16。返回值同时保留 `encoding` 与 `length`，使 UTF-16、UTF-8 和 ANSI 的判断不会依赖字符串内容猜测。

### 4. memory Resource 的范围解析

`x64dbg://memory/{address}/strings{?offset,limit,length}` 中的 `address` 接受 x64dbg
表达式。用 `DbgMemFindBaseAddr` 找到该地址所在的可读 region 并扫描完整 region；返回的
`scanStart/scanSize` 是解析后的实际范围。扫描器的 `rangeSize` 只存在于内部抽象，不作为
MCP query 参数暴露，避免和 `length`（最小解码字符数）混淆。无法解析的表达式和不属于
可读 region 的地址都作为 Resource 读取错误报告。

### 5. 结果可分页但扫描范围不随页变化

Resource 支持 `offset`/`limit`，默认 `0/100`，`limit` 限制在 `1..100`。每次读取会对同一个地址范围完成一次扫描，然后对结果分页；返回 `_links.self`、`next`、`prev`、`module` 和 `session`。扫描达到 5000 行时保留 `truncated=true`，避免在恶意或高噪声模块上无界增长。

## 后果

- 模块和 memory Resource 共享解码、缓存、反汇编操作数处理和分页前的结果生成逻辑。
- 结果与 x64dbg GUI 的引用行可比对，但不承诺 GUI 的本地化列标题或设置相关格式；`string` 是未加引号的内容，`encoding` 明确表示来源。
- 该实现是 x64dbg `strref` 语义的结构化复现，不是任意内存字符串枚举器。若未来需要直接枚举没有被指令引用的字符串，应增加独立的 memory-string scanner/URI，不得复用本 Resource 名称伪装成 `strref`。
- `DbgGetStringAt` 仍可用于单地址 `get_string_at`，但不作为本 Resource 的解码后端，因为它没有长度参数且不提供 UTF-8/ANSI 优先级控制。

## 依据

- x64dbg `strref` 命令：[`cmd-searching.cpp`](https://github.com/x64dbg/x64dbg/blob/17233957ea0a7e70d188187380bd74f80c2a4b93/src/dbg/commands/cmd-searching.cpp)
- x64dbg 范围扫描：[`reference.cpp`](https://github.com/x64dbg/x64dbg/blob/17233957ea0a7e70d188187380bd74f80c2a4b93/src/dbg/reference.cpp)
- x64dbg GUI 入口：[`MainWindow::findStrings`](https://github.com/x64dbg/x64dbg/blob/17233957ea0a7e70d188187380bd74f80c2a4b93/src/gui/Src/Gui/MainWindow.cpp)
- 本项目 Resource 分层：[ADR-003](003-tool-resource-action-three-layer.md)
