# ADR-007：HATEOAS `_links` 使用带作用域的 snake_case 关系键

- **Status**: Accepted
- **Date**: 2026-08-20
- **Deciders**: @nblog
- **Related**: [ADR-005](005-hateoas-links-on-navigation-roots.md)

## 背景

项目的 Resource 响应使用 HATEOAS `_links` 提供下一步导航。此前部分关系键使用短名
（例如 `debuggee`），部分关系键已经按 URI 层级补充了作用域（例如
`attach_processes`、`memory_maps`）。短名在单个响应中通常可理解，但无法表达它所处的
导航上下文；同时也与项目已有的 snake_case 关系键风格不完全一致。

这里有三个需要分开的命名层次：

- MCP Resource metadata 的 `name`，供客户端展示或识别，例如 `session-debuggee`；
- Resource 的 canonical URI，例如 `x64dbg://session/debuggee`；
- 响应 `_links` 中的 relation key，例如 `session_debuggee`。

改变 relation key 不会改变 URI 的读取地址，也不会改变 Resource 是固定 Resource 还是
Resource Template；但它会改变响应 JSON 的可观察字段，因此必须作为契约变更记录。

## 决策

`_links` relation key 统一使用小写 `snake_case`。当目标是带有明确父级作用域的嵌套
Resource，且短名可能与其它关系混淆时，关系键应包含该父级作用域。

因此，当前会话的被调试进程使用：

```jsonc
{
  "_links": {
    "session_debuggee": {
      "uri": "x64dbg://session/debuggee"
    }
  }
}
```

Resource metadata name 保持 `session-debuggee`，canonical URI 保持
`x64dbg://session/debuggee`。其它导航根跨资源指向该 URI 时使用
`session_debuggee`；该 Resource 自身仍使用标准的 `_links.self`。本 ADR 只约束
`_links` 的关系键，不要求关系键与 metadata name 或 URI 的文字形式相同。

## 后果

**正面**

- `session_debuggee` 在跨 Resource 导航时直接表达目标所属的 session 作用域；
- 与 `attach_processes`、`memory_maps` 等现有关系键保持一致的 snake_case 风格；
- URI 和客户端读取逻辑不变，Resource catalog 不会因此从 `resources/list` 移到
  `resources/templates/list`。

**负面**

- `_links.debuggee` 到 `_links.session_debuggee` 是一个响应字段级 breaking change；
  已缓存旧字段的客户端需要适配；
- 文档、响应样例和回归断言必须同步更新，不能只改某一个 Resource。

## 后续约束

- 新增导航关系时，先按本 ADR 选择 snake_case relation key，再在
  [conventions.md §6](../conventions.md#6-hateoas-_links-navigation-roots-only) 和对应
  [tools-spec.md](../tools-spec.md) 的 payload 注释中登记；
- 回归验证应同时断言 relation key 和其 URI，避免只验证其中一项而掩盖命名/目标错配；
- 如果未来要恢复短名或引入另一套命名词汇，应新增 ADR 取代本决策，不能在单个调用点
  静默例外。

## 备选方案

1. **继续使用 `debuggee`**：改动最少，但丢失 session 作用域，且与现有 scoped relation
   key 风格不一致；不采用。
2. **使用 `session-debuggee`**：与 Resource metadata name 相同，但 `_links` relation key
   应保持 snake_case；不采用。
3. **修改 canonical URI**：会破坏已有 Resource URI 契约，并不解决 relation key 与
   metadata name 的层次分离；不采用。
