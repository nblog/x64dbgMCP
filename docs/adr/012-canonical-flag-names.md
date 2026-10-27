# ADR-012: MCP 边界使用统一的 flag 名称

- **Status**: Accepted
- **Date**: 2026-10-27
- **Deciders**: @nblog
- **Partially supersedes**: ADR-002，仅限完整的 flag 名称适配

## 背景

2026-10-26 的 Electron 验证确认原生表达式解析接受 `_zf`，而文档中的 MCP 输入 `zf` 失败。用户已明确要求输入和输出统一使用 `zf`，由内部消化原生下划线写法。ADR-002 对普通寄存器与表达式仍然有效，但需要为 dump 已有的 flag 词汇增加一个有限例外。

现有 dump 已维护 `cf/pf/af/zf/sf/tf/if/df/of` 及其 EFLAGS 位掩码，vendored [`_scriptapi_flag.h`](../../x64dbgMCP/plugintemplate/pluginsdk/_scriptapi_flag.h) 也提供相同九项。为 get/set 再维护另一套表，会重新引入 ADR-002 要避免的漂移。

## 决策

一份内部 flag 名称/位掩码定义统一供完整名称适配、get/set 的 canonical 名称和 dump 位提取使用。公开完整 flag 名称大小写不敏感，在调用原生表达式解析或 scalar assignment 前转换为下划线名称。原生下划线输入继续兼容，但结果一律使用小写公开名称。

这只是有限词汇适配，不是寄存器 enum 镜像或表达式解析器。适配只匹配完整的 flag 名称；其它复合表达式保留原生语法，不做 token 改写。flag 写入返回原生 boolean 实际回读值，涵盖原生把非零整数归一化的情况。dump 的键继续为 `flags.zf` 等。

## 后果

客户端使用 `registers{action:"get",name:"zf"}` 和 `registers{action:"set",name:"zf",value:"0"}`，与 dump 输出保持一致，九项定义只有一个维护点。相同的完整裸名称成为 MCP 保留 flag 词汇，包括也可视为十六进制数的 `af/cf/df`；需要该数值时使用明确的 `0x` 前缀。模块限定名称、复合表达式及一般寄存器/地址词汇仍由原生引擎处理。

## 考虑过的替代方案

1. 将公开示例改为 `_zf`：与用户明确要求冲突。
2. 恢复 flag/register enum 镜像：没有必要，原生 scalar API 已完成读写，dump 定义足以提供有限集合。
3. 替换任意表达式中看起来像 flag 的 token：可能改写符号、模块限定导出和字符串，需要新的解析器，超出本次修复。

## 参考

- [ADR-002](002-resolve-via-x64dbg-expression.md)
- [2026-10-26 验收](../validate/2026-10-26-electron27-mcpc.md)
- [Register 契约](../tools-spec.md#registersget-set-dump-)
