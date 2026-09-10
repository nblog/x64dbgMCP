# ADR-010: Replace analyzed XREF lookup with on-demand RefFind-style scanning

- **Status**: Accepted
- **Date**: 2026-09-07
- **Deciders**: x64dbgMCP maintainers

## Context

The previous `xrefs` Tool exposed `DbgXrefGet` and related bridge functions. Those
functions read x64dbg's analysis database and therefore depend on the module having been
analyzed. They are not equivalent to the x64dbg GUI command behind Ctrl+R. The upstream
`reffindrange` implementation in `reference.cpp` reads the current debuggee memory into a
local buffer, decodes instructions, and matches immediate, static-memory, and branch
operands against a target range. The public Plugin SDK does not export `RefFind` itself,
but it does export `DbgMemFindBaseAddr`, `DbgMemRead`, and `DBGFUNCTIONS::DisasmFast`, which
are sufficient to reproduce the data path without using the global GUI Reference View.

The requested behavior is deliberately a replacement of the old analyzed-database
surface, not an additive compatibility layer. Keeping the old actions would make the
same wire name report two incompatible data sources.

## Decision

`xrefs` is an on-demand, structured RefFind-style scanner. Its `find` action accepts a
target address (`addr`), an optional inclusive target end (`end`), and optional scan
address/size (`scanAddr`, `scanSize`). When scan parameters are omitted, the scanner
uses the current instruction pointer and the containing memory region, matching the
default `reffindrange` command behavior. The requested scan is bounded to that region.

The scanner reads a snapshot before decoding, decodes locally through
`DBGFUNCTIONS::DisasmFast`, applies x64dbg's `TYPE_VALUE`, `TYPE_MEMORY`, and `TYPE_ADDR`
matching rules (including the sign-extended immediate workaround), and returns one
structured row per matching instruction. Rows include the source address, disassembly,
match kind, and matched value. No GUI Reference View is created or read, and no analyzed
XREF database is queried or modified.

The implementation enforces a bounded scan size and reports the requested/normalized
scan range in the result. Partial remote reads retain the upstream scanner's 0xCC
unreadable-byte behavior; decode failures advance one byte so a malformed region does not
abort the whole scan.

## Consequences

- Results reflect current process memory and do not require completed x64dbg analysis.
- The MCP response contains the target and operand evidence that the two-column GUI view
  discards.
- Existing `list_at`, `add`, `count_at`, and `type_at` clients are intentionally broken;
  callers must use `action=\"find\"`.
- Scan cost is proportional to the selected memory range, so the bounded request size is
  part of the safety contract.
- The vendored `2026.05.27` release decodes without consulting the analysis Encode Map,
  so this implementation does the same. A future SDK upgrade that adopts the development
  branch's Encode Map behavior requires an explicit parity review rather than silently
  reintroducing an analysis-database dependency.

## Alternatives Considered

1. Keep `DbgXrefGet` and add a second `find_references` Tool. Rejected because the request
   explicitly asks to replace the old design and reserve one unambiguous `xrefs` name.
2. Execute `reffindrange` and scrape `GuiReference*` rows. Rejected because the GUI view is
   global mutable state, exposes only Address/Disassembly, and introduces races between
   MCP calls and user activity.
3. Continue using `DbgDisasmFastAt` per address. Rejected because it re-reads remote memory
   for every instruction and does not reproduce x64dbg's snapshot-first scan behavior.

## References

- [x64dbg `2026.05.27` `reference.cpp` (`RefFind`/`RefFindInRange`)](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/reference.cpp)
- [x64dbg `2026.05.27` `cmd-searching.cpp` (`cbInstrRefFindRange`)](https://github.com/x64dbg/x64dbg/blob/9c8ca1cae0b6d56cc44f31fddcb10e3b02ffbb87/src/dbg/commands/cmd-searching.cpp)
- [x64dbg `reffindrange` command documentation](https://help.x64dbg.com/en/latest/commands/searching/reffindrange.html)
- [Plugin SDK bridge declarations](../references.md#x64dbg-plugin-sdk)
