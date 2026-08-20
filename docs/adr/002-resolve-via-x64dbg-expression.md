# ADR-002: Resolve names via x64dbg expression rather than maintaining enum mirrors

- **Status**: Accepted
- **Date**: 2026-05-24
- **Amended**: 2026-08-10
- **Deciders**: @nblog

## Context

The PoC implementation in `copilot/refine-x64dbg-handler-todos` maintains explicit name-to-enum mappings for registers and flags via `Helpers::FlagFromName` and `Helpers::RegisterFromName` (see [poc-handler.h:49-177](https://github.com/nblog/x64dbgMCP/blob/copilot/refine-x64dbg-handler-todos/x64dbgMCP/x64dbgHandler.h)). The `RegisterFromName` function alone is ~110 lines of `if (lower == "xx") return Script::Register::YY;` covering DR0-7, 8/16/32/64-bit GPRs, R8-R15 sub-registers, and architecture-agnostic CIP/CSP/CAX-family aliases.

This violates two project principles:

1. **DRY** — every register name appears at least twice across get/set call sites
2. **Schema drift risk** — when x64dbg adds new register names (e.g. AVX-512), our mirror table goes stale silently

The x64dbg pluginsdk already exposes `Script::Misc::ParseExpression(const char*, duint*)` and the lower-level `DbgValFromString` / `DbgValToString` ([bridgemain.h](../../x64dbgMCP/plugintemplate/pluginsdk/bridgemain.h)). These accept any string the debugger itself understands: register names, flag names (`zf`, `cf`, ...), labels, module:export pairs, arithmetic expressions, and built-in functions like `peb()` or `mem.base(cip)`. The vocabulary is maintained inside x64dbg and tracks SDK upgrades automatically.

## Decision

**Name-shaped inputs are resolved by delegating to x64dbg's expression engine, not by mirroring enum tables in C++/CLI.** Concretely:

- Address-like parameters → `Helpers::ResolveExpression(String^)` → `Script::Misc::ParseExpression`
- Register read → `DbgValFromString("rax", &out)` (or `Script::Register::Get` if a typed enum value is needed for downstream native API)
- Register write → `DbgValSetScalar("rax", value)` (the current name of the API previously called `DbgValToString`) or `Script::Register::Set` when a typed enum is required downstream
- Flag read/write → resolve `"_zf"` / `"zf"` via the expression engine; raw boolean exposed via `Script::Flag::Get/Set` only at the lowest layer if needed

The `registers{get, set}` mega-tool ([tools-spec.md §5](../tools-spec.md#registersget-set-dump-)) accepts a free-form `name: string` parameter. We do not enumerate valid names in our schema — the description points users to the x64dbg vocabulary.

**Exceptions** (where a small mirror is unavoidable):

- `BPXTYPE` / hardware breakpoint type / Xref type — these are closed sets used in our **return** values (so we control the vocabulary) and are not addressable as expressions. Keep small `*FromName` / `*ToString` helpers for these.

## Consequences

**Positive**

- ~110 lines of mirror table replaced by 1 call site
- Vocabulary stays in sync with x64dbg automatically
- AI clients can use any expression x64dbg understands (not just bare register names) — `cip+0x10` and `kernel32:CreateFileW` work uniformly
- Aligns with our prior decision to make `ResolveExpression` the canonical address-input shape

**Negative**

- Invalid inputs are reported with the project's `not_found` / `invalid_argument` envelope while the accepted vocabulary still comes from x64dbg rather than a curated enum. If discoverability proves insufficient, add a dedicated documentation Resource or help link under a separately specified contract; `x64dbg://session` does not currently expose register vocabulary.
- A typo by the agent may resolve to a label or symbol with the same name. Acceptable: that's how x64dbg itself behaves; we don't add a new failure mode.

**Constraints on future work**

- New name-shaped inputs default to expression resolution. Adding an enum mirror requires an ADR explaining why expression resolution is insufficient.
- Result classes that include register/flag names use lowercase strings (`"rax"`, `"zf"`), not enum integers, so the over-the-wire vocabulary stays human-readable and aligned with input vocabulary.

## Alternatives Considered

1. **Keep the PoC's `*FromName` mirrors** — rejected for the DRY/drift reasons above.
2. **`Dictionary<String^, Script::Register::RegisterEnum>` lookup table** — slightly tighter than if-else chains but still requires manual maintenance and doesn't widen accepted vocabulary. Same drawbacks.
3. **Mirror x64dbg's enums into managed `enum class` and use `Enum.Parse`** — would let us return strongly-typed enum values, but requires keeping the managed enum in sync with the native one (worse than the current PoC pattern). Rejected.
4. **Accept only numeric register indices (current `x64dbgHandler.h` shape — `int reg`)** — extremely AI-hostile (forces the agent to memorise an enum) and brittle to SDK reordering. Rejected.

## References

- x64dbg SDK: [_scriptapi_register.h](../../x64dbgMCP/plugintemplate/pluginsdk/_scriptapi_register.h), [_scriptapi_flag.h](../../x64dbgMCP/plugintemplate/pluginsdk/_scriptapi_flag.h), [_scriptapi_misc.h](../../x64dbgMCP/plugintemplate/pluginsdk/_scriptapi_misc.h), [bridgemain.h](../../x64dbgMCP/plugintemplate/pluginsdk/bridgemain.h)
- PoC reference: [copilot/refine-x64dbg-handler-todos branch, x64dbgHandler.h](https://github.com/nblog/x64dbgMCP/blob/copilot/refine-x64dbg-handler-todos/x64dbgMCP/x64dbgHandler.h)
- x64dbg expression syntax: [help.x64dbg.com — Expressions](https://help.x64dbg.com/en/latest/introduction/Expressions.html)
- Related: [conventions.md §2](../conventions.md#2-address--expression-inputs)
