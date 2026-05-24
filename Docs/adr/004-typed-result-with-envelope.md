# ADR-004: Typed result classes wrapped in a common `McpResult` envelope

- **Status**: Accepted
- **Date**: 2026-05-24
- **Deciders**: @nblog

## Context

Two questions need a joint answer:

1. **Result shape**: should tools return ad-hoc `Dictionary<String^, Object^>` (PoC pattern) or named typed classes?
2. **Error semantics**: should errors propagate as exceptions (MCP framework converts to JSON-RPC `internal_error`) or be inlined into the response payload?

The PoC mixes both — most tools return `Dictionary<String^, Object^>`, errors throw `ArgumentException`. This is convenient to write but produces three problems:

- **No schema**: `Dictionary<String, Object>` serialises to JSON but the agent can't know the field names without calling the tool, defeating MCP's schema-as-description value-add.
- **No invariants**: defaults, required-vs-optional, formatting rules (hex addresses) are scattered across call sites instead of centralised.
- **Inconsistent error UX**: caller-input errors (`ArgumentException` for unknown register name) and operational failures (debugger not attached) are reported the same way as programmer errors (null deref). Agents can't distinguish "I should fix my call" from "the tool itself broke".

The user's preference (per project profile) is structured, declarative types — pydantic-style schema-as-constraint. C++/CLI ref classes are the closest analogue with `System.Text.Json`-friendly properties.

## Decision

**Every tool returns a typed result class derived from a common `McpResult` envelope.** Errors that the caller can act on are returned in the envelope; errors that indicate a bug propagate as exceptions.

### Envelope shape

```cpp
public ref class McpResult
{
public:
    property bool Success;                                 // false → Error is set
    property ErrorInfo^ Error;                             // null when Success
    property Dictionary<String^, LinkRef^>^ Links;         // navigation roots only
};

// concrete results inherit and add typed Data (and Page if list-shaped)
public ref class DisassembleResult : McpResult
{
public:
    property List<DisassembleEntry^>^ Data;
};
```

Implementation note: C++/CLI generic ref classes are awkward, so we don't use `McpResult<T>` — each domain defines a concrete subclass with a typed `Data` property. The envelope is the contract; the generic is sugar we don't need.

### Error classification

| Class | Mechanism | Examples |
|---|---|---|
| **Caller error** (the agent can fix by changing inputs) | Envelope, `Success=false`, closed-set `Error.Code` | `invalid_argument`, `not_found` |
| **Operational error** (right call, wrong state) | Envelope, `Success=false`, closed-set `Error.Code` | `not_attached`, `not_paused`, `unsupported`, `x64dbg_failed` |
| **Programmer error** (genuinely unexpected) | Throw; framework converts to JSON-RPC error | null deref, invariant violation |

The closed `Error.Code` set is enumerated in [conventions.md §5](../conventions.md#5-error-semantics). New codes require updating that section.

### Why "envelope-and-throw" rather than "all-throw" or "all-envelope"

- **All-throw**: the agent sees `JsonRpcError(code=-32603, message="invalid_argument: unknown register 'rxxx'")` for every miss. Generic JSON-RPC error semantics don't preserve our taxonomy; agents have to parse strings.
- **All-envelope**: programmer errors get serialised into a misleadingly-structured response. We lose stack traces in logs and the agent gets bad data dressed as good data.
- **Envelope-and-throw**: caller/operational errors get a typed shape the agent can branch on; bugs surface loudly to logs/operators, not to agents.

This matches what the MCP C# SDK does internally — `McpServerTool` accepts any return type and JSON-serialises it; uncaught exceptions bubble to JSON-RPC errors.

### Resources are exempt

`[McpServerResource]` methods follow the MCP resource contract (return raw text or `ResourceContents`), not the envelope. The MCP spec does not allow envelope-wrapping for resources, and forcing one would break standard MCP clients.

## Consequences

**Positive**

- Tool schemas are concrete and inspectable — agents see field names, types, descriptions
- Defaults and formatting rules are centralised in result class definitions
- Caller can distinguish "fix my input" from "wait for state" from "report a bug" without string parsing
- Compatible with `System.Text.Json` out of the box; no custom serialiser

**Negative**

- ~30 small ref classes to write. Mitigated by the fact that they're cheap (declarative property bags) and gate-checked by the schema → reduces churn during implementation.
- Mega-tool methods return `Object^` (since action determines the concrete result type). Lost compile-time typing on the method signature; recovered at runtime via the typed result subclass.
- Adding a new error code is a (light) cross-file change: closed set in [conventions.md](../conventions.md), validation logic in `Helpers`.

**Constraints on future work**

- New tools must define a named result class. `Dictionary<String^, Object^>` returns require an ADR explaining why a typed shape doesn't fit (extreme polymorphism is the only known case).
- New error conditions must map to an existing `Error.Code` or extend the closed set in [conventions.md §5](../conventions.md#5-error-semantics).
- Programmer errors (null deref, asserts) stay as exceptions. Catching them to convert to envelope is forbidden — it hides bugs.

## Alternatives Considered

1. **`McpResult<T>` generic** — rejected. C++/CLI generic ref classes have awkward syntax (`generic <typename T>`) and don't compose well with method-overload resolution. Concrete subclasses are clearer.
2. **All errors as exceptions (PoC pattern)** — rejected. Loses error taxonomy; agents see opaque JSON-RPC errors.
3. **All errors as envelope (no exceptions)** — rejected. Programmer errors silently pollute responses; debugging gets harder.
4. **OpenAPI-style discriminated union (`oneOf`)** — closer to industry HTTP norms but `System.Text.Json` doesn't natively bind `oneOf` without polymorphic deserialisation attributes ([JsonDerivedType]). Adds machinery for marginal benefit; rejected for v0.
5. **Untyped `Dictionary` returns (PoC pattern)** — rejected. Defeats MCP's schema value-add.

## References

- [conventions.md §4-§5](../conventions.md#4-result-envelope) for the canonical envelope and error code set
- [tools-spec.md §1](../tools-spec.md#1-result-envelope) for the C++/CLI envelope code
- [System.Text.Json polymorphism docs](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/polymorphism) — for future reference if `oneOf` becomes worthwhile
- Related: [ADR-003](003-tool-resource-action-three-layer.md) (mega-tool method signatures return `Object^` because of this), [ADR-005](005-hateoas-links-on-navigation-roots.md) (`Links` field on the envelope)
