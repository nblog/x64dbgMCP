# Architecture Decision Records

ADRs capture **load-bearing design decisions** — choices that constrain how future code/docs are written. Each ADR is a small, dated, reviewable unit. Code conformance refers back to ADRs by number.

## Index

| # | Title | Status |
|---|---|---|
| [001](001-mcp-only-no-rest-shadow-api.md) | MCP-only transport; no REST shadow API | Accepted |
| [002](002-resolve-via-x64dbg-expression.md) | Resolve names (registers/flags/labels) via x64dbg expression rather than enum mirrors | Accepted |
| [003](003-tool-resource-action-three-layer.md) | Three-layer surface: Resources + rich-param Tools + action-mega Tools | Accepted |
| [004](004-typed-result-with-envelope.md) | Typed result classes wrapped in a common `McpResult` envelope | Accepted |
| [005](005-hateoas-links-on-navigation-roots.md) | HATEOAS `_links` on navigation roots only, not on every leaf | Accepted |
| [006](006-debug-gui-evidence-capture.md) | `DebugGUI` visual evidence capture and CPU-pane selection control | Accepted |
| [007](007-scoped-hateoas-relation-keys.md) | Scoped snake_case relation keys for HATEOAS `_links` | Accepted |
| [008](008-mcp-endpoint-path.md) | Use `/mcp` as the single Streamable HTTP endpoint | Accepted |

## Status taxonomy

- **Proposed** — written, under discussion, not yet binding
- **Accepted** — binding; code/docs must conform
- **Superseded by NNN** — replaced by another ADR; keep file for history
- **Deprecated** — no longer applicable; behaviour grandfathered or removed

## Authoring rules

1. **One decision per ADR.** If you find yourself writing "and also…", split it.
2. **Frozen once accepted.** Substantive changes require a new ADR that supersedes the old one. Trivial wording fixes are fine in place.
3. **Cite evidence.** Reference SDK docs, repos, benchmarks, prior incidents. No "I think" without a "because".
4. **Record alternatives.** A decision without rejected alternatives is a guess.
5. **Number sequentially.** Never reuse a number, even if an ADR is deprecated.

## Template

```markdown
# ADR-NNN: <Title>

- **Status**: Proposed | Accepted | Superseded by ADR-XXX | Deprecated
- **Date**: YYYY-MM-DD
- **Deciders**: <handles>

## Context

What forces are at play? What problem is this decision answering?
Cite sources and prior art.

## Decision

What did we decide? State it as a rule a future contributor can apply.

## Consequences

What follows from this decision — both positive and negative?
What does it constrain in future work?

## Alternatives Considered

What did we reject and why? At least 2 alternatives should be listed.

## References

- External docs, repos, prior ADRs, conversation references.
```
