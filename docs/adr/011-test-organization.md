# ADR-011: Organize tests by capability group under test/

- **Status**: Proposed
- **Date**: 2026-10-16
- **Deciders**: x64dbgMCP maintainers

## Context

The repository currently ships no `test/` directory. Validation today is live smoke
through mcporter against a running x64dbg (see
[docs/README.md](../README.md#进程闭环验证)), with outcomes recorded in
[docs/validate/](../validate/README.md). The unit/integration test strategy itself is
deliberately deferred ("Next implementation order" item 5 in
[implementation-status.md](../implementation-status.md)) until behaviour stabilizes.

When repeatable tests do arrive, the recurring failure mode without a structural rule is
well known: entry scripts, fixtures, and helper modules pile up flat under `test/`,
directory names like `misc` or `temp` hide intent, and shared helpers get extracted into
a speculative framework before any real second consumer exists.

An external convention template proposing a capability-group test layout was reviewed.
Its Python-specific parts (PEP 723 script metadata, standalone Python test entries) do
not apply to this C++/CLI codebase and are dropped; the structural rules are retained and
made language-neutral.

## Decision

Tests live under `test/<capability-group>/`, one grouping level by capability or domain
under test.

1. Group names are lowercase and hyphenated, and they name the tested capability
   (illustrative, grounded in project vocabulary: `mcp-contract`, `server-lifecycle`,
   `string-references`, `debug-gui`). Bare `misc`, `temp`, or meaningless numeric names
   are not valid group names. Groups are created when their capability gains tests, not
   speculatively.
2. The `test/` root holds only the test overview README and genuinely necessary global
   test configuration. No loose test scripts, platform scripts, or helper modules at the
   root.
3. Each group is self-contained: its entry points, helper modules, fixtures, and local
   run dependencies live inside the group. When execution order matters, entries use
   `00_`-style prefixes inside the group; numbering supplements grouping and never
   replaces it.
4. `test/_shared/` is created only once real cross-group reuse exists. No pre-built
   common test framework, and no copying helper code between groups to avoid the
   extraction decision.
5. Adding or renaming a group must, in the same change, sync build artifact targets,
   include/import paths, `.gitignore` rules, and documented commands, and must verify
   that the group's entry runs from the repository root.

## Consequences

- Capability is the unit of navigation: everything about one domain (entries, fixtures,
  helpers) is findable and evolvable in one folder.
- Groups can change independently because fixtures and helpers stay private to the group.
- Cross-cutting needs force an explicit `_shared` extraction decision instead of silent
  duplication or premature abstraction.
- The constraint binds from the first `test/` introduction; until then it is a standing
  rule with no code to conform. The example group names are illustrative, not a
  commitment to specific groups.
- This ADR fixes layout only. Which layers to test and how live smoke becomes repeatable
  remain a separate future ADR per implementation-status item 5.

## Alternatives Considered

1. Flat `test/` root with filename prefixes. Rejected because prefix schemes do not
   scale past a handful of scripts, fixture ownership becomes unclear, and intent lives
   in naming conventions rather than structure.
2. Mirror the source tree (`test/x64dbgMCP/...`). Rejected because it couples test
   layout to implementation layout, so refactors churn test paths; capability grouping
   survives reorganization. The interesting seams here (MCP contract, live debugger
   behaviour) also cut across source files rather than following them.
3. Group by test type first (`unit/`, `integration/`, `live/`). Rejected because one
   capability's evidence scatters across three trees, and the unit/integration boundary
   is exactly what will shift as the deferred test strategy matures.

## References

- [docs/README.md — 进程闭环验证](../README.md#进程闭环验证) — current mcporter live-smoke validation path
- [implementation-status.md — Next implementation order](../implementation-status.md) — item 5, pending test-strategy ADR
- [ADR authoring rules](README.md#authoring-rules) — one decision per ADR, cite evidence, record alternatives
