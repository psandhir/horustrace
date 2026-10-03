# Pydantic AI fundamentals study

## Purpose

This study asks a narrow product question:

> Does HorusTrace understand the security-relevant Pydantic AI execution model well enough for first-class support, without requiring exhaustive static interpretation of arbitrary Python?

It is a **construct/conformance study**, not a new estimate of ecosystem-wide precision.

## Baseline

- Branch created from current `main` on 2026-10-03.
- The study runner and expectations are committed before the first workflow execution.
- No scanner behavior is changed by this branch.

PR #323 is intentionally not part of the baseline unless it has already landed on `main`; its destination-provenance work is framework-neutral and does not change the Pydantic binding model being tested here.

## Canonical construct surface

The cases are based on current Pydantic AI concepts that affect effective authority:

1. direct `Agent(..., tools=[...])`
2. `@agent.tool` with approval
3. post-construction `agent.tool_plain(...)`
4. `FunctionToolset` decorators and `add_function`
5. `CombinedToolset` + `ApprovalRequiredToolset`
6. filtered/deferred toolset composition
7. remote `MCPToolset`
8. local stdio MCP plus repository-local FastMCP implementation
9. runtime `agent.run*(..., toolsets=[...])`
10. dynamic `@agent.toolset`
11. built-in/harness capabilities including MCP, WebSearch, FileSystem and Guardrails
12. declarative `Capability(...)` bundle with a decorated tool
13. factory-returned Agent with function-local toolset
14. RunContext dependency/session-state mutation
15. source-visible pure functions with authority-looking names

Reference documentation used for construct selection:
- Pydantic AI Tools
- Pydantic AI Toolsets
- Pydantic AI Capabilities
- Pydantic AI Deferred Tools / approval
- Pydantic AI Extensibility

## Architectural invariants

Each case is scored against the applicable form of these invariants:

1. **agent_discovery** — a real Agent principal is represented.
2. **tool_binding** — explicit model-callable tools remain bound.
3. **toolset_mcp_binding** — explicit toolset/MCP relationships remain in the authority model.
4. **dynamic_visibility** — dynamic authority is retained as authority or explicit unresolved authority; it must not silently disappear.
5. **effect_semantics** — source-visible execution/network/read/write effects are recovered.
6. **local_vs_external** — local/session mutation is not promoted to persistent/external authority.
7. **scope_provenance** — known fixed destinations/resource scopes survive normalization.
8. **controls** — approvals/guardrails survive normalization.
9. **authority_driven_findings** — findings follow reconstructed authority, not names alone.

## Interpretation rule

This study does **not** require every case to be fully statically enumerated.

A dynamic construct is acceptable when HorusTrace preserves:

- the principal;
- the fact that authority is bound;
- known constraints; and
- the unresolved dimension.

The study treats **silent loss of explicit authority** as a fundamental failure.

Likewise, a scanner that invents privileged effects from a function name when source contradicts them fails the fundamentals criterion.

## Decision rule

The architecture is considered sound for Pydantic AI when:

- direct Agent/tool/toolset/MCP/control constructs are consistently normalized;
- canonical dynamic composition degrades to explicit unresolved authority rather than disappearing;
- source semantics dominate semantic naming;
- known restrictions survive into effective authority; and
- any remaining failures cluster in bounded extension/composition classes rather than the basic Pydantic execution model.

The purpose is to identify architectural classes, not to patch each case in this study.
