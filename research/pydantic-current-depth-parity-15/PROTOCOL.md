# Pydantic AI current-surface depth parity 15

## Purpose

This is a delta depth-parity study for the current Pydantic AI / Pydantic AI Harness security surface.

The existing `pydantic-fundamentals-15` suite is already closed at 15/15 with all nine original invariants at 100% after PR #332. This study does not re-test those solved basics. It asks whether HorusTrace also preserves the authority and control semantics of newer/current Pydantic constructs that materially change what an agent can reach or execute.

## Freeze

- HorusTrace baseline: current `main` at branch creation on 2026-10-04.
- Current Pydantic reference source: `pydantic/pydantic-ai@40147f7d03cd26a5b415eb1d34653ab0f6153dfb`.
- Cases and expectations are committed before the first HorusTrace execution.
- No scanner code is changed on this research branch.

## Delta surface

1. `LocalWorkspace` + `FileSystem` fixed workspace scope.
2. Read-only `LocalWorkspace` removing write authority.
3. E2B remote sandbox + `Coder`.
4. Sprites remote sandbox + shell/filesystem.
5. SSH workspace destination and remote-user authority.
6. Bubblewrap sandbox constraining network authority over SSH.
7. Explicit `SubAgents` delegation to named child agents.
8. `SubAgents(include_self=True)` recursion/depth control.
9. Harness `Memory(FileStore(...))` persistent state scope.
10. Harness `Skills` deferred capability catalogue from workspace.
11. `CapabilityCreation` model-authored executable Python.
12. Harness GitHub capability and hosted MCP authority.
13. Harness Slack read-only capability and credential-aware MCP authority.
14. `TemporalDurability` as a runtime capability without inventing model-callable authority.
15. Provider-managed `NativeTool(CodeExecutionTool())`.

## Invariants

1. **agent_discovery** — the real Pydantic principal remains represented.
2. **authority_binding** — source-visible model-callable authority is bound to the principal.
3. **dynamic_visibility** — deferred/dynamic authority remains explicit rather than disappearing.
4. **effect_semantics** — read/write/process/network/delegation effects match source semantics.
5. **execution_boundary** — local host vs remote workspace/sandbox boundaries are preserved.
6. **scope_provenance** — fixed workspace roots, remote hosts, stores and service destinations survive normalization.
7. **controls** — read-only, sandbox, recursion/depth and approval-like restrictions are not discarded.
8. **delegation_binding** — named/self sub-agent relationships remain explicit when applicable.
9. **authority_projection** — effective authority reflects the normalized construct without inventing authority that controls remove.

## Interpretation

A dynamic current-surface construct may remain unresolved, but it must retain the proven binding, known constraints and unresolved dimension. Silent loss is a failure.

A sandbox/control case also fails if HorusTrace over-projects authority that the source explicitly removes. In particular, read-only workspaces and Bubblewrap's default network isolation are precision tests, not only recall tests.

This is a construct/conformance study. A fresh unseen real-world Pydantic-only cohort follows after bounded fixes, using pinned public repositories and LLM source adjudication of findings/misses.
