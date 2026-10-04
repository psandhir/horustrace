# Google ADK depth-parity fundamentals study

## Purpose

This study asks whether HorusTrace understands the security-relevant Google Agent Development Kit (ADK) Python execution model deeply enough to hold Google to the same first-class standard as Pydantic AI and OpenAI Agents SDK.

It is a **construct/conformance study**. The branch contains study code only. Scanner behavior is intentionally unchanged before the first run.

## Baseline

- Branch created from `main` at `18caca37b992402351b3c53d93d47c783f218d82`.
- The 15 canonical cases and acceptance checks are frozen before the first workflow execution.
- Any scanner fixes discovered by this study must be made in a separate follow-up PR and rerun against this unchanged suite.

## Canonical authority-bearing surface

The 15 cases cover:

1. direct plain-function tool binding with source-visible fixed network effects;
2. `FunctionTool(require_confirmation=True)` around destructive external mutation;
3. local unsafe vs provider-managed code-execution boundaries;
4. `ComputerUseToolset` high-authority browser/computer control;
5. `UrlContextTool` provider transport vs model-selected target URL provenance;
6. remote Streamable HTTP MCP with fixed endpoint, auth, allowlist and confirmation;
7. local stdio MCP transport and tool allowlist;
8. `AgentTool` delegated-agent authority;
9. native `sub_agents` delegation and transfer restrictions;
10. ADK 2.x `Workflow(edges=[...])` topology and route projection;
11. evidence-based `before_tool_callback` control classification;
12. `RemoteA2aAgent` remote delegation, destination and authentication evidence;
13. `OpenAPIToolset` fixed servers plus operation-level destructive/mutation semantics;
14. source-proven dynamic tool collection binding retained as unresolved authority;
15. Google identity/scope evidence plus BigQuery write-mode restriction.

## Architectural invariants

Each case is scored against the applicable form of these invariants:

1. **agent_discovery** — source-proven ADK principals are represented.
2. **tool_binding** — explicitly model-callable tools remain bound.
3. **delegation_mcp_binding** — subagents, AgentTool, Workflow, A2A and MCP survive into the authority model.
4. **dynamic_visibility** — dynamic authority remains present with explicit uncertainty instead of disappearing or becoming invented concrete authority.
5. **effect_semantics** — source-visible execution/network/read/write/destructive effects are recovered.
6. **local_vs_external** — local/provider-managed execution and local state are not confused with external authority.
7. **scope_provenance** — fixed/dynamic destinations, MCP endpoints, tool filters, API servers and cloud scopes survive normalization.
8. **controls** — confirmation, callbacks, transfer restrictions and write restrictions survive without being overstated.
9. **authority_projection** — the normalized construct is visible in Effective Authority where the product contract requires it.

## Interpretation rule

The study does not require arbitrary Python execution or runtime catalogue enumeration. For dynamic tool collections, runtime endpoints, callbacks whose implementation is unavailable, or provider-managed catalogues, acceptable behavior is:

- retain the source-proven binding;
- retain every statically known constraint;
- mark the unresolved dimension explicitly;
- never invent a concrete catalogue or silently treat unknown evidence as safe.

Provider-managed execution must remain distinct from local process execution. A callback merely being present is not proof of enforcement.

## Decision rule

Google ADK reaches depth parity when:

- canonical agents/tools/MCP/delegation/workflows normalize consistently;
- model-selected URL and fixed-provider/fixed-server scopes remain distinguishable;
- high-authority execution surfaces retain their security boundary;
- source-proven controls are neither dropped nor overstated;
- dynamic authority remains explicit;
- identity/resource evidence survives into authority; and
- any failures are bounded semantic classes rather than basic ADK construction failures.

Current ADK references used to select the surface include Google ADK v2 workflow, tools, MCP, A2A and deployment documentation current as of 2026-10-04.
