# Anthropic depth-parity fundamentals study

## Purpose

Validate current Anthropic agentic security semantics at the same standard used for Google ADK and Amazon.

The study covers three first-class Anthropic build paths:

1. Claude Agent SDK — Python
2. Claude Agent SDK — TypeScript
3. Claude Managed Agents — persisted agent/environment definitions

Scanner behavior is frozen before the first run.

## Baseline

- Branch created from `main` at `195d5ad43b4b076b85792155a98048fe1c5f6196`.
- Existing Claude Agent SDK Python real-world cohort is already independently validated 12/12 on current main lineage.
- These 15 canonical cases are frozen before first execution.
- Any scanner fixes must be made in a separate PR and rerun against the unchanged cases.

## Canonical surface

1. Python built-in tool authority and auto-approval.
2. Python default Claude Code tool surface.
3. Python custom SDK MCP tool with source-visible process/network effects.
4. Python stdio MCP with allow/deny approval rules.
5. Python remote HTTP MCP with auth and dynamic/fixed endpoint provenance.
6. Python AgentDefinition delegation and transitive authority.
7. Python dynamic MCP/subagent registries remain unresolved but visible.
8. Python permission modes, hooks and can_use_tool controls.
9. Python sandbox, cwd and add_dirs filesystem scope.
10. Python Workflow tool / dynamic workflow authority.
11. TypeScript Agent SDK built-ins and permission posture.
12. TypeScript SDK MCP + subagent delegation.
13. Managed Agent built-in toolset + MCP permission policies.
14. Managed Agent coordinator/multiagent + skills.
15. Managed Agent environment networking + session vault/MCP authentication evidence.

## Architectural invariants

- **agent_discovery** — source-proven agents are represented.
- **tool_binding** — explicitly enabled tool authority remains bound.
- **delegation_mcp_binding** — MCP, AgentDefinition, Workflow and Managed multiagent relationships survive.
- **dynamic_visibility** — dynamic catalogues/endpoints remain visible with uncertainty.
- **effect_semantics** — read/write/process/network/destructive effects are recovered.
- **local_vs_external** — local filesystem/process authority is distinct from server/remote authority.
- **scope_provenance** — filesystem roots, endpoints, tool policies, network hosts and skill/agent references survive.
- **controls** — permission modes/policies, hooks, sandbox/network restrictions and approvals are not overstated.
- **authority_projection** — normalized constructs survive into Effective Authority where applicable.

## Interpretation

Do not execute target code or contact Anthropic/MCP endpoints. Dynamic runtime catalogues do not need enumeration; their source-proven binding and uncertainty must remain explicit.

A hook being configured is not itself proof of enforcement. A Managed Agent `auto` permission policy is not equivalent to mandatory human approval. `always_ask` is the human-confirmation state.

Managed Agents is a separate authority boundary from Agent SDK: server-managed toolsets execute in an Anthropic-managed or self-hosted environment, while custom tools execute in application/worker code.

## Decision rule

Anthropic reaches current depth parity when all 15 canonical cases preserve the authority/control semantics above and the already-frozen 12-repo Python cohort remains green.
