# Amazon SDK depth-parity fundamentals study

## Purpose

This study asks whether HorusTrace understands the security-relevant Amazon agentic execution model deeply enough to hold Amazon to the same first-class standard as Google ADK, OpenAI Agents SDK and Pydantic AI.

The primary SDK surface is current **Strands Agents SDK** (Python and TypeScript), with the deployment/authority boundary extended into **Amazon Bedrock Agents** and **Amazon Bedrock AgentCore** where identities, gateways, policies and execution roles change effective authority.

This is a **construct/conformance study**. Scanner behavior is intentionally unchanged before the first run.

## Baseline

- Branch created from `main` at `1be194c94b3b643f2c8d081e5fa14e6643eb3a9f`.
- The 15 canonical cases and acceptance checks are frozen before first execution.
- Any scanner fixes discovered by this study must be made in a separate follow-up PR and rerun against this unchanged suite.

## Canonical authority-bearing surface

The 15 cases cover:

1. Strands Python `@tool` binding with fixed external mutation;
2. source-visible AWS SDK effects (read/write/destructive) behind a Strands tool;
3. Strands vended high-authority tools such as shell/file editing/AWS access;
4. local stdio MCP with explicit tool filtering;
5. fixed remote Streamable HTTP MCP with authentication evidence;
6. runtime-configured remote MCP endpoint retained as unresolved/dynamic authority;
7. direct agent-as-tool delegation and transitive authority;
8. explicit `.as_tool()` agent delegation;
9. `GraphBuilder` nodes, edges, entry point and transitive authority;
10. `Swarm` membership, handoff topology and execution bounds;
11. A2A client/provider authority with runtime-discovered remote agents and SigV4-style auth evidence;
12. `BeforeToolCallEvent` enforcement vs observer-only hook semantics;
13. TypeScript Strands tool + MCP + agent-as-tool parity;
14. Bedrock Agent declarative authority: action groups, knowledge base, guardrail and collaborators;
15. AgentCore/IAM deployment authority: runtime role, gateway/MCP target, memory and IAM permission/resource projection.

## Architectural invariants

Each case is scored against the applicable form of these invariants:

1. **agent_discovery** — source-proven Strands/Bedrock/AgentCore principals are represented.
2. **tool_binding** — explicitly model-callable tools remain bound.
3. **delegation_mcp_binding** — agent-as-tool, Graph, Swarm, A2A and MCP relationships survive normalization.
4. **dynamic_visibility** — runtime catalogues/endpoints remain visible with explicit uncertainty instead of disappearing or becoming invented concrete authority.
5. **effect_semantics** — source-visible execution/network/read/write/destructive effects are recovered.
6. **local_vs_external** — local process/filesystem authority is distinguished from provider/network authority.
7. **scope_provenance** — fixed/dynamic endpoints, MCP filters, AWS resources, KB IDs and IAM resource scopes survive.
8. **controls** — hooks/HITL, guardrails, execution bounds, gateway auth and policy-related controls are neither dropped nor overstated.
9. **authority_projection** — normalized authority is visible in Effective Authority where the product contract requires it.

## Interpretation rule

The study does not require runtime execution, live AWS discovery or enumeration of dynamic provider catalogues.

For runtime-discovered A2A agents, MCP servers, dynamic tool providers, Graph/Swarm routing and AgentCore targets, acceptable behavior is:

- retain the source-proven binding;
- retain every statically known constraint;
- mark the unresolved dimension explicitly;
- never invent concrete remote agents/tools/endpoints or silently treat unknown evidence as safe.

A hook merely being registered is not proof of enforcement. Source-visible cancellation/interrupt behavior is required before classifying a control as enforcing.

AWS default credential-chain evidence is not equivalent to a source-proven execution role. IAM roles and policies from IaC must remain distinct from ambient runtime credentials.

## Decision rule

Amazon reaches depth parity when:

- canonical Strands Python and TypeScript agents/tools/MCP normalize consistently;
- agent-as-tool, Graph, Swarm and A2A authority survive into the security graph;
- local execution and AWS/provider effects retain their correct boundaries;
- dynamic authority remains explicit;
- source-visible hooks/HITL and deployment controls are not overstated;
- Bedrock/AgentCore identity/resource/IAM evidence survives into Effective Authority; and
- failures, if any, form bounded semantic classes rather than basic SDK construction failures.

Reference surface selected against current Strands SDK documentation/releases and current Amazon Bedrock AgentCore documentation as of 2026-10-04.
