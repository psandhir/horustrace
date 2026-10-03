# OpenAI Agents SDK fundamentals study

## Purpose

This study asks a narrow product question:

> Does HorusTrace understand the security-relevant OpenAI Agents SDK execution model well enough for first-class support, without requiring exhaustive interpretation of arbitrary Python?

It is a **construct/conformance study**, not an ecosystem-wide precision estimate and not a new scanner-fix branch.

## Baseline

- Branch created from current `main` after PR #323 merged.
- The study runner and expectations are frozen before the first workflow execution.
- No scanner behavior is changed by this branch.

## Canonical construct surface

The 15 cases cover current OpenAI Agents SDK authority-bearing primitives:

1. direct `@function_tool` binding and source-visible network effects
2. `@function_tool(needs_approval=True)`
3. conditional `is_enabled` on a function tool
4. conditional `needs_approval` on a function tool
5. hosted/provider tools: WebSearch, FileSearch, Code Interpreter
6. ShellTool and ApplyPatchTool with approval
7. HostedMCPTool with fixed server, allowlist and approval
8. local Streamable HTTP MCP with static filter, approval and tool guardrail
9. local stdio MCP plus repository-local FastMCP implementation
10. `Agent.as_tool(..., needs_approval=True)`
11. direct handoffs and the `handoff(...)` helper
12. runtime `Agent.clone(mcp_servers=[...])`
13. agent input/output guardrails
14. factory-returned Agent with a function-local tool
15. source-visible pure functions with authority-looking names

Current SDK references used for construct selection:
- https://openai.github.io/openai-agents-python/
- https://openai.github.io/openai-agents-python/ref/tool/
- https://openai.github.io/openai-agents-python/agents/
- https://openai.github.io/openai-agents-python/handoffs/
- https://openai.github.io/openai-agents-python/guardrails/
- https://openai.github.io/openai-agents-python/mcp/

## Architectural invariants

Each case is scored against the applicable form of these invariants:

1. **agent_discovery** — a real Agent principal is represented.
2. **tool_binding** — explicitly model-callable tools remain bound.
3. **delegation_mcp_binding** — handoffs, agents-as-tools and MCP bindings remain in the authority model.
4. **dynamic_visibility** — conditional/dynamic authority is retained as authority plus its unresolved condition; it must not silently become unconditional or disappear.
5. **effect_semantics** — source-visible execution/network/read/write effects are recovered.
6. **local_vs_external** — local/internal state is not promoted to persistent or external authority.
7. **scope_provenance** — known fixed destinations, MCP endpoints and tool allowlists survive normalization.
8. **controls** — approval and guardrail semantics survive normalization without being overstated.
9. **authority_driven_findings** — findings follow reconstructed authority, not names alone.

## Interpretation rule

This study does **not** require every runtime condition to be statically decided.

For dynamic `is_enabled`, conditional approval, dynamic handoff enablement or remote MCP catalogues, acceptable behavior is:

- preserve the bound principal/relationship;
- preserve known constraints;
- mark the conditional or unresolved dimension explicitly;
- do not silently convert conditional authority into unconditional authority.

Input/output guardrails are boundary controls, not blanket tool-execution approval. Tool guardrails are likewise distinct from handoff guardrails. The scanner should preserve those distinctions rather than treating generic “guardrail present” as universal enforcement.

## Decision rule

The architecture is considered sound for OpenAI Agents SDK when:

- Agent/tool/handoff/MCP constructs normalize consistently;
- agent-as-tool and handoff delegation survive into Effective Authority;
- conditional tool/approval constructs degrade to explicit unresolved/conditional authority;
- hosted/local execution tools retain their material authority and controls;
- source semantics dominate semantic naming; and
- any failures cluster in bounded construct classes rather than the basic SDK execution model.

The purpose is to identify architectural classes first. Scanner changes, if any, happen only after the study result is reviewed.
