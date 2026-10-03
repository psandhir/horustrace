# OpenAI Agents SDK fundamentals — baseline result

Frozen conformance run: `37154340065`

## Result

- 15/15 cases completed.
- 9/15 cases fully passed.
- No scanner behavior was changed for the study.
- A study-harness correction was made after the first execution so metadata signals only inspect semantic metadata keys rather than temporary-path values.
- The handoff invariant was also tightened to require delegation to survive into Effective Authority, matching the product contract.

| Invariant | Passed | Total | Rate |
|---|---:|---:|---:|
| agent_discovery | 15 | 15 | 100.0% |
| tool_binding | 15 | 15 | 100.0% |
| delegation_mcp_binding | 14 | 15 | 93.3% |
| dynamic_visibility | 13 | 15 | 86.7% |
| effect_semantics | 15 | 15 | 100.0% |
| local_vs_external | 15 | 15 | 100.0% |
| scope_provenance | 15 | 15 | 100.0% |
| controls | 11 | 15 | 73.3% |
| authority_driven_findings | 15 | 15 | 100.0% |

## Passing fundamentals

HorusTrace correctly handles the basic OpenAI Agents execution model:

- Agent discovery.
- Direct function-tool binding.
- Literal function-tool approval.
- Source-visible network/process/read/write semantics.
- Hosted WebSearch/FileSearch/CodeInterpreter authority.
- ShellTool and ApplyPatchTool authority and literal approval.
- Hosted MCP endpoint, allowlist and approval.
- Local stdio MCP and repository-local FastMCP linkage.
- Runtime clone MCP attachment.
- Factory-returned Agent with a local tool.
- Source behavior overriding authority-looking names.

The strongest result is that **agent discovery, tool binding, effect semantics, scope provenance and authority-driven findings are all 100% on the canonical suite**.

## Fundamental gaps

### 1. Conditional FunctionTool enablement is flattened

Case: `oai-fund-03-conditional-tool-enable`

`@function_tool(is_enabled=callable)` remains bound, which is conservative for maximum authority, but the runtime enablement condition disappears. The tool is represented as if no conditional activation exists.

Desired invariant:

```
source-bound tool + runtime enablement predicate
    -> relationship present
    -> capabilities preserved
    -> activation/availability marked conditional or unresolved
```

### 2. Conditional FunctionTool approval is flattened

Case: `oai-fund-04-conditional-approval`

`needs_approval=callable` becomes generic unknown approval with no evidence that an approval policy exists. This loses an SDK control primitive and leads to categorical AGT020/AGT040 findings.

Desired behavior is to preserve that approval is **conditional/per-call**, without claiming it always protects execution.

### 3. Local MCP per-tool approval and tool guardrails are lost

Case: `oai-fund-08-local-http-mcp-controls`

The static tool allowlist is preserved, but:

- a mixed per-tool `require_approval` map collapses to unknown;
- `tool_input_guardrails=[guardrail_function]` is not retained.

The MCP relationship therefore loses two source-visible controls.

### 4. Agent-as-tool approval is lost

Case: `oai-fund-10-agent-as-tool-approval`

`specialist.as_tool(..., needs_approval=True)` correctly preserves the delegated target and `agent.delegate` capability, but the approval requirement is dropped.

This is a small parser gap on a first-class delegation primitive.

### 5. Handoffs do not survive into Effective Authority

Case: `oai-fund-11-handoffs`

Both direct handoffs and `handoff(...)` are discovered. The Agent graph contains delegated-agent tools and `delegates_to` metadata, but `effective_authority_relationships()` emits no relationship for either handoff.

Given HorusTrace's product contract, delegated authority should not stop at discovery/ADG projection.

### 6. Agent input/output guardrails are not retained

Case: `oai-fund-13-agent-guardrails`

The Agent is discovered, but its `input_guardrails` and `output_guardrails` disappear.

These controls must be preserved as **boundary controls**, not misrepresented as blanket approval for tool execution or handoffs.

## Architecture conclusion

The OpenAI Agents SDK architecture is fundamentally sound; the failures do **not** indicate a need to redesign agent discovery or effect reconstruction.

The failures cluster around one coherent theme:

> HorusTrace understands what OpenAI agents can do better than it currently understands the SDK controls and conditionality governing when they can do it.

Recommended next step: implement these five bounded semantic classes, rerun this exact frozen 15-case suite unchanged, and stop OpenAI-specific work if it reaches full conformance without regression.
