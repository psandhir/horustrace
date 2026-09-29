# Blind semantic generalization cohort — results

## Executive result

The post-#214 scanner generalizes **partially but not completely** beyond the seven repositories that drove the recent fixes.

The blind cohort was frozen before HorusTrace output was inspected, and all 11 source reviews were committed before scanner reveal. No scanner code was changed during comparison.

The strongest result is that the remaining misses cluster into a small number of reusable semantic primitives rather than eleven unrelated framework exceptions.

### What generalized well

- **Effective-authority precision:** `rw-071` contains a Snowflake SQL execution helper that is imported but not actually bound to the LangGraph tool node. HorusTrace does **not** raise destructive SQL findings.
- **Inactive MCP precision:** `rw-140` defines an `@latest` MCP constructor, but its runtime server list is empty. HorusTrace correctly reports zero effective MCP servers and does not raise AGT050/AGT053 for it.
- **Narrow network precision:** `rw-180` has a read-only Reddit research tool with source-constrained service destinations and receives no broad-network/state-change finding.
- **Remote MCP semantics:** `rw-110` correctly produces NET001 + AGT032 while keeping AGT031 absent for an observed HTTPS default endpoint.
- **Pydantic state authority:** `rw-165` recovers AGT022, AGT040 and CAP005 for Jira/local-task writes.

### Recurring gap families

1. **Effective authority binding — highest priority.**
   - `rw-002`: FastAgent per-agent MCP server lists are discovered structurally but privileged MCP findings lose agent attribution.
   - `rw-026`: `ALL_TOOLS = BANKING_TOOLS + OBSERVABILITY_TOOLS` is not resolved; 13 source-effective tools collapse to one scanner-visible tool.
   - `rw-081`: a complete Gemini `model -> list_tools -> function_call -> call_tool` loop is present, yet the scanner creates zero agent principals and therefore cannot bind its MCP authority.

2. **Trust flow into privileged/state sinks.**
   - `rw-165`: interactive Click input reaches `agent.run_sync` and state-changing tools, but PATH002 is absent.
   - `rw-071`: Streamlit input reaches a graph compiled with `MemorySaver`; PATH007 is absent. This remains a semantics decision because the checkpointer is in-memory rather than durable.

3. **Network/auth evidence conversion.**
   - `rw-110`: source explicitly constructs the MCP HTTP client with no auth parameter and only Accept/User-Agent headers, but AGT030 is not emitted.
   - `rw-140`: model-callable GitHub/Tavily tools accept arbitrary URL arguments without a destination allowlist, but NET001 is absent.

4. **Rule-contract precision.**
   - AGT053 is documented as a **bound MCP** rule, but `rw-081` (and several `rw-002` findings) show AGT053 with `agent=null`. Structural discovery and effective authority should remain distinct.

5. **Lower-priority dynamic factory recall.**
   - `rw-121` source creates multiple named OpenAI Agents through a factory, while HorusTrace represents one principal. No privileged findings are fabricated, so this is lower security priority.

## Reviewer corrections

The blind source reviews initially expected both NET001 and NET002 in two URL-egress cases. Reconciliation against the built-in rule implementation established that these represent alternative states:

- NET001: broad/dynamic destination is observed;
- NET002: outbound authority exists but the destination constraint remains unresolved.

Accordingly, `rw-038` is considered a policy agreement with NET001, and `rw-140` is considered a missing NET001 only.

## Per-case outcome

| Case | Framework | Outcome | Main conclusion |
|---|---|---|---|
| rw-002 | FastAgent | Gap | MCP discovery exists, but per-agent binding/attribution and AGT050 coverage are weak |
| rw-038 | Google ADK | Agreement | Arbitrary URL authority correctly becomes NET001 |
| rw-026 | Google ADK | Gap | Imported tool-list composition loses 13 effective banking/safety tools |
| rw-071 | LangGraph | Mixed | Correctly ignores unbound SQL; possible checkpoint PATH007 gap |
| rw-066 | LangGraph | Mostly unresolved | External MCP implementation prevents strong policy adjudication |
| rw-110 | custom MCP | Gap | NET001/AGT032 good; source-proven no-auth is not converted to AGT030 |
| rw-081 | custom MCP | Gap | 42 tools/MCP servers found, but source-proven model/tool loop has no agent/binding |
| rw-140 | OpenAI Agents | Mixed | Excellent inactive-MCP precision; arbitrary URL network scope is missed |
| rw-121 | OpenAI Agents | Mixed/low impact | Dynamic agent instances collapse; adjacent MCP topology creates no findings |
| rw-165 | Pydantic AI | Gap | Authority findings strong; CLI -> state-change PATH002 missing |
| rw-180 | Pydantic AI | Agreement | Narrow read-only Reddit workflow remains clean |

## Next build order

The study argues against adding more one-off constructor heuristics. The next scanner tranche should address reusable primitives in this order:

1. imported/composed tool-list and per-agent MCP binding;
2. custom model/tool-loop binding to discovered MCP catalogues;
3. source-proven CLI/Streamlit ingress propagation into privileged sinks;
4. explicit no-auth and model-selected destination semantics;
5. AGT053 bound-authority contract enforcement.

After each tranche, rerun both this frozen 11-case cohort and the full Frozen-180 precision gates. Do not change the cohort to accommodate scanner behavior.

## Evidence boundary

This is an LLM-assisted, source-verified post-hoc generalization study. It is not a replacement for the preregistered Frozen-180 metrics and does not satisfy Issue #157's independent-human accuracy requirement.
