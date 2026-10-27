# Wave C C02u — independent Pydantic conditional source-tool AST oracle

Parent [#606](https://github.com/psandhir/horustrace/issues/606) / [#543](https://github.com/psandhir/horustrace/issues/543).
Following MCP C02s and ADK C02t, this slice verifies bounded source-level Pydantic *conditional* tool-list syntax with a completely separate Python standard-library AST parser (not HorusTrace's Pydantic adapters and not prior LLM source opinions).

## Real exact pinned study

`rw-149` `LeonieFreisinger/pydanticai-base-agent@0cf88a4caf2b5da29ff7af8364d4db14ac9e50b4`. Four source files are Git object-verified: `agent/tools.py`, `agent/agent.py`, `agent/base_agent.py`, and `app.py`. No scanned target dependencies are imported, installed or executed.

For `get_tools_for_level(level)`, AST checks explicit **literal** branches:
- `level == 1` returns the empty tool list (a hard negative for direct tool-list binding at that source level).
- `level == 2` returns `list_tables` and `describe_table`.
- `else` returns five static source symbols `list_tables`, `describe_table`, `execute_query`, `get_current_date`, `get_stock_query_template`.

**Important nuance:** that `else` branch covers all integers other than 1 and 2, not only levels 3 or 4. Its source-visible consequences for levels 3 and 4 can be verified, but the source does NOT guarantee a bounded `DEMO_LEVEL` or any deployed value. No runtime `AGENT_CAN_CALL` claims.

Separately, inspect exact AST plumbing from `SQLQueryAgent.__init__` `tools=get_tools_for_level(self.demo_level)`, to `BaseAgent(tools=tools)`, to the wrapper loop `for tool in self.tools: self._agent.tool(tool)`. This proves source statements exist, not that a package/SDK version successfully registers or authorizes any tool.

## Adversarial and validation coverage

- Source-level level1 emptiness vs merely existing functions is never inflated to a positive binding.
- Reject changed conditions, dynamic factory returns, duplicate source symbol returns, invalid/unsafe paths, and missing method/registration-loop shape.
- Metamorphic harmless comments do not alter declared selections.
- Pin Git SHA/tree/blob and source hashes; run current static scanner on same exact source and retain source output artifact without automatically declaring measured precision/recall.

CI retains the complete existing Fresh-16/Full-60, Ruff/Python3.11/3.12, CodeQL, source-regression and same-head accuracy gates. No production Graph, ADG, authority, findings, paths, rules, controls, thresholds, reports or UX change.

The mechanically bounded positive/negative syntax reference **is not independently reviewed/exhaustive V2 release truth**. Genuine unseen externally selected D01, #558 admin enforcement, Amazon12 UNKNOWN SDK/runtime effects, and C03/C04 release NO-GO remain in force.
