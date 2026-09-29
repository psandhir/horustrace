# GPT ↔ HorusTrace Differential — Batch 001

## Purpose

This batch tests a different question from the frozen automated reference:

> When a strong source-review model independently analyzes the same pinned repository, where does its semantic security model agree with or diverge from HorusTrace?

GPT is used as a **differential oracle, not ground truth**. The source review was committed before case-specific HorusTrace findings were revealed.

## Batch

Five fresh Frozen-180 cases were selected for framework diversity and non-trivial authority:

| Case | Repository | Framework |
| --- | --- | --- |
| rw-017 | mxyhi/always-on-memory-agent | Google ADK |
| rw-065 | KomachiZ/BICO | LangGraph |
| rw-112 | ayushshah04/DashBoard_Agent | custom OpenAI + MCP |
| rw-139 | IAmTomShaw/stock-tracker-agent | OpenAI Agents |
| rw-152 | kumarvipu1/agentic-ppt-slide | Pydantic AI |

GPT source review was frozen at commit `fc1925a59091b212ed8e82f6a0ce44e04d1f24be`.

HorusTrace comparison uses scanner SHA `9149f4cb27b509cacc150c1f533a8db9927e05df` (the post-#233 Frozen-180 run).

## Headline result

Raw finding counts are intentionally **not** treated as precision/recall because HorusTrace emits multiple policy rules for one semantic condition.

- GPT semantic findings: **15**
- Full HorusTrace semantic matches: **8**
- Partial semantic matches: **1**
- GPT findings without an equivalent HorusTrace claim: **6**
- GPT end-to-end attack paths: **11**
- HorusTrace attack paths: **3**
- Matching attack paths: **3**
- GPT paths with no HorusTrace equivalent: **8**

The dominant gap is therefore **path composition**, not basic entity discovery.

## 1. Largest gap — ingress → authority → sink

HorusTrace frequently detects the sensitive tool but does not connect the full source-proven chain.

Examples:

- **rw-017:** public-mode HTTP `/ingest` → ADK orchestrator → ingest agent → `store_memory` → SQLite.
- **rw-065:** Chainlit message/upload → LangGraph model → database/QuickSight tools.
- **rw-112:** unauthenticated WebSocket → custom model/MCP loop → bound `workspace__run_python` → Python subprocess.
- **rw-139:** validated Twilio/CLI user input → Message Handler Agent → tracker mutation → persistent JSON.

HorusTrace emitted no attack paths for these four cases.

### Product implication

The next scanner accuracy work should prioritize **cross-file ingress binding and effective-authority path assembly** for ADK, LangGraph, OpenAI Agents, and custom MCP loops.

## 2. Effective MCP authority gap — rw-112

HorusTrace correctly notices `run_python` as a process-execution tool, but calls it **unbound**.

The source review proves:

1. fallback configuration starts the local workspace MCP server;
2. `session.list_tools()` enumerates its tools;
3. each returned tool is converted to an OpenAI function;
4. model function calls map back through `tool_map`;
5. `session.call_tool(...)` dispatches the selected MCP tool.

That turns `run_python` from an isolated server capability into effective model authority.

This is a high-value miss because it changes the security statement from:

> “A process tool exists.”

to:

> “Unauthenticated user input can cause this effective agent to invoke arbitrary Python.”

## 3. Runtime viability qualification — rw-152

HorusTrace and GPT strongly agree on the three critical Python-execution paths.

However, the pinned source constructs `presentation_agent` using:

`model_settings=settings`

and no definition/import of `settings` was found.

The application therefore appears blocked during module initialization. GPT recorded the dangerous authority as **declared but conditional on fixing the source error**. HorusTrace reports the paths with `source_context=runtime` and `analysis_incomplete=true`, but does not surface the initialization blocker.

### Product implication

Add a distinction between:

- declared static authority;
- source-proven runnable authority;
- initialization-blocked / conditional authority.

This improves accuracy without discarding valuable potential-risk findings.

## 4. Capability-classification gap — rw-065

The LangGraph model receives `execute_query`, and the implementation forwards the model-selected SQL string to `SQLDatabase.run_no_throw` against PostgreSQL.

HorusTrace detects general read/write authority on the workflow but does not surface the arbitrary SQL execution primitive itself.

The same repository also binds `build_compile`, whose implementation ultimately calls `client_qs.create_analysis`; the scanner catches several adjacent QuickSight write tools but not that final cloud write primitive specifically.

## 5. Candidate scanner overreach / scope questions

### rw-112 — generic dynamic MCP URL

HorusTrace emits two NET001 and two AGT032 findings from generic remote transport handling. The code accepts a `server_config` URL, but the WebSocket caller controls a **config path**, not a URL directly.

The finding text “caller-selected destination” is therefore stronger than the source-proven data flow in this case. This should be rechecked before being counted as a true positive.

### rw-139 — provider-mediated web search

HorusTrace emits NET002 for OpenAI `WebSearchTool` because no destination allowlist is declared.

GPT treated this as a provider-constrained search capability rather than an arbitrary model-selected network destination.

The rule should distinguish:

- fixed/provider-mediated network tools; from
- tools whose URL/host/destination is model-controlled.

## 6. Duplicate finding noise

In four of five cases, generic `AGT040` duplicates a more specific finding on the same effective tool/authority:

- ADK001 + AGT040;
- AGT021/AGT022 + AGT040.

This is not primarily a correctness problem, but it inflates finding counts and makes the report look noisier than the semantic risk set.

HorusTrace already has the product principle that a specific rule should represent the risk when it subsumes a generic rule. The differential study reinforces that this should be enforced in output.

## Recommended build order

1. **End-to-end ingress path assembly** for the four missed frameworks/cases.
2. **Effective local MCP binding** for config/fallback + `list_tools` + `call_tool` loops.
3. **Model-selected URL sink recognition** for bound MCP/custom tools.
4. **Runtime viability / initialization blocker status**.
5. **Network destination semantics**: provider-constrained vs model-selected destination.
6. **Specific-over-generic finding deduplication**.

## Interpretation

This first blind batch is encouraging. HorusTrace is already close to GPT on explicit sensitive authority and performs particularly well on Pydantic-AI static dataflow. The remaining difference is concentrated in the part of the problem that matters most for the product’s thesis: proving **effective end-to-end authority**, not merely detecting dangerous primitives.
