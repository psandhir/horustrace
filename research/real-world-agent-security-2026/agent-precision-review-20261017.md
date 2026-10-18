# Wave B agent-precision root cause — source review (17 October 2026)

**Scope:** exact 145 non-LangGraph cases from immutable Frozen-180. **Status:** independent production precision **not** certified. Original locked cohort/truth and historical metrics are retained unchanged.

## The comparator's historical claim

Source-locked non-LangGraph 145 report compares a baseline **101 matched + 4 unmatched = 96.19%** against the latest scanner **105 matched + 31 unmatched = 77.21%** on 56 reference-complete agent cases. Successful scans differ (historical `rw-177` failed, latest `rw-085` failed), but on the **143 common-success cases**, the precision numerators and denominators remain identical. Thus scan completion is not the source of this particular delta.

**Metric defect:** `scripts/real_world_agent_security_execute.py:predicted_nodes_for_dimension()` maps `agent_entities` to both Graph `agent` and Graph `workflow_node`. The locked source truth lists agent/workflow **root constructs**, not all intermediary workflow steps. A second defect is the incomplete original automated source review for several cases marked `agent_entities=true` under reference completeness. Precision uses **only marked-complete source cases**, meaning omissions there are wrongly penalised as scanner false positives.

## Source-anchored evidence — all 31 unmatched nodes

See exact observed Graph kind, name, path and line in [six-case workflow run 39043581158](https://github.com/psandhir/horustrace/actions/runs/39043581158), artifact `12105116299`, and individually pinned review `agent-precision-adjudication-v1.json`. Source references below are **original target SHAs**, not branch HEAD.

| Frozen case | Unmatched | Source adjudication | Pin / example |
| --- | ---: | --- | --- |
| `rw-025`, Google ADK Course Creator | 18 | **12 workflow_node** graph intermediates in two workflows (not agents), plus **6 source-backed LlmAgent** constructors omitted by truth, three per original source file | [agent.py](https://github.com/litmus-zhang/course-creator/blob/881acff4847f96454ebf50135b19ebe95fda1cb8/agent.py#L65-L115), [app/agent.py](https://github.com/litmus-zhang/course-creator/blob/881acff4847f96454ebf50135b19ebe95fda1cb8/app/agent.py#L72-L119) |
| `rw-163`, Pydantic MCP-Transition | 7 | Seven source-backed `self.agent = PydanticAgent(...)` constructor sites across seven scripts. Locked truth records only two *outer-wrapper* `agent = Agent()` call sites. They have different identity/source lines; matching fails. Some wrapper variants also have initial constructors missing from Graph and need independent **recall** evaluation. | [improved_agent.py](https://github.com/rachedblili/MCP-Transition/blob/7c1941f6b592787622b91a321d031c1cd77a688d/improved_agent.py#L32-L50), [naive_agent.py](https://github.com/rachedblili/MCP-Transition/blob/7c1941f6b592787622b91a321d031c1cd77a688d/naive_agent.py#L23-L37) |
| `rw-170`, Pydantic Smart Web Scraper | 2 | Two distinct module-level bound agents call a factory returning `pydantic_ai.Agent`. They share the constructor source line but are different bindings. Original truth lists zero. | [scraping_agent.py](https://github.com/Croups/smart-web-scraper/blob/a157701a22ae1853a00156b2364830130958c82d/scraping_agent.py#L43-L61) |
| `rw-034`, Google ADK Design Agent | 2 | `DeepThinkPreparationAgent` and `LoopTerminationAgent` are source-defined `BaseAgent` subclasses instantiated as children of `LoopAgent`; both omitted by original reference. | [deep_think_loop.py](https://github.com/salomonerobert/adk-design-agent/blob/b3aba77570f3891f836ac031257fe25872fc4000/deep_think_loop.py#L154-L164) |
| `rw-089`, custom MCP | 1 | `DeepSeekMCPAgent` implements OpenAI-compatible model + MCP tool loop. Agent/client categorisation to be confirmed. | [agent.py](https://github.com/jiamingkong/agent_demos/blob/6fab148888845bc08e762b82ce0477a3a213d712/agent.py#L84-L100) |
| `rw-103`, custom MCP | 1 | `MCPClient` implements model + MCP tool-call dispatch loop, but classification as autonomous agent vs agentic client remains **unresolved**. | [client.py](https://github.com/Nagharjun17/MCP-Ollama-Client/blob/aa54c8d8f808123ba26922138126afa6675dce68/client.py#L23-L46) |

**Decomposition:** 12 workflow-step comparator errors, 17 source-supported agent constructors/bindings omitted or mismatched in locked truth, 2 unresolved boundary-case clients.

## Non-blinded sensitivity, not corrected release accuracy

Legacy reference score is **77.21%**. Excluding only mismatched `workflow_node` kinds in the six outliers yields **84.68%** before any source-reference corrections, assuming no previously matched workflow nodes exist elsewhere (the new 145-case witness report checks that). If 17 actual source-supported agent kinds are accepted, and the other legacy matched candidates remain assumed correct, the two unresolved custom clients imply a **98.39–100% sensitivity interval**. These are *conditional diagnostic ratios, not source-independent benchmark precision*.

The frozen source labels were generated in advance by two **automated** source-review passes, not blinded human review. The additive 31-node overlay is **post hoc** and was selected after observing unmatched scanner findings. Neither reference is an exhaustive, independently adjudicated truth. Neither workflow steps nor imported source-constructor presence establish runtime instance deployment, callability, authority, findings or attack-path validation.

**Correct next acceptance:** (1) separate canonical `agent` inventory from `workflow_node` execution/control flow; (2) decide custom model/tool-loop identity; (3) create a separately versioned, source-blinded, negative-labelled reference with source-anchored agent-instance cardinality; (4) rerun **both historical and current scanners with the same corrected scorer and same 143 common-success cases**, or an explicitly versioned new cohort with consistent denominator; (5) separately adjudicate ADK/Pydantic *agent recall*, not just precision; (6) preserve all six active non-LangGraph release thresholds and the remaining semantic findings and authority gates. No Wave B or Wave C GO until those analyses pass.
