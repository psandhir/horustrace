# Wave C C02k — pinned VeriQ ADK typed candidate evidence (`rw-005`)

This continues #614's **source-first reviewer preparation** with a second real
Frozen-180/active-145 Google ADK source case, **not a new blinded holdout**.

| Source field | Pinned value |
|---|---|
| Cohort ID | `rw-005:agent:unknown` |
| Repository | `Ojas-Patil26/VeriQ` |
| Immutable source commit | `067cb330ab943279b4b8ea13c91c9042bdd9f421` |
| ADK dependency *declared* | `requirements.txt:1 google-adk==1.19.0` |
| Role | `unknown` (deployment/source-context NOT proven) |
| Ledger | `rw-005-source-candidates.json` |
| Status | Syntax-only, no independent V2 positive/hard-negative adjudication |

## What source inspection supports

34 GitHub-source-read syntax observations and 14 linked declared-source
relationship candidates pin file paths, Git blob SHA, line
numbers and exact statement snippets. They include:

- **Five distinct local constructor sites** in `agent.py`: 17
  `ingestion_agent = LlmAgent(`; 44 `anomaly_agent = LlmAgent(...)`;
  70 `root_cause_agent = LlmAgent(...)`; 106 `report_agent = LlmAgent(...)`;
  and 134 `root_agent = LlmAgent(...)`. Local constructor identity alone
  does not certify five deployed agents.
- **Four declared subordinate memberships**, lines 158–163 of
  `agent.py`: root's `sub_agents` list names the four earlier constructor
  variables. These are *candidate declared delegation links*, **not four
  observed runtime handoffs** and not root's direct tool bindings.
- **Eight direct tool-list entries across three child agents** (3
  ingestion, 2 anomaly, 3 root cause). The `get_metric_timeseries`
  symbol occurs in two different children's `tools` lists; likewise
  `get_metric_lineage`. Preserve distinct owner/binding relationships
  rather than collapsing all listed tools into root's effective authority.
- **Two important near-miss sites**: `report_agent` has an explicit
  `tools=[]` at line 129, whereas root has `sub_agents`, not a
  direct `tools=[...]` argument in this pinned constructor. An empty
  *direct tool list* does not prove zero delegation, zero future injected
  tools or unavailable runtime capabilities.
- **Entrypoint and alias**: package `__init__.py:1` imports the root
  symbol; `api.py:46,51` dynamically imports the package's agent module
  and aliases its root object. `api.py:87–91` configures one ADK
  `Runner(agent=_root_agent)`; this is a configured runner reference,
  **not a sixth agent**, not one Runner per sub-agent and not proof the
  service executed successfully.
- **Direct FastAPI calls are not agent calls**: `api.py:122–124` exposes
  a REST `/api/metrics` route which invokes `list_metrics()` in Python.
  This is not a model-controlled invocation and must not be re-labelled
  `AGENT_CAN_CALL` without a separate source-backed ADK binding.

The ledger also captures six local Python tool-function definition anchors
in `tools/metrics_tools.py` and `tools/schema_tools.py`. Its 14 source-linked
**candidate** edges are 4 `DECLARED_SUBAGENT_MEMBERSHIP`, 8
`DECLARED_AGENT_TOOL_LISTING`, 1 `DECLARED_RUNNER_AGENT_REFERENCE`
and 1 `DIRECT_APPLICATION_FUNCTION_CALL`. Each edge links two pinned
source observation IDs plus a source statement witness and deliberately
sets `runtime_verified=false`, `source_semantics_independently_adjudicated=false`,
`effective_authority_established=false`. Do not project these records into
production `AGENT_CAN_CALL` or attack-path certainty.

Source blobs directly verified by pinned GitHub fetch:

```text
agent.py         89ce05579a18e8e09822d4157cace7121a5d7c99
__init__.py       4caf51810fb5cf8babe6391d31d2116d6f9be05d
api.py            bfed9d84fd977eb20a4e7f8453aebff675ac9faf
requirements.txt  4742c50311e93ede85fcfff2cfc44702aef56ec6
tools/metrics_tools.py f1641c3f53ec5eb66516fdac15847d8067f8581d
tools/schema_tools.py  bdab09514401e679b08e101feb2fcb4023e18284
```

## Limits and required follow-on

The source file content and anchors were fetched from GitHub at the archived
commit; no full local checkout was materialized for C02b Git witness replay,
and no ADK runtime was installed/imported. Do not infer from a requirements
pin that installed API implementations or approval controls were verified.
Do not execute target code, confuse static routes with model-directed calls,
or count documentation claims as observed runtime security boundaries.

The JSON record explicitly fixes all release/independence/completeness flags
to **false**. A separate source-first reviewer must enumerate *all* source
sites and negative near-misses per framework/construct/source-role stratum,
replay Git witnesses and adjudicate the intended ontology blind to scanner
predictions, before deriving V2 TP/FP/FN/TN or attempting C03/C04 cutover.

This seed remains **previously exposed** and cannot count as an unseen D01
holdout. The 12 Amazon third-party runtime/control unknowns remain UNKNOWN;
Frozen-180 and the active 145 excluding LangGraph are unchanged.
