# Wave C C02q — current scanner vs provisional source judge

Issue [#606](https://github.com/psandhir/horustrace/issues/606) / Wave C [#543](https://github.com/psandhir/horustrace/issues/543).

## Study question

Does the **current HorusTrace scanner/ADG** project the specific declarations
and selected hard-negative near-misses that a **single unblinded model judge**
identified in two exact, pinned real-world repositories?

1. **rw-005** Google ADK — `Ojas-Patil26/VeriQ` at
   `067cb330ab943279b4b8ea13c91c9042bdd9f421`.
   Source-only model opinions: **18 positive / 5 negative / 3 UNKNOWN**.
2. **rw-080** custom MCP — `Amlan66/SSEEnabledMCPAgent` at
   `11531239e71b123f25b3c6103ee36a9d614d0032`.
   Source-only model opinions: **16 positive / 7 negative / 5 UNKNOWN**.

The historic Frozen180 study already contains old scanner results for both
cases. Those numbers are **not a current-scanner test** or valid
independently-certified V2 truth. This workflow re-runs current scanner
against both exact source revisions rather than reusing old results.

## Source verification and execution limits

`wave-c-c02q-source-model-scanner-differential.yml` runs two matrix jobs
and an aggregate. Each job:

- Uses exact PR head SHA of HorusTrace; fetches only the public source
  repository at the frozen exact Git commit.
- Checks the local detached `HEAD` equals the source case pin and
  verifies **every** source observation's exact Git blob SHA, line number and
  source expression using Git objects. Expected **34 rw-005** and
  **47 rw-080** anchors.
- Checks every model label against the originally pinned source ledger,
  and for rw-080 independently replays the recorded original ledger blob ID
  before converting its model opinions to C02a source reference.
- Runs `horustrace.scanner.scan()` twice, once on the original
  preregistered `agent.py` application file and again on the complete
  source tree. This is a **static, read-only** scanner run.
  No target dependency installation, import, execution, cloud call,
  MCP connection or LLM API call is permitted.
- Records exact source scan scope, scanner git head SHA, coverage flag,
  raw ADG node/edge documents, source/model/ADG alignment rows,
  findings and potential path counts, and unresolved source-level/authority
  candidates in per-case GitHub Actions artifacts.
- Fails if source pin/blobs/line text are mismatched, target scan fails,
  two-case coverage is incomplete, or model verdicts are promoted to
  release-certifying TP/FP/FN/TN.

Run manually as an offline source study in a pinned checkout:

```bash
python -m scripts.wave_c_c02q_source_model_scanner_compare \
  --case-id rw-005 --checkout /path/to/VeriQ-pinned-checkout \
  --project-root . --output artifacts/rw-005

python -m scripts.wave_c_c02q_source_model_scanner_compare \
  --case-id rw-080 --checkout /path/to/SSEEnabledMCPAgent-pinned-checkout \
  --project-root . --output artifacts/rw-080
```

## Explicitly mapped scanner/source claims

**rw-005:** five distinct source agent constructor sites; four declared
`DELEGATES_TO` source child relations; eight specific child agent
`INVOKES` source tool-list projections; negative alias/import sites that
must not create another agent; `report_agent`'s empty direct tools list;
the coordinator must not gain direct `list_metrics` from its child.

**rw-080:** four distinct FastMCP source construction sites, including
the two separate same-label `Calculator` server files; four server
`EXPOSES_TOOL` candidate relations. A `@mcp.resource` declaration
must not become a tool export, where the corresponding raw ADG
can be matched to that source witness.

These are **provisional alignment observations**, not formal TP/FP/FN
counts. The following distinctions are preserved:

- ADG `INVOKES` expresses a source association, not successful runtime
  `AGENT_CAN_CALL` or deployed authorization.
- Model `unknown` authority is retained as `source_model_runtime_unknown`
  even if a scanner project emits a source edge.
- Any non-isomorphic V2 model claim without a defensible legacy ADG
  matcher is marked `not_mapped_to_legacy_adg_ontology`.
- Source-positive with no matching scanner ADG relation is
  `candidate_positive_not_projected`, **not a certified FN**.
- A scanner ADG edge contradicting a selected source hard-negative
  becomes `candidate_invalid_projection_for_review`,
  **not a certified FP**.
- Source-negative not projected is not a certified true negative.
- A source match does not certify model accuracy, installed runtime
  support, source context completeness or actual deployed identity.

Every output leaves `certified_precision`, `certified_recall`,
`certified_tp/fp/fn/tn` null. Production cutover is **NO-GO**.

## Actions after source-aligned runs

1. Inspect aggregate + per-case `result.json`, both raw ADG files,
   actual source witness hashes and scanner coverage before deciding
   whether any omission is genuine. Compare application/file versus
   repository-root scan scopes before blaming the detector.
2. For each suspected issue, independently inspect target exact source
   and applicable framework/SDK contract; create narrow regression
   fixtures for positive, hard-negative and UNKNOWN cases.
3. Fix scanner projection/Graph only when a pinned witnessed semantic
   discrepancy is substantiated. Re-run unchanged Fresh16 and Full60
   plus target cases, and reconcile source-specific deltas.
4. Continue separate independent-source V2 completeness review and unseen
   D01 holdout; administrator [#558](https://github.com/psandhir/horustrace/issues/558)
   must enforce the stable accuracy gate. The 12 Amazon runtime authority
   claims remain unresolved. Exclude LangGraph from active145 without
   mutating Frozen180. C03/C04 production cutover remains NO-GO.

This study **does not** compute release-grade precision/recall, because the
source-positive/negative model-opinion universe is deliberately incomplete
and the reviewing model was unblinded.


## Executed initial two-case source/ADG results — 25 October 2026

The pinned two-case GitHub Actions run [40170692136](https://github.com/psandhir/horustrace/actions/runs/40170692136) completed, followed by a dedicated raw-adapter diagnostic run. All 34 rw-005 and 47 rw-080 original source syntax witnesses matched their Git blobs/lines; both case scans succeeded.

| Case | Scope | ADG agent nodes | ADG MCP server nodes | Selected positive claims not projected |
|---|---|---:|---:|---:|
| rw-005 | application file | 5 | 0 | 8 (child function definitions outside scan scope) |
| rw-005 | full repository | 5 | 0 | 0 (all 17 mapped positive claims projected) |
| rw-080 | application file | 0 | 0 | 8 |
| rw-080 | full repository | 1 | 17 | 6 |

For rw-005 the initial study mapper erroneously expected `get_metric_schema`
for the source `declared_direct_tool_listing:cause_schema` opinion;
the pinned source registers **`get_schema_summary`**. The mapper was
corrected, **without modifying the production scanner**. All five source
ADK constructors, four declarations of child delegation and eight distinct
child-owned tool registrations now align with the full-repo ADG projection.
The `Runner` API reference is not mapped to an equivalent legacy ADG
construct; authority remains three UNKNOWN labels.

For rw-080, 17 full-repository ADG nodes of kind `mcp_server` **do not
imply 17 source FastMCP implementations or deployed servers**: some
represent client-side stdio/SSE connection configurations. The only
projected source FastMCP constructor among the four pinned source sites is
`mcp_telegram_server.py:27`, with 3 corresponding `EXPOSES_TOOL` edges.

The follow-up probe of **raw `mcp_python.scan_python_file` compared with
final normalized `Graph` and `ADG`** localizes the source-provenance loss:

| Pinned server constructor | Raw adapter constructor | Raw MCP tools | Final unbound Graph server constructor | ADG source EXPOSES_TOOL |
|---|---|---:|---|---:|
| `mcp_server_1.py:33` (Calculator) | yes | 20 | no | 0 |
| `mcp_server_2.py:28` (Calculator) | yes | 3 | no | 0 |
| `mcp_server_3.py:209` (ddg-search) | yes | 2 | no | 0 |
| `mcp_telegram_server.py:27` | yes | 3 | yes | 3 |

This is **not** a syntactic source detection failure. The current
`resolve_local_stdio_implementations` in
`src/horustrace/mcp_context.py` copies source `discovered_tools` and
implementation path/name onto an agent-bound client-side server, marks the
source implementation as used, then removes the original implementation
from `graph.unbound_mcp_servers`. The ADG currently builds unbound source
`EXPOSES_TOOL` links only from the retained unbound implementation nodes.
This is a concrete **source-provenance representation gap**; a
source-aware ADG projection fix needs distinct server identity per file
and must not create additional effective `AGENT_CAN_CALL` edges.
It does **not** establish a false positive, a false negative, or actual
runtime MCP sessions.

The probe itself records explicit `runtime_server_connected=null`,
`effective_agent_can_call=null`. Future remediation must be validated
against same-file duplicate-name hard negatives, server-side `@mcp.resource`
versus tool decorators, and complete unchanged Fresh16/Full60 gates.
