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
