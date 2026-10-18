# Wave B #540 — current-main source-to-Graph/ADG pilot review

**Acceptance role:** execute scanner on the *five original exact pinned target
source trees*, compare their source evidence to the scanner Graph, source-native
shadow, effective-authority relationships, ADG inventory, findings and potential
attack paths, and preserve all non-runtime/conditional/negative controls.
This is a claim-level **discrepancy queue**, not an independent or exhaustive
TP/FP/FN benchmark. Wave B and Wave C GO remain false.

New runner: `scripts/reconcile_wave_b540_pilot_graph.py`.
Workflow: `.github/workflows/wave-b540-current-pilot-graph.yml`.
Original ledger: `research/accuracy-wave-b540-four-pilot-20261017/source-edge-ledger.json`.
No target code is imported or executed, no target dependencies installed, and
no cloud credentials requested. The scanner executes statically against
repository SHA-locked source checkouts.

## Per-case source and current graph obligations

| Pilot | Independent source-claim reference already collected | What the fresh scanner report checks |
|---|---|---|
| WAB-01 Pharmiq | 22 registered source decorators, local stdio client | Native candidate tool symbols vs ledger; Graph/ADG inventory; no `AGENT_CAN_CALL` inferred from `EXPOSES_TOOL` |
| WAB-02 Microsoft | 2 declared manifest servers, remote `ListToolsAsync` | Dynamic catalogue remains unresolved, source-unknown names are not proof of zero tools; current Graph/ADG and findings/path queue |
| WAB-03 Couchbase | 53 conditional registered ToolSet candidates, provider only | Native candidate tool symbols vs ledger; no synthetic Agent in provider-only scope; read-only, disabled and auth gates stay unknown |
| WAB-04 Amazon | 10 source-distinct constructor lines, 9 orchestrator membership candidates (7 direct deferred two-hop) | Exact Graph source path/line identity of each constructor, Strands native candidate list, all authority relationships runtime not verified, findings/path provenance gaps |
| WAB-05 LinkedIn | 124 source-qualified unbound MCP sites = 121 test + 3 runtime-source | Native scanner/shadow source role count, provider-only, no fabricated agent or deployed test server |

The source reference is **model-adjudicated**, not an independently labelled
complete negative universe. The produced `source_native_candidate_missing`,
`amazon_constructor_source_diff`, `finding_witness_queue` and
`potential_path_queue` require case-level review. Missing scanner evidence
does not, by itself, establish a true false negative; extra inventory is not,
by itself, a false positive. Endpoint, namespace, credential, installed package
and effective tool or permission states remain explicitly unresolved.

## Hard-negative fail-closed assertions

- Exact repository, commit and application root for each named case; never
  broaden to LangGraph or change Frozen-180 truth.
- All current effective authority relationship records must retain
  `runtime_effectiveness=not_verified`; source-only shadow must not assert
  `agent_can_call` as a proven edge.
- A provider-only Couchbase/LinkedIn target cannot become an agent without a
  fresh source-positive proof.
- WAB-05 test source count cannot become runtime source count.
- Dynamic Microsoft tool catalogue cannot be inferred from a manifest endpoint;
  `tool_names=[]` is a source-unknown placeholder, not proven empty.
- Missing ADG data is a fail-closed error, never scored as zero nodes/edges.
- High-severity finding location/provenance gaps and unverified potential paths
  are exported rather than counted as successful vulnerability detection.

The checker intentionally returns `source_precision=null`,
`source_recall=null`, `finding_precision=null`,
`attack_path_precision=null`, `wave_b_go=false` and `wave_c_go=false`.
It should never be cited as proof the whole non-LangGraph 145-case cohort
passes unchanged independent accuracy thresholds. Current 145/145 scan
**completion** and the archived paired 144/145 witness study are separate.

## Exit steps outside this five-case discrepancy workflow

1. Adjudicate source-positive and *source-negative* Graph/ADG inventory and
   every changed high-severity finding / potential attack path, including
   genuine misses; maintain independent/methodologically isolated review.
2. Preserve 12 unversioned Amazon third-party tool, dynamic MCP, approval and
   actual AWS/network effects as unresolved under pinned-source-only scope
   (source-boundary #593), unless deployed runtime evidence is actually
   supplied.
3. Add `accuracy-regression-gate` to Protect main required status checks
   under #558 and verify red/stale/missing cohort checks block merges.
4. Run all final current-main validation cohorts (Fresh-16, Full-60,
   Wave-A-30, Amazon unseen-10, active non-LangGraph 145 and source-negative
   V2) on the same production scanner SHA; publish qualified GO/NO-GO with
   rollback implications. Don't initiate Wave C production migration based
   on merely green diagnostic workflows.
