# Wave B #551 — current-main acceptance reconciliation (18 October 2026)

**Decision: Wave B NO-GO; Wave C #543 BLOCKED.** This is model-assisted
source adjudication and CI-based artifact inspection, **not** independently
certified precision/recall, true-positive findings, effective runtime authority,
or verified attack-path exploitability. The original Frozen-180 truth is
immutable; the active evaluation is the 145 non-LangGraph pinned cases and the
six applicable numeric thresholds remain unchanged.

## Integration state

- `main@baa8ac81633fc951328e0f225145bd77dde01f11` includes
  [#578](https://github.com/psandhir/horustrace/pull/578) Claude SDK
  approval/availability split and version-conditional Workflow and
  [#591](https://github.com/psandhir/horustrace/pull/591) source-declared
  ADK agent with unresolved import provenance. This is the scanner baseline
  at the beginning of #551 final integration, **not** the final #551-tested head.
- #578 was independently pipeline-validated at its exact PR head (13/13
  workflow groups: CI, CodeQL, Full-60, Fresh-16, Amazon unseen-10, Claude-12,
  accuracy, framework parity) before merge. All source-conditional catalogues
  remain unresolved; cohort success does not certify source-claim truth.
- [#586](https://github.com/psandhir/horustrace/pull/586)
  paired per-agent historical/current source witnesses: current scanner
  **145/145**, frozen historic executable **144/145** because `rw-177`
  has a legacy Bazel symlink PermissionError; **144/145 comparable**.
  Structural 355 versus 448 agent-kind identity sites (+104/−11), 12 workflow
  nodes separate; **neither TP/FP nor release-certified agent precision**.
  The exact-head run status and merge state must be independently checked.
- This #551 PR deliberately contains pinned historic pre-/post-Strands
  differentials. Those historical workflow run SHAs **must not** be described
  as current merged-main reruns.

## WAB-01–05 source-to-inventory/relationship acceptance

| Pilot | Source-positive evidence | Hard negative / unknown | Result |
|---|---|---|---|
| WAB-01 Pharmiq (`gen-pyd-001`) | 22 `@mcp.tool` registrations, local stdio client/server path | Provider export is NOT proof of `AGENT_CAN_CALL`, active approval or runtime tool invocation | Conditional source edge, runtime unverified |
| WAB-02 Microsoft (`ff60-microsoft-04`) | Two source-defined MCP server configurations and `McpClient.ListToolsAsync` | Dynamically enumerated tool names not present in pinned source: UNKNOWN, never zero by assumption | Unresolved dynamic catalogue |
| WAB-03 Couchbase (`gen-mcp-003`) | 53 source-defined FunctionTool candidates (40 operational, 13 insights) | Mode/read-only/auth/feature gates condition registration; provider alone not an agent | Conditional tool registrations |
| WAB-04 Amazon (`ff60-amazon-04`, `amazon-hold-004`) | 10 Agent constructor sites, eight decorated wrappers, seven deferred two-hop candidates | Constructors inside wrappers are not unconditional deployed instances; `agents.__all__` module names not bound callables | Source identities retained; tool effects and effective authority unknown |
| WAB-05 LinkedIn (`rw` source context) | 124 source role records: **121 tests, 3 runtime-source** | Test fixtures/provider exports do not establish deployed agent authority or runtime server inventory | Source-context diagnostic only |

The [#579](https://github.com/psandhir/horustrace/pull/579)
four-pilot source ledger and [#580](https://github.com/psandhir/horustrace/pull/580)
WAB-05 source-context proof are merged. **Source-positive and hard-negative
source facts do not prove live MCP export catalogues, identity grants,
control effectiveness or attack-path reachability.**

## 73 immutable historical finding-claim deltas

The two original model-judge ledgers cover exactly **20 high and 53 medium**
changed historical `ff60-amazon-04` claims. These are an identity space
separate from the new scanner finding fingerprints:

- **45** source-supported *conditional* claims, not verified live effects.
- **16** invalid historical claim/line anchors, not necessarily absent risks.
- **12** still unresolved (4 high CAP004/AGT020/CAP003×2; 8 medium
  AGT040 and NET002×7).
- Pinned application declares `strands-agents-tools` **unversioned** and
  AWS pricing MCP server with `@latest`; upstream Strands source checked in
  #566–567 does **not** establish installed bytes, runtime approval or actual
  AWS/network effects.
- The #551 checker `scripts/verify_wave_b540_unresolved_claims.py`
  fails closed if any of 73 claim identities, source pins, evidence, model-only
  reviewer fields, or 12 unresolved statuses are silently changed. Its output
  `evaluation/unresolved-claim-acceptance.json` reports these as
  `source_unresolved_runtime_unverified`, precision/recall null, GO false.
  This is an **honest bounded verdict**, not a substitute for independently
  labelled truth.

## Exact-current candidate release checks

Merge acceptance for this *research/evidence* PR may occur once its latest
candidate branch is integrated with current `main` and has green exact-head
CI, CodeQL, source-claim differential, Wave-A-30 and Amazon unseen-10,
Fresh-16/Full-60 plus same-head accuracy. Verify their case SHA, app root,
pipeline-integrity and source claim evidence; a green workflow alone is not a
GO. Do not turn this research merge into a scanner release decision.

Wave B GO additionally needs:

1. **Independent or methodologically isolated exhaustive positive and
   hard-negative** agent/tool/MCP/delegation/authority reference, including
   unreported source constructs and source-claim negative denominator.
2. Exact scanner Graph/ADG equivalence or explicit unresolved dispositions
   per WAB-01–05, not merely positive source observation counts.
3. High-severity findings and potential attack paths traced through concrete
   source-bound identities, reachable tool/MCP capabilities, destinations,
   controls, with dynamic/permission/runtime unknown distinguished.
4. The twelve unresolved historical external-effect claims adjudicated with
   actually resolved, immutable installed dependency versions and runtime
   evidence **or retained as non-certified conditional** with explicit release
   risk disposition; none can be silently promoted.
5. Repo administrator enforcement of stable
   `accuracy-regression-gate` in Protect main ruleset #558 and a deliberate
   fail-closed blocking exercise.
6. Same-SHA production-main acceptance with pinned Fresh-16, Full-60,
   Wave-A-30, Amazon unseen-10 and active non-LangGraph benchmarks.

**No independent human source-truth review is available.** Model-generated
source judgements must remain labelled model-assisted. With these blockers
still outstanding, retain `wave_b_go=false`, `wave_c_go=false`.
