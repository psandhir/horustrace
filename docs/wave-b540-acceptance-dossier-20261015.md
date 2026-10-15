# Wave B #540 — pinned source acceptance dossier
**Assessment date:** 15 October 2026  
**Gate:** NO-GO pending independent source truth; Wave C #543 remains blocked.  
**Scanner baseline:** `main@1ab391e1513c01ec6fa122c6f29953652fe8df76`, with corrective PRs #552 and #553 merged.  
**Authority semantics:** Observed source constructs do not by themselves establish runtime instances, credentials, effective authority or exploit reachability.

## Acceptance contract from issue #540

| Original acceptance requirement | Evidence so far | Decision |
|---|---|---|
| Complete per-instance/per-tool source proof and hard negatives | Source-pinned witness tests for WAB-01–04, plus negative controls; no independently approved complete WAB-01–05 ledger | PARTIAL |
| Explain scan-stage inventory/edge changes | WAB-04 10→2 collapse explained and source identities preserved; other stage and finding deltas partially reconciled | PARTIAL |
| Do not invent authority or silently lose observed facts | Fixed Strands duplicate tool/edge in #553 and lost AGT022 in #552; remaining source/authority claim deltas need review | PARTIAL |
| Independently source-adjudicated improvements | No independent complete claim-level TP/FP/FN ledger or exhausted negative-label cohort | **NOT MET** |

A green pipeline certifies artifact/test completion, **not** security classification correctness.

## Case-level adjudication backlog (fixed frozen target sources)

| WAB | Pinned source and positive witness | Essential hard negative | Present decision |
|---|---|---|---|
| 01 | `newsbubbles/pharmiq@c69949739647a47ec8339b473bdf578c8cf8bfd9`: source-local `agent.py:54,73` stdio client targeting `mcp_server.py`; 22 decorated source functions, explicit provider entry point | A registered `EXPOSES_TOOL` is **not** proof of `AGENT_CAN_CALL`, credentials, approval or execution. Ambiguous provider objects, aliases, script escape and unsupported argv must not be linked | Source chain witnessed; independent exhaustive per-tool review missing |
| 02 | `qmatteoq/agent365-demos@937f8c12421b6eebfbff764dbafbdbe13cc72f68`: C# `McpClient.ListToolsAsync` after token exchange; source-known server manifest | No token, failed network call, or runtime-unknown names must remain **unresolved**, not empty/zero tools or invented per-tool authority | Source mechanism witnessed; actual catalogue deliberately unresolved |
| 03 | `couchbase/mcp-server-couchbase@df5d9ceb013f57143171f65ec3ba033ace06aa9a`: 53 **candidate** tools across two ToolSets (operational 40, insights 13) via `FunctionTool.from_function` → `FastMCP.add_tool` | Mode-based read-only gating; disabled tools; auth-scoped tools; standalone provider has **no inferred Agent**; no automatic `AGENT_CAN_CALL` | Source candidate ledger exists; conditioned active catalogue and full independent per-tool truth missing |
| 04 | `aws-samples/sample-multi-agent-region-expansion-planner@30d03d7c9f6512e5bf10601879382fac9c3a16b1`: 10 distinct `Agent(...)` constructor source sites (nine in separate specialist modules and orchestrator main.py:56); exact source verifier | Eight nested specialist constructors are **deferred inside source @tool wrappers**; do not conflate 10 sites with 10 live instances, or tool wrapper with unconditional `DELEGATES_TO` | Source identity collapse repaired; source/runtime authority and finding truth unresolved |
| 05 | Source-context partition runtime/test/example/provider; pinned `stickerdaniel/linkedin-mcp-server@f142502` had 121 of 124 unbound MCP records sourced under tests | Test fixture source is not deployed MCP server inventory; provider-only, fixtures and examples should not be conflated with production instances | Context classifier exists; no complete per-instance independent decision ledger |

## High-impact WAB-04 quantitative reconciliation

Source-pinned Full-60 `ff60-amazon-04`, compared with pre-Strands remediation:
| Measure | Historical pre-change | Merged Strands pilot (ccbbfc34) |
|---|---:|---:|
| Agent constructor source sites retained | 2 | 10 |
| Tool inventory records | 77 | 110 |
| MCP server records | 13 | 15 |
| Authority relationship records | 17 | 52 |
| Findings | 27 | 68 |
| Attack paths | 0 | 0 |
| Synthetic source-line-1 findings | 14 | 0 |

The merged pilot's **52 of 52 relationships are only partially resolved** and explicitly have `runtime_effectiveness=not_verified`. All 52 have unknown approval and identity; none contains positively declared approval or identity evidence. The graph records the source context as `runtime`, but this describes the path classification and does **not** prove a live instance.

Findings by rule on the pinned pilot: `AGT020=5`, `AGT021=4`, `AGT040=28`, `AGT050=3`, `CAP003=4`, `CAP004=5`, `CAP005=10`, `NET002=9`. Of 68 findings, **65 have no raw structured provenance entries**; 55 have an explicit deferred/conditional limitation (some remaining findings apply to orchestrator rather than deferred specialists). Source location is not a substitute for complete effective-authority provenance.

The initial per-source differential across Full-60 found **57 added and 17 removed finding instances** (74 changed keys), concentrated in `ff60-amazon-04` (57 added / 16 removed) and `ff60-amazon-09` (one removed). #552 separately restored the source-backed `AGT022` missing from the latter; #553 eliminated one phantom tool and authority relation in `ff60-amazon-07`. **Recompute all counts against the final merged-main SHA**, not an intermediate PR or baseline.

**Do not call added findings 57 TPs or removed findings 17 FPs.** They are claim deltas. Missing actual source truth could still hide false negatives.

## Reviewer work required before GO

1. **Lock the inputs:** scanner SHA, case source SHA/application root, before/after case artifacts, integrity reports, source blob and source line per claim.
2. **Per source instance:** label positive constructor/provider/tool/catalogue edges; explicitly label hard negatives and ambiguous alias/credentials/configuration cases. Record each observation's `observed`, `declared`, `conditional`, `unresolved` or `proven-absent` role.
3. **Per changed security claim:** review the exported `changed_claim_details` in `evaluation/full60.json` against the pinned source pack, authority object and controls. Assign `source_confirmed`, `false_positive` or `unresolved` with exact witness and independent reviewer identity. A change from an old claim to a new claim may require both labels.
4. **Evidence chain:** for each claimed reachable finding or path, verify agent instance → tool/MCP/skill → capability → identity → resource/destination → control → actual/effective authority. Do **not** promote conditional source associations to runtime-reachable calls.
5. **Complete source-truth recall:** adjudicate *missing* source constructs, not only scanner-reported findings, on the pilot cases and independently selected blinded holdout. Provide positive/negative denominators before making any recall or precision percentage.
6. **Quality and negative gates:** repeat Fresh-16, Full-60, frozen Wave-A-30 and unseen holdout on the final production candidate, reconcile each material source/relationship/finding/path delta, and record independent GO/NO-GO plus rollback implications.

### Current sign-off

- Correctness engineering: source-specific positive evidence and two proven P0 regression fixes exist.
- Reproducibility: previous frozen runs succeeded; final combined-main validation must be pinned and reviewed.
- Complete ground truth: **NOT AVAILABLE**.
- Independent verdicts for material finding claims: **NOT AVAILABLE**.
- Wave B #540 acceptance: **NO-GO**.
- Wave C #543: **BLOCKED**.

This dossier deliberately does not invent signatures, TP/FP classifications or a precision/recall percentage.
