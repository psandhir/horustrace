# Retrospective adjudicator calibration — ChatGPT source adjudication

## Status

This note records the source-level adjudication performed after the GitHub Copilot quota was exhausted. The GitHub workflow successfully generated all 16 pinned source/scan bundles in bundle-only mode. Frozen-90 historical reruns reproduced archived finding/path counts in 6/6 cases, so the historical comparison is reproducible.

The purpose of this pass is the central calibration question: **did recent results look worse mainly because we introduced a stricter LLM adjudicator, or because HorusTrace actually regressed?**

The answer from the fixed-source comparison is: **evaluator strictness explains a material part of the apparent deterioration, while current post-#287 scanner precision is better than the historical scanner generations on the same source.**

## Adjudication standard

The same #285 evidentiary rules were applied conservatively:

- existence is not effective agent authority;
- unbound tools are not treated as agent-reachable authority;
- graph/application plumbing is not automatically model authority;
- fixed/operator-configured destinations are not treated as model-selected egress;
- prompt-level confirmation is preserved as a weak control, but is not treated as an enforced approval boundary;
- partial means the core security fact is source-supported but a material principal, scope, control, destination, or reachability qualification is missing or overstated.

This is a ChatGPT source adjudication of the exact bundles emitted by workflow run `36896923330`. It is not a replacement for human ground truth.

## Panel A — Frozen-90

Six exact-SHA Frozen-90 repositories were compared between v0.6 and post-#287.

| Scanner state | Findings | TP | Partial | FP | Materially supported | Strict TP precision |
|---|---:|---:|---:|---:|---:|---:|
| Frozen-90 v0.6 | 23 | 7 | 11 | 5 | 18/23 = **78.3%** | 30.4% |
| Current post-#287 | 22 | 9 | 11 | 2 | 20/22 = **90.9%** | 40.9% |

Important examples:

- `f90-001`: the RAG/GCS agent genuinely exposes read/write/destructive tools, but its prompt explicitly says to confirm operations. Claims that there is no approval/control at all are therefore partial rather than strict TP; NET002 is unsupported because the source shows service-specific GCP operations rather than arbitrary model-selected egress.
- `f90-002`: a remote MCP configuration exists with no explicit tool allowlist, but the source pack does not prove that this MCP catalogue is effectively bound to the travel agent. This is partial under the effective-authority standard.
- `f90-003`: `update_seat` is directly bound and mutates agent state without an approval boundary; both historical and current claims are supported.
- `f90-004`: `update_customer_region` is directly bound; current additionally recovers the equally source-supported `add_customer_note` mutation.
- `f90-005`: v0.6 treated LangGraph workflow/VM setup plumbing as privileged effective-agent authority. Those three historical findings are unsupported under the current effective-authority standard; post-#287 emits none.
- `f90-006`: both states report an explicitly **unbound** process-execution tool. Under the current adjudication contract that is inventory, not proven agent authority, so the security claim is unsupported.

Panel A therefore falsifies the idea that the old Frozen-90 results would remain uniformly “good” if judged by the current LLM rubric. The old scanner loses precision under the same strict adjudicator.

## Panel B — Frozen-180 longitudinal panel

The 10 frozen ADK/Pydantic cases were compared across the original Frozen-180 scanner, v0.10, and post-#287.

A conservative source-supported classification gives:

| Scanner state | Findings | TP | Partial | FP | Materially supported |
|---|---:|---:|---:|---:|---:|
| Frozen-180 baseline | 17 | 7 | 5 | 5 | 12/17 = **70.6%** |
| v0.10 | 23 | 7 | 10 | 6 | 17/23 = **73.9%** |
| Current post-#287 | 47 | 19 | 26 | 2 | 45/47 = **95.7%** |

The largest longitudinal changes are consistent with the fixes already made:

- `rw-007`: historical states emit nothing; current recovers the model-selected local-file read -> external-service path without reintroducing the old unsupported broad-resource claim.
- `rw-009`: historical generic NET002 claims are unsupported; current removes them.
- `rw-017`: current recovers state-changing memory authority and ADK delegation composition. Several claims remain partial because runtime model selection/approval semantics cannot be fully verified statically.
- `rw-147`: current recovers search-derived server-side URL dereference and explicitly preserves the important qualification that the model chooses search terms, not the final provider-returned URL.
- `rw-150`: historical generic unconstrained-egress claims are not sufficiently supported; current replaces them with source-specific URL-fetch findings/path composition.
- `rw-152`: the three command-execution flows are source-supported in all states; current additionally recovers URL-fetch and write authority. Generic NET002 remains the weak claim.
- `rw-155`: plan-management mutations are materially real but mostly partial as security findings because they operate on internal plan state. Current additionally identifies the user-configured dynamic MCP catalogue; that source fact is supported.

## What this means

The recent “poor-looking” results were being read too harshly if every `partial` verdict was treated as a failure.

The #285 evaluator deliberately uses a demanding definition of strict TP: a finding becomes partial when the core risk exists but HorusTrace omits or overstates a material qualification. That makes strict-TP precision look low even when the claim is useful and source-supported.

The apples-to-apples retrospective shows two separate effects:

1. **Evaluator calibration effect:** old Frozen-90/Frozen-180 outputs also fall sharply when judged by the newer strict rubric. Earlier cohort reports therefore cannot be compared directly with recent strict-LLM TP counts.
2. **Real scanner improvement:** post-#287 materially improves supported precision on the same pinned source, especially by removing unbound/plumbing authority and generic destination overclaims while recovering more source-specific paths.

The current panel result (~95.7% materially-supported findings) is consistent with #285's 96.4% materially-supported precision on the 30-repository adjudicated cohort. That consistency is much more informative than strict TP alone.

## Design implication

Do **not** redesign HorusTrace around “LLM instead of scanner” based on the recent partial-heavy adjudication.

The evidence still supports the hybrid architecture:

- deterministic discovery and authority graph;
- bounded LLM semantics for cases static analysis cannot resolve cheaply;
- deterministic policy/path logic;
- source-visible provenance and constraints;
- LLM adjudication as an evaluation/discrepancy tool, not production ground truth.

The metric we should use for scanner iteration is not raw strict-TP rate alone. Track at least:

- materially-supported precision = TP + partial;
- strict TP precision;
- partial-rate and the reason taxonomy for partials;
- explicit FP rate;
- locked source-review recall;
- fresh blind-review discrepancies separately.

## Remaining calibration work

The GitHub aggregate currently leaves blind-review recall cells empty because bundle-only mode intentionally skipped the Copilot calls. That does not block the precision/evaluator conclusion above. For recall, keep the existing project rule from #286: locked source reviews are regression truth; fresh blind LLM review is discrepancy discovery and must be source-adjudicated before changing scanner semantics.
