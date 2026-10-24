# Wave C C02m — model-assisted source-only interpretation of VeriQ rw-005

**Status: provisional, not an independent oracle; no accuracy release numbers.**

This work moves beyond the 34 source syntax observations and 14 typed relation
candidates in merged #621. It applies one *explicitly model-reviewed*
source-first pass to the original pinned source witnesses, recording
source-only claim interpretations **without consulting scanner predictions
for this review**. Such review is still **not externally proven blinded or
independent**, and the reference therefore sets `scanner_blind=false`.

## Source / scope

- Case: `rw-005`, exact existing active-145 scope, non-LangGraph.
- Repo: `Ojas-Patil26/VeriQ@067cb330ab943279b4b8ea13c91c9042bdd9f421`.
- Labels use only exact `path:line` / Git blob SHAs in merged #621
  `research/wave-c-c02g-real-source/rw-005-source-candidates.json`.
- Three C02a source-reference scopes: `agent`, `typed_edge`, and
  `effective_authority`, all `source_role=unknown`.
- Reviewer classification: `model_reviewed`, one assistant source-only
  review, **not** an independent human or a second isolated adjudicator.
- Positive/negative source *universe completeness is false*. These are a
  **selected set of witnesses**, not a closed denominator.

## 26 source-level claim opinions

| Construct | Provisional positive | Source-level near-miss negative | Runtime unknown |
|---|---:|---:|---:|
| Source-declared agents | 5 | 2 | 0 |
| Typed source relations | 13 | 3 | 0 |
| Effective authority | 0 | 0 | 3 |
| **Total** | **18** | **5** | **3** |

**Source declaration positives:** Five `LlmAgent` constructor expressions,
four `sub_agents` list member declarations, eight exact owner→tool list
entries and one `Runner(agent=_root_agent)` reference. These are statements
about source declarations and local bindings, not verified runtime
instances/permissions. Repeated `get_metric_timeseries` and
`get_metric_lineage` entries retain their distinct owning child agents.

**Explicit near-misses, with positive source witnesses for the negative
*source interpretation*:** importing `root_agent` in the package initializer
and aliasing `_root_agent` in the API are not two extra constructor sites;
the FastAPI `/api/metrics` route calling `list_metrics()` is not itself an
ADK model-directed tool call; `report_agent`'s `tools=[]` is not a
nonempty direct registered tool list; and the root's `sub_agents` field is
not direct registration of a child's `list_metrics` on the root.

**Unknown effective authority:** Installed SDK/API compatibility, import
success, agent callable surface, model-driven delegation, and actual
service/Runner execution are not observed. None of the five selected
near-misses proves a deployed runtime cannot invoke a tool.

## What this does **not** prove

This JSON is a valid C02a source-reference **model opinion ledger**. It is
not a genuinely blinded D01 reference; rw-005 has been previously exposed
and cannot be reclassified as unseen. The C02a scorer must output
`not_assessed` and `aggregate=null` for any predictions because
`positive_complete=false`, `negative_complete=false`,
`review_method=model_reviewed`, `scanner_blind=false`; the
effective-authority labels also remain `unknown`. Unit tests assert the
blocked scoring state with both empty and all-positive synthetic prediction
inputs. No scanner/Graph/ADG/findings/paths behavior changes.

Independent reviewer work still needed: full pinned checkout replay of
witness blobs and lines, enumeration of missed agent and relationship
near-misses for the entire source/context stratum, independent dual-source
opinions before scanner exposure (with external provenance checks),
consensus/disagreement adjudication, and source-matched scanner claim IDs.
Do not confuse this **18/5/3 source-opinion distribution** with
TP/FP/FN/TN or precision/recall. D01 sealing, #558 enforcement, Amazon12
runtime UNKNOWNs and C03/C04 NO-GO remain.

Frozen-180 archive and active145 LangGraph exclusion are unchanged.
