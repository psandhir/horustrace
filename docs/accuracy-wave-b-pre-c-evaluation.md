# Wave B pre-Wave-C evaluation gate (draft)

Run a separate **post-implementation evaluation** after Wave B #540 source and
authority work is accepted, before any Wave C issue #543 development.

This utility consumes exported GitHub Actions case ZIP archives, with
result.json, scan.json and effective-authority.json. It does not execute
third-party repositories, does not fetch or mutate GitHub state, and does not
depend on an LLM's unsupervised claims. Inputs for every cohort must be pinned
to the **same repository SHA and application root**. Source scope is validated,
case identity is keyed by the embedded case_id, and missing/duplicate cases
fail closed. The mandatory separate cohort pipeline-integrity files must also
be reviewed; a ZIP containing the required JSON files does not certify CI.

## Use

Export the same frozen study cases into two directories (one ZIP per case),
then run:

    python scripts/evaluate_wave_b_pre_c.py \
      --before-dir ./before \
      --after-dir ./after \
      --expected-cases 60 \
      --output ./evaluation/full60.json

Repeat for frozen Fresh-16 (16) and Wave-A-30 (30), plus the mixed
framework holdout without using the holdout to implement source heuristics.

Optional reviewer evidence can be provided with --adjudications, shaped as:

    {
      "claims": {
        "case-id:claim-sha": {
          "status": "source_confirmed",
          "source_witness": "path/to/source.py:line and review rationale",
          "reviewer": "independent-reviewer"
        }
      }
    }

Allowed statuses are source_confirmed, false_positive and unresolved.
Unreviewed or unresolved claims prevent claim-review signoff. A source-backed
claim review is not the same as runtime exploit confirmation.

The report provides source-location-normalised finding multiset deltas and
per-case inventory, authority-relationship, findings and path count changes,
including line-1 source anchor quality. It never turns count shifts into
precision/recall. Output intentionally leaves precision/recall null and
wave_c_go false until **separate** exhaustive/independent source truth,
control and relationship adjudication, negative examples, false-positive and
false-negative review, and release acceptance exist. In particular no
automatic tool converts an unresolved dynamic MCP catalogue into a false
negative or creates agent-callable tool relationships by association.

## Acceptance gate

1. All B01–B04 packages and WAB-01–WAB-05 proof ledgers merged and reviewed.
2. No *unexplained* source-instance, binding or control-regression deltas.
3. Independently source-adjudicated Agent -> Tool / MCP / Skill ->
   capabilities -> identity -> resource/destination -> controls -> finding
   and attack-path graph.
4. Reproducible source-pinned 16, 30, 60 and Amazon unseen holdout runs with
   complete pipeline-integrity reports and review of high-severity deltas.
5. Formal GO/NO-GO evaluation signed off before issue #543 Wave C starts.

The utility is an additive evaluation harness, not a claim that Wave B
or its independent accuracy benchmark is complete.
