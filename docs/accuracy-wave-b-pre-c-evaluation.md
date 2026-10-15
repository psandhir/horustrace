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

## Execution checkpoint — 15 October 2026

The merged Wave B source-identity and deferred-wrapper remediation is
`ccbbfc34d7e3a4ac6e9e4cd19cf15716932b1a42` on `main`.
CI, CodeQL, Fresh-16 and Full-60 completed successfully on that commit:

- Fresh-16: https://github.com/psandhir/horustrace/actions/runs/38795405512
- Full-60: https://github.com/psandhir/horustrace/actions/runs/38795405406

A pinned-source differential must compare *before* and *after* case bundles:

| Cohort | Before run / scanner | After run / scanner |
|---|---|---|
| Fresh-16 | 38769782161 / 980c5446 (pre-Strands remediation) | 38795405512 / ccbbfc34 |
| Full-60 | 38768531774 / e5b588da (pre-Strands remediation, shadow-only #547) | 38795405406 / ccbbfc34 |

The separate `Wave B540 Pinned Evidence Differential` workflow downloads
exact original case artifacts, checks both run conclusions and scanner SHAs,
verifies the cohort pipeline-integrity archives, and invokes
`scripts/evaluate_wave_b_pre_c.py` with identical target source SHAs and
application roots. It publishes changed finding claims and Amazon Strands
case-level metrics. A successful differential workflow means **the comparison
was performed**, *not* that Wave B accuracy was independently proven.

The same acceptance PR reruns the frozen Wave-A-30 semantic survival
diagnostic via `wave-a-semantic-survival.yml` and the 10-case Amazon unseen
holdout via `amazon-sdk-unseen-holdout-10.yml`. The prior 30-case benchmark
at run 38633885195 is a diagnostic baseline, *not* an exhaustive source-truth
ledger. An unseen holdout is also not automatically an adjudicated security
label set.

### Specifically unresolved sign-off matters

- WAB-04 source-object preservation changed the pinned Amazon case from
  2 to 10 discovered agent source sites, 17 to 45 authority relationships
  and 27 to 70 security findings in the earlier candidate comparison.
  These additional claims are not automatically true positives.
- Tool-wrapper agent constructors are deferred until invocation. Findings
  and graph edges must remain conditional where runtime invocation,
  credentials or configured authority are unverified.
- The earlier Amazon review documented 67 of 70 findings without raw
  structured provenance; audit exact merged-source changes and distinguish
  source-line attribution from full effective-authority provenance.
- WAB-01 through WAB-05 need independent, per-instance/per-tool
  positive and hard-negative proof, including provider-only versus agent
  contexts and unresolved dynamic MCP catalogues.
- A formal source-adjudication reviewer must examine the changed claims,
  controls and attack paths. The evaluator correctly sets
  `independent_exhaustive_ground_truth=false`, `precision=null`,
  `recall=null` and `wave_c_go=false`.

**Release decision remains NO-GO until the above evidence and independent
claim reviews close issue #540's acceptance gate.**
