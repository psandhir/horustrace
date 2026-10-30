# Wave C C02e — paired source-only scanner delta ledger

Parent #606; independent of #611 holdout sealing, based on merged #610.

This is a **reproducible comparison of two scanner versions on the exact same
source claim universe and pinned source**. It is not a claim that every
historical source reference has been independently adjudicated.

## Inputs

Supply C02a JSON \`reference\`, C02b offline local \`checkouts\`, and
\`old.json\` / \`new.json\` scanner snapshot files:

\`\`\`json
{
  "schema_version": 1,
  "ontology_version": "v2_source_claims",
  "reference_sha256": "<canonical C02a source reference hash>",
  "scanner_commit_sha": "<40-hex scanner Git commit>",
  "predictions": [
    {"scope_id": "pinned-case:agent:runtime", "claim_id": "agent:worker"}
  ]
}
\`\`\`

This source/ontology matching is an explicit input contract: the scanner
prediction exporter must map stable scoped claim identity into this format.
This implementation does not manufacture a comparator from scanner
legacy node names, guess instance identities or use LLM output as truth.

## Run

\`\`\`bash
python -m horustrace.source_truth_delta \
  --reference v2-source-reference.json \
  --checkouts pinned-local-source-checkouts.json \
  --old old-scanner-claims.json \
  --new new-scanner-claims.json \
  > paired-source-delta.json
\`\`\`

The module forces both scanner snapshots to share the same source oracle
digest, source scope and V2 ontology and to have **different full pinned
scanner commits**. Before emitting results it re-verifies every reference
label against local Git HEAD/tree/blob/line witnesses. It reports per-claim
\`introduced\`, \`removed\`, \`retained\`, \`not_detected\`, the provisional
source label and source witness, plus source-role-scoped tallies.

Changes to source-labelled positives/negatives receive **candidate-only**
effects such as \`candidate_true_positive_added_not_certified\` or
\`candidate_false_positive_removed_not_certified\`. These are *not*
certified TP/FP counts: C02a labels can be provisional and the negative
universe may be incomplete. A prediction absent from the reference gets
\`source_candidate_label=unreviewed\`, no fabricated witness and
\`unresolved_change_requires_source_adjudication\`; never auto-FP.

Always emitted:
- \`independent_source_truth_verified=false\`
- \`certified_precision=null\`
- \`certified_recall=null\`
- \`production_cutover_authorized=false\`

A paired scanner delta becomes releasable only after external reviewer
provenance, source interpretation and complete positive-and-hard-negative
candidate enumeration are actually established. Do not silently rewrite
historical Frozen-180 metrics; preserve immutable historical measurements,
active 145 non-LangGraph exact-SHA cases and the original six gate floors.

## Remaining blockers

Still needed: source-backed independently collected V2 reference with a
comprehensive hard-negative universe, C02d genuinely unseen private D01
holdout with externally verifiable pre-scanner access chronology, per-framework
decision on cutover of C03 projection slices, and #558 administrator enforcement
of the stable branch-required \`accuracy-regression-gate\`.

The 12 Amazon third-party runtime/control unknown claims remain UNKNOWN.
This tool does not execute third-party target source or call an LLM.
