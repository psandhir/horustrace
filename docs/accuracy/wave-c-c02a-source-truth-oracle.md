# Wave C C02a — source-truth oracle contract (research, not a release GO)

Parent: #606. Baseline: merged Wave C C01a #604 and C01b source-native shadow crosswalk #607.
No Graph, ADG, effective authority, scanner, finding or attack-path behavior changes here.

## Goal and scope

Build a **separately collected source-truth reference** rather than treating either the
legacy Graph or the LLM review of scanner output as an independent accuracy oracle.

This initial C02a module is a fail-closed **format, validator, and scorer**. It does not
make any existing historical assertions newly independently adjudicated. Synthetic
unit-test samples exist only to test arithmetic and failure behavior, not to claim
review coverage or blinded human participation.

Current active evaluation has 145 exact-SHA non-LangGraph source cases. The original
Frozen-180 historical reference stays immutable; 35 LangGraph cases remain excluded
from active Wave C accuracy runs. The original six quality floors are unchanged.

The inherited legacy reference has 89 agent-incomplete cases, one known nominally
complete source-reference case incompatible with the V2 agent ontology, and 55
nominally complete but not independent V2 negative-universe reviewed. There are
**no certified independent complete V2 positive-and-negative source universes yet**.
This code is a mechanism to collect and score new evidence, not a finding that the
scanner's true accuracy has improved.

## Format and reviewer provenance

An oracle JSON file contains:

- \`schema_version\`: integer \`1\`.
- \`scopes\`: separate source populations keyed by \`scope_id\`, each containing
  \`case_id\`, pinned \`repository\` and **full 40-character commit_sha**,
  \`construct\`, \`source_role\`, explicit \`positive_complete\` and
  \`negative_complete\` booleans, \`review_method\`, \`review_ref\`,
  \`scanner_blind\` and documented \`negative_method\`.
- \`labels\`: unique claim IDs within the scope, with
  \`truth=positive|negative|unknown\`, a repo-relative \`source.path\`, exact
  Git \`source.blob_sha\`, inclusive line_start/line_end, and adjudication reason.

Negative labels are positive source **witnesses for a near miss**, for example an
application factory that is *not* an agent, an import that does not resolve to the
claimed SDK, a test-only MCP provider or a fixed destination that is not a general
external write capability. These labels are never inferred from absence in scanner
output. A source-unverified runtime condition stays \`unknown\`.

Review provenance values are \`independent_blind\`, \`source_reviewer\`,
\`model_reviewed\`, \`test_author\`, and \`unreviewed\`. They are recorded
declarations, **not cryptographic or human independence proof**. Only a scope
declaring *both* complete positive/negative universes, independent-blind review,
review without scanner exposure, and nonempty positive and negative labels is
methodologically eligible. Unknown labels or predicted claims missing from the
reference block scoring that scope.

Reviewers must retain external evidence of collection order, reviewer identity,
source access and independent labeling. Do not label a source-review result
"independent" merely because a model reviewed it; do not call the legacy Amazon-10
a new blind holdout.

## Offline scoring

Run from an installed HorusTrace environment:

\`\`\`bash
python -m horustrace.source_truth_oracle \
  --reference /path/to/source-reference.json \
  --predictions /path/to/predicted-claim-ids.json \
  > /path/to/source-score.json
\`\`\`

Predictions are a JSON list of \`{"scope_id":"...","claim_id":"..."}\`
objects. **Upstream prediction→claim identity mapping must itself be independently
reconciled and pinned**; the scorer does not inspect the scanner or invent a
matcher. It intentionally does not fetch GitHub blobs or verify the declared
source SHA/line against a source checkout. That verification is planned for C02b.

Precision, recall, TP/FP/FN/TN are **null** unless all scope conditions pass.
Missing predicted positives are FN *only in an explicitly closed universe*.
Missing negative labels become TN only when complete negative review was
attested. Extra, unlabelled scanner predictions are not auto-called FP. Even
when scope metrics are eligible, pooled accuracy is null if any requested scope
is unassessable. The report prints a canonical reference SHA-256 for audit
and always marks \`independent_reviewer_attestation_externally_verified=false\`.

All included example/test labels are synthetic; no release threshold is
evaluated against those numbers.

## Hard release prerequisites

C02a alone does **not** unlock C03/C04. Requirements remain: real independently
source-adjudicated positive and hard-negative ledgers with blob verification;
a newly sealed D01 holdout selected before scanner exposure; field-by-field
versioned agent/tool/MCP relationship, authority and finding/path review;
exact-head cohort validation, reversible Graph flags, and branch-required
\`accuracy-regression-gate\` enforcement in #558. Preserve the 12 unresolved
Amazon third-party runtime package/effect/control claims as UNKNOWN until
same-environment source/SBOM/runtime evidence exists.
