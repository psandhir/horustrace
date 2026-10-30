# Wave C C02c — source-first candidate review, with a closed release gate

Parent #606. Follows #608 (versioned source oracle) and #609 (Git source
anchor verification). It does not add any independent human reviewer, open a
source repository, certify a negative universe, or enable production cutover.

## Purpose

The remaining gap is not finding more Git references. It is assigning
defensible **positive, negative and unknown** source interpretations to
specific typed claims (agent vs factory, tool registration vs call authority,
runtime vs test-only MCP, conditional effects, identity, findings and paths)
before inspecting the scanner's predictions.

This module separates that job into two offline steps.

### 1. Prepare a scanner-blind source-first review packet

Supply a C02a source manifest with **unreviewed** scopes, **unknown** claim
verdicts, and both positive/negative completeness flags false. The source sites
and candidate identities must be independently assembled from the pinned
repository rather than lifted selectively from a scanner report. This
implementation **does not automatically discover an exhaustive candidate
universe**.

The packet builder verifies every pinned Git commit/tree/blob/line via C02b.
It emits source paths, source SHA-256 digests, claim IDs, typed scope metadata
and the negative-search plan; **it strips expected truth and scanner findings**.
It does not embed source contents or arbitrary source review reasons. A
deterministic packet SHA-256 binds the reviewer responses to the exact proposed
source candidate set.

\`\`\`bash
python -m horustrace.source_truth_review prepare \
  --reference unreviewed-source-candidates.json \
  --checkouts pinned-local-checkouts.json \
  > source-only-review-packet.json
\`\`\`

### 2. Record provisional independent source opinions

For every candidate, collect two reviewer responses in a separate JSON file:

\`\`\`json
{
  "packet_sha256": "<copied from source-only-review-packet.json>",
  "reviews": [
    {
      "scope_id": "case1:agent",
      "claim_id": "agent:worker",
      "reviewer_ref": "reviewer-pseudonym-1",
      "review_session_ref": "isolated-review-session-1",
      "decision": "positive",
      "reason": "Exact imported Agent constructor is instantiated at this source site",
      "source_only_review": true
    }
  ]
}
\`\`\`

In practice supply at least two distinct reviewer identifiers **per
candidate** (the example deliberately shows only one record). Reviewers must
independently inspect source and provide a justification; their honest
self-declaration is evidence collection, **not independent attestation**.
Two unanimous non-unknown, source-only opinions produce provisional consensus.
Conflicting, missing, unknown or scanner-exposed opinions remain unresolved.

\`\`\`bash
python -m horustrace.source_truth_review adjudicate \
  --packet source-only-review-packet.json \
  --reviews independent-opinions.json \
  > provisional-source-review.json
\`\`\`

### 3. Hard stop on premature metrics

The provisional source-oracle export always sets:

- \`review_method=source_reviewer\`, not \`independent_blind\`
- \`scanner_blind=false\` (not externally verified)
- \`positive_complete=false\` and \`negative_complete=false\`
- \`release_accuracy_assessable=false\`

Thus, even unanimous synthetic reviewers **cannot** convert a one-case
sample into an accuracy release claim. The existing C02a scorer returns
\`not_assessed\` until source completeness, reviewer provenance and independent
blinding are externally adjudicated. The packet digest is not a signature.
Do not enter reviewer names, secrets, or confidential raw code into committed
fixture JSON or public CI logs.

### Next study work

C02d must select and seal a new genuinely unseen D01 holdout before scanner
exposure. Then enumerate positive and hard-negative source universes by
framework/context/construct (especially runtime vs test-only MCP, conditional
Couchbase tool exposure, agent constructor vs app factory, and Strands nested
wrapper/instance), record reviewer disagreements, demonstrate source-based
coverage and independently verify reviewer/blind provenance. Unknown dynamic
tool catalogues and historical twelve Amazon third-party runtime
effect/control claims stay unresolved, not negatives.

Active 145 non-LangGraph exact-SHA cases and six numeric release floors are
unchanged; original Frozen-180 archive remains immutable. #558 branch-required
accuracy gate and production C03/C04 cutover are separate blockers.
