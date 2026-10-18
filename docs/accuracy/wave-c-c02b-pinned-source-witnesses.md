# Wave C C02b — offline Git-object verification of source-truth witnesses

Parent: #606. Depends on merged C02a #608. The new read-only verifier in
\`horustrace.source_truth_witness\` accepts the **same schema v1** as C02a and a
JSON map of \`scope_id → local repository checkout directory\`.

## Why this exists

C02a only checked that a source witness *looked* like a pinned Git SHA, blob,
file and line. Those strings can be outdated, incorrectly anchored or invented.
C02b fails closed unless every reference source label resolves to **the same
regular file in the exact pinned checkout**.

This verifies **source anchoring only**. It does not prove that a labelled
construct is really an agent, that a negative source site is truly excluded,
that a reviewer was independent/blind, or that a declared tool is runtime
callable. Those require separate independent source adjudication.

## Workflow

First prepare exact-SHA **local Git checkouts** for each source scope. Checkouts
must have HEAD equal to their \`scope.commit_sha\` and must be Git repository
top-level paths. No network fetch is performed by this tool, and no third-party
target code is imported/executed.

Supply a \`checkouts.json\` with a mapping such as:

\`\`\`json
{
  "d01:agents:runtime": "/tmp/d01-case-checkout"
}
\`\`\`

Run the verified (but still research-only) scorer:

\`\`\`bash
python -m horustrace.source_truth_witness \
  --reference source-oracle.json \
  --predictions scanner-claim-ids.json \
  --checkouts checkouts.json \
  > checked-oracle-score.json
\`\`\`

The verifier uses read-only local Git plumbing:
- HEAD must equal the scope's 40-hex commit SHA.
- \`git ls-tree\` at the commit must resolve exactly the source-relative file;
  symlink mode \`120000\`, submodule mode \`160000\` and trees are rejected.
- The declared blob SHA must equal the actual tree entry SHA.
- \`git cat-file\` must return the same blob bytes and SHA-1 Git blob digest;
  no source worktree files, symlink targets or content filters are read.
- The inclusive source line span must exist and contain nonblank source.
- Blob size and witness spans are bounded; Git invocation has a finite timeout.
- The report includes a cryptographic SHA-256 fingerprint of the Git blob,
  but not source code, credentials, absolute checkout path or an inference
  of deployed capabilities.
- A missing, forged or unresolved witness raises an error **before** any score
  is emitted. There is no fallback to C02a's syntactically checked numbers.

The local Git commit and bytes are evidenced; repository owner identity,
review provenance, independent source-interpretation accuracy and blind source
collection remain *unverified*. The scorer flags
\`independent_reviewer_attestation_externally_verified=false\` and
\`production_cutover_authorized=false\` even for valid anchors.

## Release separation

The source-only positive and *hard-negative* truth ledger is not yet built,
the original Frozen-180 must remain immutable, active study scope remains
145 non-LangGraph cases, and the historical 12 third-party Amazon runtime
claims stay UNKNOWN. The existing six accuracy gates are untouched.

Do **not** use the synthetic unit-test source corpus as independent ground
truth. C02c source-reviewed claim classification and sealed D01 genuinely
unseen holdout must precede any C03/04 production authority/graph cutover,
along with the #558 branch-required accuracy regression check.
