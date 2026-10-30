# Wave C C02d — D01 holdout selection and sealing contract

Parent #606. Follows source-truth contract #608, Git witness #609, provisional review packets #610.

## Deliberate scope

This tooling **does not create or certify an actually independent unseen
holdout**. No new D01 repository has been independently chosen and checked,
and selection times/source access logs are not externally attested. The
purpose is to make source-only candidate selection replayable and to prevent
*known* historical exposure from being silently reused.

The old Amazon-10 and active 145 non-LangGraph cases are **already exposed** to
the scanner/reviewer workflow: they must not be rebranded as a new blind
holdout. The Frozen-180 archive remains immutable.

## Inputs (three local JSON files)

1. \`candidates.json\`: \`schema_version=1\`, \`cases\` with
   \`case_id\`, \`repository=owner/name\`, pinned full 40-hex
   \`commit_sha\`, \`framework\`, \`source_role\`. Gather candidates from
   *independent source discovery*, not scanner positives or false negatives.
   No truth claims, source labels, runtime tool execution or scanner fields.
2. \`prior-exposures.json\`: \`schema_version=1\`, list
   \`known_exposed_repositories\` (owner/name), \`inventory_ref\`, and
   \`inventory_declared_complete\`. Include historically exposed source
   cases (especially Frozen-180, active-145, pilot/ADK/LLM studies and
   Amazon-10) **before** choosing D01. If completeness cannot be
   established, keep the flag false; sealing will refuse it. This flag is
   self-declared, not proof an inventory is exhaustive.
3. \`selection.json\`: \`schema_version=1\`, \`selected_case_ids\`,
   \`source_selection_ref\`, \`selection_protocol\`. The source selection
   reference must predate scanner results and be externally auditable.

## Offline command

\`\`\`bash
python -m horustrace.source_truth_holdout \
  --candidates candidates.json \
  --exposures prior-exposures.json \
  --selection selection.json \
  --private-output /restricted/private-d01.json \
  --public-output public-d01-commitment.json
\`\`\`

The sealing CLI writes **two separate files** and prints only the public commitment. The private file is created exclusively with owner-only permissions (0600 on POSIX), never overwritten. Do not redirect a combined library result to public CI logs. The files are:

- \`private_manifest\`: exact selected case IDs, repositories, 40-hex
  pinned source SHAs, roles, framework, candidate/exposure/selection input
  digests, a private random 256-bit nonce and all explicit independence limitations. Keep it in restricted
  storage; **never commit or upload it to public GitHub**.
- \`public_commitment\`: manifest SHA-256 digest, number of selected cases,
  a nonce-bound manifest digest and coarse case count, but **not case IDs,
  repository names, unsalted source-input digests, selection references or
  scanner labels**. It can be published in a review
  issue to establish a pre-exposure fingerprint.

Verify a saved seal against the exact three original inputs:

\`\`\`bash
python -m horustrace.source_truth_holdout \
  --candidates candidates.json \
  --exposures prior-exposures.json \
  --selection selection.json \
  --private-manifest private.json \
  --public-commitment public.json
\`\`\`

The tool rejects selected repos present in the complete **declared** exposure
list (including other commits of the same repository), unknown/duplicate case
IDs, multiple selected commits from one repository, unpinned sources,
malformed schemas, altered private manifests and public commitments.

It cannot: verify that the public commitment was actually published before
scanner access; audit every other engineer's repo access; prove that a newly
listed repo was unseen; prove reviewer blinding; infer negative-source
completeness; verify git blobs; or certify production precision/recall.
\`release_certified=false\`, \`holdout_unseen_externally_verified=false\`
and other unverified flags are intentionally immutable in output.
SHA-256 is a replay fingerprint, **not** a digital signature/independence
attestation. Identical inputs get distinct public digests because a new private
nonce is generated on every seal; verification uses the saved private nonce.
Do not publish that nonce or the private manifest.

## Next evidence required

A reviewer independent of scanner development should assemble the new
unseen source pool, external exposure inventory and time-stamped selection
event, keep private case IDs inaccessible to the detector author,
source-review the full positive **and** hard-negative universe, and
pin Git blob/line witnesses with #609. Only after a verifiable seal, study
access log and independent review can D01 go to a separate paired
comparison; no self-declared flag converts the synthetic fixture to a
real D01.

#558 administrator branch-required accuracy check and C03/C04 Graph cutover
remain release blockers. No source code is fetched or run by this tool.
