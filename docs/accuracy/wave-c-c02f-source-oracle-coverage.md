# Wave C C02f — source-oracle scope coverage matrix

Parent #606. This is a diagnostic for the expected source-reference
**denominator**, not an independent adjudication or production release gate.

## Why

A precise-looking 95% score can be a cherry-picked artifact when the reference
contains only a few source sites or when unreviewed framework/source-role
combinations are absent from scoring. In the active 145 exact-SHA non-LangGraph
cohort, inherited 89 incomplete, one ontology-invalid and 55 nonindependently
negative-reviewed historical case categories should not disappear merely
because a new oracle format or scoring script has been introduced.

## Inputs

- \`expected.json\`: \`schema_version=1\`, \`manifest_ref\`, and an
  \`expected_scopes\` array. Each scoped item has \`scope_id\`, \`case_id\`,
  \`repository=owner/name\`, exact 40-hex source \`commit_sha\`, framework,
  construct (agent, tool, MCP, typed edge, authority, finding, path etc) and
  source_role (runtime/test/provider_only/unknown etc). Prepare from the
  independently source-scoped study manifest, **not observed scanner nodes**.
- \`reference.json\`: existing strict C02a source oracle, with all available
  pinned source label witnesses and completeness/reviewer flags.
- \`checkouts.json\`: exact C02b scope-to-local-pinned-checkout map for all
  existing reference scopes; absent expected scopes do not require a checkout.

\`\`\`bash
python -m horustrace.source_truth_coverage \
  --expected expected.json \
  --reference reference.json \
  --checkouts checkouts.json \
  > coverage.json
\`\`\`

The offline evaluator fails closed on unexpected reference scopes, wrong
source roles/constructs, case/repo/source commit drift, missing/bad Git
source witnesses and invalid/duplicate expected identities. It preserves
every expected scope in the matrix, even when no oracle scope exists.
Each row reports positive, hard-negative and unknown source labels,
source-witness verification and blockers. Aggregates are grouped by
framework × construct × source role to guide the *next* source-review work.

The tool does not verify that \`expected.json\` is exhaustive or sourced
without scanner influence, that reviewer IDs are independent, or that
source-candidate semantics are correct. Its output intentionally fixes:

- \`independent_review_externally_verified=false\`
- \`expected_cohort_completeness_externally_verified=false\`
- \`certified_precision=null\`, \`certified_recall=null\`
- \`production_cutover_authorized=false\`

These controls deliberately do **not** reclassify unknown MCP dynamic
catalogue sites or the 12 unresolved Amazon third-party runtime/control
claims as negatives. No source code execution, GitHub network requests
or mandatory LLM enrichment. Preserve original Frozen-180 archive and
six required source accuracy floors.

## Real next action

Produce an independent active-145 cohort expected-scope file, source
annotate every missing/uncertified stratum (especially MCP server/tool
bindings vs agent callability, unique agent instances, runtime vs
test-only, resources, controls, paths) and genuinely audit reviewer
provenance and negative enumeration before taking any number to release.
Run C02e paired source deltas on the same pinned universe, hold D01
private after independently reviewed C02d sealing, and retain #558's
branch administrator requirement.
