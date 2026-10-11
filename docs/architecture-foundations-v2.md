# Architecture Foundations v2 — P0/P1 compatibility bridge

HorusScan is static-first, source-backed and graph-first. This stage of the
architecture evolution deliberately **does not replace** the current Graph,
framework adapters, policy catalogue, ADG, or security rules.

## Pipeline contract v1

Each scan publishes ordered diagnostics under
`graph.coverage.resolution.analysis_pipeline`:

1. `discovered` — all supported input files have been scanned or diagnosed.
2. `normalized` — repository enrichment, resolution, skills and optional LLM
   semantic enrichment have completed.
3. `flows_resolved` — source flow analysis, entrypoint and reachability
   attribution are recorded.
4. `attack_paths` — static and potential attack paths have been derived.
5. `adg` — the versioned graph of assets and relationships has been built.
6. `findings` — rule evaluation, source provenance, configuration and
   suppression application have completed.

The new `pipeline_contract.PipelineCheckpoints` validates order; it records
entity counts, cross-framework canonical semantic errors, duplicate ADG node and
edge identifiers, and dangling ADG references. It does not rewrite findings or
silently mark unsupported claims as verified. Existing stage implementations
remain in `scanner.py` for compatibility during this step.

`valid=false` means the pipeline exposed unresolved contract issues that
require review; it is **not** automatically an exploitability finding. CI can
assert the report with `PipelineCheckpoints.assert_valid()` or inspect
the JSON evidence directly. This is initially non-blocking in the scanning API
to avoid hiding evidence from real projects during migration.

## Cross-framework semantic contract

`semantic_contract.validate_graph_semantics` now validates unbound tools,
skills, and MCP server declarations as well as agent-bound entities. A syntactic
declaration cannot be turned into an agent authority relationship merely
because it is discovered or validated.

Canonical fields remain authoritative; incidental framework-specific details
may remain in metadata. Adapter v2 / observation IR migration is a separate
follow-up because it requires source-backed conformance tests on each language
and framework.

## Attack-path proof envelope

Each attack path retains existing rule ID, severity, confidence, findings and
`metadata.basis`. The additional `metadata.proof` categorizes its evidence:

| Proof category | Static source-to-sink | What is established |
| --- | --- | --- |
| `static_dataflow` | true | Supported dependency through the bounded flow engine |
| `authority_reachability` | false | Source-supported control/delegation reachability |
| `source_backed_pattern` | false | Source-supported risk pattern, not general taint proof |
| `capability_combination` | false | Co-occurring or reachable capabilities |
| `other_potential` | false | Unclassified potential basis; do not upgrade |

No category establishes runtime exploitability; all report
`runtime_exploitability=not_verified`.

## Regression promotion gate

The pinned Fresh-16 source-claim workflow is now triggered on PRs that change
the scanner, its regression cases or the gate itself. It reuses exact target
SHAs and the locked postmerge source-claim inventory. Disappearing historical
protected claims require source-backed disposition, not a higher finding
count elsewhere. The dataset is reviewer-labelled, **not independent ground
truth**; passing demonstrates continuity of reviewed claims, not improved
precision or recall.

## Postmerge study protocol

After CI, review and merge, record the **exact merged scanner SHA**. Replay
Fresh-16 and Full-60 with identical source SHAs and application roots,
retaining case-level scan JSON, ADG, source packs, findings and diagnostics.
Compare, per repository:

- Agent → tool / MCP / skill → capabilities → identity → resource and
  destination → control relationships.
- Entity and edge identities, orphaned references, pipeline validation status.
- Source-backed claim removals and additions with adjudicated dispositions.
- Attack-path counts by proof category and supporting evidence basis.
- Unresolved data-flow and authority attribution, with source context.
- Runtime impact, scan duration and resource use when measurement is available.

An **improvement** requires more validated, useful coverage or fewer proven
errors with no unexplained loss of previously supported claims. Do not promote
a branch based solely on aggregate findings, paths or code coverage.

## Remaining P1 follow-up work

- Replace the v1 `Path -> Graph` adapter seam with a versioned, typed
  evidence-observation IR without changing canonical security semantics.
- Separate stage implementation orchestration from its present scanner entrypoint
  and declare explicit stage dependencies.
- Pilot Tree-sitter on one TypeScript and one C# source cohort; compare
  source-backed recall, diagnostics, run time and dependencies before adoption.
- Extend dataflow/path evidence only where independently validated.
- Keep external OPA and persistent enterprise graph decisions for later P2.
