# Wave C C03a — reversible MCP source-only ADG migration candidate

Parent [Wave C #543](https://github.com/psandhir/horustrace/issues/543).
Follows [C02r #629](https://github.com/psandhir/horustrace/pull/629),
[C02s #630](https://github.com/psandhir/horustrace/pull/630) and
[C02x #639](https://github.com/psandhir/horustrace/pull/639).

## Why this slice exists

Without an available independent human adjudicator, continue **engineering**
and bounded mechanical validation, but do not quietly replace independent
truth with agreement between a scanner, AST parser and LLM judge.

C03a produces a **typed, fully isolated ADG-shaped preview** of the proven
source-representation gap from exact Git-pinned rw080. It is a migration
candidate, **not a migration of production Graph/ADG or security semantics**.

The existing canonical ADG and its SHA-256 digest remain unchanged.

## Source-to-candidate projection

`build_mcp_adg_candidate(base, sealed_v2_evidence, checkout)` accepts only
the same Git HEAD, tracked blobs, unmodified worktree bytes and source
node/edge claims digest verified by C02x. It then constructs
`ADGNode`/`ADGEdge` typed candidate objects **in a new graph**:

| Source node or relation | Candidate projection | Authority |
|---|---|---|
| MCP client configuration | Distinct `mcp_client_configuration` source node | UNKNOWN |
| Local source FastMCP implementation | Distinct `mcp_source_implementation` source node | UNKNOWN |
| Decorated MCP tool source site | Distinct `mcp_source_tool` declaration node | UNKNOWN |
| Configuration → implementation | `CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION` source link | Not a successful connection |
| Implementation → tool | `EXPOSES_TOOL` source declaration link | Not `AGENT_CAN_CALL` |

All proposed IDs are namespaced `c03-candidate:`. Source witness,
Git commit, source context and explicit `c03_candidate_only` labels are
preserved. The candidate graph **cannot be read as canonical schema-v1 ADG**:
its serialized `schema_version` is the deliberately incompatible value
`c03_preview_only_incompatible_with_adg_v1`.

There is deliberately **no** new `AGENT_BINDS_CLIENT`, `AGENT_CAN_CALL`,
credentials, `INVOKES`, effective permissions, findings or attack paths.
A source agent name on a client configuration is *context*, not a verified
agent-to-client authorization edge.

## Deterministic diff and rollback

`c03-mcp-candidate.json` contains:

- Exact canonical baseline digest and a separate candidate snapshot digest.
- Namespaced added source node IDs and edge IDs, by type.
- Empty removed/changed canonical node/edge sets.
- Zero added `AGENT_CAN_CALL` edges and no finding/path changes.
- Same exact canonical digest as the rollback anchor.
- `production_cutover_authorized=false`,
  `independently_adjudicated=false`, and unscored precision/recall.

Rollback for this slice is to **discard the preview**; no production
migration ever occurs. `verify_mcp_candidate_rollback` tests immutable
canonical digest, incompatible candidate schema and prohibited changes.

## Real source study and test gates

The existing pinned source study
`scripts/wave_c_c02r_pinned_mcp_shadow_study.py` retains its source-sealed
Workbench and independent source HTML evidence, and now also generates
`artifacts/c03-mcp-candidate.json`. On
`Amlan66/SSEEnabledMCPAgent@11531239e71b123f25b3c6103ee36a9d614d0032`
the candidate must preserve:

- Three distinct local stdio source FastMCP implementation sites, including
  two different same-named Calculator servers.
- Twenty-five source-level declared tool exports.
- Three `CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION` and twenty-five
  `EXPOSES_TOOL` candidate edges, **zero** runtime agent-call edges.
- Exact pre/post canonical ADG parity and a verified discard rollback.

Hard negatives reject legacy/unsealed evidence, stale commits or altered
source bytes, tampered claims, promoted authority edges, invalid endpoints,
invalid base ADG collisions, impossible rollback and duplicate same-name
identity collapses.

Do **not** reduce current Fresh-16, Full-60, full CI, CodeQL or same-head
accuracy gates. Every changed source head requires its own results.

## Explicitly unproven

- This is **not independent complete V2 source truth** or certified TP/FP/FN,
  precision/recall. It does not establish a complete negative universe.
- The source artifact is internally sealed against matching Git bytes; it
  cannot prove independent correctness, installed framework SDK contracts,
  deployed MCP availability or credentials.
- The remaining twelve Amazon runtime contracts and genuine unseen D01
  continue to be outside the reference.
- [#558](https://github.com/psandhir/horustrace/issues/558):
  the administrator must still make the stable accuracy gate mandatory in
  main branch protection. Manual latest-head review remains required.

**C03 production cutover, C04 authority/finding/path recalibration and
release certification remain NO-GO.** This slice makes the later migration
reviewable, reversible and quantitatively inspectable without inventing an
adjudicator.
