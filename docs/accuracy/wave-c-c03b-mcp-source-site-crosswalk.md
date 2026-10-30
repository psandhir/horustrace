# Wave C C03b — exact-source-site crosswalk (read-only, non-authoritative)

Depends on merged C03a #640 and the attested MCP source evidence C02x #639.
This **adds no production projection or effective authority edges**.

The existing C03a reversible candidate adds MCP client configurations,
original server implementations and declared static tools to a quarantined
ADG-shaped snapshot. C03b supplies a deterministic *source-site correlation*
between those candidate nodes/edges and canonical ADG source witnesses,
rather than merely reporting counts of additions.

## Contract

- Input: canonical `AgentDependencyGraph` and C03a candidate produced from
  exact-revision Git/blob/worktree-attested MCP source evidence.
- First run C03a's full rollback verifier: reject altered canonical nodes,
  renamed candidate nodes, invalid edge kinds, tampered snapshots, mismatched
  digests, authority promotion, incomplete identities or changed differential.
- Candidate nodes can correspond to canonical source sites **only if all three
  path, line and display name match exactly**. Canonical kinds remain visible
  even when they differ from source candidate kinds.
- Zero matching canonical sites → `candidate_only`; exactly one →
  `corroborated_source_site`; multiple → `ambiguous_source_site`.
  Same display name in a different file or line is **not a match**.
- Candidate edges can correspond only to existing canonical edges with
  identical kind and exact source-site-correlated canonical endpoints.
  Ambiguity remains explicit, and an existing `AGENT_CAN_CALL` edge is never
  interpreted as an `EXPOSES_TOOL` declaration.
- Preserve every source candidate node and edge, original canonical graph,
  site/path/line, matched canonical IDs and kinds, unresolved states, source
  Git commit, source claims digest, baseline ADG digest and candidate snapshot
  digest.
- Deterministic SHA-256 binds the crosswalk output. The report **never**
  asserts semantic/runtime instance equivalence, source completeness,
  independently adjudicated truth, effective authority or release cutover.
  `certified_precision` and `certified_recall` remain null.

## Pinned real-source test

The rw080 study writes `c03-mcp-source-crosswalk.json` alongside
`c03-mcp-candidate.json` and the v2 source-attested shadow. Expect 31
candidate nodes (3 source implementations, 3 client configurations,
25 decorated tools) and 28 source edges (3 configuration resolutions,
25 `EXPOSES_TOOL`). Hard negatives cover duplicate-name servers at
different source paths/lines, multiple same-site canonical rows,
source-site corroboration with different ontology kinds, exact-edge matching,
tampered candidate snapshots and runtime-authority promotion.

This remains a **source-only sidecar**, off the canonical Graph and downstream
finding/path engines. Latest-head full Python CI, CodeQL, Fresh-16, Full-60,
pinned rw080 study and replacement same-head accuracy gate are required
without reducing any existing checks.

## Evidence limitation without an independent adjudicator

Mechanical AST corroboration and exact-source crosswalks help identify what
Horustrace currently drops or folds. They do **not** establish a complete
negative universe for certified accuracy, runtime MCP availability, identity
or permissions. C03 production cutover and C04 authority/path migration
remain NO-GO until a separately approved evidence and release policy is met.
#558 administrator-enforced required accuracy status remains outstanding.
