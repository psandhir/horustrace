# Wave C C03 — reviewless, bounded Graph projection preflight

Status: **RESEARCH ONLY / NO-GO for production activation**. Baseline: `5d80ee67917a52efd5201a8471d0438fe54b0d3d`.

## Decision without an independent adjudicator

Proceed with mechanical engineering and reproducible tests, not fabricated independent source truth. A separate AST parser, an LLM judge, or a source hash is **corroboration**, not a blinded independent V2 adjudication. The closed C02 issue #606 does not certify a complete positive and hard-negative universe or an unseen D01 holdout. Keep the original labels, unknowns and numeric regression floors unchanged.

## C03 first slice: MCP local source implementations

1. Define a versioned **projection candidate** contract from the C02x attested MCP source shadow. Validate exact Git HEAD, tracked blob, SHA-256, line witness and claims digest before any comparison. Preserve distinct server implementation identities (including same-name Calculator implementations), configuration bindings and declared tool exposures.
2. Build a **read-only dual projection**: existing canonical graph and candidate source graph from the same pinned checkout. Record each node/edge added, removed, folded or unresolved, source witness, role and reason. Do not silently map source-only `EXPOSES_TOOL` to `AGENT_CAN_CALL`.
3. Evaluate the pinned rw080 case with separate mechanical AST evidence (4 constructors, 28 tool declarations, 3 local stdio implementations and 25 local tool sites), hard-negative fixtures (resource/prompt, duplicate name, unbound config, dynamic remote catalog) and per-edge provenance. Distinguish **observed declaration**, **verified runtime**, **unknown** and **not applicable**.
4. Add a **non-mutating opt-in preview** (off by default) to export a machine-readable before/after diff; no default production graph, policy, finding, authority, path, OWASP or risk-score change. Reject mismatched SHA, stale worktree, unsupported edge kinds, incomplete provenance and unsupported authority assertions.
5. Run exact-head CI, CodeQL, pinned source study, Fresh-16 and Full-60 with same-head accuracy gate. Preserve the existing complete cohorts, LangGraph exclusion and Frozen-180 archive. Reconcile every apparent loss and gain at source-site level, rather than using path-count floors as a substitute for accuracy.

## Release gates

- **Engineering GO:** opt-in preview is reproducible and passes fail-closed tests, source-witness comparisons and full cohorts. May merge as dormant tooling.
- **Production C03 GO:** separately approved bounded reference with independently established complete relevant positives and hard negatives, actual scoped precision/recall or explicit `not_assessed`, no unsupported authority promotion, reversible rollback and enforced admin accuracy status gate #558. **Currently NO-GO.**
- **C04/C05:** no authority/findings/attack-path recalibration or release certification until C03 release evidence meets its gates.
- **No independent adjudicator available:** publish transparent machine-only corroboration and uncertainty; pursue externally reviewable evidence packets and a genuinely unexposed D01 later. Never relabel machine opinions as independent human verdicts.

## Follow-up implementation boundary

Implement candidate projection and source-level differential in a separate PR. Keep the comparison sidecar isolated from production Graph/ADG until release approval. This preflight document records a concrete implementation plan, **not** completion of C03.
