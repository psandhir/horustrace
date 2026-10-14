# Wave B01 — source-scoped shadow Observation IR v2

**Scope:** additive, non-enforcing compatibility seam. Implements the first
slice of [Wave B issue #540](https://github.com/psandhir/horustrace/issues/540).
The active scanner, Graph, ADG, findings and paths are not rewritten. This does
not yet add the source-symbol/object linker required for B02.

Run against a fixed checkout:

```sh
horustrace scan ./repo --format json --output /tmp/scan.json \
  --shadow-observation-output /tmp/shadow-v2.json
```

The sidecar reuses `semantic_discovery` entities/bindings and adds a version-2
source observation record. IDs are derived from repository-relative paths,
line and available instance keys. Roles distinguish existing agent membership
from unbound inventory, and unresolved MCP references stay unresolved. Multiple
instances named identically are retained when source-qualified instance keys
distinguish them. Where the original graph cannot disambiguate same-line
instances, the shadow cannot prove they are distinct: this remains a B02 blocker.

A typed `INVOKES`, `BINDS_MCP`, `USES_SKILL` or `USES_IDENTITY` binding
reports **legacy Graph membership** with **partial**, not source-adjudicated,
resolution. It must not be treated as independently source-proven authority.

In particular, the projection does **not** infer `EXPOSES_TOOL` from an MCP
allowlist, `AGENT_CAN_CALL` from merely binding an MCP endpoint, identities
from server environment variables, or findings/paths from any projected edge.

`comparison` counts pre-existing member-list occurrences against distinct
typed shadow edges; duplicates can account for a difference. It is not
precision/recall. Sensitive arbitrary metadata and full source text are not
exported. The canonical projection remains immutable during sidecar generation.

## B01-to-B03 acceptance before production cutover

1. Source-symbol observations must be emitted by a pilot Pydantic/OpenAI
   adapter plus its MCP composition, rather than only from the legacy Graph.
2. Independently inspect WAB-01/02/03/04 source; preserve exact positive and
   negative registration/client/delegation evidence, including dynamic cases.
3. B02 must produce deterministic source-qualifiable links and explicit
   ambiguity reasons; B03 must keep provider exposure separate from access.
4. Compare exact source-adjudicated edges, stable identities and delegated
   authority against the frozen source cases. No path-count floor, inferred
   precision percentage, or legacy Graph cutover before review.
5. Run paired Fresh-16 / Full-60 and source-only blind review separately;
   this retrospective pilot cannot prove production quality.

**Current status:** B01 compatibility seam and mixed fixture, **not** B01's
full native adapter producer or independently adjudicated B02/B03 fixes.
