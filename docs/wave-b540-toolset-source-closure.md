# Wave B540 — Couchbase conditional source catalogue closure

## Scope and claim type

This changes **only the opt-in semantic shadow report**. The new
source_native_toolsets canonical SemanticDiscovery v2 sidecar identifies
source-declared, mode-qualified MCP tool candidates. It resolves imports
without importing/executing scanned code: ServerSpec.tools -> ToolSet
-> read_only/write symbol -> locally imported function definition.
A trusted FunctionTool.from_function + FastMCP.add_tool factory must also
be present in the same project. All source files must remain within the
scan root, with bounded input sizes, and unique module-scope bindings.

The pinned diagnostic case is
couchbase/mcp-server-couchbase@df5d9ceb013f57143171f65ec3ba033ace06aa9a.
Two ServerSpecs link to two package ToolSets with 53 declared entries:

| Server | read_only | write | Total |
|---|---:|---:|---:|
| operational | 28 | 12 | 40 |
| operational_insights | 11 | 2 | 13 |

The count is source-backed *candidate registrations*, **not** 53
successfully exposed runtime tools or new production inventory entries.
The write group is registered only if read_only_mode is false. Either
group may be filtered by disabled_tools; per-tool scopes and source-level
controls can also change effective access. The same status function is
declared by both servers (two source candidate edges to one definition),
and some names map to different implementations per server. Preserve
those distinct server->tool identities.

Every candidate EXPOSES_TOOL relationship is PARTIAL with
exposure_state=conditional_candidate, disabled_tools=unresolved,
auth_scope=unresolved and agent_callability=not_adjudicated. The
underlying scan Graph/findings/ADG/paths are untouched. No AGENT_CAN_CALL
or live connection is claimed; this is a **provider-only** repository.

## Source truth and work still outstanding

The verifier checks six original Git blob hashes and per-server bucket
cardinalities, alongside hard-negative tests for constructor/source
shadowing, unresolved imports, missing definitions, invalid factories,
and unstable assignments. It is *a pinned-source claim witness*, not an
independent blind adjudicator. Before closing issue #540, the product
still needs:

1. General cross-framework source-symbol/object linker beyond the
   bounded local Python import grammar in this slice.
2. Configuration/CLI gating and per-instance reachable MCP catalogue
   closure, including unresolved runtime semantics.
3. WAB-04 ten-to-two agent consolidation source-stage reconciliation.
4. Per-case before/after stage evidence, independently adjudicated
   claims and meaningful positive/negative accuracy metrics; regressions
   against Fresh-16, Full-60 and Wave A 30 source baseline.

The cross-module linker deliberately *does not* follow arbitrary
runtime imports, dynamic expressions, or mutated references. Missing
source certainty results in no candidate links and remains an
investigation item; it is not automatically a false negative.
