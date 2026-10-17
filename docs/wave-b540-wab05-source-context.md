# WAB-05 — Source-role-accurate MCP inventory and negative evidence

**Status: pinned diagnostic / not a Wave B release GO.**
This is a source-only counterpart to the four WAB-01–04 case review merged by #579.
Frozen case: `gen-mcp-001`, `stickerdaniel/linkedin-mcp-server@f1425029ca426e850dc9f52b0097f0fff1aa7b3d` (application root `.`).

Original Wave A trace observed 124 unbound MCP records, including 121 source paths under `tests/`. This is a source-location distribution, **not** 121 confirmed false positives and **not** 124 deployed server instances.

## Immutable source-positive witnesses

- Production-source **factory declaration**: `linkedin_mcp_server/server.py` pinned blob `2bc6f86e8696baea6a4d1f9ef88fccb862fa7153`, `create_mcp_server` and `FastMCP(...)` source call. A factory declaration does not establish an instantiated running process.
- Explicit **test-only provider fixture**: `tests/test_server.py` pinned blob `84f6bea4c5e2e22fc794898214a9489fd287e979`, helper `_owner_serving` constructing `FastMCP("owner")`. It is an in-process test stand-in, not a production owner process.
- Positive source name collisions are not identity equivalence: two declarations with the same text label (`test`, `owner`) but different file/line sites remain separately visible. Duplicated `path:line:name` observations are explicitly reported as ambiguous rather than promoted to another deployed server.
- Source context is `runtime`, `test`, `example` or `unknown`, derived from repository-relative locations; a runtime-source label **does not** prove server execution or effective callability.

## New acceptance evidence

`scripts/verify_wave_b540_wab05_source_context.py` pins the exact source blob IDs, performs an ordinary static HorusTrace scan without importing the target or installing its dependencies, and cross-checks every unbound MCP record against the passive `shadow_observation_report.inventory_partition.observations_by_role.unbound_mcp_inventory`. The workflow uploads a complete per-observation source-location ledger, contextual counts, unknown/duplicate-site inventory, plus comparison to the historical 124/121 baseline **without enforcing a count floor**.

The pinned witness fails closed if test fixture observations disappear from the source partition, if a source-only provider is turned into a fabricated agent, if an MCP callability edge is invented, or if shadow silently drops/misclassifies the scanner's unbound server observations. Negative unit fixtures cover same-name distinct sites, duplicate same-site records, unknown locations, and checkout parent paths named `tests`.

The outcome is a **source-context verification test**. It is not exhaustive independent source truth, real-world deployed asset verification, or a security accuracy percentage. If the current scanner yields a different source-context distribution, inspect the exact per-instance output and explain the source delta rather than force 124/121 to match.

## Remaining Wave B release acceptance

#540 and #551 still need per-case Graph/authority/finding/path correspondence to the original source proof (including WAB-01–04), the independent negative-labelled D01 truth universe, 12 unresolved Amazon imported-tool control/effect claims or explicit version-dependent UNKNOWNs, and branch-rule enforcement of the stable same-head accuracy gate from #558.

No production detection/rules/ADG/attack-path changes are part of this PR. Keep Fresh-16, Full-60, Wave-A-30, Amazon unseen holdout and CodeQL gates for applicable scanner changes. **No Wave C production cutover** on this diagnostic alone.
