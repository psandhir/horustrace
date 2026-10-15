# Wave B02 — source-context-partitioned shadow inventory

This opt-in observation sidecar extends Wave B01 with an explicit **per-source-context** inventory partition for every legacy shadow entity and observation. The active scanner's Graph, findings, effective authority, ADG and attack paths remain unchanged.

Run:

```sh
horustrace scan ./checkout --shadow-observation-output shadow.json
```

Inspect `inventory_partition.entities_by_kind` and `inventory_partition.observations_by_role` to distinguish constructs whose source is classified `runtime`, `test`, `example`, `notebook`, etc. An invalid preexisting metadata `source_context` is ignored and independently reclassified from the source location, so arbitrary input metadata is not echoed into the report. The partition uses the canonical `SOURCE_CONTEXTS` classifier already in the scanner.

**Interpretation:** These are distinct **shadow entity records** versus **evidence observation records**, not a census of deployed components. A runtime-source label is not a successful execution, network connection, or active permission. Test-scoped providers remain visible and source-addressable rather than being silently removed; graph memberships are still only partial until source adjudication. No server-to-tool `EXPOSES_TOOL` or `AGENT_CAN_CALL` edge is invented from a context label.

**Targeted motivation — WAB-05:** Wave A observed 124 unbound MCP records in the pinned `stickerdaniel/linkedin-mcp-server@f142502` diagnostic, 121 with paths under `tests/`. Summing those into an undifferentiated "production MCP servers" count is misleading, but declaring them 121 scanner FPs without source verification would also be incorrect. This sidecar exposes the categories explicitly as the first safe measurement, without changing legacy scanner output.

**Gate:** Fixture tests assert the test/runtime/unresolved partitions, sums of entity and observation counts, source path portability and refusal of untrusted context metadata. Fresh-16 and Full-60 must pass, and WAB-05 must still be checked on its exact pinned source with an independent per-instance ledger before a production inventory default is altered. No precision/recall figures are claimed.
