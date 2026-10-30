# Wave A03 — passive semantic stage survival trace

Opt in to a research sidecar without changing scanner findings, ADG, ASG,
rules or Effective Authority:

```bash
horustrace scan examples/google-adk-vulnerable --format json \
  --fail-on none --output report.json \
  --semantic-trace-output stage-trace.json
```

The versioned JSON contains eleven *named observation boundaries* within the
existing pipeline. Records describe only source-scoped entity/binding/effect
shape, not source code, secrets, model prompts or full provenance. Each stage
reports added/removed **multisets** and a portable snapshot SHA256. If the
event budget is exceeded, the report includes `events_truncated=true`.
The operation is opt-in and never mutates the canonical security graph.

**Important evidence limitation:** a change between stages localizes the
earliest observed difference to an interval. The `basis` is expressly
`observed_graph_delta_not_root_cause`. The recorder cannot determine which
individual function inside that interval caused an issue. A source-backed
review is still required to call it a false positive or false negative.

Temporary notebook identifiers are marked (not exposed as absolute paths).
Wave A04 must fix their originating semantic IDs, not merely sanitize this
debug sidecar. Use paired source-pinned scanner runs with/without trace to
assert production projection invariance. Historical A01/A02 cases are not
independent blind accuracy truth.

**Study baseline:** `research/accuracy-wave-a-retrospective-20261014/` retains the
30 source-pinned historical cases. Stage deltas must be read alongside
per-case source assertions; neither the total number of removed observations
nor the existence of an ADG edge is itself an accuracy verdict.
