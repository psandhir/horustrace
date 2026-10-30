# Wave B model-as-judge high-severity source review — first 20/73 keys

## Scope, reproducibility and limitations

Source-only OpenAI/ChatGPT model adjudication at pinned `aws-samples/sample-multi-agent-region-expansion-planner@30d03d7c9f6512e5bf10601879382fac9c3a16b1`. All original file/blob SHA and source-line witnesses are recorded **per key** in `high-severity-adjudication.json`. Review concerns *source-claim validity*, not confirmed runtime access, actual exploitation, or independent human review.

Run deterministic coverage tests with `pytest -q tests/test_wave_b540_model_judge_high_severity.py`. This proves ledger structure, unique exact keys, original source pin and explicit limits; it **does not** independently verify truth.

## Results

- 20/20 high-severity changed finding keys reviewed in source-only mode: **10 source-confirmed conditional/potential**, **6 false positives in the old source-claim identity/location**, **4 unresolved exact capability-count or third-party tool semantics**.
- All six removed high-severity keys are old invalid source anchors or a bogus `agent`-as-tool projection. Five are obsolete line-1 locations. These are **not** automatically six removed security risks; several risks reappear with corrected source locations.
- Current source at `src/utils/config.py:43-46` sets `BYPASS_TOOL_CONSENT=true`; this is explicit configuration evidence, **not** successful runtime authorization proof.
- Specialist `Agent(...)` instances are constructed inside guarded `@tool` wrapper invocation. Any `AGT020`/`AGT021`/`CAP004` source-confirmed label is conditional capability exposure, not observed execution.
- `src/agents/__init__.py:9` re-exports `compare_regional_pricing`, while `src/main.py:15,54` references `pricing_explorer`. Python module import resolution must be verified before claiming a callable edge from the orchestrator. Remote MCP tool enumeration in pricing case is runtime unknown.
- `CAP003` exact four privileged classes in nested Strands agents remain unresolved until each imported external tool effect is source- or contract-proven.
- The `python_repl` external tool's exact `process.execute` semantics are unresolved absent its pinned implementation.

## Next iteration

1. Continue remaining **53 medium** claim keys in batches against pinned source blobs; reuse the published source witnesses, but independently assess locations and hard negatives. Do not reuse the high-severity key verdict to auto-approve another key.
2. Investigate actual `strands_tools` source contracts and `BYPASS_TOOL_CONSENT` semantics; add explicit control evidence and clarify over-asserted runtime authority.
3. Correct known residual scanner defects only when source-proven, including the bogus `agent`-as-tool and pricing module/callable reachability if still emitted; run targeted regression tests and frozen cohorts.
4. Complete WAB-01–05 source-ledger positive and negative facts, establish complete blind negative/positive ground truth denominators. Only then judge Wave B #540 gate; model judge != independent human or exhaustive truth.
5. Execute all Wave C phases C01–C05 when quality gate permits; preparatory shadow work can proceed without irreversible cutover.

See `HANDOFF.md` for work isolation, CI, scratchpad and restart protocol.

## Medium-severity source review complete as **model adjudication**, not independent truth

The second ledger records all 53 medium-severity changed claims in the exact same frozen source revision and derives original source import/tool-registration/guard witnesses (original Git blobs). Source-confirmed claims mean conditional tool configuration, **not** effective runtime permission. The hard-negative field explicitly preserves unknown remote MCP catalogues and the difference between a local missing guardrail and a missing effective control.

Breakdown: 35 source-confirmed conditional configuration, 10 obsolete source identity/location records, 8 unresolved effect/control/allowlist. Combined with first 20 high-severity: **45 source-confirmed, 16 invalid historic claim IDs, 12 unresolved** across 73 changed keys. This is a source-pinned LLM assessment with known non-blind review context, not an independently constructed gold standard or precision/recall metric.

This handoff is updated on the feature branch; check GitHub CI before merge.
