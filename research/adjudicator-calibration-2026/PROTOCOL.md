# Retrospective adjudicator calibration — protocol

## Question

Did HorusTrace appear to get worse mainly because recent studies introduced a stricter LLM adjudicator that earlier Frozen-90/Frozen-180 studies did not apply per finding/path?

## Design

The study changes the evaluator while holding repository source pinned, and separately changes scanner generation while holding the evaluator fixed.

### Panel A — Frozen-90 evaluator calibration

Six exact-SHA Frozen-90 application repositories, stratified across Google ADK, OpenAI Agents, LangGraph and MCP/custom, are rescanned with:

- Frozen-90 v0.6 scanner: `bee59738dd8ea4778a8dd0ea74039304dc307a78`
- current post-#287 scanner: `fff61df194b085bc06839884f99248943e8ec579`

The panel is claim-bearing by design: it is a precision/evaluator calibration, not a population recall estimate.

### Panel B — Frozen-180 longitudinal calibration

The 10 already-frozen ADK/Pydantic litmus cases are rescanned at the same pinned source SHAs with:

- original Frozen-180 baseline scanner: `418db4e29798a7d25df686dd7bccfd9fefa225bd`
- v0.10 authority-fidelity scanner: `a17449da60d6c87018558f4fb8bee126a4bd5090`
- current post-#287 scanner: `fff61df194b085bc06839884f99248943e8ec579`

## Adjudicator

Every state uses the exact #285 Copilot claim-adjudication, blind-source-review and recall-match prompts and the same source-pack construction.

For each repository:

1. one blind source review is generated without seeing scanner output;
2. each scanner state is independently claim-adjudicated against the same source pack;
3. the same blind review is matched back to each scanner state.

This prevents scanner-generation comparisons from changing the recall denominator.

## Metrics

Per state:

- finding TP / partial / FP / unresolved;
- path TP / partial / FP / unresolved;
- strict precision;
- TP+partial materially-supported precision;
- blind-review full / partial / missed / unresolved;
- full and full+partial recall;
- finding/path counts.

## Interpretation

The LLM is a differential adjudicator, not ground truth. A high partial rate in historical scanner states would demonstrate that recent “poor-looking” results are partly caused by evaluator strictness. Scanner changes are judged longitudinally only within the same panel and exact source SHAs.

Historical reruns record scanner execution failures and count drift where archived counts are available; non-reproducible states are not silently treated as product regressions.
