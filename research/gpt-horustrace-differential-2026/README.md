# GPT ↔ HorusTrace Differential Study

This study compares HorusTrace against an independent GPT source review over the same pinned repositories.

## Why

The objective is not to make GPT the ground truth. The objective is to discover **semantic disagreements** between a deterministic scanner and a strong source-level reviewer, then adjudicate those disagreements against source.

Useful outcomes include:

- HorusTrace misses a source-proven authority relationship;
- GPT misses a scanner-supported rule condition;
- both identify the same semantic risk through different abstractions;
- HorusTrace overstates reachability or destination control;
- GPT assumes runtime behavior the source does not prove;
- both agree, increasing confidence in the scanner result.

## Required sequence

1. Select pinned cases.
2. Perform GPT source review with `GPT_SOURCE_REVIEW_PROMPT_V1.md`.
3. Save/commit that review.
4. Only then reveal HorusTrace case findings/attack paths.
5. Build the differential mapping.
6. Verify each meaningful disagreement against source before changing scanner behavior.

This ordering reduces anchoring on HorusTrace output.

## Metrics

Do not compare raw finding counts as precision/recall because HorusTrace can emit several rule findings for one semantic condition.

Track instead:

- semantic finding full matches;
- semantic partial matches;
- GPT-only semantic claims;
- HorusTrace-only semantic claims;
- end-to-end attack-path overlap;
- effective-authority disagreements;
- runtime/reachability qualification disagreements;
- rule-scope disagreements;
- duplicate finding noise.

## Batch 001

See:

- `batch-001-gpt-source-review.json` — frozen GPT side;
- `batch-001-differential.json` — semantic comparison;
- `BATCH_001_REPORT.md` — conclusions and build priorities.
