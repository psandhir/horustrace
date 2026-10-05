# Agent Skill LLM semantic calibration v1

This study calibrates the production `skill-security-semantics-v1` prompt against
a locked, hand-labelled synthetic corpus.

The study measures semantic classification only. It does not treat LLM output as
effective authority and does not use the LLM to emit HorusTrace findings.

## Design

- 44 cases.
- 12 explicit positives.
- 12 subtle/inferred positives.
- 12 hard negatives/near-misses.
- 8 realistic multi-concept cases.
- 12 fixed semantic concepts.
- Confidence thresholds scored from one set of model outputs: 0.65, 0.75, 0.85.
- Primary model for the initial run: `gpt-6.1-sol`.
- Gold labels are frozen in `cohort.json`.

The runner reports per-concept and aggregate precision, recall, F1, exact-case
accuracy, difficulty-stratum performance, confidence bins, and full FP/FN error
details.
