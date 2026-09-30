# Unseen ADK + Pydantic AI holdout — protocol

This batch is a true external holdout relative to the frozen 180.

- 5 Google ADK + 5 Pydantic AI public repositories.
- Exact source commits are pinned before review.
- Every selected repository is outside the frozen 180 and earlier GPT differential cases.
- Selection is source/framework based and does not use HorusTrace output.
- The independent source review uses `GPT_SOURCE_REVIEW_PROMPT_V1.md`.
- HorusTrace findings and attack paths remain hidden until the source-review JSON is committed.
- After reveal, disagreements are source-adjudicated rather than treating either side as ground truth.
- Scanner code under test is merged `main` at cohort execution time.

The batch tests generalisation of the semantic fixes established by the locked 10-repository regression litmus.
