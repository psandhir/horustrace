# Agent-centric generalization rerun — protocol

## Purpose

Re-run the exact frozen first-class-framework cases from `fresh-unseen-generalization-20`
after LangGraph is removed from the production security-analysis path.

This is a regression/generalization check for the three priority frameworks:

- Google ADK
- Pydantic AI
- OpenAI Agents SDK

## Controls

- The 12 repositories and SHAs are unchanged from the prior frozen cohort.
- No case is replaced because of sparse or inconvenient output.
- LangGraph and MCP/custom strata are excluded from this product-scope metric.
- Scanner output is not used to select the cohort.
- This rerun first verifies scan/output stability. Source adjudication uses the same
  effective-authority rubric as #288/#290.

## Comparison baseline

The prior #290 first-judge framework results were:

- Google ADK: 23/24 materially supported = 95.8%
- Pydantic AI: 15/21 = 71.4%
- OpenAI Agents: 18/25 = 72.0%

The rerun should first establish whether removing LangGraph causes any unintended delta
for these same frozen repositories. Any later precision-improvement work is evaluated
separately from this cleanup regression.
