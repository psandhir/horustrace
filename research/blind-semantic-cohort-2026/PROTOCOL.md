# Blind semantic cohort v1

## Purpose

Measure whether the semantic improvements developed during the seven-case LLM parity exercise generalize to repositories that did not drive those scanner changes.

This study is intentionally result-blind at selection time.

## Selection

The cohort is derived from the existing frozen 180-repository study. Eligibility requires:

- `previously_studied=false`;
- exclusion of all seven repositories used in the semantic tuning exercise;
- exclusion of repositories already present in the independent-human Issue #157 validation pack.

Selection is deterministic and does not inspect HorusTrace findings, counts, attack paths, or pass/fail status.

Within each framework stratum, eligible cases are sorted by the final 12 hexadecimal characters of their pinned commit SHA. The first two are selected, except FastAgent where only one eligible case remains after exclusions.

This yields 11 exact-SHA repositories: 1 FastAgent and 2 each for Google ADK, LangGraph, custom MCP/model-tool-loop, OpenAI Agents, and Pydantic AI.

## Blinding order

For every case:

1. freeze repository + SHA;
2. perform the independent LLM/static source review using `llm-review-prompt.md`;
3. persist the source-review output;
4. only then reveal HorusTrace output for that case;
5. compare authority graph, policy findings, attack paths and unresolved evidence;
6. classify mismatches as scanner gap, reviewer/reference error, unresolved static ambiguity, or representation mismatch.

Do not alter the cohort after HorusTrace output is inspected.

## Scanner change policy

No scanner code change is allowed until all 11 independent reviews and HorusTrace comparisons are complete.

After comparison, prioritize only recurring/generalizable gaps. A single exotic repository pattern should normally be recorded as a limitation unless it represents a clear reusable semantic primitive.

## Measurements

Report at minimum agent/workflow structural agreement, effective tool/MCP binding agreement, policy-finding agreement by rule, attack-path agreement, FP/FN causes, unresolved-rate differences, and framework-stratified mismatch patterns.

This is a post-hoc generalization study, not a replacement for the preregistered Frozen-180 metrics or the independent-human accuracy study in Issue #157.
