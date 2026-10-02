# Agent-centric generalization rerun — results

## Executive result

The exact 12 frozen Google ADK, Pydantic AI and OpenAI Agents repositories from #290
were rerun after LangGraph support and its framework-specific production plumbing were
removed from HorusTrace.

All **12/12 scans completed successfully** on merged main commit
`faec409216bbbd77c8800f3fc041f31e1212132c`.

The cleanup reduced the cohort from **70 to 61 findings** and from **7 to 5 attack
paths** across these three first-class frameworks. Exact claim/path comparison found
**no new findings or attack paths**. Every removed claim/path had already been
adjudicated as a false positive in #290.

## Finding result

| Framework | #290 findings | Post-cleanup findings | Previously supported | Post-cleanup supported precision | Post-cleanup FP |
|---|---:|---:|---:|---:|---:|
| Google ADK | 24 | 24 | 23 | **95.8%** | 1 |
| Pydantic AI | 21 | 17 | 15 | **88.2%** | 2 |
| OpenAI Agents | 25 | 20 | 18 | **90.0%** | 2 |
| **Total** | **70** | **61** | **56** | **91.8%** | **5** |

Carrying forward the exact #290 verdicts for unchanged claims gives:

- true positive: **22**
- partial: **34**
- false positive: **5**
- materially supported: **56/61 = 91.8%**
- strict TP precision: **22/61 = 36.1%**
- explicit FP rate: **5/61 = 8.2%**

This carry-forward is valid for this regression comparison because every surviving
claim matches the prior frozen output by rule/agent/source/message identity and the
post-cleanup run introduced no new claims.

## Removed false positives

Nine findings disappeared:

- **OpenAI Agents — 5 NET002 false positives**
  - one Search Agent claim in `openai-agents-demos`;
  - four AgentOps WebSearch/ImageGeneration claims.
  - These were previously adjudicated as fixed/provider-managed destinations rather
    than arbitrary model-selected egress.
- **Pydantic AI / PharmIQ — 2 path findings**
  - PATH001: MCP server startup represented as agent-reachable process execution.
  - PATH006: MCP startup/environment composition represented as model authority.
  - Both were previously adjudicated as MCP bootstrap, not agent authority.
- **Pydantic AI Research Agent — 2 capability findings**
  - AGT020 and CAP004 around restricted in-process calculator `eval`.
  - Both were previously adjudicated as capability misclassification rather than
    host process execution.

No Google ADK finding changed.

## Attack paths

The exact path delta is:

- prior first-class-framework paths: **7**
- post-cleanup paths: **5**
- removed: **2**
- added: **0**

Both removed paths are the already-adjudicated PharmIQ bootstrap false positives:

- PATH001 — untrusted input -> MCP startup -> process execution
- PATH006 — untrusted input -> process execution + secrets read

The four ADK Pipeline Reviewer paths and the one materially-supported Pydantic path
remain unchanged.

## Interpretation

Removing LangGraph was not merely a reporting-scope change. It removed hidden
LangGraph/LangChain-oriented production semantics that were leaking false authority
into Pydantic/OpenAI cases.

For the exact frozen first-class-framework cohort, materially-supported precision moves
from **56/70 = 80.0%** to **56/61 = 91.8%** without removing a previously supported
claim.

This supports the product decision to make HorusTrace agent-centric around:

- Google ADK
- Pydantic AI
- OpenAI Agents SDK

Framework-neutral MCP/tool discovery remains useful as inventory, but security
authority should require a supported or otherwise source-proven agent binding.

## Caveat

This is an apples-to-apples regression/generalization rerun of the same frozen 12
repositories, not a new unseen cohort. The next validation step should therefore be a
new unseen cohort restricted to these three first-class frameworks after the remaining
systematic semantic defects are addressed.
