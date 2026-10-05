# Full-framework 60 repository study

## Purpose

Evaluate HorusTrace current `main` end to end across six supported framework families, using **10 unique public repositories per family**:

- Google ADK
- Pydantic AI
- OpenAI Agents SDK
- Amazon Strands / AgentCore
- Anthropic Claude Agent SDK / Managed Agents
- Microsoft Agent Framework / Agent 365 / M365 Agents / GitHub Copilot SDK

This is a full security-analysis study, not a Skill-only study and not a detector-count benchmark.

## Frozen baseline

- cohort lock: 2026-10-05
- scanner baseline: `76351e075807e66b248d341198c6057bf6c7f1bc` (current main after PR #390)
- 60 unique repositories
- exact upstream commit SHA per repository
- 10 repositories per framework family

The cohort is assembled from earlier source-screened/frozen studies. Current-main HorusTrace output was not used to select cases. Because some repositories have been used in earlier studies, framework results are evidence of current correctness/regression resistance; they are not all independent unseen-generalisation estimates.

## Evidence captured per repository

Each case retains:

1. bounded source pack for independent source review;
2. normal scan JSON and all findings;
3. security graph and attack paths;
4. Effective Authority report and relationships;
5. Authority Contract assessment;
6. normalized agent/tool/MCP/Skill/identity inventory;
7. unresolved/unbound Skill inventory;
8. coverage diagnostics;
9. scan assurance output, including policy/OWASP views where emitted.

## Adjudication dimensions

Every repository is reviewed for:

- true agent/principal inventory;
- model/tool/MCP/Skill binding;
- delegated/multi-agent authority;
- process, filesystem, data, network and destructive effects;
- identity and credential evidence;
- resource and destination scope/provenance;
- approval/guardrail/control fidelity;
- Effective Authority completeness;
- finding precision and missed material findings;
- attack-path correctness;
- unresolved/dynamic authority treatment;
- Authority Contract / organisation-policy / OWASP reporting correctness.

## Finding classification

Source review uses four scanner-alignment outcomes:

- **full match** — material source security fact is represented with correct principal, authority and security meaning;
- **partial match** — risk is detected but loses material scope/provenance/control/topology semantics;
- **miss** — material source-supported security fact is absent;
- **unsupported** — scanner finding materially overstates or contradicts source evidence.

Ambiguous or runtime-only facts are marked **unresolved** rather than forced into true/false.

## Error taxonomy

Root causes are assigned to one primary layer:

`discovery → binding → repository composition → authority projection → control semantics → deterministic rule → attack path → reporting`

LLM Skill semantic analysis is separately evaluated where Skills are present. Semantic intent alone is never treated as proof of runtime authority.

## Reporting

Results are reported both per framework and across the full 60-repository cohort. Raw finding counts are not accuracy metrics. Final conclusions are based on source-grounded adjudication and explicitly distinguish known regression sentinels from stronger generalisation evidence.
