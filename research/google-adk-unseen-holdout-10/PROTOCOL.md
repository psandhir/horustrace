# Google ADK unseen holdout 10

## Purpose

Test whether the Google ADK depth-parity result generalizes beyond the frozen canonical suite to real repository composition.

This cohort was selected entirely from source before HorusTrace execution. The cases are pinned to exact upstream SHAs and must not be changed in response to scanner output.

## Baseline

- scanner baseline: `1be194c94b3b643f2c8d081e5fa14e6643eb3a9f`
- canonical Google ADK depth suite: 15/15 passing, 9/9 invariants at 100%
- target cases: 10
- unique repositories: 9
- source selection used HorusTrace output: no

## What this cohort stresses

- factory-returned and async-factory agents
- custom `BaseAgent` subclasses
- repository-local helper-built tools and MCP toolsets
- dynamic tool/MCP registries that must remain visible as unresolved authority
- subagent and AgentTool delegation
- SkillToolset and unsafe local execution
- callbacks/plugins and A2A exposure
- database and cloud resource effects
- MCP transport/auth/tool-scope provenance

## Interpretation

Raw agent, finding, relationship and path counts are not accuracy scores.

Source adjudication must answer:

1. Was every material application-level ADK principal discovered?
2. Did explicit model-callable authority remain bound?
3. Did delegation and MCP survive into effective authority?
4. Did source-visible read/write/process/network/destructive effects survive?
5. Were dynamic constructs retained with uncertainty instead of silently dropped?
6. Were controls preserved without being overstated?
7. Were fixed/operator/model-selected resources and destinations distinguished?
8. Did HorusTrace invent authority unsupported by source?

A runtime-only catalogue does not need to be enumerated. The required conservative result is a source-proven relationship with the unresolved dimension made explicit.

## Freeze rule

Any scanner fixes discovered by this study must be made separately. This cohort, target SHAs, application paths and source signals remain unchanged for post-fix reruns.
