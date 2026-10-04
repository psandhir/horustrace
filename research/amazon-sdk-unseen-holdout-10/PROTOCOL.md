# Amazon SDK unseen holdout 10

## Purpose

Test whether the canonical Amazon SDK depth-parity result generalizes beyond synthetic constructs to real repository composition.

This cohort was selected entirely from source before HorusTrace execution. The cases are pinned to exact upstream SHAs and must not be changed in response to scanner output.

## Baseline

- scanner baseline: `1c3aac96851f2fe9856eaf858d7c2ffac0e46784`
- canonical Amazon depth suite: 15/15 passing, 9/9 invariants at 100%
- target cases: 10
- unique repositories: 10
- source selection used HorusTrace output: no

## What this cohort stresses

- Strands agents created in methods/classes rather than module-level assignments
- helper/factory-built tool collections
- dynamically listed MCP catalogues from fixed and runtime-configured endpoints
- direct agents-as-tools and nested agents
- high-authority vended shell/file/AWS tools
- source-defined hook/HITL enforcement
- AgentCore memory/session/runtime composition
- Swarm and Graph construction from runtime/cross-file agent collections
- conditional tool binding
- repository-local AWS/DevOps tools

## Interpretation

Raw agent, finding, relationship and path counts are not accuracy scores.

Source adjudication must answer:

1. Was every material application-level Strands/AgentCore principal represented?
2. Did explicit model-callable authority remain bound?
3. Did direct delegation, Graph, Swarm and MCP survive into Effective Authority?
4. Did source-visible AWS/network/process/filesystem/read/write/destructive effects survive?
5. Were runtime catalogues/endpoints/member sets retained with uncertainty instead of silently dropped?
6. Were hooks/approval/consent controls preserved without being overstated?
7. Were fixed/operator/runtime-selected resources and destinations distinguished?
8. Did HorusTrace invent authority unsupported by source?

A runtime-only tool or remote-agent catalogue does not need to be enumerated. The required conservative result is a source-proven binding with unresolved dimensions explicit.

## Freeze rule

Any scanner fixes discovered by this study must be made separately. This cohort, target SHAs, application paths and source signals remain unchanged for post-fix reruns.
