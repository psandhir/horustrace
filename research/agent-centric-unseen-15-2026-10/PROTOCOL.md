# Fresh agent-centric unseen 15 — protocol

## Objective

Measure generalization of HorusTrace after the agent-centric scope cleanup and residual-fidelity fixes, restricted to the three first-class frameworks:

- Google ADK
- Pydantic AI
- OpenAI Agents SDK

The study is designed to measure **blind source recall** and **claim precision** separately.

## Freeze and leakage controls

1. The 15 repositories and exact commit SHAs in `cohort.json` are frozen before any HorusTrace execution.
2. Selection used public source signatures and architecture diversity only.
3. HorusTrace output was not used to select, replace, or reject a case.
4. 215 repositories already present in prior project studies were excluded before selection.
5. No case may be replaced because HorusTrace output is sparse, noisy, inconvenient, or surprising.
6. LangGraph is outside product scope and is not a cohort stratum.

## Two-stage evaluation

### Stage A — blind source review

The source-only workflow clones each pinned repository and emits a source pack and file manifest. It does **not** install or invoke HorusTrace.

Before scanner reveal, each case receives a source review recording:

- effective agents and binding relationships;
- model-callable tools/MCP/delegated agents;
- effective capabilities;
- resource and destination scope;
- approval/guardrail/sandbox qualifications;
- source-supported security claims;
- source-supported attack paths;
- explicit negative controls / things that must **not** be claimed;
- evidence paths and confidence.

The blind review files are committed before Stage B.

### Stage B — scanner reveal

Only after Stage A is persisted do we add/run the HorusTrace scan workflow at the frozen scanner commit. Evaluation then computes:

- claim precision: TP / partial / FP;
- materially-supported precision: (TP + partial) / emitted claims;
- blind recall over preregistered source claims;
- blind path recall over preregistered source-supported paths;
- framework-level breakdown;
- failure taxonomy;
- negative-control violations.

## Adjudication standard

Use the calibrated effective-authority rubric from #288/#290/#294:

- existence is not effective agent authority;
- unbound inventory is not agent-reachable authority;
- bootstrap/configuration is not model-callable execution;
- fixed/operator/provider destinations are not caller-selected unrestricted egress;
- in-process helpers are not privileged external actions without a concrete sink;
- sandbox, approval, HITL, resource scope, runtime viability and source context must be preserved;
- delegated/handoff authority is included only when the binding is source-proven;
- test/example claims retain their source context and do not silently represent production runtime.

## Reporting

Do not compare this study's precision directly to the tuned 53/53 frozen-cohort figure as if they were equivalent populations. The primary question is whether those framework-level invariants generalize to unseen source.
