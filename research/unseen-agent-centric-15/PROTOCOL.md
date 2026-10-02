# Unseen agent-centric 15 — protocol

## Purpose

Measure out-of-sample semantic fidelity for HorusTrace after the agent-centric scope
change and PR #295 residual-fidelity fixes.

The only first-class agent frameworks in this study are:

- Google ADK
- Pydantic AI
- OpenAI Agents SDK

LangGraph is outside product scope and is not a cohort stratum. Generic MCP/tool
inventory may still appear when it is used by one of the three supported agent
frameworks.

## Cohort controls

- 15 repositories total: exactly 5 per supported framework.
- Repositories were selected by GitHub framework signatures and source-semantic
  diversity, not by HorusTrace findings.
- Each repository is frozen at the current default-branch commit recorded in
  `cohort.json`.
- Repository names were checked against the HorusTrace repository to exclude prior
  study cohorts and known regression fixtures.
- No repository may be replaced because its scan is sparse, noisy or inconvenient.
- Selection and exact SHAs are committed before any HorusTrace execution.

## Evaluation order

1. **Freeze cohort** — complete before scanner execution.
2. **Blind source review** — inspect source without HorusTrace output and record the
   important effective-agent authority expected for each case, including material
   controls and scope qualifications.
3. **Scanner reveal** — run the post-#295 scanner against the exact frozen SHAs.
4. **Claim precision adjudication** — adjudicate every emitted finding/path against
   source using the calibrated #288/#290 effective-authority rubric.
5. **Recall comparison** — compare the blind source-review claims against HorusTrace
   output and classify full / partial / missed.
6. **Framework and defect taxonomy** — aggregate by framework and systematic failure
   class. Do not patch scanner code until the study result is frozen.

## Effective-authority rubric

The study carries forward the calibrated rubric:

- inventory/existence is not effective agent authority;
- an unbound tool is not agent-reachable authority;
- application/bootstrap process execution is not model-callable process authority;
- fixed, operator-configured or provider-managed destinations are not arbitrary
  model-selected egress;
- provider sandboxing, fixed executable/command scope, filesystem containment,
  approval/HITL, guardrails and runtime/source blockers are material qualifications;
- local/session/test state is not automatically external real-world impact;
- delegation authority must preserve the child agent/tool scope rather than flatten
  it into unconstrained parent authority.

## Primary metrics

Precision:
- strict TP precision;
- materially-supported precision = TP + partial / all claims;
- explicit FP rate;
- attack-path supported precision.

Recall:
- blind source claims fully matched;
- partially matched;
- missed;
- high-value path coverage.

Report both raw and framework-level metrics. A high frozen-cohort result from #295 is a
regression baseline only; it is not used as a prior for adjudicating this unseen set.

## Scanner baseline

The scanner under evaluation is current `main` after merged PR #295. The exact scanner
commit used by the workflow must be recorded in the final report.

## Stop-the-line rule

If a scanner execution or study harness defect occurs, repair only the harness or
serialization needed to obtain valid output. Do not make semantic scanner fixes during
the study. Semantic defects become the next product queue after the result is frozen.
