# Wave B #540 — current scanner on locked Frozen-180 source reference

**Date:** 17 October 2026. **Purpose:** quantitative *structural* regression study, **not Wave B GO**.

## Active evaluation scope: non-LangGraph 145 (user decision, 17 October 2026)

The user has removed the **LangGraph framework stratum** from the current active Wave B study scope. Of the original 180 pinned repositories, exactly **35** are LangGraph and **145** are in scope. This is an explicit **framework-level product/evaluation-scope change**, not a claim that previous LangGraph misses were fixed. LangGraph remains visible in the archived full-180 diagnostic only; we do not delete or change any source truth or prior score.

The completed [original 180-case run](https://github.com/psandhir/horustrace/actions/runs/39037652771) and artifact `12102694714` remain archived and unchanged. **New study runs scan only 145 non-LangGraph repositories**, and generate the **primary active** `non-langgraph-145-{baseline,candidate,delta,semantic-parity}.json` and `non-langgraph-145-delta.md` from the exact 145-case scanner output and original pinned 180-case historical baseline. Both sides are reaggregated on the identical 145 pinned case IDs, not by subtracting rounded aggregate scores. Original reference completeness rules are unchanged. The historical v0.9 LangGraph-agent/tool-specific gates are explicitly excluded from the active policy; **all other six original numeric thresholds and source semantics are preserved**. The seven-case semantic set loses only the six assertions for LangGraph `rw-058`; remaining **17 semantic assertions across six cases** are still reported with no adjustment to pass criteria.

**Preliminary filtered read of the already completed 180-case run** (historical baseline → current candidate, *before CI verification of the committed scope script*): agent precision **96.19% → 77.21%**, agent recall **73.52% → 81.61%**, tool recall **29.70% → 76.69%**, and effective-authority recall **61.11% → 84.73%**. The agent-precision problem remains despite the LangGraph exclusion. New non-LangGraph timeouts `rw-002` and `rw-085`, ADK/Pydantic false-positive adjudication and conditional claim validity remain substantive blockers. Neither the GitHub execution-success status nor the scope change constitutes Wave B accuracy acceptance.


The earlier 2026 Real-World Agent Security study froze 180 exact-revision repositories and
two-pass automated source references before the historical baseline scanner executed.
The original scanner is `418db4e29798a7d25df686dd7bccfd9fefa225bd`.
The 180-case cohort/review sources and historical results are retained unmodified
under `research/real-world-agent-security-2026`.

The present workflow scans the **PR's exact verified checkout HEAD** against the **145 non-LangGraph pinned source SHA/application roots**, using the original `real_world_agent_security_execute.py` harness with opt-in `--exclude-framework langgraph` and `--mode postfix`. It reaggregates original baseline case-level results for the same 145 cases using `real_world_agent_security_non_langgraph.py`, then evaluates six unchanged applicable thresholds and six-case semantic benchmark (17 assertions). No excluded target is scanned in an active scoped run. It does **not** install or execute any target
repository or use credentials. Workflow outputs are uploaded as artifacts, with
no mutation of frozen truth, cohort or baseline.

## What this can and cannot prove

- Frozen reference totals: **180 source-pinned cases**, 2,091 assertions,
  692 explicit agents, 1,115 tools, 22 MCP servers and 85 delegation edges.
  **72** cases have explicitly complete agent-entity source labels; other
  dimensions have heterogeneous/partial completeness.
- An agent precision denominator is defensible only for cases and dimensions
  whose source reference was marked complete. A missing reference elsewhere is
  **not** automatically a false-positive scanner claim.
- Reference labels were assembled by **two automated source passes**. This is
  source-before-scanner *methodological separation*, but **not a new unseen or
  independent human-blinded holdout**. Historical source reference data may
  have been consulted during subsequent product engineering.
- This panel does not establish actual deployment, live authority, successful
  tool execution, security exploitation, attack path precision/recall or
  independent human correctness.
- Avoid extrapolating source-observation coverage to effective permission
  inheritance. Unknown dynamic remote catalogues, approval and unpinned
  external tool implementations remain UNKNOWN.
- The exact-current scanner **may fail existing benchmark thresholds**. A red
  result is an investigation task, never grounds to edit frozen truth, reduce
  cohort size, lower floors, or rename lost source claims without evidence.
- The previous frozen scan's precision/recall were limited to completeness
  marked dimensions; the output must retain this scope. Existing benchmark
  metrics are **not** a substitute for per-instance source-path adjudication
  required by #551.

## Pre-registered workflow integrity

Workflow `.github/workflows/wave-b540-frozen180-source-truth.yml` checks:
original frozen 180 case count, exact reference scanner SHA, 72 agent-complete labels and original source pins; scanned candidate SHA via `git rev-parse HEAD`; selected 145 exact pinned, non-LangGraph case IDs; no omitted in-scope case, no wrong source repo/framework/SHA, no reused baseline subset/denominator. It publishes new 145-case scanner and source-differential artifacts without altering the archived 180-case truth. It does not weaken CI/Fresh-16/Full-60.

The workflow is a separately named diagnostic to avoid placing three hours of
full 180-case work into every small scanner PR. Any **production scanner source
change** retains the existing complete Fresh-16 and Full-60 quality gates.
The manually administered same-head accuracy branch rule (#558) is separate.

## Wave B acceptance relation

This panel provides an old-reference vs new-scanner structural delta on
the full historical source-locked cohort and a separately explicit **non-LangGraph 145** active evaluation. LangGraph is out of active scope, not retroactively corrected. MCP/custom, ADK, OpenAI Agents, Pydantic AI and FastAgent remain in scope. It **does not itself close** #540.

Still needed for full #540:
1. Current-main source-to-graph equality and regression reconciliation against
   all WAB-01–05 merged proof ledgers (#579, #580), not just aggregate counts;
2. Independent or methodologically isolated *new* negative-labelled per-instance
   and high-severity claim review, including 12 unresolved historic Amazon
   imported-tool/control assertions;
3. Reconciliation of #578 Claude SDK default/approval and dynamic registry
   semantics so no unproven runtime catalogue/tool-bound edge yields a fully
   resolved claim;
4. Approval/identity/destination runtime UNKNOWN states, no fabricated
   `AGENT_CAN_CALL` or attack path;
5. #558 admin enforcement of stable same-head gate and final current-main
   Fresh-16, Full-60, Wave-A-30 and Amazon unseen-10 evidence.

**Decision before results and source-claim signoff: Wave B release NO-GO,
#551 draft, #543 production cutover blocked.**
