# Wave B #540 — current scanner on locked Frozen-180 source reference

**Date:** 17 October 2026. **Purpose:** quantitative *structural* regression study, **not Wave B GO**.

The earlier 2026 Real-World Agent Security study froze 180 exact-revision repositories and
two-pass automated source references before the historical baseline scanner executed.
The original scanner is `418db4e29798a7d25df686dd7bccfd9fefa225bd`.
The 180-case cohort/review sources and historical results are retained unmodified
under `research/real-world-agent-security-2026`.

The present workflow scans the **PR's exact verified checkout HEAD** against the same
source SHA and application roots using the existing `real_world_agent_security_execute.py`
harness, `--mode postfix`. It scores both versions against the same locked
source references using the existing, separately versioned comparison script and
the prior post-hoc semantic benchmark. It does **not** install or execute any target
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
frozen 180 case count and exact original scanner reference, 72 explicitly
agent-complete cases and all per-case repository pins; scanned candidate SHA
via `git rev-parse HEAD`; source-locked runner and a same-case differential
against `results/frozen-baseline.json`; preserved output and comparison
artifacts even if a later step fails. It does not weaken CI/Fresh-16/Full-60.

The workflow is a separately named diagnostic to avoid placing three hours of
full 180-case work into every small scanner PR. Any **production scanner source
change** retains the existing complete Fresh-16 and Full-60 quality gates.
The manually administered same-head accuracy branch rule (#558) is separate.

## Wave B acceptance relation

This panel provides an old-reference vs new-scanner structural delta on
the largest source-locked cohort, especially historically poor LangGraph and
MCP/custom recall. It **does not itself close** #540.

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
