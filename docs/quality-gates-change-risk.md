# HorusScan quality gates by risk of change

**Operating decision — 16 October 2026:** Keep full Fresh-16 and Full-60
cohorts on EVERY production scanner source change. A small code diff can change
cross-framework node identity, tools, source contexts, authority, finding
provenance and attack paths. Faster CI is not a justification for weaker gates.

## Required evidence

| Scope / change | Minimum validation |
| --- | --- |
| Documentation or unrelated tests | Always-on core CI: Python 3.11 and 3.12, branch coverage >=82%, lint, package, self-scan, CodeQL. Applicable documentation/source contract tests. |
| Report UX | Core CI, real-browser report smoke, component/OWASP/graph drill-down and provenance tests. Add scanner cohorts if findings or Graph representations change. |
| Any production source file under src/horustrace | **Core CI + complete Fresh-16 and Full-60**, aggregate artifact and case-integrity proof. Keep all 76 cases even on source-local parser and adapter fixes. Add pinned positive and hard-negative source assertions for the affected framework. |
| Shared semantic discovery, Graph, rules, capabilities, identities, controls, authority or attack paths | All production-source checks plus affected framework depth/holdout suites, meaningful before/after source-qualified inventory and finding/path comparisons, and specific negative controls. |
| Evaluation harness, frozen cohort, truth labels or comparator | Full affected frozen replay, source-pin and manifest integrity, explicit baseline-change adjudication, missing-case and negative-label checks. Never automatically rebaseline on count changes. |
| Wave B GO / Wave C production migration / release | Full current-head cohorts, Wave-A stage survival, relevant unseen holdouts, evidence-backed per-instance/per-tool claims, independent or methodologically isolated positive AND negative truth, unresolved-risk disposition, effective-authority semantics, regression reconciliation and rollback. Explicit documented GO/NO-GO decision. |

**Always classify by semantic impact, not by the number of lines changed.**
Tests are evidence of repeatability and invariants; model-adjudicated source
claims alone cannot establish independent precision/recall or runtime authority.

## Workflow and branch-protection audit

- The GitHub Actions Full-60 workflow has 60 case jobs, one preparation job
  and one aggregation job. Fresh-16 has 16 case jobs plus an aggregate.
  The many checks on PR #556 were intentional and appropriate.
- Both cohorts run for changes to src/horustrace/**; tests in
  tests/test_accuracy_ci_gate_contract.py protect this trigger breadth and
  the completion/aggregation contract against accidental changes.
- Main is protected by repository ruleset **Protect main** (ID 23823545).
  Strict required statuses are package, test (3.11), test (3.12),
  self-scan and analyze. GitHub requires the up-to-date head.
- **Enforcement gap:** neither the Fresh-16 nor the Full-60 aggregate is
  currently included in that ruleset. They run automatically but branch
  protection alone does not ensure they passed before merge. An authorized
  merger must inspect their exact-current-head conclusions and source
  evidence. Do not confuse a scheduled job with an enforced merge check.

## Additional hardening needed (without reducing coverage)

Create an always-emitted, fail-closed regression status that, on scanner or
security-contract changes, waits for the **same-head** Fresh-16 and Full-60
aggregate and rejects failures, missing runs, partial artifact manifests,
cancellation and stale checks. On truly non-scanner PRs, that check can prove
the scope is not applicable. Add its stable context to the protected-main
ruleset, and verify rejection on a deliberately failing regression PR.

**Do not add the current path-filtered cohort job contexts as mandatory
without an always-emitted fallback.** They are absent for documentation-only
PRs and could indefinitely block unrelated changes. The connected GitHub
integration can read but not administer this protected ruleset, so the
ruleset itself remains unchanged in this PR.

## Merge discipline until hardening is enforced

1. Identify the affected scanner/Graph/authority contract and required cohort.
2. Confirm exact PR head SHA is current with main and all five required
   statuses are green.
3. For scanner changes, confirm Fresh-16 AND Full-60 workflow aggregate
   success, all expected cases and artifacts; check pinned source-specific
   proof and newly introduced hard negatives.
4. Review any source-level change in agents, tools, MCP servers, skills,
   identities, resources, controls, finding claims or attack paths. Mark
   unresolved facts UNKNOWN, never silently infer runtime callability.
5. Keep Wave B NO-GO and Wave C cutover blocked until the source-backed
   acceptance gate is satisfied. A green workflow is necessary but not a
   substitute for signed source-truth evidence.

For subsequent automation, a successful GitHub merge is NOT proof that
all optional cohorts ran; check each relevant workflow before merging.
