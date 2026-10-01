# Post-#284/#285 hybrid adjudication

## Scope

This report records the completed 30-repository post-#281/#283 hybrid rerun (#284,
workflow run `36845071044`) and the independent LLM adjudication (#285, workflow
run `36851385919`). The three pinned cohorts were frozen-litmus, unseen-v2, and
framework-holdout (10 repositories each).

#285 used a separate Copilot evaluator. Each repository received: (1) claim
adjudication against source for every HorusTrace finding/path, (2) a blind source
review that did not see HorusTrace output, and (3) matching of that blind review
back to HorusTrace.

## #284 rerun

Across all 30 repositories:

| Metric | Deterministic | Hybrid |
|---|---:|---:|
| Findings | 79 | 91 |
| Attack paths | 14 | 14 |

Relative to the earlier pre-P0 hybrid study, finding inflation fell from +25 to +12
and attack-path inflation fell from +3 to 0.

On the frozen cohort specifically, the same 23 semantic calls changed from
40 -> 52 findings and 10 -> 13 paths before #283 to 40 -> 42 findings and
10 -> 10 paths after #283/#281. This is evidence that constraint-preserving
semantic projection improved precision rather than simply reducing escalation.

#281 also recovered the two former zero-candidate framework cases: ho-001 now
resolves the higher-order ADK MCP factory, and ho-002 now discovers custom
BaseAgent instances and semantic entrypoints. The ho-002 dynamic RiskGuard/A2A
destination flow is still not composed.

## #285 finding precision

The evaluator adjudicated 89 HorusTrace findings:

| Verdict | Count |
|---|---:|
| true_positive | 14 |
| partial | 67 |
| false_positive | 3 |
| unresolved | 5 |

Treating TP + partial as materially source-supported gives 81/84 resolved claims
(96.4%). "Partial" generally means the core issue is present but a material
qualification such as principal, scope, runtime condition, sandbox, auth,
approval state, or destination provenance is incomplete.

The three explicit false positives are:

1. `rw-007 / DATA001`: reports `resources=*` without source support for broad
   resource scope.
2. `hold-adk-003 / NET001`: describes an operator-configured MCP URL as a
   caller-selected destination.
3. `hold-adk-005 / NET002`: reports no destination constraint despite fixed
   OpenAPI server origins.

All three are deterministic findings; none was introduced by hybrid LLM
enrichment.

Path adjudication produced 1 TP, 11 partial, 0 false positives, and 2 unresolved.

For findings the evaluator could unambiguously tag as hybrid-only, it reported
2 TP, 6 partial, 0 false positives, and 1 unresolved. The remaining concern is
`rw-155`: CAP004 is only partially supported because external network authority
is source-backed but the combined process-execution authority is not; CAP005 is
unresolved because combined read/write authority is not established.

## Blind false-negative pass

The fresh blind reviewer returned 18 partial finding matches and 11 misses, plus
1 full/8 partial/19 missed paths. These raw counts are not authoritative recall
metrics.

Several fresh "misses" conflict with the earlier locked reviews or expand outside
the intended effective-agent-authority scope (for example generic deployment
credentials, application-only unauthenticated endpoints, provider-side image URL
fetching, or CI/workflow risks). The fresh blind reviewer also failed to
rediscover some previously locked gaps.

The project therefore treats locked source reviews as regression truth and fresh
LLM reviews as discrepancy discovery. Disagreements require source adjudication
before scanner semantics change.

## Confirmed P0 precision work

1. Fix DATA001 broad-resource overclaim in rw-007.
2. Preserve operator-configured MCP provenance in NET001.
3. Preserve fixed OpenAPI server origins so NET002 does not claim unconstrained
   egress.
4. Gate synthetic-projection CAP004/CAP005 on source-supported combined effective
   authority.
5. Exclude framework dependency/context objects such as Pydantic RunContext from
   model-selected filesystem selector inference unless a concrete
   model-controlled field is traced.
6. Deduplicate repeated CAP005 for the same effective principal/authority bundle.

## Confirmed path/recall work after P0

1. ho-002: task payload -> custom BaseAgent -> RiskGuard/A2A helper ->
   A2ACardResolver dynamic destination.
2. ho-005: model-selected Box file/folder IDs -> effective Box content authority.
3. ho-009: CLI -> factory-created Pydantic agent -> console toolset ->
   process/filesystem authority.
4. hold-pyd-004: cross-file CLI ingress -> budget agent -> mutation/destructive
   tools.
5. Improve generic ADK root-input -> source-bound privileged-write composition
   where framework invocation semantics provide a source-supported edge.

## Decision

Keep the hybrid architecture: deterministic graph discovery/composition, bounded
LLM semantic resolution, source-visible constraints and uncertainty preserved,
and deterministic HorusTrace rules/path logic as the security adjudicator.

Do not increase LLM budgets yet. The next gains should come from deterministic
precision and path composition. After those tranches, rerun this 30-repository
regression set and then use a fresh unseen cohort for generalization evidence.
