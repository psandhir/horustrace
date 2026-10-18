# Wave B — V2 agent truth eligibility, not merely historical completeness

**Date:** 18 October 2026. Frozen original 180-case source evidence remains
immutable; active set is 145 non-LangGraph cases. No original release
thresholds change.

## Denominator issue

The historical reference explicitly marks **56/145 active cases agent
complete**, and **89/145 incomplete**. That completeness flag describes the
older reference method and the older ontology; it is **not** a certification
that the labels are valid V2 individual-agent entities, or that a
scanner-blind negative-labelled universe exists.

The post-hoc pinned source proof merged as #600 demonstrates that
`rw-001`, one of the *56 supposedly agent-complete cases*, has **six
source-positive factory-as-agent labels** that conflict with the V2 ontology.
A `FastAgent(...)` *application factory* is not an individual
`@fast.agent` declaration. The exact six Git blobs also show eight valid
decorated agent source declarations and two commented-out decorators that
do not execute. This source review is **post-hoc**, not independently blind,
and must not rewrite any original truth.

The second and third FastAgent cases `rw-002` (#599) and `rw-003`
(#598) already belong among the 89 *historically incomplete* cases:
their source corrections do not make their whole repositories complete.
Across the remaining original cases, the reference has **no explicit
absent assertions**, so neither the 55 historically complete but
unreviewed V2 cases nor the 89 incomplete cases may be promoted to
an exhaustive true-negative denominator.

## Audited active-145 disposition

| State | Cases | V2 complete-negative accuracy eligible |
|---|---:|---|
| Historical agent reference incomplete | 89 | No |
| Historically complete, known V2 ontology-incompatible | 1 (`rw-001`) | No |
| Historically complete, not independently V2-adjudicated | 55 | Not yet |
| Independently labelled full V2 negative universe | **0 established** | None certified |

**Zero established** means lack of independently completed V2 negative
reference adjudication. It does *not* mean there are no true positives,
no correct scanner detections, or that all historical source labels are
wrong. The original historical source reference still contains useful
source-positive facts.

`scripts/audit_wave_b540_v2_oracle_eligibility.py` joins all 180 exact
pinned source truth records, uses the original completeness audit, verifies
the original six `rw-001` factory-as-agent claim records and unchanged
pinned source SHA, and outputs all 145 cases with explicit eligibility
statuses, scoped reasons and known post-hoc proof references. It fails
closed if known conflicts disappear, source references change, or a
new negative assertion appears without re-adjudication. All new precision
and recall values stay NULL, and Wave B/Wave C GO remain false.

## Actual exit conditions

An independent or explicitly methodologically isolated V2 reference
requires **positive and hard-negative** labels for agents, agent
instances, workflows, tools, MCP export candidates, executable
`AGENT_CAN_CALL` edges, identity, effective permissions, controls,
findings and attack paths, at precise source revisions and construct
locations, with a scoped *negative denominator*. Runtime-dependent
claims must remain unknown unless their installed package and live
permission evidence is obtained; notably the 12 Amazon third-party
effects under #593. Build a separate new V2 oracle rather than editing
the old Frozen-180 archive. The #558 GitHub main ruleset still needs
`accuracy-regression-gate` enforced as a required stable check.

This is an integrity gate, not an accuracy score. No Wave C production
cutover is justified by a green diagnostic study alone.
