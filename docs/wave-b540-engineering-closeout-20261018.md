# Wave B source-pilot closeout decision — 18 October 2026

**Decision: Wave B source-pilot engineering package is ready for bounded
closeout only. Overall security-accuracy release is NO-GO. Wave C production
Graph/ADG cutover is NO-GO.**

This distinguishes completing a fixed source-pilot investigation from
certifying scanner precision, deployed authorization, security findings,
or reachable attack paths. Closing engineering tasks must not become
a dashboard claim of production-ready agent security.

## Completed source-backed Wave B work

- Wave-A 30-case semantic survival study and current 145 non-LangGraph
  source-identity differential were completed. Current scanner completed
  145/145 cases, historical scanner 144/145 common older rw-177 symlink
  failure, with structural +104/-11 agent-site deltas. These were not
  measured true positives or false negatives.
- Five targeted source pilots: Pharmiq 22 local tool exposures, Microsoft
  two configured dynamic MCP servers with unknown runtime catalogues,
  Couchbase 53 conditional ToolSet registration candidates in a
  provider-only case, Amazon ten constructor sites and nine orchestrator
  composition candidates, and LinkedIn 124 source MCP contexts
  (121 test/3 runtime-source). Source-declared exposures are separate
  from agent callability and *effective* permissions.
- WAB-05 ADG now exposes source_context and deployment_verified=false
  on source-only MCP edges; no test-only tools are silently certified as
  runtime service permissions.
- Microsoft AGT032 configured URL provenance is exact per server and does
  not claim verified deployed tool-allowlist absence; Pharmiq CAP005 without
  separate read and write witnesses remains POTENTIAL, not a proven
  exercised capability combination.
- Three bounded FastAgent source-negative cases rw-001, rw-002, rw-003
  distinguish app factories, custom agent decorators and workflow nodes.
  ADK rw-004 identifies two source constructors but also alias, runner,
  model Client and Pydantic nonagents. The second constructor has an
  unresolved SDK import binding; it is not an independently proven FN.
- 73 model-reviewed historical Amazon claims retain 45 conditional
  source-supported, 16 invalid historical anchors, **12 unresolved
  installed dependency, dynamic MCP tool and runtime approval/effect**
  claims. No runtime test was fabricated.

The validated scanner `src/horustrace` Git tree SHA is
`7c1ce9fb257f85b7de1c4dc10bd7475fc96cdd16` at the last
full cohort-validation commit
`3b3aca87eb6e27859b4708d5564bc64513670841`.
Subsequent source-only acceptance work has retained exactly the same
scanner implementation. The closeout CI asserts the Git tree identity
on its own current head and fails closed if this ever changes. This
does not substitute for validating changes elsewhere that affect
execution or evaluation contracts.

## Outstanding items and hard release barriers

| Requirement | State | Proper destination |
|---|---|---|
| Five pilot source-witness and negative/unknown mechanisms | Source evidence complete, bounded by static scope | Close Wave B investigation with explicit caveats |
| Active145 V2 independent closed-world positive/negative oracle | **0 certified complete V2 negative-universe cases**; original truth 89 incomplete, 1 incompatible, 55 not V2-adjudicated | Wave C C02 research/independent ground truth, block production cutover |
| Source traceable effective authority, finding/path TP/FP/FN | Partial case-level deltas; deployment/executability not independently proven | Wave C C03/C04 production differential, require rollback |
| 12 Amazon third-party runtime effect/control claims | UNKNOWN on pinned public source; installed versions, tool schemas and permissions absent | Explicit runtime attestation requirement or non-certified release scope |
| Stable accuracy-regression-gate mandatory in Protect main | Must query live GitHub ruleset ID 23823545; historically absent | #558 administrator update and red/stale PR test, mandatory before production cutover |
| Final release approval | NO-GO until above met | #543 controlled Wave C plan; never claim source-pilot completion = production GO |

## Exact acceptance and governance

The archive Frozen180 and the non-LangGraph active145 scope stay intact.
Do not lower the six original numeric thresholds, silently redefine
positives, count unresolved runtime tool catalogues as empty, or rewrite
frozen historical truth to inflate V2 metrics.

The closeout job enforces the original source ledger witness counts, the
12-unknown model crosswalk, the active145 reference completeness statuses,
and the last fully validated scanner source-tree SHA. It reads the
**live active main branch-protection ruleset**, preserving existing core
required checks while stating if `accuracy-regression-gate` is not
enforced. A passing closeout job certifies **bounded evidence integrity**,
not full scanner accuracy.

Wave C's research/design planning can proceed; any production canonical
Graph/ADG migration or security release remains gated on #558 and the
new source-negative/reference studies. A source-only uncertainty that
cannot be resolved without user-controlled runtime evidence must remain
explicitly unresolved, not be silently closed as true or false.
