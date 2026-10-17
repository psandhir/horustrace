# Wave B #540 / #551 — 17 October source-claim closure checkpoint

**Disposition: evidence updated; NO-GO for independent truth / Wave C.**
This is a model-assisted source review, **not independent human adjudication**, a measured
precision/recall study, a runtime exploit test, or a request to weaken a gate.
Historical model-review claim keys and **current** scanner result fingerprints are
different identity spaces and must not be counted interchangeably.

## Reproducible current candidate (unmerged #578)

- Scanner PR head: `43a122cb7c5d5b141c7b0b0066042b50fd6b380a`; base main was
  `3965f75407858ea8cb63f5cf4113455e1772ae3f`. #578 remains **draft**.
- [Full-60 39032559714](https://github.com/psandhir/horustrace/actions/runs/39032559714):
  60/60, scanner errors 0; aggregate artifact **12101445391**,
  `regression_gate.passed=true`, 540/715=75.5245% **core** fully-resolved
  authority (threshold unchanged at 75%), 509 findings, 26 **potential** paths.
  Eight potential paths are blocked by source errors, and none is runtime-validated.
- [Fresh-16 39032559734](https://github.com/psandhir/horustrace/actions/runs/39032559734):
  16/16, artifact **12101346187**, 48 findings and five *potential* paths.
- [Amazon unseen-10 39032559688](https://github.com/psandhir/horustrace/actions/runs/39032559688):
  10/10, aggregate artifact **12100584621**, 37 agents, 179 authority
  relationships (all 179 *detail*-partially resolved), 106 findings, zero
  generated paths. These are **not independently labelled TP/FP/FN counts**.
- Python 3.11/3.12 CI, same-head accuracy, CodeQL, Claude-12, and all six
  framework parity suites passed at this exact head. Cohort pass is necessary
  but **not** source-truth release certification.

### Immutable WAB-04 application witness, current candidate

Case `amazon-hold-004` is
`aws-samples/sample-multi-agent-region-expansion-planner@30d03d7c9f6512e5bf10601879382fac9c3a16b1`,
application root `src`; exact current case artifact **12100901464**
from Amazon unseen-10 run **39032559688**.
Current result: **10** constructor agents, **52** authority relationships,
**68** source-conditional heuristic findings, **zero** published paths.
The **52/52** edges have `runtime_effectiveness=not_verified`,
identity and approval *detail* dimensions `unknown`, and detail
`partially_resolved` (different from core status: **38 core-fully-resolved,
14 core-partially-resolved**). This distinction prevents mistaking a
core-resolved binding for resolved credentials/approval.

Current findings: AGT020=5, AGT021=4, AGT040=28, AGT050=3,
CAP003=4, CAP004=5, CAP005=10, NET002=9 (18 high / 50 medium).
**68/68** result findings now have at least one `provenance` record.
There are **182 inferred and 37 observed provenance facts** across those
findings. A provenance record with `origin=inferred` is **not**
third-party implementation truth, and the counts must not be compared
uncritically with the historic 65/68 *raw structured provenance* gap
(earlier scanner schema/run). The current 68 findings retain
source-conditional/runtime-not-verified limitations.

Pinned independent repository source:
- [`src/main.py:15,52–60`](https://github.com/aws-samples/sample-multi-agent-region-expansion-planner/blob/30d03d7c9f6512e5bf10601879382fac9c3a16b1/src/main.py):
  constructs `common_tools+agents` for an orchestrator. Tool references in
  a constructed list are **not evidence that every wrapper is invoked**.
- [`src/agents/__init__.py:9–21`](https://github.com/aws-samples/sample-multi-agent-region-expansion-planner/blob/30d03d7c9f6512e5bf10601879382fac9c3a16b1/src/agents/__init__.py):
  explicitly imports `compare_regional_pricing` but puts the name
  `pricing_explorer` in `__all__`, without defining a same-named
  callable; `from agents import pricing_explorer` can be the
  **module**, not the decorated function. Current scanner conservatively
  represents orchestrator→`pricing_explorer` as an
  `unresolved_bound_symbol` / `dynamic_tool_collection`, **not**
  an independently verified callable. WAB-04 hard-negative fixture exists
  on draft #551: `tests/test_wave_b540_strands_module_negative.py`.
- [`requirements.txt`](https://github.com/aws-samples/sample-multi-agent-region-expansion-planner/blob/30d03d7c9f6512e5bf10601879382fac9c3a16b1/requirements.txt)
  declares `strands-agents-tools` **without a version constraint**.
  [`src/agents/pricing_explorer.py:69–92`](https://github.com/aws-samples/sample-multi-agent-region-expansion-planner/blob/30d03d7c9f6512e5bf10601879382fac9c3a16b1/src/agents/pricing_explorer.py)
  configures `awslabs.aws-pricing-mcp-server@latest`,
  `list_tools_sync()`, adds imported `strands_tools` tools and conditionally
  constructs/invokes the nested agent. This is a **source-positive**
  conditional binding, **not** an immutable tool implementation, enumerated
  MCP catalogue, known runtime AWS effect, installed permission policy,
  or a verified outbound destination.

## Exact twelve historically unresolved high/medium model-review claims

Claim hashes below refer to the frozen historical `ff60-amazon-04`
73-key model-judge differential accepted by #554/#551; they **must not**
be silently mapped to new `arg-v1` result fingerprints.

| Priority | Rule | Historical claim hash | Source-associated question still UNKNOWN |
|---|---|---|---|
| High | CAP004 | `0de03732933c171d96b4` | Exact per-instance joint process.execute + network.external effects |
| High | AGT020 | `34e0345cd816a7b394f5` | Imported `python_repl` process effect and approval for installed package |
| High | CAP003 | `391d0a5e8be35376802b` | Exact four-effect capability bundle through external tool implementations |
| High | CAP003 | `e9eccd96b25d7aac2746` | Distinct four-effect source/effective witness for second instance |
| Medium | AGT040 | `d3388fd929c8794bfce6` | Installed `python_repl` scope/approval inside pricing_explorer |
| Medium | NET002 | `1cd6188f31f7ae6ae9ae` | report_writer conditional destination/write effects |
| Medium | NET002 | `2ad096fe63994b320f70` | planning_report_generator dynamic MCP / AWS effect |
| Medium | NET002 | `36830b3ae86117942e1e` | multi_region_expansion_planner dynamic MCP / AWS effect |
| Medium | NET002 | `84724ebc1b42818721ea` | tech_analysis conditional external effects |
| Medium | NET002 | `9a644fee027e44fe2bd5` | cfn_explorer dynamic MCP / AWS effect |
| Medium | NET002 | `ae7e4aadfa7c31e34044` | cloudtrail_explorer conditional AWS effect |
| Medium | NET002 | `f37bdf0d899c7565a374` | pricing_explorer `@latest` MCP / AWS effect |

**Pin-level positives and negatives.** `pricing_explorer.py:26,69–92`
source-proves an imported symbol and dynamically constructed tool list;
`report_writer.py:17,60–83` binds imported shell/filesystem tools and
invokes a nested Agent in its callable body; `cfn_explorer.py:67–95`,
`planning_report_generator.py:78–107`, and
`multi_region_expansion_planner.py:80–107` dynamically retrieve MCP
catalogues. These sources **do not** prove an installed `strands_tools`
release, effective invocation policy, successful live AWS permissions,
actual outbound transfer, or guaranteed execution of deferred wrappers.
Older upstream `strands-agents/tools@1dd0465da8a748b0e8ac87ec5b3485bccb60d70e`
`python_repl`, `use_aws` and `file_write` implementations have been
inspected in #566–567, but **cannot be asserted as the unpinned application
version**; consent/guard conditions are runtime-dependent. No claim above
is newly promoted to source-confirmed TP, FP or runtime-exploitable.

## Remaining acceptance actions / blockers

1. Secure **immutable installed dependency identity** (package lock,
   resolver metadata or build artifact) for `strands-agents-tools` and
   each `awslabs.*-mcp-server@latest`; without this, close claims as
   explicitly **unresolvable under pinned-source-only scope**, not false.
2. Run separately version-pinned source-contract positive and hard-negative
   fixtures for `python_repl`, `shell`, `file_write`, `use_aws`,
   `MCPClient.list_tools_sync`, and conditional approval; distinguish
   source-declared capability, tool availability, per-invocation approval,
   actual effect and observed runtime access.
3. Independently label per-instance and per-finding **negative** source
   universe (not just scanner positives); reconcile the 73 changed historical
   claim keys and the 12 UNKNOWN against versioned provenance, with no
   invented precision/recall denominators.
4. Complete #540 WAB-01–05 edge ledgers and #551 acceptance dossier,
   including suppressed non-runtime paths and low-coverage controls.
   Gate #558 requires an administrator to add stable
   `accuracy-regression-gate` to `Protect main` (ruleset 23823545)
   and verify fail-closed blocking on a deliberately red PR.
5. Retain #578 as draft until signed release acceptance; once accepted,
   merge exact green head, rerun cohorts on **merged main SHA**, then
   consider Wave C #543. The 17-Oct CI green result is **not Wave C GO**.
