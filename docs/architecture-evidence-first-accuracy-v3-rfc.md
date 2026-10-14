# RFC: Evidence-first accuracy architecture v3 (14 October 2026)

**Status:** Proposed design / review only. This RFC changes **no scanner behavior**.
**Goal:** Production-worthy accuracy in agent/skill/tool/MCP/model inventory, exact binding and delegation relationships, effective authority, findings and attack-path detection **across supported frameworks**.

This extends [Architecture Foundations v2](architecture-foundations-v2.md), not a replacement of its typed metadata, ADG/ASG, graph integrity, proof envelopes or existing frozen studies. Use existing [independent-study evaluation contract](../research/STUDY_EVALUATION_CONTRACT.md) G0–G3 to judge success. Do not mark this design implemented because its RFC CI checks pass.

## Architectural conclusion

The core *security concepts* are sound: deterministic parsing -> normalized graph -> data flow / effective authority -> security rules and paths -> reports. **The producer/linking architecture needs redesign.**

Today:
- Framework adapters typically emit the final public `Graph` directly; `adapters/registry.py:scan_python_file` concatenates those graphs. `semantic_discovery.py` already has typed provisional entities/bindings and their `PROVEN/PARTIAL/UNRESOLVED` states, but it is **not yet the required primary interface** for every adapter.
- `scanner.py:_scan` contains many ordered, mutating repository-wide enrichers, repeated agent consolidations, inferred MCP bindings, delegation propagation and input/flow annotators. A count delta is hard to attribute to a unique originating observation, linker rule and pass version.
- `Graph.agents[*].tools/mcp_servers/skills` encode bindings as list membership. `effective_authority_relationships` iterates these lists; the ADG and ASG project them afterward. An incorrect attachment therefore propagates into authority, risk and UI.
- `Agent.capabilities` aggregates capabilities of all bound tools/skills/MCP and inputs separately; without precise execution roles (bootstrap/declared/model-callable), object/instance identity and control/effect qualifiers, downstream compositions can overstate authority.
- `flow.py` is explicitly a bounded Python source-to-sink analyzer rather than arbitrary cross-language interprocedural taint analysis. `analysis.py` mixes proved static flows, source-backed authority reachability and co-occurrence potential paths. Its existing proof envelope is useful and must be preserved.
- `pipeline_contract.py` records ordered diagnostics, but is observational and does not gate normal scans. This is not a bad default for a research scanner, but production quality gates must operate on **semantic source assertions**, not only counts or graph well-formedness.
- Stable IDs are not completely portable: issue #528 demonstrates a notebook temp-directory path leaked into an effective-authority key.

These are observed code structures and documented study discrepancies, not newly measured precision/recall.

## Evidence indicating where to focus

1. Original Fresh-20 source review found 24 TP, 35 partial, 23 FP among 82 findings, and 0 full TP / 5 partial / 2 FP among 7 paths. This was a **single claim-visible reviewer**, not independent human ground truth or a blind recall estimate. See `research/fresh-unseen-generalization-20/ADJUDICATION_REPORT.md`. Key failure modes: provider/fixed destination represented as unconstrained egress, MCP server startup treated as agent execution authority, internal state mistaken for external writes, insufficient HITL/guardrail qualification, wrong bound/unbound attribution.
2. Frozen Fresh-16 76 -> 49 finding change had 32 exact-identity unmatched claims (16 historical FPs, 14 partial, 2 historical TPs), with case-level source reconciliation. See `research/source-claim-regression/legacy-fresh16-review-20261010.md`. **Net count reduction is not an FN denominator.**
3. Full-60 Amazon/Microsoft 20-case review had 141 findings, 0 attack paths; four representative source cases indicated unresolved ingress, user-controlled inputs gated by controls, fixed literal agent input and per-command grant constraints. See `research/source-claim-regression/full60-amazon-microsoft-path-source-review-20261010.md`. Do not manufacture paths to meet count quotas.
4. Fresh-16 paired LLM study #526 selected 25 model calls and all failed due to quota; equal graph/finding/path counts do not establish LLM parity. Issue #527.
5. Existing metamorphic issue #511 is closed and protects simple alias/parameter/helper transformations. It does **not** cover all Python dynamic binding, other languages, long agent-to-tool-to-MCP chains or a blind repository-level recall denominator.

## Reference architectures: adopt principles, not their engines wholesale

| Open source | Relevant design | HorusScan adaptation | Not a substitute for |
| --- | --- | --- | --- |
| [Syft](https://oss.anchore.com/docs/architecture/syft/) / [cdxgen](https://github.com/cdxgen/cdxgen) | Independent file/package catalogers; declared versus installed components; reusable CycloneDX inventory | Inventory catalogers with explicit file scope, provenance and role. Optional dependency/MCP cross-check imported as **declarations**, not assumed authority | Agent binding, tool callability, IAM, dynamic paths |
| [Joern](https://docs.joern.io/code-property-graph/) | Typed layered code-property graph with AST, call/data/control flow and overlays | Introduce reusable program-symbol and relationship IR, preserve source edges and typed overlays, stable IDs and queryable evidence | Immediate mandatory Neo4j/Joern replacement |
| [CodeQL](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/) | Separate local/global data flow and taint; scoped source/sink queries and barriers | Pilot offline comparison/oracle for *selected source-to-sink chains*; add bounded cross-file summaries, control barriers and explicit unresolved branches | Agent/MCP-specific security semantics; zero-cost production dependency without evaluation |
| [garak](https://github.com/NVIDIA/garak) / [PyRIT](https://microsoft.github.io/PyRIT/latest/code/framework/) / [promptfoo](https://www.promptfoo.dev/docs/red-team/architecture/) | Independent probes/test inputs, execution, scoring, replay | Reuse evaluation contracts (#510), metamorphic transforms (#511), independent scorer work (#512), evidence ledgers (#513) | Static inventory graph construction and effective-authority inference |

Do not adopt a graph database, new generic IR dependency or wholesale parser replacement without an accuracy/latency benefit demonstrated on pinned blind source.

## Target design

```text
Source snapshot (repo SHA, first-party roots, config, deployment/IaC)
  |
  v
File catalogers / parsers (framework, MCP, Skill, manifest, IaC)
  |   emit immutable, source-anchored observations
  v
Observation IR v2: declarations, instances, control/flow constructs,
                  role, evidence, context, certainty, unresolved references
  |
  v
Repository-wide symbol/object linker (imports, aliases, factories, wrappers,
  calls, MCP catalogs, client sessions, runtime registration, delegation)
  |   typed entity & edge IDs; never guess ambiguity away
  v
Evidence-backed Agent Security Graph
  +-- inventory and Agent BOM projection
  +-- exact bindings/permissions and authority dimensions
  +-- ingress, sink, provenance and control-aware flow summaries
  |
  v
Proof-graded security queries -> findings, attack-path candidates, diagnostics
  |
  v
Source assertions + independent adjudication + releases + UX drilldowns
```

### Required contracts

- **Observations:** `Observation(id, source_sha, source_path, span, parser_id/version, framework, declared_kind, role, attrs, evidence)`. Stable repository-relative source and semantic identifiers; no temporary notebook filenames in public IDs.
- **Typed relationships:** `Binding(id, from_entity, to_entity, kind, confidence={proven,partial,unresolved}, source_spans, origin, conditions, source_context, resolution_reason)`. Examples: `DECLARES`, `REGISTERS`, `EXPOSES_TOOL`, `AGENT_CAN_CALL`, `DELEGATES_TO`, `READS_FROM`, `USES_IDENTITY`, `GUARDED_BY`, `SENDS_TO`. Do not infer `AGENT_CAN_CALL` from `EXPOSES_TOOL`.
- **Entity identities:** Name is *not* object identity. Distinguish same-name agents, object instances, factory returns, tool registration, imported aliases, models, sessions and server declarations. Preserve aliases as additional references, not merged capability unions.
- **Execution roles:** `runtime_agent`, `model_callable_tool`, `registered_external_tool`, `mcp_server_bootstrap`, `package_declaration`, `test_fixture`, `example`, `infrastructure_control`, etc. Unknown role stays unknown.
- **Effects:** Structured `(verb, resource, destination, target_control, identity, scope, impact, effect_origin)`, distinguishing `subprocess fixed argv` vs free command, sandboxed eval vs host OS execution, internal state vs persisted write, model-selected domain vs fixed/provider/operator endpoint.
- **Controls:** Represent *declaration*, *enforcement proof*, *scope*, *applies-to binding*, *runtime verification* independently. Model an approval/check as a potential barrier only if it applies to the actual path; treat unknown enforcement as unresolved, not disabled.
- **Uncertainty:** Preserve `proven`, `partial`, `unresolved` at entity and edge level. An unresolved edge is not silently true or false. Explain unresolved reference, required missing evidence and analysis budget.
- **Claims:** A finding or path is a query result with IDs of each supporting entity/edge/control and original source spans. Proof tiers remain `static_dataflow`, `authority_reachability`, `source_backed_pattern`, `capability_combination`; **none** means exploit proven. Co-occurrence must not be shown as a source-to-sink trace.
- **Projection compatibility:** Keep public `Graph`, ADG/ASG, AIBOM, SARIF, OWASP and Workbench contracts stable initially. Build shadow v2 linkage and compare against old graph before moving framework groups over.

## Ordered PR plan

**P0.0 — Baseline source truth pack, zero scanner behavior changes**
- Freeze representative current pinned repositories by framework, language, context and risk; add positive **and negative** source-anchored assertions for every node/edge type, binding/effect/control/path edge case.
- Include known failures: fixed PyPI host vs model-selected URL; env-placeholder vs literal secret; provider-managed web tool; MCP server bootstrap vs callable server; test-only URL; in-memory update vs persistent write; same-name agent instances; fixed command vs shell string; handoff with scoped control; Strands CLI to agent; Microsoft command grant; notebook stable IDs.
- Distinguish source-adjudicated reference from independent human ground truth; new blind holdout G0–G3 to follow. Publish uncovered source slices and unknown counts.

**P0.1 — Observation IR + stable identities and lineage**
- Extend existing `semantic_discovery`, do not start a competing schema. Have one pilot adapter emit immutable observations and v1 Graph in parallel.
- Canonical source IDs, stable notebook / import / alias keys (#528), exact provenance/role; assert no unattached or invented edges; preserve unbound inventory.
- No performance regression beyond an agreed measured threshold; no changes in protected claims without adjudication.

**P0.2 — Shared repository linker**
- Make one cross-file source-symbol/call/registration index reusable by ADK, Pydantic, OpenAI and MCP adapters; support bounded alias, import, constructor, factory, wrapper, decorator, `add_tool`, `MCPServer`, runtime registration and delegation cases.
- Link `agent -> client MCP server -> exposed tool` only with supporting consumer binding; retain server-only inventory independently. Unknown dynamic dispatch remains unresolved.
- Add metamorphic and source-driven positives and near-miss negatives for each supported construct; account for every regression.

**P0.3 — Authority/effect/control fidelity**
- Resolve permissions and capabilities per *proven binding*, carrying actor identity, reachable effect, destination source, resource, execution scope and applicable approval/guardrail checks. Separate configuration hygiene observations from agent-exploitable authority.
- Unit/regression tests for fixed/operator/provider destinations, subprocess constraints, internal versus external effects, MCP startup, permission callbacks, multiagent handoffs and manifest-vs-source conflicts.
- No finding claims elevated merely because a field is missing or unknown.

**P1.0 — Control-aware flow and path queries**
- Compose `untrusted entry -> reachable agent/dispatcher -> callable tool/MCP/skill -> concrete sink -> scope/control` using a bounded interprocedural graph query. Preserve proven/possible/unresolved paths and distinguish source-to-sink dataflow from authority reachability and co-occurrence.
- Pilot CodeQL as independent Python flow oracle on selected frozen cases; only integrate a dependency if measured improvement warrants it. Pilot Tree-sitter on TS/C# (already proposed in v2), not all languages at once.
- Deliberately include **negative** fixed query, denied-grant, sandbox-only, test-only and unrelated-server paths.

**P1.1 — Findings and report contract**
- Rules consume typed proof/authority claims, not raw graph presence. Deduplicate *logical* security condition only after attribution; preserve individual evidence links and multiple distinct contexts.
- Report `confirmed source-supported` / `qualified` / `possible` / `unresolved`, counts by stage, source context, proof basis, effective authority, runtime not-verified. Default UX keeps unbound/inactive components discoverable but visually differentiated.
- Optional LLM enrichment feeds proposed observations requiring source-grounded validation; not rule adjudication. Defer SIWC (#530) until needed.

**P1.2 — Release gate and scored blind validation**
- Complete/integrate existing independent scorer (#512) and replay ledger (#513); do not duplicate #510/#511.
- Same pinned SHAs, blind source-only candidates before scanner reveal, multi-reviewer disagreement and FN/FP tracking as in `STUDY_EVALUATION_CONTRACT.md`.
- Require a paired source-specific delta table for every PR that changes a construct; measure latency, coverage and unresolved percentage. Claim neither accuracy improvement nor regression from count alone.

## Proposed production gates (targets, NOT achieved performance)

For declared **in-scope, statically decidable constructs**, ratify thresholds after a blind baseline:
- **Entity inventory**: precision and recall >= 95% macro across framework strata; no unsupported model/skill/MCP declarations promoted to bound authority.
- **Binding/relationship edges**: precision >= 97%, recall >= 90% on source-adjudicated decidable links; unresolved and dynamic cases counted separately, not as correct negatives.
- **Effective authority**: >= 95% accuracy on independently judged actor/tool/operation/resource/destination/control qualification assertions; zero unqualified bootstrap-to-authority promotions.
- **Critical/high findings**: >= 90% supported precision on independently adjudicated strata; no high/critical rule released with a known unresolved systematic FP mode.
- **Source-supported path templates**: >= 90% recall for explicitly covered positive chains and >= 95% precision on the source-adjudicated emitted path sample. **No paths upgraded to full data-flow proof from co-occurrence or LLM confidence alone.**
- **Reproducibility**: same-source double-scan normalized graph/authority/finding digests equal; no temp paths; 100% of released findings/paths carry reconstructible source anchors.
- **Safety/performance**: 100% incomplete source analysis diagnosed, bounded memory/cpu budgets, 0 unreviewed changes in protected source-claim inventory. Report confidence intervals and sample sizes, not single percentages alone.

These are candidate release gates and must be calibrated for sufficiently large, newly sampled cohorts. No denominator means **not assessed**, not perfect recall. Component coverage must be segmented by framework × language × construct × source context.

## Decisions and non-goals

1. **Do not rewrite all framework adapters or ADG at once.** Use a shadow adapter/graph migration with equality and counterexample tests; cut over only after proved improvement.
2. **Do not import CodeQL/Joern/Neo4j as a mandatory production runtime now.** Prototype restricted oracle comparisons first.
3. **Do not optimize to count more findings or paths.** Optimize independently supported source claims and explainability, with unresolved measurements.
4. **Do not resume Plus/Sign in with ChatGPT or make production scans dependent on LLM subscriptions.** LLM analysis is an optional, separately evaluated layer.
5. **Do not call the product production-grade merely because CI/code coverage is green.** A source-blind G2/G3 independent-quality gate is mandatory for that assertion.

## Reconciliation with earlier HorusScan design decisions (October 2026)

This is an **execution gap reconciliation**, not a new independent architecture proposal. Prior conversation tracks already agreed on these invariants:

1. **Cross-framework output must use controlled semantics, never private metadata dialects** (Oct 6–7: the `enforcing_tool_control` vs `tool_control_enforcing` regression). [#409](https://github.com/psandhir/horustrace/pull/409) corrected canonical writers/readers; [#414](https://github.com/psandhir/horustrace/pull/414) added six-framework invariants; [#426](https://github.com/psandhir/horustrace/pull/426), [#427](https://github.com/psandhir/horustrace/pull/427) and [#455](https://github.com/psandhir/horustrace/pull/455) extended model/data provenance. **Merged.** Keep and expand this contract; do not introduce a competing semantics vocabulary in IR v2.
2. **Source behavior wins over names and generic heuristics** (prior fresh unseen generalization and Oct 6 findings audit). [#322](https://github.com/psandhir/horustrace/pull/322) stopped arithmetic `add` => persistent write, business `execute` => host process, and mock calls => egress. **Merged.** A central effect-semantic evaluator still needs structured roles, sinks, side effects and identity/resource/destination scope, applied across languages. Do not restart broad method-name rules.
3. **Repository composition must be cross-file and source-instance-specific** (Oct 5–10 agent/tool/delegation audits). [#397](https://github.com/psandhir/horustrace/pull/397) added factories/comprehensions/MCP transport/Strands workflow; [#473](https://github.com/psandhir/horustrace/pull/473) prevented same-name transitive agent authority contamination; [#488](https://github.com/psandhir/horustrace/pull/488) added source-qualifiable remote AgentCore delegation. **Merged**, but procedural per-framework implementations remain. New shared linker must use these as acceptance fixtures and migrate, not replace without comparison.
4. **Catalog existence, binding, authority and runtime effect are different states** (Oct 5 Skill construct review, Oct 9 AI-BOM, Oct 10 MCP/OWASP/supply chain). [#382](https://github.com/psandhir/horustrace/pull/382) made Skills first-class including unresolved catalogues; [#476](https://github.com/psandhir/horustrace/pull/476) scoped unbound MCP configuration findings independently of runtime authority; [#506](https://github.com/psandhir/horustrace/pull/506) emitted `EXPOSES_TOOL` edges without fictional `AGENT_CAN_CALL`. [#423](https://github.com/psandhir/horustrace/pull/423) provides CycloneDX export, not extraction truth. **Merged.** [#459](https://github.com/psandhir/horustrace/pull/459) cdxgen comparison was research-only and **closed unmerged**; do not claim an established external component-discovery advantage until its source observations are independently reviewed.
5. **Provenance must be attached to the individual claim/path, not copied agent-wide** (Oct 10, repeated 55-fact displays). [#495](https://github.com/psandhir/horustrace/pull/495) changed presentation and [#497](https://github.com/psandhir/horustrace/pull/497) fixed source attribution. **Merged.** The next step is claims carrying exact typed edge/source-span IDs *by construction*, so UX needn't infer provenance after findings are produced.
6. **Unknowns, source context and proof category remain first-class** (Oct 8–11 attack-path reviews, P1.2). [#468](https://github.com/psandhir/horustrace/pull/468) added per-agent authority completeness; [#503](https://github.com/psandhir/horustrace/pull/503) stage contracts and proof envelopes; [#504](https://github.com/psandhir/horustrace/pull/504) fail-closed study integrity; [#505](https://github.com/psandhir/horustrace/pull/505) stopped C# default parameters being agents and marked factory templates. **Merged.** [#524](https://github.com/psandhir/horustrace/pull/524) still proposes separate non-runtime path candidates (open draft), and [#528](https://github.com/psandhir/horustrace/issues/528) records nondeterministic notebook paths (open). Address these existing items explicitly before designing new path/ID systems.
7. **Graph topology is canonical; the UI must traverse rather than reconstruct it** (Oct 10–11 OWASP, MCP inventory, supply-chain drilldown). [#501](https://github.com/psandhir/horustrace/pull/501), [#502](https://github.com/psandhir/horustrace/pull/502) and [#508](https://github.com/psandhir/horustrace/pull/508) are merged; [#523](https://github.com/psandhir/horustrace/pull/523) remains an **open** usability fix to show all nodes and defocus unrelated edges, not discard them. Correct the graph producer before changing visualization semantics, and complete #523 separately from detection architecture.
8. **Evaluate semantics, not raw finding/path counts** (Oct 8 source-first LLM comparison; Oct 9 Fresh-16 76→46 and Full-60 24→15; Oct 10 product assessment). [#450](https://github.com/psandhir/horustrace/pull/450) established source-only LLM reviewer contract; [#477](https://github.com/psandhir/horustrace/pull/477)/[#481](https://github.com/psandhir/horustrace/pull/481) preserve adjudicated claims; [#519](https://github.com/psandhir/horustrace/pull/519), [#520](https://github.com/psandhir/horustrace/pull/520), [#521](https://github.com/psandhir/horustrace/pull/521), [#522](https://github.com/psandhir/horustrace/pull/522) delivered evaluation data contracts, metamorphic variants, offline scorers and tamper-evident replay. **Merged.** [#525](https://github.com/psandhir/horustrace/pull/525) is **open draft** for claim lineage/blind-calibration hooks. #512/#513 open issue state reflects remaining real-source, blinded validation/ledger integrations, not absence of the merged MVP implementations. Do **not** rebuild these foundations.
9. **LLM enrichment is optional and must be measured independently** (Oct 5 Skill intent calibration; Oct 11 Fresh-16 hybrid quota). [#388](https://github.com/psandhir/horustrace/pull/388)/[#389](https://github.com/psandhir/horustrace/pull/389) tested Skill semantic intent on calibration/holdout, but chat adjudication is not a live scanner provider. [#526](https://github.com/psandhir/horustrace/pull/526) documented 25 failed calls, and [#527](https://github.com/psandhir/horustrace/issues/527) requires LLM fail-open transparency. The local ChatGPT-plan PR [#529](https://github.com/psandhir/horustrace/pull/529) is **parked**. Static accuracy redesign must not depend on its completion.
10. **Coding style changes must preserve semantics or become explicit unresolved coverage** (Oct 5 general coding styles and Oct 10 PyRIT/garak/promptfoo design). [#520](https://github.com/psandhir/horustrace/pull/520) already added eight metamorphic families and strict near-miss negatives. Extend beyond bounded Python imports and local methods only after measuring lost semantic claims; do not overfit one syntactic spelling.

### Legacy decisions that must not be silently overwritten

| Existing safeguard | Why preserve | Remaining gap |
| --- | --- | --- |
| [#414](https://github.com/psandhir/horustrace/pull/414), [#426](https://github.com/psandhir/horustrace/pull/426), [#427](https://github.com/psandhir/horustrace/pull/427) shared semantic contracts | Prevent producer/consumer metadata drift | Typed observation schemas and all-framework contract compliance |
| [#473](https://github.com/psandhir/horustrace/pull/473) instance-safe delegation | Prevent cross-agent authority leakage | Shared cross-file alias/instance/index linker |
| [#382](https://github.com/psandhir/horustrace/pull/382), [#476](https://github.com/psandhir/horustrace/pull/476), [#506](https://github.com/psandhir/horustrace/pull/506) declarations ≠ authority | Prevent false effective tool and MCP access | Coverage and recall of actual caller/server/tool links |
| [#495](https://github.com/psandhir/horustrace/pull/495), [#497](https://github.com/psandhir/horustrace/pull/497) source-local evidence | Avoid 55 unrelated facts on every finding | Native evidence-edge provenance in all claims |
| [#503](https://github.com/psandhir/horustrace/pull/503), [#504](https://github.com/psandhir/horustrace/pull/504) checkpoints | Detect structural regression | Stage-level semantic lineage and quality-specific release gates |
| [#519](https://github.com/psandhir/horustrace/pull/519)–[#522](https://github.com/psandhir/horustrace/pull/522) evaluation foundation | Repeatable model-free regression/scoring/replay | Blind adjudicated real-world precision/recall and release enforcement |

### Updated execution order (do not duplicate past merged work)

**0. Consolidate the queue first:** Review open [#523](https://github.com/psandhir/horustrace/pull/523) (UX only), [#524](https://github.com/psandhir/horustrace/pull/524) (source-backed non-runtime path candidates), [#525](https://github.com/psandhir/horustrace/pull/525) (semantic claim lineage), and existing issues [#527](https://github.com/psandhir/horustrace/issues/527), [#528](https://github.com/psandhir/horustrace/issues/528). Decide merge/rebase/close independently; do not fold UI work into linker construction. `#529` remains parked at user request.

**1. Baseline the *existing* graph pipeline:** Instrument entity/edge/fact lineage at the existing checkpoint boundaries without changing detection. Pin source-grounded positives and negatives from #322, #397, #473, #476, #505, #506, #520 and #524. Produce a per-stage `discovered -> linked -> authority -> path -> rule` **survival matrix** for each case showing exactly what is created, lost, merged, reclassified or unresolved, with source spans. Compare both Fresh-16 and representative Full-60 framework cases.

**2. Pilot one Observation IR producer and shadow linker:** Extend existing `semantic_discovery.py` rather than invent a second IR; preserve `Graph`, ADG/ASG and #409/#414 contracts. Choose an OpenAI Agents/Pydantic/MCP mixed example exercising imported tool factory, client MCP session and same-name agent instance. Publish old vs shadow semantic edge multiset and discrepancies.

**3. Migrate high-value binding/effect work only after evidence:** Implement shared symbol resolution and exact `agent -> tool/MCP -> exposed tool` linkage with no unproven edges, plus structured source-effect/control qualification. Require negative tests for fixed/provider endpoints, sandboxed process capability, bootstrap-vs-callable split and in-memory state updates. The success metric is **reduced source-adjudicated error**, not more edges.

**4. Extend control-aware paths and reporting:** Reuse #503 proof taxonomy, #524 non-runtime candidates, #497 per-claim provenance and the canonical ADG source. Preserve `unresolved` when reachability, controls or runtime evidence are missing. Separate uncertain possibilities from supported paths and runtime-verified observations.

**5. Enforce the existing evaluation infrastructure:** Use the already-merged #519–#522 data/scoring/ledger system plus [G0–G3](../research/STUDY_EVALUATION_CONTRACT.md) for independent source-only reference construction, two-judge disagreement handling, case-level TP/FP/FN/TN calibration and a blind holdout. If a study is only a scanner run or a mocked scorer check, label it G1/synthetic, not production readiness.

**Stop/go:** Don't widen to all frameworks until a pilot shows fewer adjudicated misbindings and false qualified authority assertions, no unexplained loss of known true source bindings, stable portable IDs and acceptable runtime overhead.

## Concrete go/no-go checkpoint

Before P0.2 implementation, publish the frozen source assertion ledger, first adapter IR shadow comparison and initial misbinding taxonomy on the same 16 cases. If the shared linker proposal cannot reduce *verified* relationship errors relative to current main without damaging protected claims, change the design rather than scaling it across frameworks.

**Reference issues:** #509 evaluation epic; #510/#511 completed evaluation foundations; #512 scorer; #513 replay ledger; #514 LLM grounding; #527 LLM availability; #528 portable notebook IDs. **Reference architecture:** [v2](architecture-foundations-v2.md).
