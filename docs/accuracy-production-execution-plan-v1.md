# HorusScan production-accuracy execution plan — v1

**Proposed 14 October 2026. Status: planning only; no implementation acceptance has occurred.**  
**Parent:** [Evidence-first Architecture v3 RFC](architecture-evidence-first-accuracy-v3-rfc.md) / PR #531.  
**Priority:** accurate **inventory -> bindings -> effective authority -> findings -> attack paths**.  
**Decision rule:** source-adjudicated semantic correctness outranks graph, finding and path counts.

This plan consolidates previous HorusScan decisions and merged implementation. It **does not** assume historical reviewer labels are independent ground truth, and does **not** reopen the parked ChatGPT-plan work.

## 0. What is already built, and what is genuinely missing?

| Reuse as-is / enhance, not rewrite | Verified scope | Missing capability for production |
| --- | --- | --- |
| Canonical cross-framework semantics: #409, #414, #426, #427, #455 | Tool controls, model/data provenance and adapter conformance | Uniform typed observation and linker interface for every framework |
| Source-behaviour effects: #322, #465, #476, #478 | Some name false positives and fixed/provider egress distinctions corrected | Per-binding typed effect/role/impact constraints, across languages |
| Repository composition and instance-safe delegation: #397, #473, #488 | Several targeted cross-file factories, handoffs and remote AgentCore cases | One reusable resolution index with deterministic precedence and ambiguity semantics |
| Skills/MCP/ADG: #382, #423, #476, #501, #506 | Skills and declarative MCP exposure represented; CycloneDX is **export** | Completeness of `agent -> MCP client -> server -> exposed tool` and Skills bindings |
| Finding provenance: #495/#497 | Finding-scoped evidence digest | Typed observation/edge IDs referenced directly by each claim |
| Stage/proof/coverage: #468, #503, #504, #505 | Stage-order/graph-contract checks; proof categories; nonruntime classification | *Per-construct* stage lineage and independent quality gates |
| Evaluation: #450, #477/#481, #519–#522 | Source-review schema, protected-claim regression, metamorphic tests, scoring and tamper-evident ledger | Blinded, independent real-source TP/FP/FN/TN denominators and reproducible stage-delta analysis |

**Open work disposition on planning date:**
- **#523** graph defocus/component click UX: keep separate. Validate and merge/close independently; it is not a detection-accuracy dependency.
- **#524** non-runtime source-supported attack-path candidates: preserve and evaluate as a proposed additive projection; reconcile against the new path-state contract *before* integrating overlapping code.
- **#525** source-pinned claim lineage and blind calibration hook: reuse for initial reference ledger after source/CI review; do not recreate its capability.
- **#527** LLM request failures: preserve as diagnostics work, but optional LLM integration is **not** a blocker for deterministic accuracy.
- **#528** temporary notebook path in authority semantics: make the portable-ID requirement part of phase A.
- **#526** deterministic-vs-hybrid study: evidence only; 25/25 failed Copilot quota calls do **not** demonstrate LLM enrichment parity.
- **#529** user-controlled ChatGPT-plan auth: **parked** at user request. No API/plan login dependency in this plan.
- **#531** architecture RFC: this plan is an implementation annex; remain draft until contracts and gates are reviewed.

## 1. Scope and dependency rules

**Core in-scope constructs:** Agent, runtime vs factory/template agent, workflow/control node, Tool, MCP client/server/exposed tool, Skill/catalogue, model, identity, input/entrypoint, resource, destination, control, delegation, data and authority flow, finding and attack-path proof. Distinguish standalone/server-only inventory from agent-bound runtime surfaces.

**Framework cohorts:** Google ADK, Pydantic AI, OpenAI Agents, Amazon Strands/AgentCore, Anthropic Claude Agent SDK/Managed Agents, Microsoft Agent Framework/Foundry, standalone MCP/custom, and Skill-bearing repositories. Track framework × language (Python/TypeScript/C#) × runtime/example/test × construct. LangGraph is historically excluded from active Fresh-16; handle any future coverage as an explicitly scoped product decision, not silent inclusion.

**Constraints:**
- Deterministic static-first default; never execute scanned third-party repositories or MCP tools.
- Preserve source evidence and **do not invent** a model, identity, permission, destination, runtime binding, control enforcement or dynamic delegation target.
- Keep public Graph/ADG/ASG/AI-BOM/rules/SARIF/Workbench backward compatible until validated shadow cutover.
- Use existing `semantic_discovery.py` and `semantic_contract.py` as the migration starting point. Avoid a second conflicting intermediate representation.
- Frozen SHAs, app roots and source contexts must stay fixed; a truly unseen release holdout must be selected **before** exposing scanner outputs and held out from remediation.
- Every scanner-affecting PR adds positives, hard negatives, per-case lineage and before/after metrics. Normal CI + exact-SHA Fresh-16 + Full-60 run is necessary, **not sufficient**.
- No PR is promoted because finding/path/node counts increase, all jobs turn green, or a model agrees with itself.

## 2. Quality measurement: six denominators, not one count

Maintain an **assertion ledger** with `case_id`, `repo_sha`, `app_root`, `source_file/line/range`, `language/framework`, `construct/relationship/effect/path kind`, `expected semantic claim`, `review status`, `evidence digest`, and `source context`. Record known and unknown reference coverage. Reviewers cannot see scanner output during independent Phase A.

| Layer | Positive unit | Negative / qualifier unit | Quality readout |
| --- | --- | --- | --- |
| Inventory | Source-supported unique declaration/instance/model/MCP/Skill | Decoy import, mere parameter/factory template, duplicate, unsupported file | Entity precision/recall by kind, framework, language and runtime scope |
| Relationships | Source-supported exact directed typed edge between *instances* | Same-name wrong instance, unbound provider, unrelated server, test-only invocation | Edge precision/recall, incorrect merges/splits, unresolved-attribution fraction |
| Effective authority | Actor+binding+operation+resource/destination+identity+control tuple | Bootstrap authority, restricted subprocess, fixed/provider endpoint, in-memory write | Qualified assertion precision/recall and error taxonomy by dimension |
| Findings | Source-valid security rule claim, scoped to actual actor/effect | Source-visible enforcement, sandbox, internal-only or nonruntime near miss | Stratified finding TP/FP/partial/unresolved; severity and duplication |
| Attack paths | Exact source-backed ingress→reachable actor→callable capability→effect→control chain | Fixed literal query, denied grant, unreachable MCP, unrelated sink, mock/example-only | Path precision/recall **by proof tier**, missing-edge cause, invalid graph traversal |
| Stability | Same source/flags/versions yield same normalized semantic identities and claims | Different temp directory, cwd, file traversal ordering | Portable digest equality, traceable source anchors, CI consistency |

**Critical metric discipline:** `no source reference review` is **not assessed**, `not observed` is **not safe**, `unresolved` is **not a true negative**, and `partial` is **not a full true positive**. Report micro and macro per stratum, sample sizes and Wilson confidence bounds; present independent human-reviewed vs model-reviewed vs author-fixture labels separately.

## 3. Implementation backlog with isolated PR contracts

Each ID below is a **planned PR work package**, not an already opened/merged implementation PR. No duplicate #519–#522 frameworks and no giant rewrite PR.

### Wave A — observe, label, stabilize (must finish before semantic migration)

**A01 | Existing-backlog disposition and frozen baseline manifest**  
Depends on: none. Scope: review #523/#524/#525 against current `main`, mark reusable components, isolate UI. Freeze exact scanner SHA, representative 16 Fresh cases and stratified Full-60 diagnostic cases; preserve historic reviewer limitations. Confirm source manifest, pin SHA/app root and ensure no source drift.  
Deliverables: `research/studies/accuracy-v3-baseline/{cohort.json,study.json}`, overlap register, per-construct coverage matrix, known mismatches and candidate blind holdout manifest.  
Tests/gate: G0 valid selection, no duplicate SHA/app root identities; all expected source bundles present. **Does not assert new precision/recall.**

**A02 | Source assertion baseline and failure taxonomy**  
Depends on A01. Import *reviewed* positives and near-miss negatives already associated with #322/#397/#473/#476/#505/#506/#520, plus frozen fresh claims and representative Strands/Microsoft unresolved cases. Unit of truth is a **source-anchored entity, directed edge or qualified path**, not a finding title. Use source-visible notes and preserve historical adjudicator provenance.  
Include deliberate examples: identical agent names/different instances; imported tool factories; dynamic and static MCP sessions; standalone MCP `EXPOSES_TOOL`; Skill allow/deny without runtime grant; fixed vs model-selected network host; env placeholder vs literal credential; local state vs remote mutation; shell fixed argv vs model-controlled command; sandbox/restricted eval; conditional approval; fixed-query Copilot demo; CLI Strands ingress; grant-restricted Microsoft shell; notebook.  
Deliverables: versioned JSON assertion ledger, source hashes, assertion matching CLI/report, separate ambiguous/unknown examples and reviewer instructions. Reuse #521 scorer and #522 ledger; #525 lineage helper only if reviewed and composable.  
Tests/gate: every assertion has exact source span and expected positive/negative/qualified basis; reference-source reviewer identity retained; no counted recall claim from a scanner-derived or truncated universe.

**A03 | Stage-by-stage semantic survival tracing — the first core diagnostic**  
Depends on A01; can overlap A02. Add an **opt-in sidecar event stream** at existing scanner checkpoints and key enrichment boundaries. For every source observation/instance/binding: originating file/span, adapter/parser, identity, role, stage, outgoing IDs, resolution status, selected linker rule, action `discovered / linked / merged / split / reclassified / dropped / unresolved`, reason. Sample/limit reports for large repositories.  
Deliverables: `scanner --emit-semantic-trace` (or separate research helper) output, trace schema, per-repo waterfall for inventory/bindings/effects/findings/paths, before/after diff with precise change causes. No sensitive prompt/credential material.  
Tests/gate: canonical Graph/ADG/ASG/findings/paths identical trace on vs off; deterministic trace digests on repeat source; no secret values; no > configured tracing budget. We want **first unambiguous location of each missing/wrong relationship**, not another total-count report.

**A04 | Identity stability + referential-integrity hardening**  
Depends on A03. Fix #528 by canonicalizing notebook cell/function source IDs before graph and authority serialization; eliminate temp checkout/cwd/runner paths from instance and edge keys; stabilize duplicate same-name/same-line declarations with **source-qualified semantic identity**, not name-key fallbacks. Retain unresolved ambiguity rather than accidental merge.  
Deliverables: ID portability and reconciliation utilities; two-scan same-SHA delta audit; explicit unbound/unknown endpoints; source/edge integrity checks.  
Tests/gate: twin scans in distinct temporary roots yield identical normalized inventory, binding, authority and source-claim digests; no alias-cross-instance authority leakage (#473 test); graph edge endpoints valid; protected claims preserved or source-adjudicated.

**Wave A exit:** case/construct denominator exists; trace pinpoints missed relationships across representative cases; stable source IDs; historical quality still explicitly **not independently certified**.

### Wave B — rebuild observation/linking without breaking Graph consumers

**B01 | Observation IR v2 compatibility seam, one shadow producer**  
Depends A02–A04. Extend `semantic_discovery` types, not `Graph` public schema initially. Distinguish declarations vs instances vs runtime registration, actor/tool/MCP bootstrap/control/data constructs, parsed symbol keys and evidence spans; use `semantic_contract` canonical vocabulary. Pilot one OpenAI Agents or Pydantic adapter **plus MCP composition**; emit both v1 Graph and sidecar IR, then project to a shadow Graph.  
Tests/gate: syntax/reference validation, source-to-IR-to-shadow graph provenance preservation, explicit stable identities, zero unexpected source-backed claim changes; shadow artifacts do not change production findings.

**B02 | Repository symbol/object/registration linker (pilot)**  
Depends B01. Shared bounded index: module imports/aliases; constructor instances; assignment and `@tool` decorator registrations; imported factories; wrapper delegation; agent instance binding; project root/package resolution and lexical shadowing; ambiguity and dynamic construction. Prefer proven concrete instance to unique source-scoped alias; no name-only join across ambiguous instances.  
Tests/gate: plus/minus fixtures including #397 and #473; cross-file tool registration recovered; alias/rename/import-reorder metamorphisms invariant; unresolved dynamic targets remain unresolved; **exact semantic edge** precision/recall compared against A02, no unadjudicated losses. If no verified improvement, **stop and change design**.

**B03 | MCP/Skill/agent relationship closure**  
Depends B02. Build explicit distinct edges `DECLARES_MCP`, `MCP_EXPOSES_TOOL`, `CLIENT_CONNECTS_TO_SERVER`, `AGENT_BINDS_CLIENT`, `AGENT_CAN_CALL_TOOL`, `AGENT_DELEGATES_TO_AGENT`, `AGENT_USES_SKILL`; only infer last-stage effective callable authority where explicit source linkage and control scope support it. Keep full provider-only inventory and unresolved references.  
Tests/gate: server-only MCP positive exposure retains zero fictional agent access (#506); full client/server/tool positive chain; deny/allowlist scope; same-name target negative; local vs remote Skill catalogues; no false authority via process startup/env config (#382/#476). No automatic path count expectation.

**B04 | Multi-framework producer migration in controlled batches**  
Depends B02–B03 gate. Suggested first comparison: Google ADK, Pydantic AI, OpenAI Agents Python; then Amazon/Strands and Anthropic Python; then Microsoft Python/.NET, TypeScript and MCP/Skill discovery. **Order can change based on Wave A loss map**; ship one family group per PR with v1/shadow diff and rollback switch. Pilot Tree-sitter for TS/C# only if it outperforms existing parser on independently source-verified cases, without unacceptable run cost.  
Tests/gate: each batch passes A02 assertions, contract suite (#414/#426/#427), frozen Fresh-16 and Full-60, and isolated unseen cases; old public graph remains stable except adjudicated corrections. Publish explicit supported/unresolved framework construct matrix.

**Wave B exit:** one shared IR/linker in active use for selected frameworks; measured, source-adjudicated improvements in missing/wrong binding edges, with no uncontrolled graph or findings regressions.

### Wave C — qualify reachable effects and generate defensible security claims

**C01 | Typed effect, authority, control and boundary engine**  
Depends B03 and pilot B04. Per **actor-instance/binding**, represent action kind, sink, execution mode (fixed argv/free shell/provider sandbox), state impact (transient/internal/persistent/external), resource selector, destination actor (fixed/provider/operator/model-selected), identity and permission scope, inherited delegation constraints, applicability of approval/guardrail checks and uncertain runtime enforcement. Preserve declared vs detected vs enforcing vs observed distinctions.  
Tests/gate: #322 source-body effects, #407/#409 canonical tool control, #465 destinations, #478 internal state, #488 remote AgentCore; no arbitrary approval inheritance or bootstrap→process authority; earlier partially-supported cases become exactly scoped; unknown stays explicit.

**C02 | Bounded interprocedural source/authority-path composer**  
Depends C01. Compose **typed graph edges**: untrusted/secret entry → runtime-agent reachability → tool/Skill/MCP callable binding → actual effect and target → applicable controls/barriers. Follow bounded local/imported helpers, handoffs and grants. Preserve proof classes (`static_dataflow`, `authority_reachability`, `source_backed_pattern`, `capability_combination`) and separate **candidate** (including example/test) vs **runtime-scope potential** vs **observed runtime verified**. Keep controls as scope/barriers only where source proves applicability.  
Tests/gate: positive ADK/Strands/Pydantic and grant-aware MCP paths; negative fixed Copilot literal query, never-bound server, test-only fixture, denied command grant, source-blocked runtime and unrelated tool effects; no fabricated source-to-sink path from cooccurrence. Prototype CodeQL as an *independent oracle* on a small case subset; optional only if differential benefit shown.

**C03 | Proof-oriented findings and path evidence provenance**  
Depends C01–C02. Rules consume typed claims/evidence, not accidental graph membership or unqualified name heuristics. Every finding/path stores exact witness edge IDs, source locations, relevant controls, proof/uncertainty class, source/runtime context, and severity rationale. Preserve #497 concise source-local presentation, no 55-fact fanout. Separate configuration hygiene vs *effective agent risk* vs coverage gap.  
Tests/gate: each emitted high/critical finding and path is source-reconstructible; near-miss negatives rejected; previous protected claims reconciled case/index/evidence; no duplicate logical findings from same effect unless scopes materially differ.

**C04 | ADG/AIBOM/Workbench provenance projection**  
Depends C03. Preserve canonical topology and UI navigation (including #508). Supply explicit edge/proof metadata to component inspector, OWASP mapping and attack-path drilldown. Preserve all unbound, unresolved and nonruntime components with visibly distinct states. Independently complete #523 UX defocus issue; no UI-generated relationship or path.  
Tests/gate: clicking agent/MCP/Skill shows only **actual recorded** inbound/outbound relationships; every path step resolves to a canonical graph ID when unambiguous; no implicit topology truncation hidden from the user; report JSON/SARIF and native/ CycloneDX AI-BOM preserve claim context.

**Wave C exit:** evidence and controls support the new authority/path results; zero bootstrap/unknown-to-proven promotions; precision checks on real source sample are better or explicitly blocked.

### Wave D — independently establish production quality

**D01 | Locked blind reference and withheld unseen holdout**  
Depends A01–A02; source reviews can start early and remain locked. Construct a source-only candidate universe for each sampled repo/framework/construct, with two independent reviewers and third-party disagreement escalation as required by `research/STUDY_EVALUATION_CONTRACT.md`. Human-backed truth only when humans actually review. Include negative assertions and all scanner-emitted high/critical/path precision samples, not only missed-positive candidates. Record source pack limitations, model/judge IDs and review provenance.  
Tests/gate: G0/G1/G2 valid, source coverage adequate, reviewer independence/lock documented; unresolved disagreements block claims.

**D02 | Scored accuracy benchmark and feature ablations**  
Depends B04 + C02 + D01. Compare **identical source SHAs** for baseline main vs shadow-linker vs new authority engine vs new flow engine; run both earlier frozen regression and withheld unseen holdout. Ablate stages to isolate inventory, link, effect, finding, path accuracy improvements; include no-LLM deterministic and optionally LLM mode **only when real model calls succeed**. Reuse #521 scorer and #522 immutable ledger.  
Tests/gate: per-case TP/FP/FN/partial/unresolved, macro/micro with confidence intervals; case-level source evidence and reason for **every** newly gained or lost protected assertion; no unverifiable "lift" from counts.

**D03 | Production release gate and drift policy**  
Depends D02. Publish tested framework×language×construct scope matrix, supported/dynamic/unknown limitations, long-term reproducibility and performance envelopes. CI fail closed on protected **source assertions**, missing audit artifacts and semantic integrity failure; distinguish experimental mode from production grade. Require independent review on semantic contract, source linker and path-engine modifications.  
Tests/gate: green G0–G3 on genuinely blinded source adjudication, no unresolved high-priority FP/FN systemic class, no nondeterministic IDs, controlled diagnostic budgets and acceptable p95 scan overhead; approval by product/security owner.

## 4. Proposed release targets — objectives, not observed scanner performance

Define population first and compute CI bounds per stratum. Do not silently average away weak frameworks.

| Gate | Proposed minimum for explicitly in-scope static constructs | Qualification |
| --- | --- | --- |
| Inventory | >=95% precision **and** >=95% recall | Separately for Agent, Tool, MCP, Skill, model/identity where source provides evidence |
| Directed link precision | >=97% | Exact actor instance, target and edge type; unknown not true |
| Directed link recall | >=90% | Measured on independently enumerated true edges |
| Qualified authority | >=95% supported classification precision | Include effect, resource, destination, identity, control and declared/runtime role |
| High/critical finding precision | >=90% | Strict fully supported labels; partial separately reported |
| In-scope path recall | >=90% | Only defined source-supported source→effect classes, by proof category |
| In-scope path precision | >=95% | Static proof assertions, not runtime exploit claims |
| Provenance | 100% of released claims reconstructible to evidence | Includes exact witness relationships and applicable limitations |
| Determinism | 100% same-source semantic digest stability | Same inputs/flags/env-relevant data with normalized paths |
| Safety/incompleteness | 100% known skipped/unsupported analyses diagnosed | Cannot claim exhaustive analysis for arbitrary dynamic code |

These are **draft numerical product targets**, not P0 PR merge thresholds. Wave A establishes baseline and confidence bounds; adjust before calling any framework production-supported. Path count floor is never a criterion.

## 5. Operational guardrails for every implementation PR

Mandatory PR template sections:

1. **Root cause at stage:** parser/discovery, symbol identity, binder, semantic normalizer, authority/control, flow/path, rule, projection or evaluation; include source references.
2. **Source-backed change set:** exact pinned case ID/SHA, affected construct, expected new/lost entity and edge IDs, before/after witness and link/proof status.
3. **Paired positives + hard negatives:** demonstrate no overreach on unbound, fixed, test-only, mock, denied, same-name and dynamic near misses.
4. **Compatibility:** versions of observation, Graph, ADG, ASG, provenance, SARIF and CycloneDX schema; explicit migrations if relevant.
5. **Run evidence:** local deterministic tests, targeted static metamorphic suite, locked Fresh-16 claim gate, Full-60, pipeline integrity, CodeQL and independent adjudication state. Test pass != G2/G3.
6. **Performance/security:** timing/memory budget, reproducibility, no execution of target code, ignored/vendor/source scan scope, bounded diagnostics and input safety.
7. **Rollout/rollback:** shadow diff first; feature gate for sensitive migrators; only enable per-framework after acceptance.

**Regression severity policy:**
- **P0**: invented agent authority; wrong-instance binding; false high/critical risk after a provably enforcing scoped control; missed source-proven model-callable privileged path in declared scope; unsafe scan-code execution; invalid graph lineage.
- **P1**: missed in-scope inventory or relationship; lost low/medium supported claim; unstable semantic identity; undecidable but undiagnosed boundary; material UX misattribution.
- **P2/limitations**: dynamic runtime dispatch without statically sufficient evidence, or a documented unsupported source language construct; surface uncertainty visibly and revisit through evaluated expansion.

## 6. Decision review after each wave

| Checkpoint | Evidence required | Decision |
| --- | --- | --- |
| **A completed** | assertion source ledger + baseline; stage survival map; portable IDs | Approve/revise IR pilot based on actual loss causes |
| **B pilot completed** | shadow vs v1 per-edge adjudication, hard negatives, portable IDs, timing | **Go** only with verified edge gains and no unreviewed losses; otherwise revise linker |
| **B migration completed** | cross-framework contract comparison, per-stratum deltas, unresolved matrix | Expand only proven constructs/languages |
| **C completed** | authority/path source witnesses; control-aware near misses; finding precision sample | Promote only qualified claims with correct proof |
| **D completed** | blind source-first adjudication, G0–G3, source-specific TP/FP/FN, intervals, reproducibility | Declare production support **per scope**, not platform-wide by default |

## 7. First three executable implementation PRs

1. **PR-A01: Frozen baseline + source assertion manifest** — no production scanner logic; reuse frozen Fresh-16 and Full-60, select stratified case packs and source-anchored positive/negative criteria, record current scanner hash.
2. **PR-A03: Passive semantic stage-lineage sidecar** — no Graph/ADG/claim change; capture entity/edge survival and exact loss stage for the A01 cohort.
3. **PR-A04: Stable notebook/instance/edge IDs** — close #528 and test same SHA in two different temp directories, without silently merging different entities.

A02 source assertions can be developed alongside A03 after A01; B01 observation IR starts **only when these outputs show which linkages currently fail**. Work must be sliced by capability and evaluated at source-edge level, not by framework's raw finding counts.

**No implementation commits for A01–D03 are included in PR #531 by adding this document.**
