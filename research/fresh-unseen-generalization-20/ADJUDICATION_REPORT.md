# Fresh unseen 20 — full 82-finding adjudication

## Status

This report records the complete first-pass ChatGPT source adjudication of the frozen #290 scanner output. No scanner changes were made after cohort selection or before adjudication.

- Cohort: 20 exact-SHA repositories
- Scanner commit: `fb8e93e8b4bf499720bd4d9737dfc0979479e210`
- Source workflow run: `36992647206`
- Findings adjudicated: **82/82**
- Attack paths adjudicated: **7/7**
- Evaluator: GPT-5.6 Sol
- Human ground truth: **no**
- Second independent LLM judge: **not yet**
- HorusTrace output visible to evaluator: **yes** (claim adjudication, not blind recall review)

The rubric is the calibrated #285/#288 effective-authority standard: existence is not effective agent authority; unbound tools are not agent-reachable; graph/bootstrap plumbing is not model authority; fixed/operator/provider destinations are not caller-selected egress; and material approval, sandbox, scope, runtime and provenance qualifications must be preserved.

## Headline finding adjudication

| Verdict | Count | Rate |
|---|---:|---:|
| True positive | **24** | **29.3%** |
| Partial | **35** | **42.7%** |
| False positive | **23** | **28.0%** |
| Unresolved | **0** | **0%** |
| **Materially supported (TP + partial)** | **59/82** | **72.0%** |

The earlier PR comment's preliminary 20-FP / 75.6% upper bound is superseded by this per-claim pass. Applying the #288 destination-provenance rule consistently added three definite FPs: one fixed-destination ADK NET001 claim and two operator/CI-configured Couchbase test-MCP NET001 claims.

## Attack paths

| Verdict | Count |
|---|---:|
| True positive | 0 |
| Partial | **5** |
| False positive | **2** |
| Unresolved | 0 |

Materially-supported path rate: **5/7 = 71.4%**.

The four Pipeline Reviewer paths are partial because real model-controlled values reach fixed structured `gh` subprocess calls, but the consequence is narrower than arbitrary command execution. PharmIQ's CLI -> agent -> MCP -> FHIR data.write path is partial/materially supported. Its process-execution path and process+secret co-occurrence path are unsupported because MCP server startup/env configuration are application bootstrap, not model-callable authority.

## Framework breakdown

| Framework | Findings | TP | Partial | FP | Supported |
|---|---:|---:|---:|---:|---:|
| Google ADK | 24 | **16** | 7 | 1 | **95.8%** |
| Pydantic AI | 21 | 4 | 11 | 6 | **71.4%** |
| OpenAI Agents | 25 | 2 | 16 | 7 | **72.0%** |
| LangGraph | 6 | 0 | 0 | **6** | **0%** |
| MCP/custom | 6 | 2 | 1 | 3 | **50.0%** |

The generalization problem is therefore not uniform. Google ADK generalizes strongly. LangGraph control/plumbing semantics fail badly on the positive case. Pydantic/OpenAI are dominated by authority/destination qualification rather than basic discovery failure.

## Rule-level adjudication

| Rule | Claims | TP | Partial | FP | Supported |
|---|---:|---:|---:|---:|---:|
| ADK001 | 3 | 2 | 1 | 0 | 100% |
| AGT020 | 7 | 2 | 3 | 2 | 71.4% |
| AGT022 | 5 | 1 | 4 | 0 | 100% |
| AGT032 | 4 | 3 | 1 | 0 | 100% |
| AGT040 | 27 | 10 | 12 | 5 | 81.5% |
| AGT051 | 1 | 0 | 0 | 1 | 0% |
| AGT053 | 1 | 0 | 1 | 0 | 100% |
| CAP004 | 2 | 1 | 1 | 0 | 100% |
| CAP005 | 11 | 3 | 7 | 1 | 90.9% |
| NET001 | 4 | 1 | 0 | **3** | **25.0%** |
| NET002 | 10 | 1 | 0 | **9** | **10.0%** |
| PATH001 finding-rule | 5 | 0 | 4 | 1 | 80.0% |
| PATH002 finding-rule | 1 | 0 | 1 | 0 | 100% |
| PATH006 finding-rule | 1 | 0 | 0 | 1 | 0% |

The strongest cross-framework defect is now unambiguous: **destination provenance**. NET001/NET002 account for 12 of the 23 FPs. NET002 in particular is supported in only 1/10 unseen claims.

## Source-context sensitivity

| Context | Findings | TP | Partial | FP | Supported |
|---|---:|---:|---:|---:|---:|
| runtime | 48 | 21 | 13 | 14 | **70.8%** |
| example | 18 | 0 | 14 | 4 | 77.8% |
| notebook | 11 | 0 | 8 | 3 | 72.7% |
| test | 5 | 3 | 0 | 2 | 60.0% |

This matters because it falsifies an easy explanation: **the 72% result is not mainly caused by examples/tests**. Runtime-only supported precision is still only 70.8%.

AgentOps contributes 22 findings as 11 near-mirrored Python/notebook pairs. Removing one member of each duplicate pair yields 71 logical-ish claims with approximately **71.8% materially-supported precision**, effectively unchanged from 72.0%. Deduplication is useful for UX/noise, but it will not solve the precision deficit.

## Dominant partial/FP reason taxonomy

The most frequent qualifications/defects are:

- example context: 29
- duplicate logical source: 20
- internal-state scope: 11
- indirect delegation: 10
- provider-managed destination: 8
- graph plumbing treated as authority: 6
- sandbox qualification: 6
- HITL control missed: 5
- test context: 5
- fixed executable scope: 4
- runtime viability blocked: 4
- capability type overstated: 3
- MCP bootstrap treated as agent authority: 3
- restricted in-process eval treated as process authority: 3
- weak workflow control: 2
- operator-configured destination: 2
- binding misclassified: 2
- provider-managed capability: 2

## Key adjudications

### Google ADK — Pipeline Reviewer

The agent directly binds tools that call fixed `gh` subprocess commands. Model/tool inputs can reach command arguments, so the dataflow is real, but the executable and command structure are fixed. The four PATH001 claims are therefore partial rather than strict TP.

The same source uses fixed PyPI/Maven hosts. NET001 claiming unrestricted/caller-selected destination is **FP**: package names affect URL path/query, not the destination host.

### Google ADK — email assistant

The Gmail assistant directly binds read/draft/label/preference tools and does not have a detected enforced per-tool approval boundary. All eight findings are source-supported in this pass.

### LangGraph — customer support

The source defines `guardrail_check`, separates sensitive tool nodes and compiles the graph with:

`interrupt_before=[update_flight_sensitive_tools, book_car_rental_sensitive_tools, book_hotel_sensitive_tools, book_excursion_sensitive_tools]`.

HorusTrace still reports no approval/guardrail and attributes authority to the StateGraph `builder`/routing plumbing. **All six findings are FP as written.**

### MCP/custom — LinkedIn MCP

`"Authorization": "Bearer ${GREPTILE_API_KEY}"` is environment interpolation, not a literal embedded secret. AGT051 is **FP**. The no-allowlist MCP observation is partial because the repository config exists but production effective-agent binding is not fully established by that config alone.

### MCP/custom — Couchbase integration tests

Two NET001 claims use `MCP_SERVER_URL` supplied by CI/operator configuration. Under the #288 rubric, operator-configured destination != model/caller-selected destination, so both are **FP**. The no-tool-allowlist observations themselves are source-supported in their explicitly recorded test context.

### OpenAI Agents — hosted tools

OpenAI `WebSearchTool` and `ImageGenerationTool` allow model-selected queries/prompts, not arbitrary destination selection. NET002 claims treating them as unconstrained model-controlled egress are **FP**.

### OpenAI Agents — AgentOps

The `calculate` example is genuinely bound to LangGraph's model in source, but HorusTrace emits findings describing it as an **unbound** process tool; those are FP. Other Code Interpreter findings are partial because execution is real but provider-managed/sandboxed. Airline `update_seat` findings are partial because the mutation is in-memory `AirlineAgentContext`, not an external airline system.

### Pydantic AI — PharmIQ MCP

The application launches a fixed local MCP server using `MCPServerStdio("python", ["mcp_server.py"], env=...)`. HorusTrace converts server bootstrap and environment configuration into model-reachable `process.execute` / `secrets.read`. Those compositions are unsupported. The actual source-supported high-value authority is the MCP FHIR read/write tool catalogue.

### Pydantic AI — Research Agent

Gmail draft creation is a real state-changing external action. Brave/Gmail provider endpoints, however, are fixed/provider-defined rather than arbitrary model-selected destinations. A restricted in-process calculator `eval` is also not equivalent to OS process execution.

## Comparison with calibrated historical adjudication

| Evaluation | Materially supported |
|---|---:|
| #285 current 30-repo adjudication | **96.4%** |
| #288 Frozen-90 v0.6 | 78.3% |
| #288 Frozen-90 current | 90.9% |
| #288 Frozen-180 baseline | 70.6% |
| #288 Frozen-180 v0.10 | 73.9% |
| #288 Frozen-180 current | **95.7%** |
| **#290 fresh unseen 20 — full first judge** | **72.0%** |

The #290 result demonstrates that the ~96% figure was not yet generalization evidence. It represented strong performance on iterated/calibrated cohorts. The fresh cohort exposes substantial framework-specific semantic debt.

## Interpretation

This result does **not** imply the architecture should be discarded.

Discovery/execution reliability is strong: 20/20 repositories scanned successfully. Google ADK is already highly supported on unseen source. Many non-TP claims are partial rather than fabricated, which means the scanner often discovers the correct capability but loses material scope/provenance/control qualifications during normalization and rule composition.

The result does imply that we should **not claim 95–96% precision as generalizing across frameworks**.

The primary product-quality issue is now best characterized as **semantic fidelity of effective authority**, particularly:

1. fixed/operator/provider destination provenance;
2. LangGraph HITL/control and graph-plumbing interpretation;
3. MCP bootstrap vs model-callable authority;
4. unbound/binding fidelity;
5. capability-type scope (fixed subprocess, restricted eval, provider sandbox);
6. internal-state vs external-impact scope.

## Evaluator limitation / next validation step

This is a complete **single-judge claim adjudication**, not human ground truth and not inter-rater consensus. The evaluator saw HorusTrace claims and source; it is therefore a precision review, not a blind recall review.

Before product fixes are treated as conclusively justified by borderline partial/FP distinctions, the cleanest evaluator-validation step is to run a second independent judge on the frozen 82 claims and measure agreement/disagreement. Clear source contradictions such as LangGraph `interrupt_before`, env interpolation and fixed/provider destination cases are already high-confidence source defects; disputed cases can be escalated rather than silently changing scanner semantics.
