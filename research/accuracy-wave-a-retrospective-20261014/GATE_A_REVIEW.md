# Wave A Gate Review: evidence-first accuracy foundations

**Date:** 14 October 2026. **Status:** implementation evidence; no independent precision/recall certification.

## Evidence, scope and source fidelity

- **Frozen cases:** 30 exact source-SHA cases, 16 pre-existing Fresh cases and 14 selected diagnostic Full-60 cases. Validated by `scripts/verify_accuracy_wave_a_baseline.py`; retrospective and source-visible by construction, **not a blind holdout**.
- **Seed reference:** 35 positive, negative or unresolved **source-anchored observations** across all 30 pinned cases, in `source-assertions.json`. Original Git file blob SHA, source line, case identity, semantic role and reviewer provenance accompany every item. **Not** an exhaustive agent/edge/path reference universe, and not independently adjudicated.
- **Passive stage recorder:** 11 intervals, opt-in with `--semantic-trace-output`, with added/removed **multiset observations**, raw fact/source-scoped locations and budget/truncation diagnostics. These record changes between snapshots; they do **not** identify the causing statement within an interval.
- **Source-stable notebook IDs:** notebook extractor instance metadata is rewritten to notebook+cell source identity before authority projection. Tested in isolated temporary paths and repeat scans. Full-environment determinism remains a separate product goal.
- **30-case runnable study:** [Actions run #38599092779](https://github.com/psandhir/horustrace/actions/runs/38599092779), all 30 / 30 cases succeeded, with 31 retained artifacts (30 case traces plus summary). Original run scanner revision was the Wave A04 feature branch; the same study must be rerun after merge when a release-grade baseline is wanted.

## Observed source-scan inventory on these 30 cases (not truth)

| Observed measure | Scanner result |
| --- | ---: |
| Agent objects after normalization | 184 |
| Tools, including unbound | 592 |
| MCP servers, including unbound | 195 |
| Skills, including unbound | 46 |
| Findings | 194 |
| Attack-path records | 13 |
| Scanner coverage diagnostics | 83 |

**No precision, recall, TP, FP or FN can be derived from these totals.** Four source-provider-only MCP repositories correctly have zero agents by their scan's application scope; zero standalone-MCP paths is not inherently a defect.

## Per-stage survival measurement

| Stage | Added observations | Removed observations | Total after stage |
| --- | ---: | ---: | ---: |
| discovered | 955 | 0 | 955 |
| initial_instances_consolidated | 83 | 56 | 982 |
| mcp_context_resolved | 21 | 8 | 995 |
| source_semantics_resolved | 27 | 27 | 995 |
| delegation_projected | 30 | 1 | 1024 |
| skills_bound | 0 | 0 | 1024 |
| normalized | 0 | 0 | 1024 |
| flows_resolved | 192 | 184 | 1032 |
| attack_paths | 13 | 0 | 1045 |
| adg | 1337 | 0 | 2382 |
| findings | 0 | 0 | 2382 |

The changes are *shape/metadata and entity observations*, not necessarily source objects disappearing: 184 removed flows may reflect 184 re-keyed/qualified flow observations, not 184 lost true paths. The 1,337 ADG edge additions are a topology projection, not 1,337 newly discovered external authority grants.

## Four case-level source/trace reconciliation candidates

### WAB-01: MCP client-to-provider tool closure — Pydantic `gen-pyd-001`

- **Source:** [`newsbubbles/pharmiq@c699497/agent.py:53–73`](https://github.com/newsbubbles/pharmiq/blob/c69949739647a47ec8339b473bdf578c8cf8bfd9/agent.py#L53-L73). The agent registers `MCPServerStdio('python', ['mcp_server.py'])` via `mcp_servers=mcp_servers`.
- **Scanner observation:** one agent, one bound MCP server, **22 unbound tools**. Discovery emitted one `binds_mcp`, one `unbound_mcp` and 22 `unbound_tool`; MCP resolution removed an unbound server observation.
- **Hypothesis, NOT adjudicated FN:** the scanner may lack a source-backed link between the consumer's statically referenced local MCP server program and tools exported by that program.
- **Wave B test:** follow the command's script path and actual FastMCP tool registrations; prove or reject the exact server-to-tool catalogue and actor/client authorization boundaries. A server declaration alone must not convert all 22 tools to agent-callable authority.

### WAB-02: Dynamic remote MCP catalogue — Microsoft `ff60-microsoft-04`

- **Source:** [`WorkIqToolProvider.cs:106–153`](https://github.com/qmatteoq/agent365-demos/blob/937f8c12421b6eebfbff764dbafbdbe13cc72f68/dotnet-agent-teammate/Agent365/WorkIqToolProvider.cs#L106-L153) uses OAuth turn-token exchange, `McpClient.CreateAsync` and `ListToolsAsync` to enumerate remote MCP tools.
- **Scanner observation:** 3 agents, 2 bound MCPs and 0 enumerated tools; the trace created 2 `binds_mcp` observations during MCP context resolution.
- **Hypothesis, NOT static FN:** an exact tool-name list may not be statically discoverable because it is returned by remote runtime enumeration. The scanner should preserve a typed `dynamic remote catalogue, unresolved tool set` and the conditions of callable access, rather than inferring an empty tool server or inventing names.
- **Wave B test:** dynamic-listing source pattern plus applicable identity/scope; assert unresolved vs proven boundaries. Investigate whether `Get` and `dotnet-teammate Identity` objects labelled as agents are actual agent instances, not name-based false positives; do not classify until source-reviewed.

### WAB-03: Factory-registered MCP tools — Couchbase `gen-mcp-003`

- **Source:** [`src/cb_mcp/core/app.py:104–115`](https://github.com/couchbase/mcp-server-couchbase/blob/df5d9ceb013f57143171f65ec3ba033ace06aa9a/src/cb_mcp/core/app.py#L104-L115) constructs FastMCP, builds FunctionTool from a function list and calls `mcp.add_tool(tool_obj)`.
- **Scanner observation:** zero agents (expected server-only scope), 7 unbound MCP servers, **zero statically enumerated tools**.
- **Hypothesis, not confirmed FN:** cross-module `tools` factory resolution may be needed to enumerate actual tool registrations. If the list is dynamic, report unresolved registered tools rather than zero reachable tools.
- **Wave B test:** source-backed `EXPOSES_TOOL` edges from factory-registration code with explicit unresolved list elements. Never invent `AGENT_CAN_CALL` on this standalone provider.

### WAB-04: Instance consolidation — Amazon `ff60-amazon-04`

- **Source:** [`src/main.py:52–60`](https://github.com/aws-samples/sample-multi-agent-region-expansion-planner/blob/30d03d7c9f6512e5bf10601879382fac9c3a16b1/src/main.py#L52-L60) passes `common_tools + agents` to a Strands orchestrator. Multiple specialist agent-as-tool instances are statically referenced.
- **Scanner observation:** 10 agent observations at discovery, 8 removed in initial consolidation and 2 agents afterward. 13 tool bindings and 3 MCP bindings added at consolidation; one additional tool binding after delegation projection.
- **Hypothesis, NOT confirmed eight missing agents:** the consolidation may merge aliases or specialize agent-as-tool identities correctly or incorrectly. Count differences alone do not show which.
- **Wave B test:** exact original and resolved agent-instance keys plus specialty target bindings and source spans; require same-name-instance hard negatives and positive delegation chains from pinned source. Assert every proven child object remains addressable after normalization.

### WAB-05: Test-only MCP server inventory dominates one repository — `gen-mcp-001`

- **Source context:** pinned `stickerdaniel/linkedin-mcp-server@f142502` exposes `linkedin_mcp_server/server.py` and many test-side FastMCP instances under `tests/`. Test fixtures are legitimate source constructs but are not independently evidence of deployed MCP servers.
- **Scanner observation:** **124 unbound MCP server records**; **121/124 have source paths under `tests/`**. Repeated names `test` (80) and `owner` (33) reflect distinct test-source locations, not 113 production servers. This single repository heavily influences the 195-server total across the 30 cases.
- **Qualification:** HorusScan already applies `source_context` metadata to MCP servers in `scanner.py:_annotate_authority_source_contexts`. The Wave A passive `unbound_mcp` trace shows the source path but does **not** project `source_context` into its condensed attributes. **Do not equate an inventory count including test fixtures with production runtime inventory or with 121 confirmed FPs.**
- **Wave B test:** provide partitioned inventory (runtime/example/test/provider-only), stable instance identity, and separate agent-bound relationships. A production default should count only justified runtime inventory while keeping test constructs discoverable and visibly qualified. Preserve original source references and do not collapse distinct test fixtures silently.

## Wave A acceptance inventory

| Acceptance condition | Evidence/status |
| --- | --- |
| Frozen source SHAs / application roots and versioned retrospective provenance | Achieved by A01, validated |
| Source observation anchors exist for every selected case | 35 across 30, A02 coverage follow-up; seed **not exhaustive** |
| Passive semantic changes observable without altering graph/findings | A03 regression tests and 30-case passive trace succeed |
| Stable notebook extraction-backed instance references | A04 implementation and repeat-scan tests; full portability gate scoped |
| Source-grounded change hypotheses and first loss intervals | WAB-01 to WAB-04 identified; each still requires Wave B source adjudication |
| Independent blind precision, recall and cross-framework supported claim completeness | **Not achieved; reserved for D01–D03** |
| Accurate full entity/edge enumeration across arbitrary dynamic code | **Not achieved; Wave B core objective** |

**Gate A decision:** diagnostic foundations implemented for the declared Wave A scope. Permit the **B01 shadow Observation IR pilot** *only* after all implementation PR checks and merges are complete; do not claim production accuracy or adjudicated fixes from these observations.

## Wave B entry actions (not implementation commitments)

1. B01: reuse canonical `semantic_discovery` contract; produce v1 vs shadow `Graph` for mixed agent/MCP/Skill fixture, with source role and instance IDs.
2. B02: first linker hypotheses WAB-01/03/04, with positives and near-miss negatives.
3. B03: keep MCP `EXPOSES_TOOL` distinct from `AGENT_CAN_CALL`, and model dynamic catalogue as unresolved.
4. Keep `#529` ChatGPT-plan auth parked. Run independent source-only D01 holdout construction without exposing scanner predictions.


## Reproducing the source-to-trace correlation panel

After downloading/extracting all 30 `wave-a-semantic-trace-*` case artifacts
from the pinned GitHub Actions diagnostic workflow into a common directory:

```bash
python -m scripts.wave_a_correlate_source_traces \
  --inputs downloaded \
  --output-dir wave-a-source-correlation
```

The generated `correlations.json` and `correlations.md` index each of the
35 source assertions against file-associated trace observations. A match is
**source-file correlation only**, and may refer to a different construct on
the same line/file. A missing match is an investigation candidate, never an
automatic false negative. Negative expected claims remain unadjudicated;
precision and recall remain `null`.

Use the matching report to prioritize per-instance, typed edge inspection,
not as a substitute for the independent source-only D01 reference universe.
