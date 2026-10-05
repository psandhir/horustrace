# ADK + Pydantic AI 20-repository study — source adjudication

Scanner freeze: `eacfd1cdab06939e5fae5f65cd2536e5855ac33f`  
Workflow run: `37275145529`  
Cohort: 10 Google ADK + 10 Pydantic AI exact-SHA repositories.

## Raw locked-reference results

| Framework | Agent P/R | Tool P/R | Effective Authority P/R | Findings | Paths |
| --- | --- | --- | --- | ---: | ---: |
| Google ADK | 100.0% / 96.8% | 74.2% / 63.9% | 80.0% / 74.1% | 47 | 5 |
| Pydantic AI | 83.3% / 100.0% | 52.2% / 100.0% | 25.0% / 100.0% | 20 | 2 |

These raw figures are useful for reproducibility but materially understate current scanner quality because the source-reference-v1 ground truth predates repository-composed Pydantic authority and normalizes several wrappers to generic names such as `FunctionTool`.

## Source-adjudicated structural interpretation

### Google ADK

- Agent discovery remains strong. The single agent miss is a nested second application using `from google.genai.adk import Agent`; current canonical ADK support does not recognize it.
- The three missing delegation edges in `google/pubmed-rag` are real. A `SequentialAgent` binds three imported catalog agents, but scanning the application directory does not reconstruct those imported sub-agent bindings.
- Six `Cloud_Architecture_Review` tool/authority misses are ground-truth naming artifacts: the old reference records `FunctionTool`, while HorusScan resolves concrete underlying functions.
- `agent_payments` has the same wrapper normalization artifact: `FunctionTool(complete_purchase, require_confirmation=True)` is correctly resolved to `complete_purchase`, including its approval control.
- `apdm-agent` similarly resolves `FunctionTool(func=check_url)` etc. to runtime tool names (`check_url`, `check_phishing`, `check_malware`, `threat_score`) rather than wrapper variable names.
- `how-to-build-ai-agent` exposes a taxonomy issue: three delegated-agent helper nodes are counted as tools by the structural scorer even though the graph also has the correct `DELEGATES_TO` edges.
- After wrapper-name normalization, the sampled ADK tool score is approximately **90.3% precision / 82.0% recall**. The residual 11 tool misses are all from the nested non-canonical/legacy ADK application in `rw-004`.
- For the Tier-B Effective Authority mismatches, all seven raw FNs and the single FP are explained by wrapper-name normalization. No source-proven authority edge remains missing in those scored authority-rich cases. This does **not** erase the separate `pubmed-rag` imported-delegation gap.

### Pydantic AI

- The raw **25% Effective Authority precision is not a valid product-quality conclusion**.
- In `shotgun-sh/shotgun`, the old reference says the router has zero tools and zero MCP servers. Pinned source explicitly gives the agent five `Tool(...)` delegation functions, four plan-management tools, `read_file`, and a configuration-derived MCP toolset. HorusScan finds all ten tools plus the dynamic MCP catalogue.
- `mars-mx/portfolio` explicitly configures conditional `WebSearch()` via `Agent.capabilities`; HorusScan retains this as a dynamic capability placeholder. The relationship is real, although representing it as a tool is a taxonomy/UX issue.
- `Croups/smart-web-scraper` is the inverse problem: the old reference misses its factory-created agents, so the scanner's apparent agent FP is actually source-supported. However HorusScan collapses the factory into one logical agent and misses the two concrete registrations `_agent.tool(_scrape_tool)` and `_agent_custom.tool(_scrape_tool)`. That is a genuine factory-composition blind spot.
- Therefore all 12 apparent Pydantic authority FPs inspected are source-supported or source-declared dynamic authority. The remaining work is **factory composition and node typing**, not basic Pydantic authority discovery.

## Security-finding adjudication

The 67 emitted findings were source-reviewed against their pinned code. This is a model-assisted source adjudication, not human dual review.

| Adjudication | Count | Meaning |
| --- | ---: | --- |
| Source-supported | 24 | Finding's material security premise is directly supported by source. |
| Partially supported / overstated | 13 | A real network/authority relationship exists, but capability or risk semantics are overstated. |
| Unresolved | 8 | Binding exists but the referenced local implementation is absent from the pinned repository, so effect semantics cannot be source-proved. |
| Semantic false positive | 20 | Source contradicts the material capability/risk premise. |
| Duplicate finding | 2 | Same logical finding emitted twice. |

The largest false-positive cluster is `Cloud_Architecture_Review`: a read-only Microsoft Docs MCP lookup uses HTTP POST/JSON-RPC. HorusScan infers `external.write` from the HTTP verb, then propagates that write capability through several delegation edges. The six `CAP005` read+write findings are unsupported; another 12 control findings are directionally related to real outbound authority but overstate its semantics.

The second material cluster is `always-on-memory-agent`: pure SQLite SELECT helpers (`get_memory_stats`, `read_all_memories`, `read_consolidation_history`, `read_unconsolidated_memories`) are inferred as `data.write`. This creates false `AGT040`, `CAP005`, and two false `PATH002` paths. The actual write-capable memory tools and delegations are correctly identified.

In `shotgun`, `create_plan`, `add_step`, and `remove_step` mutate in-memory execution-plan state. Treating these as ordinary/destructive data writes produces six noisy approval findings. The dynamic MCP catalogue finding is source-supported. The combined read/write finding is structurally true but overstates the security impact because the writes are internal planner state.

`project-ideation-tool` emits two identical copies each of its outbound and server-side URL-fetch findings. The underlying SSRF-style path is source-supported; duplication is the bug.

Strong source-supported examples include the ADK Document AI path from model-selected file path -> local file read -> external Document AI, the Pydantic search-result URL dereference path, direct user/model-influenced server-side URL fetches, filesystem report writes, ticket creation, and actual SQLite memory mutation.

## False-negative / coverage review

1. **ADK imported sub-agent reconstruction:** `google/pubmed-rag` loses three explicit `sub_agents=[librarian_agent, analyst_agent, reporter_agent]` relationships because the imported catalog agents sit outside the primary application directory.
2. **Pydantic factory composition:** `smart-web-scraper` creates two agents through a factory and registers `_scrape_tool` afterwards. HorusScan sees the factory-level agent but misses the registrations and therefore misses the resulting outbound/proxy-fetch risk.
3. **Pydantic dynamic capabilities:** conditional `WebSearch()` is retained only as `dynamic-capabilities:agent`; it should be represented as a capability node/bundle with explicit WebSearch semantics.
4. **Legacy/non-canonical ADK import:** the nested `google.genai.adk.Agent` application in `rw-004` is not recognized. This is lower priority than canonical ADK gaps.

## Recommended fix order

**P0 — effect semantics:** do not infer external mutation solely from HTTP POST/JSON-RPC transport. Separate transport method from semantic side effect.

**P0 — local datastore effects:** distinguish SQLite SELECT/read helpers from INSERT/UPDATE/DELETE/DDL writes and stop write capability propagation from read-only helpers.

**P1 — ADK import closure:** resolve imported agents used directly in `sub_agents` even when definitions live outside the initial application directory.

**P1 — Pydantic factory composition:** bind post-construction `.tool(...)/.tool_plain(...)/toolsets` registrations back to factory-created agent instances/configurations.

**P1 — authority taxonomy:** do not count delegated-agent helper nodes or dynamic capability placeholders as ordinary tools in inventory/scoring.

**P1 — finding deduplication:** deduplicate identical rule + agent + source/sink semantic paths before reporting.

## Bottom line

The framework parsers are fundamentally sound: ordinary agent discovery is strong, ADK wrapper resolution is better than the old reference suggests, and the latest Pydantic repository-composed authority work is clearly working. The biggest remaining quality problem is no longer basic framework recognition; it is **effect semantics and composition closure**. Incorrect read/write classification can amplify through a multi-agent graph, while imported/factory-composed relationships can still be missed.
