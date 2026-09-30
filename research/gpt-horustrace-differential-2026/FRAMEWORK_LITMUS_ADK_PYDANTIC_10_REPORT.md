# Google ADK + Pydantic AI framework litmus — 10 repositories

## Objective

Compare current HorusTrace static security semantics against an independent source-review LLM on a balanced **5 Google ADK + 5 Pydantic AI** set. This is a differential study, not formal product precision/recall: GPT is an oracle for disagreement discovery and every important disagreement is source-adjudicated.

The LLM side uses the existing `GPT_SOURCE_REVIEW_PROMPT_V1.md`, which is deliberately aligned to the HorusTrace model: effective authority rather than entity existence, tool/MCP binding, delegation, ingress, sensitive capabilities, approvals/guardrails, destination/resource constraints, attack-path composition, and explicit runtime uncertainty.

Eight cases reuse previously locked source-only reviews. `rw-009` and `rw-155` were reviewed and committed before the targeted current-main scanner reveal.

- LLM review lock: `c893d37ba0c3f9fa83773eefca8237dd552b49e0`
- Cohort lock: `f7c5c4a31a0daebe8e997c600e0b2be2bd99182e`
- Scanner code base: `36c48f88da2106c367e3a96e2f94432e8ef595ca`
- Targeted Actions run: `36699950690`
- Scanned: **10/10**
- HorusTrace findings: **62**
- HorusTrace attack paths: **9**

## Headline differential

| Metric | Result |
|---|---:|
| LLM semantic findings | 12 |
| Full semantic matches | **6 (50.0%)** |
| Partial semantic matches | **4 (33.3%)** |
| Missed semantic findings | **2 (16.7%)** |
| Covered or partial | **10/12 (83.3%)** |
| LLM source-supported attack paths | 9 |
| Full path matches | **5 (55.6%)** |
| Partial path matches | **2 (22.2%)** |
| Missed paths | **2 (22.2%)** |
| Path covered or partial | **7/9 (77.8%)** |
| Unsupported HorusTrace paths found during adjudication | **1** |

The raw 62-finding count is not a precision metric. Several HorusTrace rules can describe the same semantic authority condition, and source-context tagging separates runtime/test findings.

## Framework split

| Framework | LLM findings | Full | Partial | Missed | Covered/partial | Key result |
|---|---:|---:|---:|---:|---:|---|
| Google ADK | 5 | 3 | 2 | 0 | **100%** | Strong authority recall; fixed-destination precision and auth/runtime qualification are the weaknesses. |
| Pydantic AI | 7 | 3 | 2 | 2 | **71.4%** | Strong on direct code execution, SSRF and RAG exposure; dynamic MCP and second-order destination provenance are clear misses. |

## Case results

### rw-009 — Cloud_Architecture_Review — Google ADK — **precision defect**

The LLM source review found no material agent-security finding. The bound GitHub retrieval tool lets the model select an owner/repository, but every HTTP request is constructed under **`api.github.com`** and the operation is repository read/retrieval. The standalone MCP server exists but is not bound into the reviewed ADK agents.

HorusTrace gets the MCP semantics right: two MCP declarations remain unbound with reason `declaration_not_agent_bound`. But it emits two `NET002` findings plus `PATH009`, claiming an **unrestricted external destination**.

This is source-unsupported. Destination scope is being lost as the FunctionTool capability propagates through the ingestion agent and delegation edge.

**Repair:** propagate fixed-provider destination evidence through helper/tool and delegation normalization; do not turn provider-constrained reads into arbitrary egress.

### rw-017 — always-on-memory-agent — Google ADK — **major improvement, one predicate gap**

Current HorusTrace now emits two `PATH002` chains through the orchestrator to the ingest/consolidate persistent writes. This closes the earlier Batch-001 path-composition miss.

The remaining gap is the specific authentication predicate: GPT proves that an empty `MEMORY_API_KEYS` configuration intentionally enables public mode on `/ingest` and `/consolidate`; HorusTrace represents generic external input but not that public-default condition.

The persistent-write-without-approval and delegated read/write findings are fully represented.

### rw-004 — agentGemini — Google ADK — **partial**

HorusTrace correctly detects the declared commerce/profile state-changing authority and lack of explicit approval. The pinned source is import-blocked by absent modules, however, and the finding layer still does not qualify that authority as initialization-blocked/conditional.

This remains the known **runtime viability qualification** gap.

### rw-007 — ocr-test — Google ADK — **covered**

`PATH010` reconstructs:

`interactive input -> ADK agent -> model-selected document path -> local file read -> Google Document AI`

`DATA001` independently captures the broad resource scope. This is a strong framework-specific success.

### rw-012 — morning-wire — Google ADK — **precision control passed**

The model-callable briefing tool has a bounded argument and a fixed Hacker News destination. Scheduler/delivery authority is application-only. GPT reports no finding and HorusTrace also reports none.

### rw-155 — shotgun — Pydantic AI — **P0 MCP recall gap**

Source proves that local configuration is converted into `MCPServerStdio` or `MCPServerStreamableHTTP` and then passed directly as Pydantic AI `toolsets` to the Router and specialist agents. The concrete catalogue is configuration-dependent, so GPT deliberately does **not** invent a dangerous sink; it reports the broader operator-configured MCP authority without a source-visible per-call approval/allowlist layer.

HorusTrace reports **zero MCP servers and zero MCP references** for this repository. This is a direct miss against advertised Pydantic AI MCP coverage.

The scanner also emits 23 other findings. Three are correctly tagged as test-source. Much of the runtime set detects real native capabilities, but source-visible controls and scope are lost: `codebase_shell` has a command allowlist/injection checks, native artifact writes are confined to `.shotgun`, and some router mutations are internal plan state. Generic principal naming (`agent`) and overlapping `AGT040`/`CAP005` rules add noise.

### rw-152 — agentic-ppt-slide — Pydantic AI — **strong core detection, partial scope**

Three critical `PATH001` findings correctly reconstruct concrete model-controlled Python `compile/exec` flows.

Two semantics remain partial:
- `NET002` notices external network authority but does not reconstruct `model URL -> WebBaseLoader`;
- file-write rules detect mutation but do not preserve the model-controlled filename/path scope.

The pinned module is also initialization-blocked by an undefined `settings`, so runtime viability remains unqualified.

GPT has three semantic attack paths here. HorusTrace's three reported paths are all code-execution variants: they cover the two GPT code-execution chains, while the separate model-selected URL chain is still absent.

### rw-147 — Pedantic-AI-Deep-Research-Agent — Pydantic AI — **miss**

A model-selected research angle drives DuckDuckGo, whose result `href` values are then passed to `requests.get(url)` without a destination allowlist. This is not direct arbitrary-URL control, but it is second-order dynamic destination authority.

HorusTrace emits no equivalent network finding or path. This is the same known Batch-002 gap and remains open.

### rw-150 — project-ideation-tool — Pydantic AI — **covered**

`NET001` plus `PATH011` reconstruct the authenticated/user-influenced URL through the Pydantic agent to the dynamic `httpx` fetch. Strong match.

### rw-164 — local-LLM-with-RAG — Pydantic AI — **covered**

`PATH013` reconstructs the full user-selected server directory -> recursive ingestion -> RAG -> Pydantic agent -> retrieved file content chain.

This validates the Batch-004 / PR #257 repair on a current-main rescan.

## What this says about framework maturity

### Google ADK

ADK is currently the stronger adapter in this test. It found material authority in every positive case and passed the fixed-scope negative control `rw-012`. The important new defect is not entity/tool recall—it is **semantic precision when a network helper has a fixed provider destination**.

### Pydantic AI

Pydantic AI is strong where authority is syntactically direct: decorated/bound tools, code execution, direct dynamic URLs, and the newly added RAG directory exposure pattern.

The weaker surface is **framework composition through dynamic toolsets/configuration and multi-stage provenance**:
1. user-configured MCP toolsets are missed entirely in `rw-155`;
2. search-result-derived dynamic destinations are missed in `rw-147`;
3. destination/resource scopes and controls are often collapsed into generic capabilities.

## Recommended build order

1. **P0 — Pydantic dynamic MCP toolsets.** Recognize `MCPServerStdio` / `MCPServerStreamableHTTP` values loaded from configuration and passed through `toolsets`, preserving configuration-dependent catalogue and approval state.
2. **P0 — fixed-provider destination propagation.** Preserve `api.github.com`/other fixed host evidence through FunctionTool helpers and delegated authority; prevent false `NET002` / `PATH009`.
3. **P1 — second-order destination provenance.** Track provider/search result URL -> downstream HTTP fetch without calling it direct model-selected arbitrary URL.
4. **P1 — runtime viability qualification.** Surface import/initialization blockers separately from declared static authority.
5. **P1 — Pydantic precision.** Preserve path confinement/internal-state mutation semantics, improve concrete principal naming, and reduce generic rule duplication.
6. **P1 — ingress authentication predicates.** Carry public/authenticated/config-dependent ingress state into composed paths.

## Bottom line

The test is useful because it does not say merely “HorusTrace found 62 things.” It shows where the product's semantic model agrees with an independent source review.

**ADK:** no semantic recall misses in this set, but one clear false attack path caused by destination-scope loss.

**Pydantic AI:** three direct high-value patterns are strong, but dynamic MCP toolsets and second-order URL provenance are still real recall gaps.

The next build should fix those two P0 defects first, then rerun this exact 10-repository litmus before expanding to another framework.
