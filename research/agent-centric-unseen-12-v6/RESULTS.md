# Agent-centric unseen 12 v6 — fresh blind holdout

## Protocol

This is a **fresh generalization cohort**, frozen before any HorusTrace execution.

- cohort freeze commit: `4ebb3bece0796502c70f4a6f9bc93d20e5cdc79f`
- scanner baseline: `fd4f3f9962452e2baa5732b482fae2bde5ef6dd1` (post-#318 main)
- workflow run: **37120016284**
- cases: **12/12**
- frameworks: Google ADK 4, Pydantic AI 4, OpenAI Agents 4
- prior committed cohort repositories excluded: **248**
- target repository SHAs changed after freeze: **0**
- HorusTrace output used for cohort selection: **false**

The repository is scanned as a repository, not only at the pre-screened evidence path. Large repositories can therefore contribute agents/findings from additional examples, notebooks, and test fixtures. This is retained as part of the blind result rather than post-hoc narrowing the scan.

## Raw scanner result

| Framework | Repos | Agents | Authority relationships | Findings | Attack paths |
|---|---:|---:|---:|---:|---:|
| Google ADK | 4 | 57 | 20 | 2 | 0 |
| Pydantic AI | 4 | 4 | 7 | 7 | 1 |
| OpenAI Agents | 4 | 45 | 46 | 30 | 2 |
| **Total** | **12** | **106** | **73** | **39** | **3** |

All 73 effective-authority relationships are partially resolved; none is fully resolved across every authority dimension. This is expected for many MCP relationships where authentication, tool catalogue, destination, or resource scope is not statically complete.

## Source adjudication — finding precision

The #313 canonical schema is used:

- **supported**: the emitted material security claim is source-supported;
- **partial**: the core security fact is real but a material effect/control/reachability/provenance qualification is wrong or missing;
- **unsupported**: a material defining predicate is contradicted by source;
- **unresolved**: source is insufficient.

| Framework | Findings | Supported | Partial | Unsupported | Strict precision | Materially-supported precision |
|---|---:|---:|---:|---:|---:|---:|
| Google ADK | 2 | 0 | 0 | 2 | 0.0% | 0.0% |
| Pydantic AI | 7 | 7 | 0 | 0 | 100.0% | 100.0% |
| OpenAI Agents | 30 | 6 | 5 | 19 | 20.0% | 36.7% |
| **Total** | **39** | **13** | **5** | **21** | **33.3%** | **46.2%** |

Attack paths:
- **1/3 supported**
- **0 partial**
- **2/3 unsupported**

The supported path is the Pydantic coding-agent static flow from model-controlled `command` to `subprocess.run(..., shell=True)`.

### Unsupported defect clusters

The 21 unsupported findings collapse into four reusable semantic defects rather than 21 independent corner cases.

#### 1. Source-visible arithmetic `add` is promoted to persistent write

In Idun's ADK calculator fixture:

`def add(a, b): return a + b`

is classified as `data.write`. That creates:
- ADK001
- AGT040

Both are unsupported. A source-visible arithmetic function must override name-only mutation semantics.

**Affected findings: 2.**

#### 2. Business API `execute` is promoted to `process.execute`

Agoragentic exposes functions named `agoragentic_execute`, but their source performs HTTP/API invocation, not local command/process execution.

The scanner manufactures `process.execute`, producing:
- PATH001
- five AGT020 findings
- four CAP004 findings

These are unsupported because the defining process-execution predicate is false.

**Affected findings: 10.**

#### 3. Fixed/operator-configured HTTP origins are treated as unconstrained dynamic URLs

Two source patterns are missed:

- Ed Donner push agent: `pushover_url = "https://api.pushover.net/1/messages.json"`
- Agoragentic: `AGORAGENTIC_API = os.environ.get("AGORAGENTIC_BASE_URL", "https://agoragentic.com")`, then fixed API paths are appended.

The model cannot select an arbitrary destination host in either case. NET001 is therefore unsupported.

**Affected findings: 7.**

#### 4. Mock business-action naming manufactures external authority

The OpenAI voice sample's `submit_refund_request` delegates to `mock_api.submit_refund_request`, whose implementation simply returns `"success"`; it performs no external/network mutation.

The scanner nonetheless emits:
- NET002 on Customer Support Agent
- PATH009 through delegation to that supposed unconstrained egress

Both are unsupported.

**Affected findings: 2.**

### Partial findings

Five AGT040 findings for Agoragentic `agoragentic_execute` are **partial / effect_semantics**.

The scanner's `process.execute` evidence is wrong, but the core control claim remains material: source shows a privileged external marketplace operation that can route paid work (the SDK documents actual USDC cost) without a source-visible per-call approval boundary. The correct effect is external/network mutation / paid invocation, not local process execution.

### Supported findings

The supported set consists of:
- six findings on the Pydantic coding agent's arbitrary file read/write and `shell=True` command execution;
- one NET002 on arbitrary-URL webpage fetch in the Pydantic research agent;
- three AGT040 findings on source-visible Pushover notification writes with no approval/guardrail;
- AGT022 + AGT040 for durable Agoragentic learning-note writes;
- CAP005 for the Agoragentic starter agent's source-backed memory read/write combination.

## Selected-signal semantic recall

This is a case-level check against the source features used to select the cohort. It is not a substitute for a fully enumerated authority-recall study, but it shows whether the preselected high-value composition survived normalization.

| Case | Preselected source signal | Result |
|---|---|---|
| ADK-001 Idun | `tools=get_adk_tools()` imported dynamic MCP registry | **missed** — selected agent receives no effective MCP authority |
| ADK-002 ABACUS | custom `CalculationMCPToolset` over env/configured SSE | **partial** — `toolset` binding appears as an empty generic tool; MCP declarations remain unbound |
| ADK-003 Jarvis | filesystem stdio MCP + google_search + imported PDF reader | **partial** — all three bindings recovered, but filesystem root `CONTENT_FOLDER` is not retained as resource scope |
| ADK-004 Voiceover | starred dynamic A2A + Streamable HTTP MCP lists, auth + tool filters | **missed** — agent exists but has zero effective authority |
| Pyd-001 Coding-Agent | model-selected file read/write + `shell=True` | **full** — all principal effects and static command flow recovered |
| Pyd-002 ResearchAgent | imported Tavily/search + arbitrary-URL fetch | **partial** — arbitrary fetch network effect recovered; Tavily search helpers remain read-only with network effect missing |
| Pyd-003 Excel agent | function-local Agent with `toolsets=[MCPServerSSE(...)]` | **missed** — server inventory exists but is `declaration_not_agent_bound`; effective authority is zero |
| Pyd-004 MetaTrader | stdio MCP with local repo server including `order_send` | **partial** — MCP binding/command recovered; local MCP catalogue and trade mutation semantics are not projected |
| OAI-001 voice support | order read + WebSearch + handoffs + mock refund | **full for binding/real effects** — reads, WebSearch, and delegation are recovered; refund produces precision errors rather than a recall miss |
| OAI-002 AgentIntro | InputGuardrail + handoffs + imported file-read specialist | **partial** — handoffs and reads recovered; explicit `InputGuardrail` is not represented in control observations/effective authority |
| OAI-003 trading floor | dynamic MCP arrays + researcher `.as_tool()` delegation | **partial** — parameter-level MCP bindings exist, but concrete MCP list composition/catalogue and researcher-as-tool authority are not fully propagated |
| OAI-004 Agoragentic | configured HTTP marketplace writes + memory read/write | **partial** — network and memory effects are partly recovered, but execution semantics and destination provenance are materially wrong |

Coarse selected-signal result:
- full: **2/12**
- partial: **7/12**
- missed: **3/12**

The strongest current capability remains direct, source-visible tool effects. Dynamic/composed authority and cross-object framework semantics remain the main recall bottleneck.

## Build decision

The v6 result invalidates any interpretation of the post-v5 121/121 regression as unseen precision. That regression was useful calibration evidence, but v6 demonstrates that the current semantic engine still over-relies on names in some paths and remains incomplete for dynamic framework composition.

Do **not** tune individual v6 repositories. The next scanner tranche should implement shared primitives in this order:

1. **Body-first effect semantics / negative corroboration**
   - source-visible function bodies override semantic names;
   - `add` must not imply write when the body is arithmetic;
   - `execute` must not imply process execution without an execution sink;
   - business-action names must not manufacture network/write effects when local source contradicts them.

2. **Framework-neutral destination provenance**
   - preserve literal module constants and operator-configured environment/config values through f-strings and helper-local URL construction;
   - apply consistently to OpenAI Agents as well as ADK/Pydantic.

3. **Dynamic/composed framework binding normalization**
   - imported collection factories (`tools=get_adk_tools()`);
   - list comprehensions + starred collection expansion;
   - custom/subclass MCP toolsets;
   - Pydantic function-local Agent + `toolsets=[client]`.

4. **Local MCP server linkage and catalogue propagation**
   - link stdio commands such as `uv run mt5mcp` / local server params to source-visible FastMCP servers in the same repository;
   - propagate tool catalogue/effects such as `order_send`, account mutation, or local server tools.

5. **Control/delegation propagation**
   - OpenAI `InputGuardrail` and analogous agent-level controls;
   - ADK MCP `tool_filter` / allowed tools;
   - agent-as-tool delegation such as `researcher.as_tool()`;
   - dynamic A2A delegation.

6. **Resource-scope propagation**
   - retain filesystem roots passed as MCP stdio arguments, e.g. `CONTENT_FOLDER`.

P1/reporting follow-up:
- deduplicate semantically identical code copied between Python modules and generated/output notebooks;
- classify test/example/tutorial agents separately in repository-wide reporting so real application authority is not obscured by fixtures.

After these primitives, rerun frozen v6 strictly as regression evidence; only then freeze v7 for the next unseen generalization gate.
