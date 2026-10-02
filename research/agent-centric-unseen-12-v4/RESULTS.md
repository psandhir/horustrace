# Agent-centric unseen 12 v4 — first-pass adjudicated result

## Executive result

This is a genuinely fresh 12-repository holdout selected and frozen before HorusTrace execution, after the post-LangGraph authority work through #302.

- Scanner baseline: `dc06905be7160463be292219aee9f04c3c5ad6a5`
- Workflow run: `37074659886`
- Cases completed: **12/12**
- Findings: **48**
- Attack paths: **4**
- Effective-authority relationships: **48**
- Materially supported findings (including qualified/partial): **37/48 = 77.1%**
- False-positive findings: **11/48 = 22.9%**
- Materially supported attack paths: **2/4 = 50%**, both qualified rather than proof of exploitability

This does **not** meet the working >=90% materially-supported precision target. It also exposes material recall gaps even though inventory/relationship counts are healthier than earlier cohorts.

## Framework result

| Framework | Findings | Supported / qualified | FP | Supported precision | Authority relationships |
|---|---:|---:|---:|---:|---:|
| Google ADK | 27 | 19 | 8 | 70.4% | 24 |
| Pydantic AI | 13 | 12 | 1 | 92.3% | 18 |
| OpenAI Agents | 8 | 6 | 2 | 75.0% | 6 |
| **Total** | **48** | **37** | **11** | **77.1%** | **48** |

## Case adjudication

| Case | Findings | Supported / qualified | FP | Attack paths | Notes |
|---|---:|---:|---:|---:|---|
| unseen4-adk-001 | 13 | 5 | 8 | 0/2 | Real GCS PDF write authority is found, but `send_email` only returns a string and `check_status` uses an operator-configured endpoint. These cause false privileged/network/delegated-egress claims. |
| unseen4-adk-002 | 8 | 8 | 0 | 0 | Gmail read/draft/label mutation and persistent preference write are source-visible; no hard tool-control callback is present. |
| unseen4-adk-003 | 2 | 2 | 0 | 0 | SOP retrieval is real read/network authority without a detected hard tool control. Simulated `logIncident`/`blockCard` bodies are correctly not promoted to external mutation. |
| unseen4-adk-004 | 4 | 4 | 0 | 0 | GitHub review/comment writes plus read authority are source-visible and bound through the function-local factory. |
| unseen4-pyd-001 | 0 | 0 | 0 | 0 | **Recall gap:** five tool relationships exist, but imported `Tool(...)` wrappers for robot motion/navigation/ROS CLI have empty capabilities despite NATS command execution. |
| unseen4-pyd-002 | 0 | 0 | 0 | 0 | **Recall gap:** `get_price` is recognized as read, but decorator tool `send_alert` loses the transitive outbound SMS side effect. |
| unseen4-pyd-003 | 11 | 10 | 1 | 0 | DB writes, email send and dynamic URL scraping are real. One NET002 on the split monitoring agent is overbroad because its remaining outbound email destination is operator configured. |
| unseen4-pyd-004 | 2 | 2 | 0 | 1/1 qualified | Model-selected URL reaches server-side `httpx.get(..., follow_redirects=True)`; broad egress/SSRF-style path is source-supported. |
| unseen4-oai-001 | 0 | 0 | 0 | 0 | **Recall gap:** factory constructs `MCPServerStdio` entries from config and binds the resulting list to `Agent(mcp_servers=...)`, but authority relationships remain zero. |
| unseen4-oai-002 | 0 | 0 | 0 | 0 | **Recall gap:** `tools = await bl_tools(["blaxel-search"]) + [weather]` is bound to a function-local Agent, but no tool relationship survives the awaited/BinOp collection composition. |
| unseen4-oai-003 | 2 | 0 | 2 | 0 | `create_escalation_summary` is pure string construction; its name still causes false state-change/privileged-tool claims. |
| unseen4-oai-004 | 6 | 6 | 0 | 1/1 qualified | Source-proven model-controlled shell execution is correctly traced to `subprocess.run(..., shell=True)`; ComputerTool authority is conservatively qualified. |

## Systematic precision defects

### 1. Mutation-like names still outrank function-body semantics in some paths

`create_escalation_summary` only builds and returns a string, yet it is classified as state-changing. The earlier fix for generic name hints did not fully eliminate this class.

**Invariant:** name/documentation hints may prioritize inspection, but persistent/external mutation requires body-side-effect evidence or a known mutating API.

### 2. ADK destination provenance is still lost through environment/configuration and delegation

`check_status` calls a URL sourced from `CHECK_ORDER_STATUS_ENDPOINT`; this is operator-configured, not model-selected arbitrary egress. Delegation then amplifies the lost provenance into PATH009.

**Invariant:** destination provenance must survive imported/global constants and delegation edges.

### 3. Semantic naming can manufacture external effects

The ADK `send_email` function in unseen4-adk-001 returns an email template and performs no send/network call, but is promoted to external write by its name.

**Invariant:** external effect classification must be corroborated by the function body, known SDK/API calls, or explicit framework metadata.

## Systematic recall / authority-composition defects

1. **OpenAI MCP collection factories:** a concrete MCP list returned by a repository-local helper and bound as `mcp_servers=mcp_servers` can disappear entirely.
2. **OpenAI composed dynamic tool collections:** awaited provider tools combined with static tools using `+ [tool]` produce zero relationships.
3. **Pydantic cross-file Tool wrappers:** imported `Tool(function, ...)` objects bind correctly by name but lose the wrapped function's side-effect semantics across module boundaries.
4. **Pydantic transitive decorator semantics:** a decorated tool calling an imported side-effect helper (for example SMS send) does not inherit the helper's external-write/network authority.
5. **Relationship resolution quality:** several relationships survive only with empty capability/resource/destination dimensions, so inventory recall is materially better than authority recall.

## Comparison with v3

- v3 original: **28/43 = 65.1%** supported precision; **85** authority relationships; **5/5** qualified attack paths.
- v3 rerun on post-#302 main: **~27/34 = 79.4%** carry-forward supported precision; **88** authority relationships; **5/5** qualified attack paths.
- fresh v4: **37/48 = 77.1%** supported precision; **48** authority relationships; **2/4** supported attack paths.

The v3 improvements were real, but v4 shows they do not yet generalize to the >=90% target. The next work should focus on shared effect inference, cross-file authority propagation and collection/factory normalization rather than another round of repo-specific rules.
