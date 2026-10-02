# Agent-centric unseen 12 v2 — first-pass results

## Executive result

This is the first untouched run of the post-#295 scanner on a genuinely fresh 12-repository cohort, restricted to Google ADK, Pydantic AI and OpenAI Agents. Repository selection was frozen before HorusTrace execution and excluded 232 repositories used in prior HorusTrace research.

- Scanner baseline: `f18465fffbcac9c96457a2ef6b1fd5f26fd45857` (merged #295)
- Workflow run: `37055170677`
- Cases completed: **12/12**
- Findings: **29**
- Attack paths: **1**
- Materially supported findings after source adjudication: **16/29 (55.2%)**
- False-positive findings: **13/29 (44.8%)**
- Materially supported attack paths: **0/1**
- Strong source-visible recall/design gaps: **7 cases**

The result does **not** validate the frozen-cohort 53/53 precision as a generalization claim. The dominant product issue on this fresh cohort is no longer just precision; it is loss of effective authority at dynamic registries, local agent factories, nested tools, and MCP binding boundaries.

## Finding adjudication

| Framework | Findings | Materially supported | False positive |
|---|---:|---:|---:|
| Google ADK | 15 | 10 | 5 |
| Pydantic AI | 5 | 1 | 4 |
| OpenAI Agents | 9 | 5 | 4 |
| **Total** | **29** | **16** | **13** |

The single emitted attack path is a false positive. It treats an `ApplicationIntegrationToolset` statically fixed to `integration="sendEmail"` and `triggers=["api_trigger/send_email"]` as unrestricted external egress.

## Precision failure classes

### 1. Local/session state is being promoted to external `data.write`

In `box-community/box-openai-responses-ai-agent/test.py`, `update_seat` only mutates fields on `RunContextWrapper[AirlineAgentContext]`. HorusTrace emits AGT022, two AGT040 findings through direct/delegated authority, and CAP005. There is no external resource mutation. All four are effective-authority false positives.

**Invariant:** process-local/session/context mutation is not privileged external/resource `data.write` unless the mutated value reaches a persistent/external sink.

### 2. Unbound developer MCP configuration is still producing agent findings

In `dollro/spektr`, four findings come from repository `.mcp.json` entries that are not bound to the Pydantic application agent. Those should remain inventory/coverage. The Context7 entry also contains a `CONTEXT7_API_KEY` header, so AGT030 is independently incorrect.

**Invariant:** agent risk rules run only over source-proven agent-bound MCP authority. Unbound IDE/developer MCP config must not be projected into application authority.

### 3. Operator-configured and managed destinations are being treated as arbitrary

Two fresh ADK cases reproduce a broader destination-provenance issue:
- `CDAGENT_URL` configures a remote A2A endpoint; the value is dynamic, but the model cannot choose it.
- `ApplicationIntegrationToolset` is fixed to a named integration and trigger.

These produce NET002 and, in the integration case, PATH009.

**Invariant:** unknown-at-scan-time is not the same as model-selected. Preserve `operator_configured_destination` and fixed-managed integration provenance through authority projection.

### 4. ADK007 uses the wrong breadth abstraction for Application Integration

A single `ApplicationIntegrationToolset` fixed to one integration/trigger is flagged simply because it has no generic `tool_filter`.

**Invariant:** tool-surface breadth is framework-specific. Explicit integration/trigger restriction can itself prove a narrow surface.

## Recall/design gaps

### Dynamic bound tool registries

Two unrelated frameworks show the same structural miss:

- ADK: `ToolboxSyncClient(...).load_toolset("customer_data_tools") -> Agent(tools=tools)`
- OpenAI Agents: `get_arcade_tools(..., toolkits=["gmail"]) -> Agent(tools=tools)`

Both produce **zero tools** in effective agent authority. We do not need to invent the catalogue to preserve the relationship. The graph should contain a bound dynamic-toolset authority node with provider/registry provenance and unresolved capability/tool-scope dimensions.

### Function-local agents and nested/local tools

The scanner is still too top-level-centric.

- ADK DinoQuest builds its agent inside `build_agent()` and defines GitHub writes, Cloud Build submission, status/comment writes and artifact verification as nested model-callable tools. These disappear.
- Pydantic `BenedatLLC/agent-with-mcp-example` constructs an Agent and MCP server inside a function and immediately runs it; the MCP server is reported as unbound.
- OpenAI StarShell creates multiple shell/API/browser/MCP agents through factories. The scan finds 19 agents but only two tools and emits 18 unresolved-tool diagnostics.

This is a common source architecture, not a framework corner case.

### Bound MCP authority is not yet actionable enough

`burningion/pydantic-video-editing-agent` has 12 source-proven bound MCP relationships, including stdio package execution, but emits no agent-centric risk finding. We preserve the edge but stop before deriving policy-relevant unresolved/broad tool-scope and package-execution semantics.

## Product implication

The next build should **not** be another sequence of repo-specific pattern fixes. The unseen cohort says the current architecture needs a stronger authority composition layer:

1. **Bound dynamic authority** — preserve dynamic tool/toolset registries as explicit model-callable relationships with unresolved dimensions.
2. **Source-scoped local agent normalization** — normalize Agent instances created inside functions/factories and nested tool definitions, without conflating instances.
3. **Effect boundary taxonomy** — distinguish local/session mutation from persistent resource writes and external side effects.
4. **Binding-aware MCP policy** — findings derive from agent-bound MCP authority; unbound config stays inventory. Bound unresolved tool catalogues remain visible as uncertainty/risk.
5. **Destination provenance lattice** — fixed managed, fixed provider, operator configured, model selected and unknown must remain distinct end-to-end.
6. **Framework-specific surface constraints** — e.g. ADK Application Integration integration+trigger constraints count as explicit narrowing.

## Methodology note

This cohort is now consumed as a diagnostic/training cohort. Any fixes made from these results must be evaluated on a **new fresh holdout** before making another generalization claim. A patched rerun of these 12 repositories is useful for regression verification only.
