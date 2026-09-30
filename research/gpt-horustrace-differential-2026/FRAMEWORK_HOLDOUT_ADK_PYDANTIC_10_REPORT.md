# ADK + Pydantic AI unseen 10-repo holdout differential

## Objective

Test whether the semantic gains from the locked 10-repo ADK/Pydantic litmus generalize to a **fresh unseen holdout**.

The cohort and LLM/source review were locked before scanner reveal.

- Cohort lock: `05104912966ebfd08e500142aaac75e8b9f14626`
- Blind review lock: `ee5a1b53e187e79a7c26147a10bd322e76d38b31`
- Scanner source base: merged `main` `55f0da3d5231eb3c63591a643f338942ad1983d2`
- Reveal workflow commit: `529ed97ab134a96434bbdbabbf84d0e2e4e5f39c`
- Reveal run: `36744646489`
- Artifact: `11110894791`
- Scanned: **10/10**
- Scan errors: **0**
- HorusTrace findings: **10**
- HorusTrace attack paths: **1**

The first reveal attempt had a reporting-only serializer error (`SourceLocation.as_dict`) and is excluded from analysis. It did not produce usable scanner evidence.

## Locked-review alignment

The blind review contains **8 material semantic findings**. Current HorusTrace alignment:

| Metric | Result |
|---|---:|
| Full semantic matches | **2 / 8 (25.0%)** |
| Partial semantic matches | **2 / 8 (25.0%)** |
| Missed semantic findings | **4 / 8 (50.0%)** |
| Full + partial semantic coverage | **4 / 8 (50.0%)** |
| Precision controls | **4 / 4 passed** |

The review enumerates six source paths, but one (`ho-002`) is explicitly qualified as a deterministic/application flow rather than model-selected agent authority. Using the intended **5 model/agent paths**:

| Path metric | Result |
|---|---:|
| Full path matches | **1 / 5 (20.0%)** |
| Partial path matches | **2 / 5 (40.0%)** |
| Missed paths | **2 / 5 (40.0%)** |
| Full + partial path coverage | **3 / 5 (60.0%)** |

The separate deterministic `ho-002` dynamic A2A destination is also missed and should be tracked as an application-flow coverage gap.

## Case adjudication

### ho-001 — ADK MCP factory — **miss**

Locked finding: a root ADK LLM agent binds `search_youtube`, a higher-order wrapper that creates a stdio `MCPToolset` for the fixed command `mcp-youtube-search`. The concrete remote catalogue remains external/unresolved; no per-call approval is visible.

Scanner:
- detects `youtube_assistant`;
- detects **no bound tool** for `search_youtube`;
- detects **no MCP server**;
- emits no finding.

**Gap:** higher-order/function-factory tool provenance and ADK MCP creation inside a returned closure.

### ho-002 — custom ADK BaseAgent + dynamic A2A destination — **miss**

Locked finding: validated task input can choose `riskguard_url`, which reaches `A2ACardResolver(base_url=...)`.

Scanner:
- detects **zero agents**;
- emits no flow/finding.

The repository's AlphaBot and RiskGuard are custom `BaseAgent` subclasses rather than direct `Agent/LlmAgent` construction.

**Gap:** custom ADK `BaseAgent` subclass instances plus deterministic task-input -> dynamic A2A/HTTP destination provenance.

Precision point: source shows risk checking/proposal state, not broker trade execution. The scanner should not invent actual trade execution.

### ho-003 — ADK MongoDB cart write — **semantic full, path partial**

Locked finding: `add_to_cart` is model-callable and persists state using MongoDB `update_one(..., upsert=True)` without an explicit approval control.

Scanner correctly emits:
- `ADK001`
- `AGT040`
- `add_to_cart` capability = `data.write`
- inferred untrusted root-agent input

But it emits **no composed attack path** from root input to the state-changing tool.

**Gap:** generic ADK root-agent ingress -> source-bound write authority path composition.

### ho-004 — realtime deep research — **precision control passed**

Blind review expected no material high-risk finding: public WebSocket ingress reaches a read-only/fixed-provider Tavily research tool, not arbitrary egress or persistent mutation.

Scanner emits no findings/paths.

**Result:** precision control passed.

### ho-005 — Box remote object reads — **partial**

Locked finding: model-selected Box file/folder identifiers reach Box text extraction, recursive folder listing and Box AI ask/extract using the configured CCG client, with no wrapper-level object/resource allowlist.

Scanner correctly discovers:
- `box_generic_agent`
- seven model-callable Box tools
- `data.read` capability on those tools

It does not:
- model Box object IDs/folder IDs as remote resource selectors;
- detect broad/unconstrained external content scope;
- recover the custom parent `BoxAgent` ingress/delegation;
- emit a finding/path.

**Gap:** model-selected opaque SaaS object/resource identifiers and custom BaseAgent parent->child delegation.

### ho-006 — MongoDB RAG read-only — **precision control passed**

Scanner emits no findings/paths.

**Result:** correct. It does not invent write/exec/arbitrary-egress authority for a read-only RAG retrieval tool.

### ho-007 — HITL-gated RAG — **precision control passed**

Source withholds retrieved chunk contents from synthesis until the user explicitly approves chunk IDs.

Scanner emits no findings/paths.

**Result:** precision control passed. The source-level approval semantics are not fully normalized, but the scanner does not overstate the retrieval as uncontrolled exposure.

### ho-008 — Slack Pydantic agent — **one full, one partial**

Locked finding 1: Slack mention -> Pydantic agent -> `add_emoji_reaction` -> Slack write without per-call approval.

Scanner:
- detects source-bound Slack/application input through `run_agent:text`;
- detects `add_emoji_reaction` as `data.write`;
- emits `AGT022`, `AGT040`, and `PATH002`.

**Result:** full semantic/path match.

Locked finding 2: when `deps.user_token` exists, the Pydantic runtime attaches `MCPToolset("https://mcp.slack.com/mcp", Authorization=Bearer user_token)` with source-declared read/write/canvas authority and no per-call approval/allowlist.

Scanner finds a Slack MCP endpoint and emits `AGT032`, but the Pydantic `agent` itself has **no bound MCP server** in the normalized graph. The MCP finding is associated with the sibling OpenAI-Agents implementation in the same multi-SDK repository.

**Result:** partial at best; endpoint/tool-scope risk is recognized, but framework/principal binding is wrong.

**Gap:** Pydantic runtime-supplied `toolsets=` on `agent.run/run_sync`, plus cross-framework principal attribution in multi-SDK repos.

### ho-009 — Pydantic backend console toolset — **locked CLI findings missed; new precision issue**

Locked findings:
1. interactive CLI input -> shell execution, `require_execute_approval=False`;
2. interactive CLI input -> write/edit, `require_write_approval=False`, with directory confinement opt-in via `--restrict`.

Scanner detects the `Agent` constructor inside `create_cli_agent`, but:
- binds no console tools/capabilities to it;
- binds no CLI input;
- emits no CLI process/file findings or paths.

**Gaps:**
- `agent.with_toolset(toolset)` binding;
- `create_console_toolset` capability/approval semantics;
- factory-created agent returned to a caller and later invoked with CLI input.

The scanner instead emits three findings on the separate predictive-analytics example. Source adjudication shows there is real sandboxed read/write/delegated execution authority there, so this is not wholly spurious. However the evidence contains a **precision defect**:

- `resource_scope=<model-selected-path>`
- `path_parameters=ctx`
- `path_containment=not_detected`

`ctx` is a Pydantic `RunContext`, not a model-selected path parameter. The direct parent write is to fixed `/workspace/sales_data.json`, and the sub-agent's broader write/execute authority is inside a `DockerSandbox`.

**P0 precision gap:** exclude framework context parameters from model-selected path provenance and preserve sandbox qualification.

### ho-010 — reusable subagent library — **precision control passed**

The repository implements dynamic delegation infrastructure but does not establish a concrete privileged root application in Python source.

Scanner creates some library/test agent nodes but emits no findings/paths.

**Result:** precision control passed; it does not turn reusable library capability into deployed privileged authority.

## Framework split

### Google ADK

Locked semantic findings: 4.

- full: 1
- partial: 1
- missed: 2
- covered/partial: **50%**

The weakness is no longer basic `LlmAgent` parsing. It is **composition around custom BaseAgent classes, higher-order tool factories, external resource selectors, and ingress/path composition**.

### Pydantic AI

Locked semantic findings: 4.

- full: 1
- partial: 1
- missed: 2
- covered/partial: **50%**

The weakness is **runtime toolset binding and agent factories**, especially `agent.with_toolset(...)`, toolsets passed at `run/run_sync`, and backend capability semantics.

## What the holdout says

The frozen tuned cohort reaching 12/12 semantic and 9/9 path alignment did **not** generalize automatically. The holdout is substantially harder and exposes composition patterns that were absent from the training/fix-driving set.

At the same time, the scanner passed all four explicit negative/precision controls. This suggests the next phase should focus on **authority-binding completeness**, not broadening generic heuristics.

## Build priority

### P0 — precision regression

1. **RunContext is not a model-selected path.**
   Exclude framework/context/dependency parameters from model-controlled resource selector inference.
2. Preserve `DockerSandbox` / sandbox containment on nested console authority.

### P0 — Pydantic composition

3. Resolve `agent.with_toolset(toolset)`.
4. Normalize `create_console_toolset` read/write/execute capabilities and approval flags.
5. Bind runtime `toolsets=` supplied to `agent.run/run_sync`, including remote MCP.
6. Carry factory-created agents to later invocation/CLI ingress.

### P1 — ADK composition

7. Detect concrete custom `BaseAgent` subclass instances.
8. Follow higher-order tool factories/closures that return model-callable wrappers.
9. Recover ADK custom parent->child execution/delegation through object fields.
10. Compose inferred/root ADK input to source-bound privileged writes where framework invocation semantics support it.

### P1 — resource semantics

11. Model opaque remote SaaS resource selectors (e.g. Box `file_id`, `folder_id`) separately from local filesystem paths.
12. Track deterministic external input -> dynamic A2A/HTTP destinations without mislabeling them as model-selected.

## Recommended execution

Fix the **P0 precision regression first**, then Pydantic toolset/factory composition. Rerun this unseen holdout after each small tranche. Do not tune all cases at once: keep the original 10-repo litmus frozen and green while using this holdout as the new validation set.
