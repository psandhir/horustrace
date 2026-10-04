# Pydantic AI unseen holdout 8 — baseline source adjudication

## Validation identity

- scanner baseline: `cce9e3f286d103b587d29a32fe10c6d5396a16b8`
- frozen workflow run: **37225838818**
- cases completed: **8/8**
- zero-agent cases: **0**
- framework agents: **14**
- tools: **14**
- MCP servers: **1**
- effective-authority relationships: **15**
- findings: **10**
- cohort inputs changed after scanner reveal: **no**

The workflow result is execution status only. The conclusions below come from GPT-5.6 Sol source adjudication of the pinned source bundles and exact repository source.

## Executive result

Pydantic root discovery generalises well: all eight unseen applications produced Pydantic principals.

The material gap is **repository-composed authority**. Five applications prove that tools, toolsets, MCP or capabilities are bound to an Agent, but HorusTrace currently collapses that binding to an empty principal when the concrete catalogue is assembled through helper kwargs, runtime parameters, a configuration registry or a repository-local custom toolset.

Two cases are healthy enough to act as positive controls:
- `pyd-hold-004`: declarative `Capability` bundle -> bound retrieve tool with read semantics.
- `pyd-hold-008`: factory-local `MCPServerStdio` -> correctly bound stdio MCP authority.

No normalized-graph redesign is indicated.

## P0 — proven dynamic authority is diagnosed but then disappears

Cases:
- `pyd-hold-001` — Prefect Marvin
- `pyd-hold-002` — MCBE-AI-Agent
- `pyd-hold-005` — agentic
- `pyd-hold-007` — llm-do

### Source truth

These repositories explicitly bind authority to a Pydantic Agent, but the catalogue is assembled indirectly:

- Marvin builds `agent_kwargs`, conditionally assigns `agent_kwargs["tools"] = combined_tools` and `agent_kwargs["toolsets"] = active_mcp_servers`, then calls `Agent(**agent_kwargs)`.
- MCBE passes a runtime `toolsets` parameter into `Agent(toolsets=toolsets)`, builds a harness capability with a helper and registers repository tools after construction.
- agentic builds `capabilities` from a configuration-driven registry. The registry contains security-relevant capability families including code execution, MCP/Gitea, console execution, memory and skills.
- llm-do passes runtime `tools`, `toolsets` and built-ins through a helper-built Agent.

### Observed

The scanner usually emits a `dynamic_configuration` diagnostic, but the normalized principals contain zero tools/MCP/effective-authority relationships.

### Required

A source-proven dynamic binding must remain visible in the normalized graph even when the concrete members are unresolved.

Do **not** invent the runtime catalogue. Preserve:
- dynamic tool binding;
- dynamic toolset/capability binding;
- MCP-specific unresolved binding when the source proves an MCP-typed catalogue;
- configuration dependence/provenance;
- an unresolved effective-authority relationship instead of an empty principal.

This is an information-preservation fix, not a heuristic capability expansion.

## P0 — repository-local custom FunctionToolset authority is lost

Case:
- `pyd-hold-006` — Daytona integration

### Source truth

`build_agent()` binds `DaytonaToolset()` through `Agent(toolsets=[DaytonaToolset()])`.

`DaytonaToolset(FunctionToolset)` statically registers:
- `run_python(code)`
- `run_shell(command)` when `include_shell=True` (the default)

Both functions execute model-selected code/commands inside a fresh remote Daytona sandbox.

### Observed

The Agent root is found, but it has zero tools and zero authority relationships.

### Required

Resolve repository-local subclasses of `FunctionToolset` when their `super().__init__(tools, ...)` tool collection is statically enumerable.

Preserve the remote/sandbox boundary. Do not misrepresent Daytona execution as local host execution.

## P0 — MCP capability transport composition is not resolved

Case:
- `pyd-hold-003` — AIBA

### Source truth

The sub-agent binds:

`MCPCapability(local=playwright_transport, id="playwright", ...)`

where `playwright_transport = StdioTransport(command="uv", args=playwright_mcp_args, ...)`.

The binding is explicit and source-visible. The arguments are partly dynamic but the stdio transport and command are known.

### Observed

The sub-agent has 13 bound tools but zero MCP servers; `playwright_cap` remains an unmodeled capability.

### Required

Resolve named `local=` transports inside Pydantic `MCP` capabilities and preserve:
- stdio transport;
- fixed command when visible;
- partially dynamic args explicitly;
- MCP authority binding.

## P0 — cross-file Pydantic Agent.run delegation is lost

Case:
- `pyd-hold-003` — AIBA

### Source truth

The model-callable `spawn_sub_agents` tool invokes imported `sub_agent.run(...)`. Both parent and child are normalized Pydantic agents.

### Observed

The wrapper tool is present but has no `agent.delegate` binding and therefore does not inherit the child agent's effective authority.

### Required

Repository-level Pydantic delegation resolution should bind an imported agent alias to the unique normalized child principal without treating arbitrary object `.run()` calls as delegation.

The prior `subprocess.run` false-positive fix must remain intact.

## P1 — source effect semantics: SMTP side effect is currently missed

Case:
- `pyd-hold-003` — AIBA

The bound `send_email` tool calls `smtplib.SMTP(...).send_message(...)`. Source proves external/network side effects, but the normalized tool currently has no network/external-write capability.

This is a generic source-effect gap surfaced by the Pydantic cohort. A bounded source rule for standard SMTP clients is justified; do not infer arbitrary egress from the function name alone.

## Finding precision adjudication — AIBA

The ten AIBA findings are not all equivalent.

Source-supported:
- combined read/write authority is real for the CSV tool surface;
- the sub-agent has unconstrained internet retrieval through WebSearch/WebFetch, so the outbound-destination gap is materially supported;
- model-selected file names reach local file reads under `.playwright-mcp/` without a traversal-containment check, so the filesystem-path risk is source-supported;
- the direct CSV append authority is a real state-changing operation.

Qualifications / overstatement to fix:
- the main agent can conditionally include `ToolGuard(require_approval=...)` when guardrails are enabled. An unconditional "no approval/control" assertion loses that source-visible conditional control and should be qualified/suppressed unless the configuration proves it absent.
- `preview_click` writes an internally generated preview image under the agent's Playwright artifact directory. Treating that internal artifact write as equivalent to an externally meaningful state mutation overstates the security effect.

These precision issues should be fixed alongside recall so the cohort does not improve merely by emitting more findings.

## Healthy controls

### pyd-hold-004 — Pydantic-AI-Pinescript-Expert

Source-visible `Capability` composition and the bound `retrieve` tool are correctly retained. The tool is read-oriented; no mutation finding is expected.

### pyd-hold-008 — mcp-compose

The factory-local `MCPServerStdio` binding is correctly normalized with command and arguments. The downstream MCP tool catalogue is runtime-discovered, so not inventing concrete calculator/echo tools is correct.

## Build decision

Fix four architectural classes:

1. **dynamic binding preservation** for `**kwargs`, runtime tools/toolsets and capabilities;
2. **repository-local FunctionToolset subclass resolution**;
3. **named local transport resolution for Pydantic MCP capabilities**;
4. **repository-level cross-file Agent.run delegation**.

Also make two bounded semantic precision fixes:
- standard-library SMTP external effect;
- internal generated-artifact writes / conditional ToolGuard control posture.

Keep the exact eight repositories and SHAs unchanged for the rerun.
