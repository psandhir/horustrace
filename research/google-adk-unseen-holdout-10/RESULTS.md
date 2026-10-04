# Google ADK unseen holdout 10 — baseline results

## Validation identity

- scanner baseline: `1be194c94b3b643f2c8d081e5fa14e6643eb3a9f`
- workflow run: **37216410301**
- cases completed: **10/10**
- zero-agent cases: **0**
- agents: **18**
- effective-authority relationships: **31**
- partially resolved relationships: **31**
- findings: **35**
- attack paths: **6**
- cohort inputs changed after scanner reveal: **no**

Raw counts are not accuracy scores. The conclusions below come from comparing each frozen source signal and retained source pack with the normalized agent/tool/MCP inventory and Effective Authority output.

## Executive result

Google ADK has strong structural generalization after the canonical depth-parity work:

- every selected application produced its material ADK root;
- inline MCP, direct/sub-agent delegation and unsafe local execution generalized materially well;
- the custom `BaseAgent` case was represented without inventing tool authority;
- no study case failed because of basic `Agent` / `LlmAgent` construction.

Four bounded semantic classes remain before calling real-world depth parity closed.

## P0 — helper-built ADK authority loses source-proven depth

Cases:
- `gadk-hold-001` — google/mcp-security
- `gadk-hold-002` — GoogleCloudPlatform/race-condition
- `gadk-hold-008` — Red Hat Lightspeed Agent

Observed behavior:
- helper-returned tool lists/toolsets are retained only as generic dynamic collections;
- source-visible nested `McpToolset` construction is not projected as conditional MCP authority;
- in `race-condition`, `SkillToolset(code_executor=UnsafeLocalCodeExecutor())` is source-visible but local process execution disappears.

Required behavior:
- recursively inspect bounded repository-local helper composition without executing target code;
- preserve source-visible tools, code executors and MCP constructors;
- preserve runtime-dependent branches/catalogues as conditional unresolved authority instead of inventing concrete runtime contents.

## P1 — document-database source effects are missed

Case:
- `gadk-hold-005` — MongoDB groceries agent

Source-visible operations include:
- `aggregate(...)`
- `find_one(...)`
- `update_one(..., upsert=True)`

Observed behavior:
- all three bound model-callable tools have empty capability sets.

Required behavior:
- recognize source-proven document-database read/write operations only when persistence context is evidenced;
- `find/find_one/aggregate` -> data read;
- `insert/update/replace/bulk_write` -> data write;
- `delete/drop` -> destructive write;
- do not infer destructive semantics for `update_one(..., upsert=True)`.

This is framework-neutral source semantics surfaced by the ADK holdout.

## P0 — ADK ToolContext.state is over-promoted as external/destructive authority

Case:
- `gadk-hold-006` — GoogleCloudPlatform new-hire onboarding

Source-visible tools mutate ADK session state through `ToolContext.state`, including list `.remove(...)` and state-key assignments. They do not perform the external provisioning, shipping or email side effects implied by their names.

Observed behavior:
- internal state changes are promoted to `data.write` / `destructive.write`;
- this produces source-unsupported destructive findings and attack paths.

Required behavior:
- generalize existing internal-state semantics beyond Pydantic `RunContext.deps`;
- treat source-visible `ToolContext.state` mutation as agent/session internal state;
- retain external authority if the same function also reaches a real external sink.

## P1 — imported FunctionTool delegation can disappear

Case:
- `gadk-hold-010` — project-horizon

Source:
- root Agent binds imported `delegate_tool`;
- `delegate_tool = FunctionTool(func=delegate_task_to_specialist)`;
- the wrapped function creates an A2A client from a runtime-discovered agent-card URL and sends a task.

Observed behavior:
- root agent is detected but has no tools and no authority relationships.

Required behavior:
- resolve repository-local imported ADK `FunctionTool` assignments;
- preserve the wrapped source function;
- represent A2A send authority as network/external delegation with runtime-discovered destination scope, without inventing a concrete specialist catalogue.

## Cases materially strong at baseline

- `gadk-hold-003`: custom `BaseAgent` root detected; no unsupported model-callable authority invented.
- `gadk-hold-004`: cross-file specialist delegation preserved; dynamic/runtime tool catalogues remain conservative.
- `gadk-hold-007`: async-factory multi-agent application retains three stdio MCP surfaces and delegated authority.
- `gadk-hold-009`: SkillToolset + stdio MCP + AgentTool + UnsafeLocalCodeExecutor retains high-authority local execution and produces composed paths.

## Build decision

No Google ADK redesign is indicated.

The fixes are four bounded architectural classes:
1. repository-local helper composition;
2. persistence/document-database effects;
3. framework context-state precision;
4. imported wrapper/delegation preservation.

Keep this cohort and all target SHAs unchanged. Implement the fixes separately, rerun the exact ten cases, and require source adjudication rather than raw count improvement.
