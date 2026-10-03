# Pydantic AI fundamentals — result

## Executive result

The canonical Pydantic AI authority model is **largely sound in HorusTrace**, but two modern composition constructs still violate the fundamental rule that explicit model-callable authority must never silently disappear.

- Workflow run: **37144877122**
- Study cases: **15/15 completed**
- Fully passing cases: **13/15**
- Scanner changes in study: **none**

## Invariant score

| Invariant | Passed | Total | Rate |
|---|---:|---:|---:|
| agent discovery | 15 | 15 | 100.0% |
| tool binding | 14 | 15 | 93.3% |
| toolset / MCP binding | 14 | 15 | 93.3% |
| dynamic authority visibility | 13 | 15 | 86.7% |
| effect semantics | 14 | 15 | 93.3% |
| local vs external distinction | 15 | 15 | 100.0% |
| scope / provenance | 15 | 15 | 100.0% |
| controls / approval | 15 | 15 | 100.0% |
| authority-driven findings | 14 | 15 | 93.3% |

## Passing fundamentals

The following canonical constructs pass end-to-end in the study:

1. direct `Agent(..., tools=[...])`;
2. `@agent.tool` with approval;
3. post-construction `agent.tool_plain(...)`;
4. `FunctionToolset` decorators and `add_function`;
5. `CombinedToolset` + `ApprovalRequiredToolset`;
6. filtered/deferred toolset composition;
7. remote `MCPToolset`;
8. local stdio MCP plus repository-local FastMCP effect propagation;
9. runtime `agent.run*(..., toolsets=[...])`;
10. built-in/harness capabilities including WebSearch, FileSystem, Guardrails and MCP;
11. factory-returned Agent with function-local toolset;
12. RunContext dependency/session mutation is not promoted to persistent external write;
13. source-visible pure `add` / `execute_plan` functions are not promoted to write/process authority from names alone.

This is strong evidence that the main Pydantic normalization architecture is correct: framework syntax establishes binding, generic source semantics establishes effects, and effective-authority/rules operate on the normalized result.

## Fundamental gap 1 — dynamic @agent.toolset

Case: `pyd-fund-10-dynamic-agent-toolset`.

Observed output:

- Agent is discovered.
- A `dynamic_configuration` diagnostic is emitted.
- Agent has no tools.
- Agent has no MCP servers.
- Agent has no effective-authority relationships.
- No `dynamic_tools` authority marker is retained.

The scanner understands that the construct is dynamic, but the explicit authority binding exists only in a diagnostic side channel. This violates the study invariant.

### Required behavior

Do **not** attempt to enumerate an arbitrary dynamic toolset.

Instead preserve an unresolved bound-authority edge, for example:

```text
Agent
  -> dynamic toolset
       binding: proven
       catalogue: unresolved
       effect: unresolved
```

This is a bounded normalization fix, not a compiler-style Python analysis project.

## Fundamental gap 2 — declarative Capability(...) bundle

Case: `pyd-fund-12-capability-bundle`.

Observed output:

- Agent is discovered.
- `unmodeled_capabilities=['refunds']` is recorded.
- The capability's decorated `lookup_order` tool is not bound.
- Its source-visible network effect is absent.
- No effective-authority relationship or resulting finding is emitted.

This is more significant than an obscure extension pattern because modern Pydantic AI uses capabilities as a primary reusable extension abstraction.

### Required behavior

For source-visible declarative `Capability(...)` objects:

- collect `@capability.tool` / `@capability.tool_plain`;
- collect source-visible `tools=` and `toolsets=` on the capability;
- when the capability is passed in `Agent(capabilities=[...])`, project that authority onto the Agent;
- preserve `defer_loading` / dynamic pieces as unresolved when necessary.

Custom `AbstractCapability` subclasses can remain unresolved unless source analysis can safely identify their returned toolsets/native tools. We do not need exhaustive subclass execution.

## Architecture decision

No broad Pydantic redesign is indicated.

The study supports the existing separation:

```text
Pydantic syntax/binding
        ->
framework-neutral authority graph
        ->
repository effect semantics
        ->
controls + provenance
        ->
effective authority
        ->
findings / attack paths / Authority Contract
```

The two failures are both the same architectural class:

> **explicit authority-bearing composition is recognized but is not retained in the normalized authority graph.**

That is materially narrower than "we do not understand Pydantic AI".

## Recommended build decision

Implement only two framework-level fixes:

1. unresolved authority preservation for dynamic `@agent.toolset`;
2. declarative `Capability(...)` tool/toolset binding.

Then rerun this frozen 15-case study unchanged.

If those two classes pass without regressing the 13 passing cases, Pydantic AI should be considered sufficiently mature for first-class HorusTrace support. Further Pydantic work should be driven by production evidence rather than by searching for exotic syntax variants.
