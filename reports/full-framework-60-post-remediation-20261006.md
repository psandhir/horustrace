# Full-framework 60 post-remediation study

## Executive result

The frozen PR #391 cohort was rerun unchanged after the seven ordered remediation
items landed through PR #401.

- workflow run: `37467003426`
- frozen cohort blob: `1ea88dbb611cb7c0a81d5b8717553ef539cbdd49`
- baseline scanner: `bf02b7e831973ff733b6fab369094ce784e1a1bd`
- post-remediation scanner: `487bc856d26d072d2c0cc07489ec54cfdd477a7c`
- completed: **60/60**
- scan errors: **0**
- zero-agent cases: **2 -> 0**

| Metric | Baseline | Post | Delta |
|---|---:|---:|---:|
| Agents | 246 | 249 | +3 |
| Findings | 430 | 428 | -2 |
| Attack paths | 24 | 14 | -10 |
| Effective Authority relationships | 591 | 624 | +33 |
| Diagnostics | 161 | 156 | -5 |
| Zero-agent cases | 2 | 0 | -2 |

Raw count changes are not correctness metrics. The material deltas below were
source-adjudicated against identical retained source packs.

## Effective Authority resolution

The new two-level resolution model materially improves the usefulness of the
authority output without hiding unresolved dimensions.

- core fully resolved: **495/624 (79.3%)**
- core partially resolved: **129/624 (20.7%)**
- strict/detail partially resolved: **624/624**
- strict/detail unknown: **0**

Relationship source context:

- runtime: 469
- test: 59
- example: 56
- notebook: 22
- CLI: 12
- application-support: 6

This confirms the original “all relationships are partially resolved” metric was
low-information: most relationships have a source-proven target/capability core
while still honestly retaining unresolved identity, approval, resource or
destination dimensions.

## Attack paths

Post-remediation path basis:

- source-bound ingress authority: 6
- static dataflow: 3
- capability co-occurrence: 5

The aggregate path count fell from 24 to 14 primarily because 15 OpenAI paths in
`ff60-openai-agents-05` were generated from example agents. They are now
correctly retained as example-context findings but excluded from live attack
paths. This is an intended precision improvement, not lost runtime coverage.

`ff60-anthropic-03` moved in the opposite direction: five new paths are tied to
source-proven CLI/query ingress and explicit Bash/Edit/WebFetch authority. These
are higher-quality paths than the old capability-only projections.

## Source-adjudicated improvements

### Anthropic explicit tool surfaces

`ff60-anthropic-01`, `02`, `03` and `04` previously inherited an overly
broad Claude tool surface. Post-remediation output follows the explicit
`allowed_tools` / options configuration instead of automatically assigning the
full preset, removing unsupported Bash/write/network authority where it was not
configured.

### Anthropic missed SDK/Managed Agents

- `ff60-anthropic-09`: zero agents -> one source-proven Managed Agent.
- `ff60-anthropic-10`: zero agents -> one Managed Agent with four configured
  remote MCP servers.
- `ff60-anthropic-05`, `06`, `07`: previously unresolved TypeScript Agent
  SDK query/options composition now produces authority relationships.

### Microsoft workflow composition

`ff60-microsoft-01` now models the directly executed workflow as an
authority-bearing principal with three delegation relationships to the
source-defined workflow agents.

### Google ADK composition

`ff60-google-adk-09` now retains the Remote A2A delegation and dynamic remote
MCP surface rather than returning an empty authority graph.

### Amazon name-vs-effect semantics

`ff60-amazon-05` removed eight write/privilege findings that came from names of
tools such as `order_management_tool`. Source inspection shows these wrappers
perform authenticated HTTP invocation of specialist AgentCore runtimes; the
source-proven local effect is network egress, not a direct write. Retaining
`network.external` while dropping name-derived `data.write` /
`external.write` is correct.

## Residual gaps found by the rerun

### P0/P1 — Anthropic composed constraints and enforcing controls

Two cases remain materially over-projected.

1. `ff60-anthropic-07` explicitly configures
   `allowedTools = [Read, Write, Edit, Glob, Grep, Bash]`, then spreads the
   options into `optionsWithAbort`. The scanner widens this to the full
   11-tool Claude preset. Explicit tool constraints must survive object-spread
   composition.

2. `ff60-anthropic-06` uses `disallowedTools`, inline deny settings,
   `canUseTool`, and a PreToolUse guard to enforce read-only review semantics.
   The scanner currently projects the default tool surface without applying
   those source-proven restrictions, producing unsupported WebFetch/WebSearch
   and write authority and associated findings.

### P1 — Amazon literal MCP mutation effects

`ff60-amazon-10` demonstrates why body semantics must remain deeper than name
semantics.

- `update_iac_via_github` only returns instructions and does not perform the
  update: removing its name-derived write capability is correct.
- `create_branch_simple` directly calls
  `github_client.call_tool_sync(name="create_branch", ...)`: this is a
  source-proven external mutation, but the post-remediation scanner gives the
  wrapper no capability.
- `create_optimization_pull_request` calls `create_branch_simple`, so the
  mutation should propagate through the repository-local helper.

The repository-effect layer should understand literal MCP operation names in
source bodies and propagate their effects through local helpers.

### P1 — Managed Agent dynamic tool catalogue visibility

`ff60-anthropic-09` now discovers the Managed Agent, but
`tools=list(self.params.tools)` remains only a diagnostic. The authority report
has no relationship representing the source-proven-but-non-enumerable tool
catalogue. The scanner must not invent tools, but should expose this as explicit
unresolved authority rather than an empty authority surface.

## Recommended next remediation order

1. Preserve Anthropic explicit allow/deny/control semantics through composed
   TypeScript/Python options.
2. Recover source-proven literal MCP mutation effects and helper propagation.
3. Represent dynamic Managed Agent tool catalogues as unresolved first-class
   authority.

After those targeted fixes, rerun only the affected frozen cases first; if they
adjudicate cleanly, run the full 60 once more as the final closure check.
