# Amazon SDK unseen holdout 10 — baseline results

## Validation identity

- scanner baseline: `1c3aac96851f2fe9856eaf858d7c2ffac0e46784`
- workflow run: **37220352640**
- cases completed: **10/10**
- zero-agent cases: **1** (`amazon-hold-006`)
- agents: **20**
- effective-authority relationships: **14**
- partially resolved relationships: **14**
- findings: **19**
- attack paths: **0**
- cohort inputs changed after scanner reveal: **no**

Raw counts are not accuracy scores. The conclusions below come from comparing the frozen source signals and retained source packs with normalized inventory and Effective Authority.

## Executive result

The canonical Strands constructs are sound, but real repositories expose them through composition patterns the current per-file adapter does not yet reconstruct deeply enough.

Four architectural classes remain.

## P0 — repository-level Strands principal construction

Cases:
- `amazon-hold-001`
- `amazon-hold-005`
- `amazon-hold-006`
- `amazon-hold-010`

Observed patterns:
- `self.agent = Agent(...)`
- `Agent(**agent_kwargs)`
- direct `return Agent(...)` factory
- local/factory agent creation with tools held in function-local variables

Observed outcome:
- principals are generic/empty, or absent entirely;
- `amazon-hold-006` is a zero-agent miss;
- class/factory tool bindings disappear.

Required behavior:
- discover source-proven Strands Agent calls independent of whether the assignment target is a simple module-level name;
- resolve source-visible `**kwargs` dictionaries;
- use a literal Strands `name=` where present, otherwise retain a source-factory/class identity and mark runtime name unresolved.

## P0 — repository tool/MCP collection composition

Cases:
- `amazon-hold-001`
- `amazon-hold-002`
- `amazon-hold-003`
- `amazon-hold-004`
- `amazon-hold-005`
- `amazon-hold-006`
- `amazon-hold-007`

Observed patterns:
- `tools = client.list_tools_sync()`
- addition of multiple MCP catalogues
- starred collections (`[*tools, ...]`)
- local lists with `.append()`
- `common_tools + agents`
- `strands_tools` vended imports
- repository-local imported decorated tools

Required behavior:
- resolve bounded local list/tuple/set/addition/starred composition;
- link source-visible `MCPClient.list_tools_sync()` results back to their MCP server while keeping the remote tool catalogue unresolved;
- recognize the public `strands_tools` package as the vended-tool surface;
- preserve conditional append branches as possible/conditional authority rather than dropping them.

## P0 — real Graph/Swarm construction through methods and dynamic membership

Cases:
- `amazon-hold-008`
- `amazon-hold-009`

Observed patterns:
- GraphBuilder created inside methods and returned directly via `return builder.build()`;
- Swarm members assembled from runtime/database-backed agent dictionaries;
- source-visible execution limits and cancellation hooks.

Required behavior:
- retain a Graph/Swarm orchestrator even when `.build()` is returned rather than assigned;
- preserve known edges/limits/hooks;
- when membership is runtime-derived, retain an explicit unresolved delegation set instead of emitting an empty orchestrator;
- resolve repository-local create_* agent factories where bounded and source-visible.

## P0 — framework attribution isolation

Cases:
- `amazon-hold-009`
- `amazon-hold-010`

Observed behavior:
- generic `Agent(...)` calls in Strands repositories were enriched as `google-adk` agents by the repository ADK pass.

Required behavior:
- repository-specific enrichment must require framework provenance;
- a generic class name such as `Agent` is insufficient to cross framework boundaries;
- do not create Google ADK principals from modules whose Agent symbol is sourced from Strands.

## Materially strong baseline behavior

- the newly added canonical GraphBuilder topology works when builder/result/member agents are statically local;
- canonical Swarm and A2A semantics remain sound;
- cross-file repository source-effect enrichment recovered substantial specialist tool effects in `amazon-hold-009`, although those principals were incorrectly attributed to Google ADK;
- hook enforcement logic itself is evidence-based; the remaining issue is reaching hooks through repository composition.

## Build decision

No Strands semantic redesign is indicated.

The next fix slice should add **repository composition** around the now-stable canonical adapter:
1. source-proven principal/factory discovery;
2. local/dynamic tool and MCP collection resolution;
3. method-returned Graph/Swarm normalization;
4. framework-provenance isolation.

Keep the ten repositories, SHAs and source signals frozen for the post-fix rerun.
