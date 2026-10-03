# Agent-centric unseen 12 v5 — blind holdout result

## Protocol

The cohort was frozen at commit `7757d09d7f03ca86dc31febf4dfc2e2823c2bda1` before any HorusTrace execution. The scanner code baseline was the merged #307 commit `86145932dce3895406f9e57b6783ad6eb706a107`.

- Workflow run: **37110834365**
- Run URL: https://github.com/psandhir/horustrace/actions/runs/37110834365
- Cases: **12/12**
- Frameworks: Google ADK 4, Pydantic AI 4, OpenAI Agents 4
- Prior HorusTrace research matches for selected repositories: **0**

## Raw scanner result

| Framework | Repos | Agents | Authority relationships | Findings | Attack paths |
|---|---:|---:|---:|---:|---:|
| Google ADK | 4 | 8 | 54 | 25 | 1 |
| Pydantic AI | 4 | 6 | 17 | 11 | 0 |
| OpenAI Agents | 4 | 10 | 47 | 37 | 8 |
| **Total** | **12** | **24** | **118** | **73** | **9** |

## Source adjudication — finding precision

A finding is counted as materially supported when the source supports the core security claim. Static paths through a fixed executable/argv boundary are counted as **qualified**, not proof of arbitrary command injection.

| Framework | Findings | Supported / qualified | Clear FP | Materially-supported precision |
|---|---:|---:|---:|---:|
| Google ADK | 25 | 23 | 2 | 92.0% |
| Pydantic AI | 11 | 9 | 2 | 81.8% |
| OpenAI Agents | 37 | 35 | 2 | 94.6% |
| **Total** | **73** | **67** | **6** | **91.8%** |

Attack paths: **7/9 materially supported or qualified**. The two clear false paths are the PATH012 findings in `aaronkazah/trunks`, where both PR-agent implementations route model-selected paths through an explicit workspace-containment helper.

### Clear false positives

1. `unseen5-adk-001` — `tool_list_datalog_files` is flagged by AGT040 as a writer because local list `.append()` is treated as persistent mutation in ADK analysis. The function only enumerates/reads files.
2. `unseen5-adk-004` — NET001 treats the GitLab endpoint as an unconstrained dynamic URL even though the helper derives it from operator configuration `GITLAB_URL` (default `https://gitlab.com`).
3. `unseen5-oai-002` — two PATH012 findings miss the explicit `_safe_path` workspace-containment check before reads/writes.
4. `unseen5-pyd-004` — AGT040 says `create_order` has no guardrail, but the tool explicitly returns without trading unless `ctx.deps.allow_trading` is true.
5. `unseen5-pyd-004` — NET002 loses the operator-configured `ALPACA_URL` destination carried through `AlpacaConfig.base_url`.

## Recall / semantic-fidelity findings

The v5 holdout shows that **tool binding recall is materially stronger than effect/control recall**. The important remaining gaps are systematic rather than repository-specific.

### Google ADK

- `unseen5-adk-002` — `add_task`, `schedule_event`, `add_note`, and `execute_software_action` perform SQL INSERT + commit, but are classified as `data.read`; write authority is missed.
- `unseen5-adk-002` — root-agent delegation tools are bound but their delegated authority is not propagated.
- `unseen5-adk-003` — `require_confirmation=True` on `complete_purchase` is correctly recovered, but UCP network/write effects behind the module-level `UCPClient` instance are largely absent.
- `unseen5-adk-004` — the five direct GitLab read tools are bound, but the configured `MCPToolset` in the same `tools=[...]` list does not survive as an MCP authority relationship.
- `unseen5-adk-001` — repository-local subprocess effects are partially recovered, but `tool_find_loop_functions` is misclassified as a write instead of process execution and local collection mutation still creates one false write.

### Pydantic AI

- `unseen5-pyd-001` — `bash -> asyncio.to_thread(_run_bash_sync) -> subprocess.run(shell=True)` binds as a tool but loses `process.execute`.
- `unseen5-pyd-003` — `reply`, `run_command`, and `toggle_feature` bind, but their outbound mutation / command / config-write semantics are not recovered; the explicit allowed/blocked-action and permission checks are not represented as controls.
- `unseen5-pyd-004` — `close_position` loses destructive/external write semantics, `web_search` loses external-network semantics, `ALPACA_URL` provenance is lost, and `allow_trading` is not recognized as a runtime guard.

### OpenAI Agents

- `unseen5-oai-003` validates the post-v4 MCP factory work: async factory composition survives as a local MCP relationship.
- `unseen5-oai-004` validates cross-file FunctionTool effect propagation at larger scale: 27 relationships and source-backed GitHub writes are retained.
- `unseen5-oai-002` exposes a containment-analysis gap: `_safe_path` proves workspace confinement but PATH012 still fires.
- `unseen5-oai-001` correctly recovers model-controlled `shell=True` subprocess paths.

## Build decision

Do not tune individual repositories. The next scanner patch should add reusable semantic primitives:

1. SQL statement mutation classification for `execute(...)` / commit flows.
2. Async executor-wrapper propagation, beginning with `asyncio.to_thread` and equivalent executor patterns.
3. Mutating HTTP verb semantics (`post`, `put`, `patch`, `delete`) including destructive-write classification where appropriate.
4. Operator-configured destination provenance across helper-local URL construction and config objects.
5. ADK MCPToolset variable binding when used inside `tools=[...]`.
6. Source-proven path-containment recognition for helper functions such as resolved-path parent checks.
7. Runtime guard recognition for privileged calls gated by explicit boolean/policy checks.
8. ADK local collection-mutation suppression, matching the OpenAI fix already shipped.
9. Repository-local object-method effect propagation for module-level client/config instances.

The first seven are P0 because each closes either a clear v5 false positive or a high-value authority miss. Object-method propagation is the broader follow-on if it cannot be landed cleanly in the same patch.
