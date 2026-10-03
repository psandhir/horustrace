# Agent-centric unseen 12 v5 — post-#313 regression validation

## Scope

This is a **regression rerun**, not a new blind generalization cohort.

The exact v5 repository set and pinned repository SHAs from #309 were reused unchanged. The scanner baseline is current `main` after #312 and #313:

- scanner SHA: `0a2dd7f6098fb94321e7c2fb4602cc8cc016555e`
- frozen cohort commit: `7757d09d7f03ca86dc31febf4dfc2e2823c2bda1`
- original v5 scanner baseline: `86145932dce3895406f9e57b6783ad6eb706a107`
- regression workflow run: **37114881586**
- cases: **12/12**
- target repository SHAs changed: **0**

# Raw scanner delta

| Metric | #309 baseline | post-#313 | Delta |
|---|---:|---:|---:|
| Agents | 24 | 24 | 0 |
| Effective-authority relationships | 118 | 118 | 0 |
| Findings | 73 | 109 | +36 |
| Attack paths | 9 | 19 | +10 |
| ADK findings | 25 | 35 | +10 |
| Pydantic AI findings | 11 | 13 | +2 |
| OpenAI Agents findings | 37 | 61 | +24 |

The increase is primarily semantic recovery, not new agent/tool binding: the relationship count is unchanged while previously empty or read-only relationships gain source-backed write/process/destructive effects.

## Known v5 false-positive closure

All **6/6** clear false positives recorded by #309 disappear:

1. BinCodeQL local list mutation no longer creates the `tool_list_datalog_files` write finding.
2. GitLab `GITLAB_URL` is preserved as an operator-configured destination, removing NET001.
3. Both Trunks PATH012 findings disappear after source-proven workspace containment is recognized.
4. Alpaca `create_order` no longer emits the no-guardrail AGT040 because `allow_trading` is recognized as a runtime gate.
5. Alpaca `ALPACA_URL` provenance is retained through `AlpacaConfig.base_url`, removing NET002.

## Delta adjudication with the #313 schema

This regression review reuses the #309 source adjudication for unchanged findings and applies the #313 `supported / partial / unsupported / unresolved` schema to newly introduced findings.

- prior materially-supported findings retained: **59**
- prior false positives retained: **0**
- new findings: **50**
  - supported: **38**
  - partial: **12**
  - unsupported: **0**
  - unresolved: **0**
- current materially-supported findings: **109/109**
- materially-supported precision on this frozen regression: **100%**
- new-finding strict precision: **38/50 = 76.0%**
- new-finding materially-supported precision: **50/50 = 100%**

The 12 partial findings are the new Trunks PATH001 compositions for `pull`, `list_files`, `read`, `write`, `checkpoint`, and `push` across the two normalized agent implementations. The tools can trigger real subprocess execution, but most execution is a fixed `trunks` mount/action boundary rather than proof that untrusted content controls an arbitrary command. They are therefore materially real but require `runtime_qualification` / `reachability` qualification.

Attack paths are **19/19 materially supported or qualified**. The 12 newly added Trunks PATH001 paths are qualified for the same fixed-executable/runtime reason.

## Primitive-level result

| v5 primitive | Post-#313 status | Evidence |
|---|---|---|
| SQL mutation classification | **Fixed** | ADK-002 recovers INSERT/commit writes; 15 source-backed findings appear. |
| Async executor propagation | **Fixed** | Pydantic-001 recovers `bash -> asyncio.to_thread -> subprocess.run`; search subprocess use is also recovered. |
| Mutating HTTP semantics | **Fixed for exercised paths** | Alpaca create/close operations gain external/write/destructive effects. |
| Operator-configured destination provenance | **Fixed** | GitLab `GITLAB_URL` and Alpaca typed `cfg.base_url` are constrained destinations. |
| ADK MCPToolset variable binding | **Not fixed end-to-end** | GitLab MCP declarations remain `declaration_not_agent_bound` in `mcp_authority`. |
| Source-proven path containment | **Fixed** | Both prior Trunks PATH012 false paths disappear. |
| Runtime policy/boolean guard recognition | **Fixed for exercised Alpaca gate** | `allow_trading` suppresses the prior AGT040/AGT022 control-gap findings. |
| ADK local collection mutation suppression | **FP fixed, recall regression exposed** | Local list write FP disappears, but three real helper effects also disappear. |
| Repository-local object/client propagation | **Still incomplete** | Existing ADK/Pydantic client/object-method gaps remain. |

## Important regressions / residual recall gaps

### 1. Function-local imported helpers are still not summarized

Three previously materially-supported BinCodeQL findings disappear:

- `tool_extract_facts_batch`
- `tool_find_loop_functions`
- `tool_resolve_calls`

The direct tool bodies import repository helpers inside the function. Those helpers perform real process/persistent effects, but repository-effect propagation currently indexes module-level imports. Suppressing the old name-only write signal therefore exposes a genuine transitive-recall gap.

This should be fixed by resolving **function-local repository imports**, not by restoring name-based write inference.

### 2. ADK MCPToolset binding is not reaching effective MCP authority

In `unseen5-adk-004`, the configured `gitlab_mcp = MCPToolset(...)` is present in the repository and appears in the agent's `tools=[...]` composition, but post-#313 output still reports:

- `bound_relationships: 0`
- `unbound_servers: 2`
- reason: `declaration_not_agent_bound`

The adapter-level binding change does not yet survive the downstream MCP authority reconstruction.

### 3. Earlier v5 semantic gaps remain

These were not introduced by #312, but remain visible:

- ADK-003: UCP effects behind the module-level client remain largely absent.
- Pydantic-003: `reply`, `run_command`, and `toggle_feature` still lose important outbound/command/config mutation semantics.
- Pydantic-004: `web_search` still lacks the repository-local Tavily network effect.
- ADK-002: delegated child authority is still not fully projected through the root delegation relationships.

## Build decision

#312 is a material improvement and closes every known v5 precision defect, but the frozen rerun also exposes two P0 integration gaps that should be fixed **before v6**:

1. repository effect propagation through function-local imports;
2. ADK MCPToolset binding through the full MCP-authority reconstruction pipeline.

Do not tune the v5 repositories. Add those as shared primitives, rerun this exact frozen cohort once more as a regression check, and then freeze a fresh v6 unseen cohort.
