# P1.2 — Source-backed accuracy and regression study (2026-10-09)

## Status and provenance
Study stages completed: **Frozen-60 exact differential** and **targeted source review of 12 mixed-framework repositories**. An independent, exhaustive truth-labelled cohort and unseen holdout remain open. **This PR contains research evidence and decisions, not scanner remediations.**

- Before P1.2: `a08538858aa621e2e5f1a304c53ea753b94fe9ca`; workflow [37950577184](https://github.com/psandhir/horustrace/actions/runs/37950577184).
- After P1.2: `93c2f02fd3fc6909dc868e89aee1d8b8467b960c`; workflow [37988231309](https://github.com/psandhir/horustrace/actions/runs/37988231309).
- **60/60 exact case IDs, repository identifiers, pinned revisions, and retained source-pack bytes match.** Ten repositories per framework: Google ADK, Pydantic AI, OpenAI Agents, Amazon, Anthropic, Microsoft. Both cohort gates passed.
- Compared each retained `result.json` including relationship groups, findings, and the full `attack_paths` lists. Used **multisets**, not a dictionary by `relationship_id`, to preserve duplicate occurrences.

## Exact results

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Agents | 251 | 251 | 0 |
| Authority relationships | 606 | 606 | 0 |
| Findings | 409 | 411 | +2 |
| Attack paths | 15 | 15 | 0 |
| Core fully resolved | 479 | 465 | -14 |
| Core partially resolved | 127 | 141 | +14 |
| Core unknown | 0 | 0 | 0 |
| Core resolution ratio | 79.04% | 76.73% | -2.31 pp |

**All 60 before/after attack-path arrays were exactly identical.** This proves stability, not exploitability or recall. Path bases remain 3 static-dataflow / 7 source-bound-ingress-authority / 5 capability-cooccurrence.

A full multiset comparison of authority dimensions showed:
- **67** new resolved delegation targets and **14** new unknown delegation targets;
- **78** destination statuses changed from resolved to partially resolved;
- **17** resource statuses changed from resolved to partially resolved.

These are **176 dimension occurrences**, not new or removed relationships.

### Adjudication of the 14 core reclassifications

| Case | Count | Source evidence and decision |
|---|---:|---|
| `ff60-amazon-08` | 1 | Wazuh-Autopilot `backend/app/orchestrator.py:170–198`: runtime DB-selected `Swarm(list(agents.values()))`. **Correct unresolved membership.** |
| `ff60-anthropic-04` | 1 | data-agents `agents/supervisor.py`: registry-derived Claude subagents. **Correct conservative uncertainty.** |
| `ff60-google-adk-02` | **8** | MCP-GCP-governance-protocol `agent.py:23–54` plus `agent_liftoff_governor.py`: two entrypoints construct same-named agents. AgentTool references are lexically bound to construction-local agent objects, but repository-wide name matching reports ambiguity. **Conservative but unnecessarily imprecise; needs scoped target resolution.** |
| `ff60-google-adk-05` | **3** | adk-a2a-travel-assistant `agent.py:43–51`, imported A2A proxies in `routing.py`/`discovery.py`. Underlying agent and remote proxy can share names. **Needs source-instance-aware proxy/agent resolution; do not inherit child IAM.** |
| `ff60-google-adk-09` | 1 | voiceover `adk_agent/agent.py:43–53`: config-expanded `RemoteA2aAgent` instances. **Unresolved until dynamic configuration is known.** |
| **Total** | **14** | Five repositories; eight stable relationship identity groups. |

### Two additional findings — do not overclaim

- **`ff60-google-adk-07` / `mcp_adk` / NET002 (medium):** `examples/mcp/adk/agent.py:14–23` uses `get_adk_tools()`; `examples/mcp/adk/config.yaml:12–19` contains two fixed MCP URLs. Operator-configured endpoints are **not automatically an enforced allowlist**, but the cross-file configured targets are currently not correlated with the agent. **Adjudication: partly source-supported heuristic; destination-correlation gap.**
- **`ff60-pydantic-ai-07` / `agent` / NET002 (medium):** `excel_agent/agent_runner.py:69–105` binds `MCPServerSSE(url=self.mcp_server_url)`. **Adjudication: source-supported potential risk** due to runtime-configured endpoint; enforcement/exploitability remain unverified.

**Independent precision issue:** nine of the sixty frozen cases have duplicate `relationship_id` values across distinct relationship occurrences; source-qualified instance identity should be incorporated in portable canonical IDs. No source-backed record should be lost by keyed de-duplication.

## Targeted 12-repo source inspection

This is **construct-focused evidence review**, not an exhaustive independent gold labelling exercise.

| Framework | Cases | Source observations |
|---|---|---|
| Google ADK | 02, 07 | Local AgentTool constructor binding versus duplicate names; dynamic MCP factory versus concrete YAML endpoints. |
| Pydantic AI | 06, 07 | Model-callable `subprocess.run(..., shell=True)` risk; runtime-configured SSE MCP. |
| OpenAI Agents | 01, 10 | Box SaaS / WebSearchTool wiring; planning/search/summary agents and code-tool shell execution. |
| Amazon Strands | 08, 09 | DB-derived runtime Swarm membership; static `GraphBuilder` specialist topology. |
| Anthropic Claude SDK | 03, 04 | `bypassPermissions`, built-in tools and MCP; registry-derived specialists and tool approvals. Some scheduler-origin attack paths are **blocked by a missing local import** in pinned source. |
| Microsoft | 01, 07 | Sequential MAF workflow (`.AsAIAgent`); CopilotClient plus configured tool filters; runtime enforcement unverified. |

The selected constructs are generally recognized in the scanner's retained outputs. **Do not publish numerical precision/recall** from this pilot: the source has not been exhaustively labelled for every positive and missing graph tuple.

## Proposed work in priority order (not implemented here)

1. **P1 scoped delegation binding:** resolve by source object and application/construction entrypoint before a guarded global name fallback; test ADK02/05.
2. **P1 portable relationship identity:** stable, unique IDs per source-backed occurrence; validate nine duplicate-ID cohorts without changing workspace portability.
3. **P1 config-aware MCP destinations and NET002 semantics:** correlate ADK07 config-declared URLs while preserving the distinction from enforced egress restrictions; retain Pydantic07 dynamic state.
4. **P1 imported RemoteA2aAgent proxy matching:** keep local agent, remote proxy and destination separate.
5. **Study gate:** exhaustive truth-labelled 12–20-repo matrix across Agent → Tool/MCP/Skill → Capability → Identity → Resources/Destinations → Controls → Findings → Attack Paths; then SHA-frozen 10–12 genuinely unseen repository holdout.

### Limitations

All analysis is source-derived. The frozen cohort is a regression set, not a representative sample. Runtime IAM policy, network enforcement, tool execution, ability to exploit attack paths, and negative absence/recall were not independently tested. The final P1.2 code and Frozen-60 run are green, but the above precision issues merit targeted follow-up before a wider accuracy claim.
