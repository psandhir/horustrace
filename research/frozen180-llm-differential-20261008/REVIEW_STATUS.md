# Frozen 180 active-framework security differential — evidence checkpoint

**Study status: evidence recovered; independent LLM adjudication NOT completed.**

- Original frozen 180, fixed historical SHA and scanner commit `58a2d14ac6456b3f2e2f726484e33763352d6f17`.
- Deliberately deprecated LangGraph: **35/180 excluded from active-framework evaluation**.
- Eligible repositories: **145** (all 145 exact-commit source-only packet fetches succeeded).
- Scanner-reported individual paths: **45** across 17 cases; **45/45 reconstructed** with the original authority-scope expansion logic.
- Scanner findings: **267**, including **11 critical, 58 high and 198 medium**.
- Source packet limits: 31 cases include omitted/truncated material; do not claim exhaustive negative results from bounded source alone.
- **Attack-path/finding FP, FN, complete-miss precision/recall: unknown.** No independently executed or locked OpenAI-model Phase A or Phase B reviews. This run does not satisfy G2/G3 in [the evaluation contract](../STUDY_EVALUATION_CONTRACT.md).

## Source-only / scanner-coordinator separation

- [Source-only artifact](https://github.com/psandhir/horustrace/actions/runs/37791894378): one pinned-source text and source manifest per active framework case, **no scanner output**.
- [Scanner coordinator artifact](https://github.com/psandhir/horustrace/actions/runs/37791894378): 17 case graphs/scans and the 45 effective attack-path records. **Never pass this artifact to blind Phase-A judges.**
- The historical replay stored aggregate path counts only; the first reconstruction mistakenly captured 43/45. The original runner expands local-import scope for effective authority, so the corrected reconstruction replays that expansion and matches **45/45**.

## Retrospective GPT-6 source-inspection leads (not formal verdicts)

| Case | Observation | Preliminary inference |
|---|---|---|
| [rw-080](https://github.com/Amlan66/SSEEnabledMCPAgent/blob/11531239e71b123f25b3c6103ee36a9d614d0032/agent.py#L124-L134) | Custom `AgentLoop(user_input, dispatcher=multi_mcp)` invoked from CLI, model plans `dispatcher.call_tool` ([loop](https://github.com/Amlan66/SSEEnabledMCPAgent/blob/11531239e71b123f25b3c6103ee36a9d614d0032/core/loop.py#L112-L121)); configured MCP server [profile](https://github.com/Amlan66/SSEEnabledMCPAgent/blob/11531239e71b123f25b3c6103ee36a9d614d0032/config/profiles.yaml#L27-L31) exposes shell and [code exec](https://github.com/Amlan66/SSEEnabledMCPAgent/blob/11531239e71b123f25b3c6103ee36a9d614d0032/mcp_server_1.py#L171-L190) tools; HorusScan reports zero agents, paths or findings | High-priority candidate complete miss of custom agent/tool reachability. The configured Windows working directory may impair runtime portability; do not claim a confirmed runnable exploit without resolving this |
| [rw-152](https://github.com/kumarvipu1/agentic-ppt-slide/blob/2614076f9fbb0cdde10e481918b5177c5c3399c8/agent_tools.py#L211-L230) | Tool compiles and executes model-supplied code | Source-supported execution effect; full path controls unresolved |
| [rw-169](https://github.com/badlydrawnrod/agent-c/blob/9789e93dab47c4bd38ccc6fe19c3761f611d09e4/src/agentc/core/backends/pydantic_ai/tools/execution.py#L11-L30) | Tool passes command to `asyncio.create_subprocess_shell` | Shell-execution effect supported, runtime controls unresolved |
| [rw-135](https://github.com/wuyoscar/Internal-Safety-Collapse/blob/c3d5a33e5438edc91aacfc17f9aa090c36c1905b/experiment/tvd_agent/agent.py#L55-L79) | Tool invokes `subprocess.run(command, shell=True)` | Shell-execution effect supported; audit workspace protections |
| [rw-118](https://github.com/undertherain/PaperX/blob/25af7bd2ec41a7b0c3b4033eb7328c1874e1aefd/redelivery_agent.py#L118-L132) | `subprocess.run` uses fixed interpreter/script and separate argument list | Process invocation supported, **arbitrary shell-command execution not established**; three PATH001 records require semantic precision / deduplication review |
| [rw-124](https://github.com/Danejw/ai-companion-backend/blob/5868863046a6b3e69cba9d07e98fb2bd357976d1/app/function/supabase_tools.py#L165-L171) | `clear_history` scopes deletion to `current_user_id` | Destructive effect exists; cross-user destruction unproven and source control must be included in severity |
| [rw-115](https://github.com/Meer-Promethean/Voice_Agent/blob/7a3b6e8ae8d9e2e3da9d597ee50cdf22041bc950/backend/main.py#L144-L176) | Public token route grants caller-specified realtime room/identity and publish permission | Token-issuance concern source-supported; broader unauthorized MCP state-change chain needs middleware/runtime review |
| [rw-150](https://github.com/Amar-Ag/project-ideation-tool/blob/cebe9e137ed676905bb08ba8d3287a6e704b08fa/src/agent.py#L424-L440) | Model-visible URL reaches `httpx.AsyncClient(follow_redirects=True).get(url)`; restriction is in instructions, not function validation | Conditional server-side URL request risk |
| [rw-007](https://github.com/joshnaim1/ocr-test/blob/12a850dec83f04039862fb6ef03e0fc80c462bf3/tools/document_ocr.py#L52-L85) | Tool reads selected local path and hands contents to Document AI | Source supports data movement; policy breach depends on scope/controls |

These observations are **not** two independent source-only judgments. The reviewer knew HorusScan output. They therefore must **not** be counted as definitive TP/FP/FN or used to estimate recall.

## Next gated phases — no second cohort

1. Independently run two scanner-blind model judges on all 145 exact-SHA source packets, including supplemental checks for truncated cases. Record model ID, full prompt hash, execution ID, source anchors, reviewer disagreements and lock time.
2. Reveal scanner results **after** Phase-A lock, independently validate all 45 paths and at least all 69 critical/high findings plus the prescribed rule × severity medium strata. Distinguish validity, duplicates, scope constraints, risk versus authorized behavior and severity.
3. Resolve disagreements, enumerate complete misses (including candidate rw-080 if upheld), publish exact source-supported TP/FP/FN and unresolved denominators. Do not use one GPT retrospective reviewer as an independent consensus pair.
4. Only after adjudication should we fix scanner algorithms and rerun frozen 180. Historical source-references remain immutable.
