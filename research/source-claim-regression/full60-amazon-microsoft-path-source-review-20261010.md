# Full-60 Amazon / Microsoft attack-path source review — October 10, 2026

## Why this is not a count-restoration task

The frozen Full-60 contains **10 Amazon and 10 Microsoft repositories, 141 findings across these frameworks, and zero attack paths**. High finding counts alone do **not** prove a runnable untrusted-input → privileged-action path. A valid path requires an attributable runtime agent, actual input reachability, a supported sink/authority and correctly scoped controls. The scanner should not create PATH001/PATH002 to meet framework count targets.

The following four **pinned full-study evidence bundles** were independently inspected after the P0/P1 merge. Source locations refer to those frozen bundles (not moving repository `main` branches).

| Frozen case | Source-backed observations | Scanner evidence | Adjudication |
|---|---|---|---|
| `ff60-amazon-04` — `aws-samples/sample-multi-agent-region-expansion-planner` | `main.py:56-59` constructs a Strands orchestrator with multiple agents and `shell` / `file_write` tools. `agents/multi_region_expansion_planner.py:104-111` calls a subordinate agent with interpolated parameters. | **2 agents, 27 findings, 0 flows, 0 paths, 14 diagnostics** (unresolved tools and dynamic configuration). | **Unresolved upstream authority / ingress.** Do not call an interpolated parameter untrusted or infer runtime shell exploitability without a proven source and tool binding |
| `ff60-amazon-10` — `caylent/DevOps-Agent-using-AgentCore-Strands-and-MCPs` | `main.py:164-165` has CLI `input()` for account selection; `main.py:489-490` passes `message` to `self.agent(message)`, behind a source-visible safety check at `main.py:487`. | **1 agent, 14 findings, 0 flows, 0 paths, 0 diagnostics**. | **Targeted source-binding candidate:** trace where `message` originates and whether the safety check enforces or merely advises. The existing zero paths are not a proven false negative without showing a connected privileged sink |
| `ff60-microsoft-06` — `microsoft/agent-framework` | `github_copilot_with_shell.py:33-44` creates `GitHubCopilotAgent` with a shell-related prompt/permission callback and calls `agent.run(query)` with a **literal fixed query**; `github_copilot_with_mcp.py:45-65` similarly demonstrates fixed-source calls. | **4 agents, 31 findings, 0 flows, 0 paths, 2 diagnostics**, including a framework-not-normalized construct. | **No demonstrated untrusted ingress in these sampled snippets.** Correct action is adapter diagnostic/fidelity review, not synthesising a live attack path from examples |
| `ff60-microsoft-09` — `UBC-FRESH/agent-workbench` | `agent_bridge/mcp_server.py:142-150` contains a `subprocess.run(command, shell=True)` sink. The server's `RunGrant` defaults to an empty `allowed_exec_commands` at lines 28–35; the tool schema describes exact-match grants at lines 77–92. | **3 agents, 15 findings, 0 flows, 0 paths, 2 expanded-argument diagnostics**. | **High-priority P1 trace review:** link any caller-controlled MCP argument through a *permitted* run grant before reporting an effective agent execution attack path. Source-visible shell execution alone is insufficient |

## P1 scanner work implied by these results

1. **Cross-framework ingress provenance**: for Strands `Agent(message)` and Copilot `agent.run(query)`, distinguish literal fixed query, CLI user-controlled message, web/session ingress and model tool arguments. Mark unknown callers *unknown*, not implicitly untrusted.
2. **Control-aware source-to-sink propagation**: traverse explicit helper calls and agent handoffs only when source bindings are proven; preserve `RunGrant` exact command restrictions and permission callbacks as constraints with enforcement verification still unproven.
3. **Diagnostic calibration**: surface the 14 unresolved Amazon-04 tools and the 2 Microsoft-06 missing framework normalizations in a study coverage summary, so zero paths cannot be misread as comprehensive security proof.
4. **Attack-path grading**: report `runtime_viability` (including source-error blocks) alongside flow basis. Maintain source-supported potential-risk labels and do not interpret a path without a blocker as exploitable.

## Acceptance criteria for targeted rerun

- Fixed source IDs, repository revisions and source-context classifications remain unchanged.
- Detect a source-backed user-controlled Strands ingress into an attributable runtime agent when all steps are visible, without inferring high-risk sinks not actually reachable.
- Preserve zero PATH001 for fixed literal Copilot example queries and for run-grant-rejected shell commands.
- A nonzero attack path must retain supporting nodes, source locations, provenance and applicable control metadata.
- Measure differential **source-backed cases**, not a minimum number of attack paths per framework.

**Status:** Source assessment completed for 4 representative cases. No false-negative determination is made for the remaining 16 without source review, and no hardcoded framework-level PATH fixes are justified at this stage.
