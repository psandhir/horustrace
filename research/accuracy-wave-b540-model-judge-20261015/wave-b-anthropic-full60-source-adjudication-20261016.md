# Wave B final Full-60 — Anthropic source-to-authority adjudication (2026-10-16)

## Method and limitation

Compared frozen source packs and the exact `effective-authority.json` from the original Full-60 run `37381193593` and final Wave B run `38940896262`. Reviewed explicit pinned `ClaudeAgentOptions` source declarations and available-tool controls for the four largest relationship-loss cases. This is model-assisted, source-backed review, **not independent human ground truth**. Runtime availability/effectiveness remains unverified. Treat dynamically built options conservatively.

The four cases lose **80** previously projected agent–tool authority relationships, with zero newly added *target-name* relationships in those same cases (sum: 12 + 9 + 15 + 44). This is a target-level comparison, not necessarily a semantic equivalence comparison for retained relationships.

| Case | Frozen upstream | Baseline -> final relationships | Artifact IDs (baseline/final) | Source observation | Adjudication |
| --- | --- | ---: | --- | --- | --- |
| `ff60-anthropic-01` | `AutoForgeAI/autoforge@427c228ed1e15c5d9f5be4b8b15539034ce6c878` | 39 -> 27 (-12) | `11375495199` / `12063795366` | `client.py` passes a variable `allowed_tools=allowed_tools` into `ClaudeAgentOptions` and several specialized clients construct distinct option sets. Historical removals are broad tools (`Agent`, `Workflow`, `NotebookEdit` etc.) not universally justified by this variable. | **Conditionally corrected** broad catalogue attribution; preserve unknown dynamic-tool contents, test exact per-client bindings. |
| `ff60-anthropic-02` | `fulcrumresearch/quibbler@960089e24833007de410c97f02fdecf8fdd863d9` | 11 -> 2 (-9) | `11374816278` / `12063022177` | Source `agent.py` constructs `ClaudeAgentOptions(allowed_tools=["Read", "Write"], permission_mode="acceptEdits", hooks={}, mcp_servers={})`. Final relationships retain exactly Read and Write; historical extra 9 tools (`Agent`, `Bash`, `Edit`, `Glob`, `Grep`, `NotebookEdit`, `WebFetch`, `WebSearch`, `Workflow`) lack this instance's binding evidence. | **Source-supported false-positive corrections** (9/9 dropped), not missing authority edges. `allowed_tools` indicates declared/preapproved choices, not independently proven runtime enforcement. |
| `ff60-anthropic-03` | `LainNet-42/polymarket-auto-trading-agent@2d44e5627c74bbe74ecb4182cdbc867d619355b0` | 23 -> 8 (-15) | `11374270965` / `12062747731` | One `ClaudeAgentOptions` uses `allowed_tools=_build_allowed_tools()`; another separate option declaration includes literal `WebSearch`, `WebFetch` and `mcp__polymarket__...`. The dropped edges include repeated old built-in catalogue claims for two instances. | **Likely precision improvement, unresolved exact dynamic list**: do not propagate generic tools across option instances; trace `_build_allowed_tools()` source and actual client construction before declaring all 15 removals validated. |
| `ff60-anthropic-04` | `ThomazRossito/data-agents@9cb586eb3dbf101a81a1422240de36e168bf2fb8` | 69 -> 25 (-44) | `11375035358` / `12062194738` | Supervisor explicitly allows `Agent,Read,Grep,Glob,Write,AskUserQuestion,Bash` and binds dynamic `agents` and `mcp_servers`; workflow step options use `allowed_tools=list(agent_def.tools or [])`; Party Mode uses `allowed_tools=[]`, `agents=None`, `mcp_servers={}`; development assistant allows `Read,Write,Bash,Grep,Glob`. | **Mixed; broad catalogue shrink is correct in principle, but dynamic per-client tool binding is not yet fully adjudicated.** Specifically check whether current graph retains all explicit supervisor and Dev Assistant choices, and treats registry-derived workflow tools as unresolved rather than erased. |

## Detailed residual false-positive evidence (final scan)

An exact read of final `effective-authority.json` reveals that `ff60-anthropic-04` still emits **12 relationships** under `_build_step_options#2`: `<dynamic-mcp>` plus **all eleven built-in catalogue items** `Agent, Bash, Edit, Glob, Grep, NotebookEdit, Read, WebFetch, WebSearch, Workflow, Write`. The pinned workflow `_build_step_options` uses `allowed_tools=list(agent_def.tools or [])` for that branch, so exact membership cannot be derived merely from this option constructor. Those eleven items are **unresolved/suspected remaining false-positive edges**, not source-proven authority. The final supervisor retains exactly `Agent, Bash, Glob, Grep, Read, Write` plus `<dynamic-mcp>` and `<dynamic-subagents>`; this matches its six explicit allowed built-ins (and the dynamic context remains unresolved). The final `opts` Dev Assistant retains `Bash, Glob, Grep, Read, Write`, matching explicit source. Party Mode's empty tool list is not projected as broad authority. We should **replace the eleven catalogue edges at the dynamic workflow option with a single unresolved dynamic-tool representation**, preserving known registry source bindings when provable.

This is a **confirmed residual accuracy gap** in Anthropic-04 even though the drop 69→25 is directionally correct. Verify other instances for the same pattern before considering Wave B accepted.

## Why aggregate count gates missed this

Full-60's aggregate count floor was satisfied despite major per-case relationship changes. Even a large decline can be valid when the baseline was a generic built-in catalogue, while retaining any truly bound/allowed tools is mandatory. Raw edge preservation should **not** be used as a quality criterion. Lock source-grounded *positive* edges and *hard negatives* by exact client/options instance instead.

## Follow-up acceptance requirements

1. `ff60-anthropic-02`: pin the 2 positive `Read`/`Write` declarations and the nine negative generic-tool bindings.
2. `ff60-anthropic-01`: trace `allowed_tools` variable to its source(s); retain ambiguity when not statically resolvable; no SDK runtime effectiveness claim.
3. `ff60-anthropic-03`: review both `ClaudeAgentOptions` instances independently, resolve `_build_allowed_tools()` where possible; verify emitted MCP tool identifiers separately from built-ins.
4. `ff60-anthropic-04`: per-instance truth for supervisor, workflow registry, Party and Dev Assistant; protect explicitly allowed supervisor tools from false-negative suppression; no cross-instance authority union.
5. Run pinned cases and all locked quality gates at the same merged fix SHA; attach claim-level reasons, not only counts. No independent precision/recall calculated from this model-assisted review.

**Decision:** `ff60-anthropic-02` is source-adjudicated as corrected false-positive authority. The other three cases are **conditionally favorable but retain unresolved client-instance semantics**; do not call all 80 removed relationships verified without more evidence.
