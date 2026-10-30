# Wave B — third-party tool capability contract investigation

Status: **SOURCE-ONLY / NO-GO**. This is an evidence task, not an assertion of runtime authority or a change to scanner findings.

## Pinned application

- Repository: `aws-samples/sample-multi-agent-region-expansion-planner`
- Commit: `30d03d7c9f6512e5bf10601879382fac9c3a16b1`
- File: `src/agents/pricing_explorer.py`
- Application dependency: `requirements.txt` specifies `strands-agents-tools` without a version pin.
- The pricing MCP process uses `awslabs.aws-pricing-mcp-server@latest`, so its implementation and runtime catalogue are not reproducibly fixed by this application.

## Source-positive and hard-negative contracts

| ID | Positive source witness | Mandatory negative / unknown |
| --- | --- | --- |
| WBTC-01 | `pricing_explorer.py` imports `use_aws`, `file_read`, `file_write`, `python_repl` from `strands_tools` | Imports alone do not establish the third-party implementation's exact effects |
| WBTC-02 | Inside a per-region MCP context, `list_tools_sync()` is concatenated with the four imported tools and passed to `Agent(tools=tools)` | MCP catalogue is dynamic; do not fabricate tool names, unconditional availability or a source-proven invocation of each tool |
| WBTC-03 | `compare_regional_pricing` conditionally constructs and invokes a nested `Agent` | ImportError branch returns failure; tool invocation is not guaranteed; no unconditional live child-agent or `AGENT_CAN_CALL` claim |
| WBTC-04 | `Constants.set_tool_configurations()` is called before nested Agent construction | Local control configuration does not prove runtime bypass, external policy absence, granted identity, or reachable destinations |
| WBTC-05 | `python_repl` appears as a named imported tool | Do not infer `process.execute`, `network.external`, or four-effect CAP003/CAP004 without a pinned implementation or independently justified effect contract |

## Exact claim queue

- AGT020 `ff60-amazon-04:34e0345cd816a7b394f5` — third-party python_repl effect unknown.
- AGT040 `ff60-amazon-04:d3388fd929c8794bfce6` — python_repl control/effect unknown.
- NET002 `ff60-amazon-04:f37bdf0d899c7565a374` — pricing agent effective destination/write unknown.
- CAP004 `ff60-amazon-04:0de03732933c171d96b4` — same-instance process + network witness unknown.
- CAP003 `ff60-amazon-04:391d0a5e8be35376802b` and `ff60-amazon-04:e9eccd96b25d7aac2746` — exact four-class effect contract unknown.
- Remaining six NET002 cases must be checked separately against exact per-agent sources and runtime-conditional MCP/AWS effects.

## Acceptance criteria

1. Resolve a reproducible `strands-agents-tools` distribution version or record `unresolved_dependency_version`; never silently assume the newest implementation applies to the pinned application.
2. For each capability assertion, cite implementation repository, immutable commit/package artifact, symbol/function, exact source path and lines, and version mapping to the application.
3. Add positive and hard-negative fixtures for source binding, aliases, conditional/deferred construction, runtime-only catalogues and control configuration.
4. Preserve UNKNOWN for effective permissions, runtime network destinations, tool calls and external control enforcement without proof.
5. Run targeted tests plus **complete latest-head Fresh-16 (16/16), Full-60 (60/60), CI and CodeQL** for scanner-source changes. Do not reduce quality gates.
6. Reconcile the 12 unresolved claims in the #551 dossier; independent human adjudication and negative/recall denominator remain separate release conditions. #558 mandatory ruleset enforcement must also be confirmed before Wave B GO.

This document is an engineering source-contract plan, not an independent truth label or a precision/recall estimate.
