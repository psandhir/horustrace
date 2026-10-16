# Wave B — AWS and MCP third-party contract verification

## Immutable upstream witness

Upstream: `strands-agents/tools@1dd0465da8a748b0e8ac87ec5b3485bccb60d70e`.

| Symbol | Immutable source lines | Source-supported statement | Not established |
| --- | --- | --- | --- |
| `use_aws` | `src/strands_tools/use_aws.py:229-248, 399-417, 441-497` | boto3 session/client, dynamic service operation dispatch; confirmation for operations classified mutative or sensitive unless `BYPASS_TOOL_CONSENT=true` | installed version, AWS identity permissions, actual operation, successful write, exact destination, exhaustive mutative classification |
| `file_write` | `src/strands_tools/file_write.py:140-185, 195-223` | file-writing tool with confirmation conditional on `BYPASS_TOOL_CONSENT` | actual filesystem write, filesystem scope, runtime confirmation |
| `python_repl` | `src/strands_tools/python_repl.py:632-659` | Python code execution with conditional confirmation | installed version, process/network effect of specific code, successful execution |
| Pricing MCP | `aws-samples/sample-multi-agent-region-expansion-planner@30d03d7c9f6512e5bf10601879382fac9c3a16b1`, `src/agents/pricing_explorer.py` | per-region `MCPClient` launched with `uvx awslabs.aws-pricing-mcp-server@latest`, `list_tools_sync()` joined with imported tools for nested Agent | immutable server version, resolved runtime tool catalogue, AWS account authorization, live exposure or invocation |

## Version mapping and inference boundary

The pinned application has an **unversioned** `strands-agents-tools` requirement; the MCP command uses `@latest`. Therefore this upstream snapshot is a *conditional implementation reference*, not an attested dependency instance for the pinned application. Do not promote `inferred` effects to `observed`, or treat conditional control prompts as always-enforced or always-bypassed.

The tool's own `BYPASS_TOOL_CONSENT` mechanism must not be interpreted as evidence that the application actually enabled it. The source also cannot establish effective AWS IAM authorization or reachable external destinations.

## Claim-by-claim reconciliation

- `AGT020 ff60-amazon-04:34e0345cd816a7b394f5`: source evidence supports a possible Python execution tool at this upstream revision; **unresolved** until installed version, instance binding and runtime effects are established.
- `AGT040 ff60-amazon-04:d3388fd929c8794bfce6`: confirmation is conditional, not a verified runtime control state; **unresolved**.
- `CAP004 ff60-amazon-04:0de03732933c171d96b4`: no proven same-instance process and external network effects; **unresolved**.
- `CAP003 ff60-amazon-04:391d0a5e8be35376802b` and `ff60-amazon-04:e9eccd96b25d7aac2746`: no proven exact four-effect contract; **unresolved**.
- `NET002` seven keys `1cd6188f31f7ae6ae9ae`, `2ad096fe63994b320f70`, `36830b3ae86117942e1e`, `84724ebc1b42818721ea`, `9a644fee027e44fe2bd5`, `ae7e4aadfa7c31e34044`, `f37bdf0d899c7565a374`: dynamic AWS/MCP destinations and effective write authority not proven per agent; **unresolved**.

No independent human adjudication, exhaustive negative universe or precision/recall result has been produced. Preserve the existing 12 UNKNOWN labels and Wave B NO-GO. #558 branch-rule enforcement remains outstanding.
