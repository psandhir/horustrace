# Rule catalogue

[`rule_registry.py`](../src/horustrace/rule_registry.py) is the canonical
source of rule metadata. This catalogue mirrors its complete rule-ID set; rule
metadata will become available through the CLI in WP02.

## Layer 1 — Agent/framework configuration

### Framework-neutral

- `AGT001` — broad local MCP filesystem scope.
- `AGT020` — shell/process execution without approval.
- `AGT021` — destructive action without approval.
- `AGT022` — state-changing tool without approval.
- `AGT023` — state-changing computer/browser control without an explicit action boundary.
- `AGT030` — remote MCP without recognized authentication.
- `AGT031` — unencrypted remote MCP transport.
- `AGT032` — remote MCP lacks an explicit tool allowlist; a denylist alone is insufficient.
- `AGT040` — privileged tool without guardrail or approval.
- `AGT050` — unpinned MCP package execution.
- `AGT051` — literal credential material embedded in MCP configuration.
- `AGT052` — MCP configuration explicitly enables a broad/unrestricted tool surface.
- `AGT053` — bound MCP server exposes privileged in-repo tools without approval/guardrail controls.
- `AGT054` — source-bound dynamic remote MCP catalogue is callable without a per-call approval boundary.

### Google ADK

- `ADK001` — privileged ADK agent lacks a detected tool-control callback/plugin/confirmation boundary.
- `ADK002` — unsafe local ADK code execution.
- `ADK003` — `EnvironmentToolset` with `LocalEnvironment` exposes local shell/file I/O.
- `ADK004` — `ExecuteBashTool` lacks a detected restrictive `BashToolPolicy`.
- `ADK005` — computer-use capability lacks explicit action confirmation/guardrail.
- `ADK006` — BigQuery writes are not statically blocked.
- `ADK007` — broad ADK generated/API toolset has no detected tool filter.
- `ADK008` — `AgentTool(include_plugins=False)` may bypass inherited parent controls.
- `ADK009` — remote A2A agent card uses plaintext HTTP.
- `ADK010` — remote A2A agent has no detected authentication configuration.
- `ADK011` — privileged ADK agent is exposed over A2A without a detected safety control.
- `ADK012` — sandboxed ADK code executor lacks explicit timeout, network, or filesystem limits.

## Layer 2 — Capability analysis

- `CAP001` — effective capabilities exceed the declared capability budget.
- `CAP002` — explicitly denied capability is present.
- `CAP003` — high aggregate privileged authority.
- `CAP004` — command execution combined with external network access.
- `CAP005` — combined data read and state-change authority.
- `CAP006` — policy-required approval is not configured on every relevant tool.

## Layer 3 — Identity & permissions

- `IDN001` — broad administrative cloud/IAM role.
- `IDN002` — wildcard identity permission.
- `IDN003` — broad OAuth scope.
- `IDN004` — unsafe/static credential source.

## Layer 4 — Data & network reachability

- `AGT010` — sensitive data plus unapproved external write/network capability.
- `DATA001` — broad resource scope.
- `DATA002` — resource access exceeds declared allowlist.
- `DATA003` — sensitive data has broad/unconstrained egress reachability.
- `DATA004` — model-callable mutation of an owner/tenant-scoped object omits the repository's normal ownership check.
- `NET001` — broad destinations or a possible destination without a detected restriction.
- `NET002` — outbound capability has no destination constraint.
- `NET003` — destination exceeds declared network allowlist.
- `NET004` — bound MCP tool exposes model-selected URL destination authority without a detected destination allowlist.

## Layer 5 — Attack paths

- `PATH001` — untrusted input to command execution.
- `PATH002` — untrusted input to destructive action.
- `PATH003` — sensitive data to external destination.
- `PATH004` — untrusted input plus sensitive data plus arbitrary execution.
- `PATH005` — untrusted input to secret access and egress.
- `PATH006` — untrusted input reaches multiple high-risk capability classes.
- `PATH007` — supported untrusted-input flow reaches an agent memory/checkpoint write.
- `PATH008` — potential untrusted-input path through a delegated agent to a privileged action.
- `PATH009` — potential untrusted-input path through a delegated agent to unconstrained egress.
- `PATH010` — source-proven model-selected local file read whose data reaches an external service without a detected filesystem containment boundary.
- `PATH011` — source-bound untrusted input reaches a model-selected URL that a direct server-side HTTP client fetches without a detected destination restriction.
- `PATH012` — source-proven tool-returned local/repository content re-enters model context while the same agent has model-selected filesystem read/write authority without detected containment.
- `PATH013` — source-proven user-selected server directory reaches recursive RAG ingestion and bound agent retrieval without a detected filesystem containment boundary.
- `PATH014` — source-bound user input reaches a model-callable owner-scoped object mutation that omits the repository's normal owner/tenant authorization check.

## Interpreting evidence

Rule IDs and severities describe configuration risks and potential impact, not
proof of exploitability. Reports distinguish observed configuration, manifest
assertions, and inferred facts. PATH findings are potential capability combinations;
no executable data-flow trace or successful attack is established. Callback,
plugin, sandbox and approval observations do not verify runtime effectiveness.
Literal URLs in function bodies are possible destinations, not egress restrictions.
For supported ADK and MCP configuration, a Bash policy is only considered restrictive
when both command allowlist and blocklist evidence are present; remote MCP requires
an explicit tool allowlist. Sandbox limits require static evidence for a positive
timeout, disabled/restricted network, and constrained workspace or paths.
