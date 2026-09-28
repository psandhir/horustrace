# HorusTrace-aligned independent source-review prompt

Use this prompt for an independent static source review before exposing the reviewer to HorusTrace output.

---

You are performing an independent static security analysis intended to approximate the capabilities and policy semantics of HorusTrace.

Analyze only the supplied repository at the supplied immutable commit SHA. Do not execute the application, install it, invoke live APIs, use credentials, or assume runtime behavior that is not supported by source evidence.

For every conclusion classify evidence as:
- observed — directly established by source/configuration;
- inferred — strongly supported by static semantics but not explicit;
- unresolved — insufficient static evidence.

Do not treat unresolved evidence as safe or as a violation.

## 1. Construct the agent authority graph

Identify:
- agents and model-driven workflows;
- workflow/control nodes that should not automatically be called agents;
- tools and tool registries;
- MCP servers and MCP tools;
- agent-to-tool relationships;
- agent-to-MCP relationships;
- delegation/handoff/subagent relationships;
- identities and credential sources;
- resource scopes;
- external destinations;
- data read/write capabilities;
- process/code execution;
- destructive operations;
- browser/computer control;
- secret/credential access;
- memory/checkpoint access;
- approval and guardrail controls;
- input trust boundaries;
- deployment/IAM evidence when present.

Follow indirection through configuration files, registries, decorators, factories, constructor arguments, imported helper functions, tool-name lookup, dynamically instantiated agents, and custom LLM -> tool-schema -> tool-selection -> dispatch loops.

Do not connect every discovered tool to every agent. Establish effective authority per agent based on evidence.

## 2. Effective authority

For each agent determine, where possible:
- capabilities;
- tools;
- MCP servers/tools;
- identities;
- resources;
- destinations;
- IAM roles and permissions;
- OAuth scopes;
- approval requirements;
- guardrails;
- source provenance.

Mark dynamic or incomplete relationships unresolved rather than assuming broad access.

## 3. Authority Contract

If a HorusTrace manifest/Authority Contract is present, evaluate:
- allowed/denied capabilities;
- identities;
- resources;
- destinations;
- IAM roles;
- permissions;
- OAuth scopes;
- MCP servers;
- per-server MCP tool scope;
- required approvals.

Return compliant, violation, or unresolved per supported relationship. Missing evidence is unresolved, not compliant.

## 4. Evaluate the current HorusTrace built-in policy catalogue

### Layer 1

- AGT001 broad local MCP filesystem scope.
- AGT020 process execution without approval.
- AGT021 destructive action without approval.
- AGT022 state-changing tool without approval.
- AGT023 state-changing computer/browser control without action boundary.
- AGT030 remote MCP without recognized authentication.
- AGT031 unencrypted remote MCP.
- AGT032 remote MCP without explicit tool allowlist.
- AGT040 privileged tool without guardrail/approval.
- AGT050 unpinned MCP package execution.
- AGT051 literal credential in MCP configuration.
- AGT052 explicitly broad/unrestricted MCP tool surface.
- AGT053 bound MCP exposes privileged in-repo tools without approval/guardrail.

Google ADK-specific rules:
- ADK001 privileged ADK agent lacks tool-control callback/plugin/confirmation.
- ADK002 unsafe local ADK code execution.
- ADK003 ADK LocalEnvironment exposes local shell/file I/O.
- ADK004 ExecuteBashTool lacks restrictive BashToolPolicy.
- ADK005 computer-use lacks confirmation/guardrail.
- ADK006 BigQuery writes not statically blocked.
- ADK007 broad generated/API toolset lacks filter.
- ADK008 AgentTool(include_plugins=False) may bypass inherited controls.
- ADK009 A2A uses plaintext HTTP.
- ADK010 A2A lacks authentication.
- ADK011 privileged ADK agent exposed via A2A without safety control.
- ADK012 sandboxed code executor lacks timeout/network/filesystem constraints.

### Layer 2

- CAP001 authority exceeds declared capability budget.
- CAP002 explicitly denied capability is present.
- CAP003 excessive aggregate privileged authority.
- CAP004 process execution plus external network.
- CAP005 combined data-read and state-change authority.
- CAP006 policy-required approval missing on a relevant tool.

### Layer 3

- IDN001 broad administrative cloud/IAM role.
- IDN002 wildcard permission.
- IDN003 broad OAuth scope.
- IDN004 unsafe/static credential source.

### Layer 4

- AGT010 sensitive data plus unapproved external network/write capability.
- DATA001 broad resource scope.
- DATA002 access exceeds resource allowlist.
- DATA003 sensitive data has broad/unconstrained egress.
- NET001 broad/dynamic outbound reachability without restriction.
- NET002 outbound capability lacks destination constraint.
- NET003 destination exceeds declared allowlist.

### Layer 5

- PATH001 untrusted input -> process/command execution.
- PATH002 untrusted input -> destructive action.
- PATH003 sensitive data -> external destination.
- PATH004 untrusted input + sensitive data + arbitrary execution.
- PATH005 untrusted input -> secret access -> egress.
- PATH006 untrusted input reaches multiple high-risk capability classes.
- PATH007 untrusted input -> agent memory/checkpoint write.
- PATH008 untrusted input -> delegated agent -> privileged action.
- PATH009 untrusted input -> delegated agent -> unconstrained egress.

Do not invent additional HorusTrace rule IDs. A finding is a static capability/configuration risk, not proof of exploitation.

Avoid duplicate findings representing the same effective entity and same policy condition. Account for reassignment/overwriting of objects and distinguish live runtime objects from abandoned construction sites.

## 5. OWASP Agentic mapping

Use HorusTrace's current mapping only:
- ASI01: partial via supported untrusted-input execution paths;
- ASI02: tool misuse;
- ASI03: identity/privilege abuse;
- ASI04: agentic supply chain;
- ASI05: unexpected code execution;
- ASI07: insecure inter-agent communication.

Do not claim static coverage for ASI06, ASI08, ASI09 or ASI10 beyond noting relevant evidence or limitations.

## 6. Output

Return:
1. discovered agent/workflow count and evidence;
2. discovered tool count and bindings;
3. MCP servers and bindings;
4. effective authority relationships;
5. trust-boundary/input paths;
6. deployment identities if present;
7. policy findings with rule_id, HorusTrace severity, evidence state, agent, source file/line, evidence, rationale and limitations;
8. attack paths;
9. Authority Contract results;
10. OWASP mapping;
11. unresolved evidence;
12. likely scanner blind spots suggested by the source.

Do not see or use the HorusTrace output until this independent assessment is complete.
