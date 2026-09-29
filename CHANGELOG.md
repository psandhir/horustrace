# Changelog

## Unreleased

- Upgrade the self-contained visual report into a production-oriented security-review console with a prioritised assessment dashboard, agent review queue, search/filter workflows for agents and findings, contract triage, richer evidence/coverage context, responsive layouts, keyboard-accessible drill-downs, and reduced-motion support without adding external assets, telemetry, or runtime security inference.

## 0.9.0 - 2026-09-26

- Complete the Recall Foundation milestone against the unchanged frozen 180-repository cohort with **180/180 successful scans** and all preregistered v0.9 hard gates passing.
- Raise agent/workflow recall from **0.4993 to 0.8584** while retaining locked-reference precision **0.9526**.
- Raise LangGraph agent/workflow recall to **0.9613** and tool recall to **0.9660** through explicit workflow-node semantics, improved control-flow modeling and standalone LangChain tool discovery.
- Add conservative framework-neutral model/tool-loop discovery requiring model invocation, model-visible tools, model-selected calls and concrete dispatch; MCP/custom agent recall reaches **0.6250**.
- Expand MCP discovery across programmatic clients/servers, source-proven custom wrappers, OpenAI Agents MCP definitions and Pydantic AI MCP constructs; explicit MCP-server recall rises from **0.2727 to 0.8636**.
- Make unbound MCP entities topology-visible without fabricating agent `INVOKES` or effective-authority relationships.
- Harden repository traversal across unreadable paths, symlinks and large unrelated source trees while retaining explicit safety ceilings and coverage diagnostics.
- Remove an ADK project-descriptor false positive so the formal raw precision gate passes without modifying locked study truth.
- Preserve the key limitation that effective-authority precision remains **0.2778**; authority-fidelity redesign is deferred to v0.10.
- Publish the full frozen-180 evidence trail and residual-error ledger under `docs/research/v0.9-recall-foundation-closeout.md`.

## 0.8.0 - 2026-09-24

- Add Deployment Evidence v1, a local-first JSON/YAML contract for workload identity, IAM binding, inheritance, conditions and role-permission evidence without cloud API calls or target-agent execution.
- Resolve explicit agent-to-workload deployment relationships and canonical GCP service-account identities without fuzzy name matching.
- Reconstruct deployed GCP authority from supplied IAM evidence, including inherited project/folder/organization grants, custom-role permissions, and explicit unresolved state for conditional bindings or unknown role expansion.
- Add agent-level required-vs-deployed Authority Reconciliation with aligned, excess-authority, missing-authority, mixed and unresolved outcomes; missing intended-authority evidence never becomes a false excess-authority conclusion.
- Add semantic deployment Authority Delta for introduced/resolved excess roles and permissions, unresolved-authority regressions and permission-derived trust-boundary crossings.
- Evaluate deployed identities, IAM roles and permissions against repository Authority Contracts while retaining conditional policy conflicts as unresolved.
- Add `horustrace reconcile` with JSON/console reporting and opt-in CI gates for excess authority, deployed-policy violations and deployment regressions.
- Add first-party GitHub Action `reconcile` mode and controlled aligned/expanded deployment fixtures.
- Preserve `runtime_effectiveness: not_verified` across all deployed-authority outputs. v0.8 reasons from supplied deployment/IAM evidence; it does not prove that a permission was exercised.

## 0.7.0 - 2026-09-24

- Add `horustrace policy` to bootstrap deterministic reviewable Authority Contract proposals from supported observed authority without converting unknowns into wildcard allow rules.
- Add a correlated security-impact review joining Authority Delta, trust-boundary crossings and Authority Contract violations for pull-request review.
- Add effective-authority resolution metrics and opt-in CI budgets/regression gates so historical uncertainty can remain while new changes are prevented from increasing it.
- Add `horustrace query` for conservative authority investigation across capabilities, destinations, identities, targets, resolution state and explicit delegated reachability.
- Extend the frozen-90 validation harness with authority-resolution and policy-bootstrap adoption metrics.

## 0.6.0 - 2026-09-24

- Validate v0.6 against the exact frozen 90-repository corpus with 90/90 scans, 0 errors/timeouts and **zero delta across every compared v0.5 release metric**, including 2,076 agents, 3,413 tools, 633 MCP servers, 140 flows, 6/133/1 reachability, 25 attack paths, 117 bound / 516 concrete unbound MCP declarations and 1,105 findings.
- Add Authority Contract v1 under `policy.authority`, with normalized allow/deny authority dimensions, approval requirements and per-server MCP tool scope while preserving existing manifest-policy semantics.
- Evaluate Effective Authority Relationship v1 against Authority Contract v1 with explicit compliant/violation/unresolved outcomes, stable result IDs, approval semantics and MCP tool-scope enforcement; unknown remains neither pass nor failure.
- Add Trust Boundary Classification v1 for mutation, network, identity, approval/control and MCP scope, including evidence-backed before/after crossings without numeric risk scoring.
- Upgrade Authority Delta to schema v2 with additive trust-boundary classifications and crossings in JSON, console and Markdown while preserving v1 delta fields.
- Add a change-aware Authority Contract policy delta and opt-in `--fail-on-policy-violation` / GitHub Action gate that fails on newly introduced contract violations or contract weakening while reporting strengthening, resolved violations and unresolved policy state separately.
- Add Explainability v2 with precise Authority Contract clause provenance and structured policy → effective-authority → identity/control/resource/destination/source evidence chains in policy results and diffs.
- Add MCP unresolved-reference taxonomy v1 with evidence-backed binding reasons, separate agent-reference tracking and protection against unresolved imported placeholders being treated as bound authority; the frozen corpus exposes 15 previously hidden unresolved agent references without changing the historical 516 concrete-unbound baseline.

## 0.5.0 - 2026-09-24

- Validate the integrated release against the frozen 90-repository public corpus:
  90/90 scanned, 0 errors/timeouts, 6 proven agent-reachable flows, 133 proven
  non-agent flows, and 1 intentionally preserved unknown runtime flow.
- Add Agent Security Graph (ASG) v1 and `horustrace security-graph`, combining
  topology, effective authority, static flows, attack paths and resolution state in a
  deterministic portable document.
- Add generic Effective Authority Relationship v1 for agent-to-tool and agent-to-MCP
  relationships, with stable IDs, identity/credential evidence, approval, MCP scope,
  resources, destinations, mutation/network semantics and per-dimension resolution.
- Make AGT040, AGT032, NET002 and CAP005 authority-aware while preserving
  conservative fallbacks for incomplete relationships.
- Add semantic Authority Delta v1 to `horustrace diff`, including capability,
  identity/IAM, OAuth, approval, MCP tool-scope, resource and destination expansion.
- Add change-aware Git security diff, contextual Markdown rendering and a first-class
  GitHub Action for pull-request security deltas.
- Add canonical provenance-based flow-to-agent attribution for imported tools, remove
  weak repository-wide name/single-agent shortcuts and preserve ambiguous bindings as
  unresolved.
- Add flow execution-context and reachability semantics:
  `proven_agent_reachable`, `proven_non_agent` and `unknown`, including explicit
  CLI entrypoint evidence and source-context filtering.
- Add bounded inbound entrypoint provenance, including class methods, runtime roots and
  MCP-server lifecycle paths, with representative evidence preserved under output
  bounds.
- Trace normalized agent-tool inputs into supported security-sensitive sinks and
  promote proven agent-reachable static flows into static-dataflow-backed attack
  paths.
- Add contextual MCP authority reconstruction for OpenAI Agents, LangGraph/LangChain
  clients, LangChain `create_agent`, FastAgent and imported MCP server objects,
  including auth, destination, identity, allow/deny scope and supported resources.
- Add first-class FastAgent Python support plus `fast-agent.yaml` /
  `fast-agent.yml` MCP parsing, nearest-config binding and per-agent tool filters.
- Add first-class Pydantic AI / Pydantic AI Harness support for agents, function tools,
  toolsets, approvals, MCP and security-relevant Harness/provider capabilities.
- Project explicit approval controls into the ADG and refine LangGraph interrupt,
  OpenAI preview/confirm and ADK HITL semantics.
- Add custom LangGraph computer-control semantics and distinguish mutating actions
  from screenshot/read-only behavior.
- Add opt-in, offline Terraform GCP IAM correlation through `--authority-source`
  without cloud API access or live IAM downloads.
- Add first-class OWASP Top 10 for Agentic Applications 2026 reporting via
  `horustrace owasp`, JSON/SARIF summaries and runtime/source-context-aware status.
- Add framework Adapter Contract v1 and `horustrace adapters`, retaining the
  static/no-target-execution trust boundary.
- Add reason-level telemetry for unbound MCP references and residual unknown
  reachability in frozen-corpus research runs.
- Improve risk precision for fixed destinations vs broad egress, local/session state
  mutations vs persistent/external writes, and sensitive mutation domains.
- Remove multiple corpus-discovered false positives, including qualified
  `re.compile(...)` as code execution, name-only side-effect authority on control
  helpers, and subprocess payload/configuration data as executable control.
- Preserve unknown runtime behavior when evidence is shared or ambiguous rather than
  forcing an agent/non-agent conclusion.


### 0.4 development

- Publish the project as the `horustrace` PyPI distribution with the `horustrace` Python package and CLI.
- Preserve existing `arg-v1:` finding fingerprints and legacy SARIF fingerprint keys alongside HorusTrace keys.
- Add a versioned, deterministic Agent Dependency Graph (ADG) with typed nodes and
  relationships across agents, tools, models, prompt digests, memory, identities,
  resources, destinations, MCP servers, and policy controls.
- Add bounded cross-file source-to-sink analysis for supported Python constructs,
  including supported static paths to process execution, external sends, and
  agent-memory/checkpoint writes.
- Distinguish `supported` static data-flow attack paths from `potential`
  capability-co-occurrence paths without claiming runtime exploitability.
- Add `PATH007` for supported untrusted-input to persistent-memory write paths.
- Add SARIF code flows for supported static paths.
- Add `horustrace graph` and `horustrace aibom` export commands.
- Add initial LangGraph StateGraph normalization and OpenAI Agents handoff/delegation
  relationships.
- Add ADG and flow-analysis safety ceilings plus unresolved data-flow/handoff
  coverage diagnostics.


## 0.3.0

- Add repository-aware Google ADK analysis with cross-file tool, helper, delegation,
  identity, OAuth, MCP, and execution-boundary resolution.
- Resolve simple agent factories, nested workflow agents, local tool collections,
  conditional tool references, and common `append`/`extend` construction patterns
  without executing target code.
- Resolve static module constants used for MCP endpoints while retaining runtime
  endpoints as explicit incomplete-analysis diagnostics.
- Model ADK `ExecuteBashTool` built-in confirmation semantics and provider-managed
  code execution more accurately.
- Prevent delegated synthetic capabilities from creating duplicate execution findings
  while preserving potential attack paths through delegation.
- Reduce false positives from generic `.execute()` methods, arbitrary URL literals,
  dictionary lookups, and fixed managed-service destinations.
- Improve MCP authentication detection, including dynamic header dictionaries and
  `X-Goog-Api-Key`; report unknown authentication state as coverage uncertainty.
- Link repository OAuth helper scopes and credential evidence to the tools that use
  them.
- Restrict repository resolution to scanner-approved files so ignore rules, path
  containment, and hostile-repository limits remain authoritative.
- Add repository resolution metrics to coverage output.
- Expand public-repository regression coverage and correctness tests.
- Validate the release with 228 automated tests and the 26-case reviewed benchmark;
  the benchmark fixture corpus reports precision 1.000 and recall 1.000.

## 0.2.0

- Fix transitive delegation, classified tool-resource checks, source-location merging,
  identity enrichment, and shared-agent tool overlay isolation.
- Reject invalid manifests with versioned field/type validation and safe error reporting.
- Add coverage diagnostics and strict CI mode to all report formats and the GitHub Action.
- Add finding assessments, evidence origins and explicit static-analysis limitations.
- Report control observations with unverified runtime effectiveness.
- Describe inferred attack paths as potential capability combinations.
- Stop treating approval callbacks and literal function URLs as enforced controls.
- Add stable finding fingerprints, baseline generation, and scoped, reasoned,
  expiring suppressions with audit output.
- Add structured rule metadata, the `horustrace rules` catalogue command, and
  OWASP Agentic coverage mappings.
- Add explicit attack-path confidence values while retaining `not_verified` runtime
  exploitability semantics.
- Reject duplicate YAML repository-configuration keys and apply repository rule
  configuration before suppressions, with default/effective severity audit data.
- Bound coverage diagnostics, deduplicate canonical paths and symlink aliases, and
  report unresolved external helper semantics as `ARG-COV-008`.
- Expand hostile-repository regression coverage for deep/oversized YAML, malformed
  UTF-8, symlink loops, side-effecting Python, and non-executed MCP commands.
- Expand the reviewed benchmark to 26 materially different scenarios, including an
  expected-incomplete dynamic configuration case, with aggregate and per-rule metrics.
- Build and install the wheel in CI as a release smoke test.
- Pin GitHub Actions dependencies to verified immutable SHAs using current releases.

## 0.1.0

- Add first-class Google ADK Python static analysis.
- Add native ADK Agent Config YAML analysis.
- Model ADK workflow/sub-agent and AgentTool delegated authority.
- Add ADK MCP, A2A, code-execution, computer-use, BigQuery and Google API toolset analysis.
- Add callback/plugin/confirmation security-control discovery.
- Add Google OAuth/service-account/credential-source evidence into identity analysis.
- Add cross-file ADK delegation resolution.
- Add ADK-specific rules `ADK001` through `ADK011`.
- Add vulnerable and secure Google ADK reference fixtures.
- Expand regression suite to 32 tests.


## 0.3.0

Repository-level ADK analysis and public-corpus correctness fixes.

- Complete v0.3 public-corpus semantics: repository ignore parity, delegated control propagation, managed-service egress, loopback MCP context, auth-unknown coverage, provider-managed executor handling, resolution metrics, and helper/OAuth resolution.
