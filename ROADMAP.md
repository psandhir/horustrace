# HorusTrace Roadmap

HorusTrace is a **beta-stage / pilot-ready** static security analyser for AI agents. The roadmap is ordered around increasing confidence in **effective authority** and **attack-path** analysis rather than simply increasing rule count.

## v0.2 — Reliability and validation milestone

Completed in the v0.2 release candidate:

- Coverage counts and stable `ARG-COV-*` diagnostics in console, JSON, and SARIF.
- Strict CI failure for detected incomplete analysis.
- Version 1 manifest field/type validation and source locations.
- Regression tests for ordering, delegation cycles, cross-file resources,
  identity enrichment, shared tools, and policy/source interaction.
- Distinguish source observations, manifest declarations, and heuristic inferences
  in finding evidence, preserving source locations through delegation.
- Report control observations separately from unverified runtime effectiveness.
- Label capability combinations as potential paths with explicit limitations.
- Treat approval callbacks and literal function URLs as observations rather than
  blanket approval or enforced egress controls.
- Versioned finding fingerprints and scoped suppressions requiring reason and expiry,
  with matched/stale/expired audit output.
- Baseline generation that refuses accidental replacement and scans the full
  unsuppressed current state.
- Structured rule metadata, rule catalogue CLI, and OWASP Agentic mappings.
- Explicit attack-path confidence semantics without claiming verified exploitability.
- Repository `.horustrace.yaml` configuration with rule enable/disable and
  severity overrides applied before suppressions.
- Hostile-repository protections including resource ceilings, canonical-path
  containment/deduplication, bounded diagnostics, and non-execution regression tests.
- A reviewed benchmark gate with 26 distinct scenarios, including expected incomplete
  analysis, with aggregate and per-rule precision/recall metrics.
- Immutable-SHA GitHub Actions dependencies and package/wheel smoke testing.

## v0.3 — Repository-level reachability milestone

Completed for v0.3:

- Repository-aware Google ADK analysis across Python modules rather than isolated
  file-only interpretation.
- Cross-file resolution for imported tools, helper functions, identities, OAuth
  scope declarations, MCP toolsets, and delegation relationships.
- Conservative static resolution for simple agent factories, nested workflow agents,
  conditional tool references, and common list construction patterns.
- Static module-constant resolution for MCP endpoints while preserving genuinely
  runtime-derived endpoints as coverage gaps.
- More accurate ADK semantics for built-in Bash confirmation and provider-managed
  code execution.
- Lower-noise function capability inference that avoids treating generic
  `.execute()` calls, arbitrary URL strings, and ordinary dictionary access as
  privileged execution, network reach, or secret access.
- Managed-service network classification to avoid generic unrestricted-egress
  findings where the destination is framework-fixed.
- Repository coverage metrics for resolved and unresolved tools, delegations,
  identities, and external helper semantics.
- Regression coverage derived from representative public Google ADK repositories.

## Next reliability work

- Add sanitized representative real-world projects to the benchmark corpus.
- Publish benchmark history across releases rather than relying on a single snapshot.
- Expand false-positive traps and multi-file enterprise agent configurations.

## v0.4 — Agent Dependency Graph and path-aware analysis

In development on `v0.4-dev`:

- Evolve the normalized security graph into a versioned, framework-agnostic Agent
  Dependency Graph (ADG) for agents, tools, MCP servers, models, prompt digests,
  inputs, memory, identities, resources, destinations, and policy controls.
- Represent explicit data-flow, control-flow, delegation, identity, memory, and
  network relationships with typed graph edges.
- Add bounded cross-file static source-to-sink analysis for supported Python
  constructs while retaining explicit coverage uncertainty for unresolved semantics.
- Upgrade attack-path findings to `supported` confidence when a static source-to-sink
  dependency is established; retain capability-co-occurrence findings as
  `potential` where a path is not proven.
- Model persistent agent memory/checkpoint state as a first-class security surface.
- Add Agent Bill of Materials (AIBOM) generation and machine-readable ADG export.
- Add SARIF code flows for path-backed findings.
- Formalize framework normalization beyond Google ADK, with deeper OpenAI Agents
  handoff support. LangGraph support was explored but is intentionally out of the
  current agent-centric product scope pending a separate workflow-security model.
- Expand coverage diagnostics, reviewed path fixtures, and public-project validation.

Runtime execution, live authorization enforcement, SAT/SMT policy solving, automated
prompt mutation, and complete cloud authorization resolution remain outside v0.4.

## v0.7 — Authority adoption and investigation

Completed for v0.7:

- Bootstrap reviewable Authority Contracts from supported observed authority.
- Correlate authority expansion, trust-boundary crossings and policy violations into a
  reviewer-oriented security-impact model.
- Add change-aware authority-resolution CI budgets and regression gates.
- Add conservative effective-authority investigation queries with explicit delegated
  reachability.
- Extend frozen-corpus validation with authority-resolution and policy-bootstrap
  adoption metrics.

## v0.8 — Deployed authority and least-privilege reconciliation

Completed for v0.8:

- Add a versioned local Deployment Evidence contract for workload identity, IAM
  bindings, inheritance, IAM conditions and role-permission evidence.
- Resolve explicit agent-to-deployment relationships and GCP service-account identity
  without fuzzy name matching.
- Reconstruct deployed GCP authority from supplied evidence, including inherited
  grants and custom-role permissions.
- Reconcile required/source-observed authority against deployed authority and classify
  aligned, excess, missing, mixed and unresolved state without treating unknown
  intended authority as least-privilege evidence.
- Compare deployment snapshots for semantic authority drift, introduced excess
  authority and uncertainty regressions.
- Evaluate deployed identity/IAM evidence against repository Authority Contracts.
- Add `horustrace reconcile` and first-party GitHub Action gates for excess authority,
  deployed-policy violations and deployment regressions.

v0.8 remains local-first and evidence-driven. It does not authenticate to a cloud
provider, execute target applications, test credentials or claim that observed
permissions were exercised. Direct authenticated Cloud Asset Inventory / IAM Policy
Analyzer enrichment remains a later optional capability.

## Later — Authenticated cloud enrichment

- Optionally acquire deployment/IAM evidence through authenticated provider APIs.
- Correlate Cloud Asset Inventory / IAM Policy Analyzer evidence with the existing
  Deployment Evidence contract rather than bypassing it.
- Add additional cloud providers with independent evidence adapters and tests.
- Preserve offline operation as the default trust boundary.

## v0.5 — Change-aware security analysis

- Add `horustrace diff <base>..<head>`.
- Detect newly introduced capabilities, data access, egress, identities, and delegated authority.
- Produce PR-focused SARIF/Markdown findings.
- Add change-aware handling for existing fingerprints and suppressions.

## v0.6 — Reachability and deployment context

- Enrich GCP reachability from deployment/resource configuration.
- Improve destination/resource scope modelling.
- Model production vs non-production trust boundaries.
- Add evidence for workload identity and credential provenance.

## Framework expansion

Planned as separate adapters with independent tests rather than generic regex support:

- Google ADK JavaScript/TypeScript.
- Google ADK Go.
- Google ADK Java/Kotlin.
- Additional agent frameworks based on contributor demand.

## Ongoing

- Maintain OWASP Agentic/GenAI and other relevant framework mappings.
- Expand secure/vulnerable fixture coverage.
- Improve source locations and remediation quality.
- Keep false-positive rates conservative and findings explainable.
