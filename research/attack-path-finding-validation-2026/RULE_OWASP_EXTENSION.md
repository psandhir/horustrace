# Rule and OWASP Fidelity Extension

## Objective

Extend the existing human-adjudicated finding study so the frozen 180-repository cohort can answer:

1. Which HorusTrace threat-vector rules fire on current mainline semantics?
2. Which OWASP Top 10 for Agentic Applications 2026 categories those findings map to?
3. How many mapped findings are runtime-classified versus test/example/notebook/CLI/template/unknown context?
4. What proportion of sampled scanner assertions are supported by pinned source?
5. What is finding precision by HorusTrace rule and by OWASP Agentic category?

This extension does not change the immutable 180-case cohort or its locked source truth.

## Execution cohort

Use the unchanged `research/real-world-agent-security-2026/cohort.json`:

- 180 exact-SHA public repositories;
- target repositories are not installed, imported, or executed;
- no target credentials or live cloud/SaaS access;
- current HorusTrace candidate is evaluated against the frozen source revisions.

## Full-population descriptive outputs

For every finding emitted across the 180 cases preserve:

- rule ID;
- severity;
- confidence;
- source context;
- source location/provenance;
- OWASP Agentic category mapping;
- scanner SHA;
- repository and frozen target SHA.

Aggregate and publish:

- total findings;
- findings by rule;
- findings by severity;
- findings by source context;
- findings by OWASP Agentic category;
- runtime-only findings by OWASP Agentic category.

These are prevalence/activity measurements, not validated vulnerability counts.

## Human validation

Use the existing guarded Phase-B protocol only after Phase A is locked.

Phase B should sample **60 findings** with deterministic rule/severity stratification and repository diversity caps.

Reviewer packets must continue to hide:

- HorusTrace rule ID;
- scanner severity;
- scanner confidence;
- fingerprint;
- OWASP mapping;
- the fact that the neutral claim originated from a HorusTrace finding.

The coordinator-only hidden map retains rule/severity/source-context/OWASP metadata.

Two independent human reviewers adjudicate each neutral assertion from pinned source.

## Published validation metrics

After reviewer lock publish:

- overall finding assertion precision;
- precision by HorusTrace rule;
- precision by OWASP Agentic category;
- exact severity agreement;
- within-one-level severity agreement;
- false-positive taxonomy;
- unresolved/disagreement rate.

Finding recall remains measured from the separate source-derived Phase-A assertion pack.

## Interpretation

A mapped OWASP finding means one or more HorusTrace rules mapped to that category fired. It does **not** establish comprehensive OWASP coverage, runtime exploitability, or certification.

OWASP-category precision is derived from the human validity of the underlying mapped findings. A category with a small validation sample must be reported with its sample size and must not be generalized beyond that evidence.

Runtime effectiveness remains `not_verified`.
