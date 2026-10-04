# Microsoft expansion holdout 16

## Purpose

Validate the Microsoft agent stack added in #335-#348 against real public source, with emphasis on the surfaces not covered by the earlier core-MAF cohort:

- Microsoft Agent Framework regression safety
- Microsoft Agent 365 identity/tooling overlays
- Microsoft 365 Agents SDK ingress and delegated identity
- GitHub Copilot SDK Python/.NET
- MAF/Copilot and M365/Copilot hybrid composition

This is an **expansion validation holdout**, not a claim that every construct was unseen during implementation. The core MAF case is explicitly a regression sentinel.

## Freeze

- scanner baseline: `3ccf9bc2124bd7f6307091a9a5c49c5851db2a56` (post-#348 main)
- cohort size: 16 cases
- public repositories: 9
- every target is pinned to an exact 40-character commit SHA
- HorusTrace output was not used to select any case
- target projects are never installed, imported, or executed

The cohort scans each `application_path`, not an entire monorepo. This prevents multiple independent sample applications in the same repository from contaminating each other's inventory.

## Evaluation contract

The initial automated pass records raw HorusTrace output only. It does **not** treat finding counts as accuracy.

For each case, source adjudication should evaluate:

1. agent-root detection
2. function/provider/MCP tool binding
3. delegation and workflow projection
4. effective capabilities
5. resource and network destination scope
6. identities, token subjects and authentication posture
7. approval/permission gates
8. whether unresolved or conditional authority is represented conservatively

A structural pass requires the expected application-level agent surface to be present. A semantic pass requires the material source-visible authority to be represented without invented authority.

## Execution safety

The runner performs only:

- shallow Git fetch of the exact pinned commit
- source reads
- HorusTrace static scanning
- HorusTrace security-graph/effective-authority generation

It does not run target build scripts, package managers, tests, application code, cloud APIs, or authentication flows.

## Interpretation

The previous Microsoft cohort already demonstrated that core MAF structural detection can reach 12/12 after #341 and exposed the cross-file C# authority/provenance defects fixed in #343-#347.

This cohort answers the next question: **do the newer Microsoft slices generalize to real repository structure and adapter interactions, especially Agent 365, M365 Agents SDK and Copilot SDK?**
