# Amazon expansion holdout 14

## Purpose

Validate the Amazon agentic stack added in #350 against real public source, without tuning case selection to HorusTrace output.

The frozen cohort spans:

- Strands Agents Python and TypeScript
- Strands tools, MCP and delegation
- managed Amazon Bedrock Agents in CloudFormation and Terraform
- AWS execution-role / IAM authority reconstruction
- current `agentcore/agentcore.json`
- AgentCore runtime/gateway/authentication semantics
- current and divergent Terraform AgentCore resource shapes
- hybrid managed-Bedrock + Strands/MCP layouts

## Freeze

- scanner baseline: `18caca37b992402351b3c53d93d47c783f218d82` (main after #352; Amazon P0 #350 already merged)
- cohort size: **14 cases**
- unique public repositories: **10**
- every target is pinned to an exact 40-character commit SHA
- HorusTrace output was not used to select a case
- target projects are never installed, imported, built or executed
- cases scan the application path rather than an entire monorepo where practical

## Evaluation contract

Raw counts are diagnostics, not accuracy.

Source adjudication evaluates:

1. agent-root detection
2. function/vended/MCP/action-group tool binding
3. delegation and multi-agent projection
4. effective capabilities
5. AWS identities and execution roles
6. resource and network destination scope
7. AgentCore inbound/outbound authentication posture
8. conservative representation of dynamic, conditional or unresolved authority

A structural pass requires the material application-level agent/runtime surface to be present. A semantic pass requires material source-visible authority to be represented without invented authority.

The cohort intentionally contains two pressure tests where a fully resolved result is **not** assumed:

- `amz-br-tf-002`: multi-agent orchestration is expressed through Step Functions/Lambda rather than a native collaborator declaration.
- `amz-ac-tf-002`: independent Terraform uses `aws_bedrockagentcore_runtime`, exercising provider/schema drift.

Those cases should become explicit unresolved/generalization findings if the scanner cannot prove the relationship; silence or fabricated authority is worse than unresolved.

## Execution safety

The runner performs only:

- shallow Git fetch of the exact pinned commit
- source reads
- HorusTrace static scanning
- HorusTrace security-graph, effective-authority and Authority Contract report generation

It does not run package managers, target tests, application code, cloud APIs, credentials or authentication flows.

## Interpretation

This study answers whether Amazon support generalizes beyond the focused adapter tests in #350. Any fixes should target reusable Amazon/Strands/AgentCore constructs, not individual repositories. The cohort remains frozen through post-fix reruns.
