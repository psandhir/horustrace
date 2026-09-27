# v0.11 Deployment Identity Validation Protocol

## Objective

Measure how accurately HorusTrace reconstructs repository-declared deployment identity chains:

```text
agent/application -> workload -> runtime identity -> declared authority
```

The study is intentionally offline. Repository and IaC source are admissible evidence; live cloud or cluster state is not queried. Every reported relationship therefore retains:

```text
runtime_effectiveness: not_verified
```

## Primary endpoint

The preregistered acceptance gate from Issue #155 is:

- **deployment identity recall >= 0.90**

Identity recall is measured on source-adjudicated workload identities:

```text
TP identity relationships / all locked identity relationships
```

A predicted relationship is a true positive only when the expected agent/application principal, workload, provider and canonical runtime identity match the locked reference.

## Secondary endpoints

The final report must also publish:

- identity precision;
- workload discovery precision / recall;
- agent -> workload correlation precision / recall where application correlation is source-adjudicable;
- full agent -> workload -> identity chain precision / recall;
- provider breakout for GCP, AWS, Azure and Kubernetes;
- unresolved rate and unresolved-cause taxonomy;
- error ledger separating scanner defects, reference defects and genuinely unresolved dynamic constructs.

## Independence rules

1. The v0.8 deployment-authority frozen cohort is not reused as the v0.11 accuracy cohort.
2. Candidate screening may use public repository source and documentation.
3. **HorusTrace output must not be inspected for a candidate before its freeze decision and truth record are committed.**
4. Ground truth must cite a pinned repository commit and exact source paths.
5. Repository descriptions, READMEs and names are insufficient by themselves to establish identity truth.
6. Dynamic references may be adjudicated only when their source-level resolution chain is explicit and deterministic.
7. Live cloud/cluster queries are prohibited for truth construction.
8. Post-hoc corrections never rewrite the original locked truth; they are stored as separate adjudications.

## Case eligibility

A frozen case must contain source evidence for at least one workload identity relationship.

Examples:

### GCP

```text
google_cloud_run_v2_service.template.service_account
    -> service-account identity
```

or an equivalent source-proven workload identity binding.

### AWS

```text
aws_lambda_function.role
aws_ecs_task_definition.task_role_arn
    -> IAM role
```

References such as `aws_iam_role.agent.arn` are admissible only when the referenced role resource can be resolved in the pinned source.

### Azure

```text
azurerm_container_app.identity.identity_ids
    -> azurerm_user_assigned_identity
    -> principal/client/object identity
```

A Terraform resource address alone is not a canonical Entra principal ID. Cases requiring apply-time IDs remain unresolved unless a stable source-declared identity value exists.

### Kubernetes

```text
Deployment/Job/Pod.spec...serviceAccountName
    + explicit namespace
    -> system:serviceaccount:<namespace>:<name>
```

The study does not infer an apply-time namespace or implicit default service account.

## Truth record

Every frozen case records:

- case ID;
- provider;
- pinned repository and SHA;
- application/source paths;
- infrastructure/deployment paths;
- expected workload records;
- expected identity relationships;
- correlation status:
  - `proven`
  - `not_adjudicable`
- unresolved source constructs;
- reviewer notes;
- `reviewed: true`;
- `horustrace_results_seen: false`.

The truth record is invalid if `horustrace_results_seen` is true at freeze time.

## Cohort target

Target **20-30 independent cases** with representation from:

- GCP;
- AWS;
- Azure;
- Kubernetes.

The candidate ledger starts larger than the final cohort. Cases are screened out when deployment identity is not source-proven.

## Execution

After the cohort and truth are locked:

1. checkout each exact pinned SHA;
2. do not install or execute target application code;
3. invoke repository deployment discovery/reconciliation only;
4. capture exact HorusTrace scanner SHA;
5. score relationship multisets;
6. persist per-case matched/missing/extra relationships;
7. aggregate metrics and provider breakouts.

## Gate interpretation

Passing the >=0.90 recall gate is necessary but not sufficient for release. Precision and unresolved behaviour are reviewed concurrently.

A failed gate triggers an error-ledger phase. Product changes are permitted only for generalized scanner defects justified independently from the score. Truth is never edited to improve the result.

## Release claim

Until this study completes, HorusTrace may state that v0.11 implements repository-declared deployment identity reconstruction, but must not claim >=0.90 real-world deployment identity recall.
