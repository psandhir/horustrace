# v0.11 Deployment Identity — Validation Closeout

## Frozen baseline

The first permitted run occurred only after the 20-case cohort and source truth were locked.

- frozen scanner/study SHA: `6a6c1dc6fe789fb06923a03eaac5303c1afd5522`
- cases: **20**
- expected identity relationships: **26**
- TP / FP / FN: **8 / 0 / 18**
- precision: **1.0000**
- recall: **0.3077**
- preregistered recall gate: **0.9000**
- gate: **FAIL**

The complete baseline remains preserved in `results/frozen-baseline.*`.

## Generalized defect

All 18 baseline misses shared one source pattern: Terraform workload identity attributes referenced identity resources rather than literal principals.

Examples:

- `google_service_account.<name>.email`
- `aws_iam_role.<name>.arn`
- `azurerm_user_assigned_identity.<name>[index].id`

PR #194 fixed that generalized defect without manufacturing apply-time principal values. Symbolic source identities and their projections are retained.

## Unchanged-cohort post-fix run

PR #194 candidate SHA `4fb50de70f4fe9ed1f28b706656faf23cbc6b622` was tested against the unchanged frozen cohort.

The merged main commit `7fd25ae3666499e965819a4a177818b836375092` has the same tree:

`0bad76132ff15e7d9e9553ddc8d796ca63d966a4`

Workflow run: `36314001977`  
Artifact: `10930081872`

### Raw immutable-truth result

- cases: **20**
- TP / FP / FN: **26 / 3 / 0**
- precision: **0.8966**
- recall: **1.0000**
- preregistered recall gate: **0.9000**
- gate: **PASS**
- runtime effectiveness: **not_verified**

| Provider | Cases | TP | FP | FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| GCP | 2 | 4 | 0 | 0 | 1.0000 | 1.0000 |
| AWS | 2 | 3 | 0 | 0 | 1.0000 | 1.0000 |
| Azure | 8 | 11 | 3 | 0 | 0.7857 | 1.0000 |
| Kubernetes | 8 | 8 | 0 | 0 | 1.0000 | 1.0000 |

## Azure precision adjudication

All three raw false positives occur in `azure-006`.

Pinned source proves three additional Container App Jobs in the case file:

- `azurerm_container_app_job.memory_digest`
- `azurerm_container_app_job.memory_sweeper`
- `azurerm_container_app_job.watchdog`

Each explicitly uses:

`azurerm_user_assigned_identity.memory_governor[0].id`

The frozen reference recorded only `azurerm_container_app.memory_governor`.

Per study protocol, the original truth is **not edited**. The correction is recorded separately in:

`adjudications/azure-006.json`

### Post-hoc source-adjudicated diagnostic

If the three proven omissions are added only for diagnostic scoring:

- source-adjudicated relationships: **29**
- TP / FP / FN: **29 / 0 / 0**
- precision: **1.0000**
- recall: **1.0000**

This diagnostic does not replace the immutable frozen result.

## Acceptance decision

Issue #155 required:

- deployment identity recall >= **0.90**
- validation against a new independent deployment-only cohort
- `runtime_effectiveness: not_verified` unless live evidence exists

The unchanged frozen cohort now measures **1.0000 recall**, so the primary preregistered gate is satisfied.

The study also demonstrated a material capability improvement:

`0.3077 -> 1.0000 deployment identity recall`

after one generalized, source-justified defect fix.

## Remaining scope

This closeout validates repository-declared workload identity reconstruction for the source patterns represented in the independent cohort. It does **not** establish runtime cloud effectiveness and does not imply exhaustive coverage of every Terraform/Helm/provider construct.

Future extensions should be justified by new independent evidence rather than additional score-driven changes to this cohort.
