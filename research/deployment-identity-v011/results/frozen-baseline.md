# v0.11 Deployment Identity Frozen Baseline

First permitted HorusTrace execution occurred only after the 20-case cohort and truth were locked.

- Scanner/study branch SHA: `6a6c1dc6fe789fb06923a03eaac5303c1afd5522`
- Workflow run: `36313591327`
- Artifact: `10930101101`
- Cases: **20**
- Expected identity relationships: **26**
- TP / FP / FN: **8 / 0 / 18**
- Precision: **1.0000**
- Recall: **0.3077**
- Preregistered recall gate: **0.9000**
- Gate: **FAIL**
- Runtime effectiveness: **not_verified**

| Provider | Cases | TP | FP | FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| GCP | 2 | 0 | 0 | 4 | — | 0.0000 |
| AWS | 2 | 0 | 0 | 3 | — | 0.0000 |
| Azure | 8 | 0 | 0 | 11 | — | 0.0000 |
| Kubernetes | 8 | 8 | 0 | 0 | 1.0000 | 1.0000 |

## Error concentration

All **18** misses are Terraform workload→identity relationships expressed through source references rather than literal principal strings:

- GCP: `google_service_account.<name>.email`
- AWS: `aws_iam_role.<name>.arn`
- Azure: `azurerm_user_assigned_identity.<name>.id`
- Azure also requires first-class Container App / Container App Job workload extraction.

The Kubernetes literal-manifest path is **8/8** with no false positives.

## Engineering conclusion

The next product change is **provider-neutral Terraform identity reference resolution**. The locked truth must not be changed based on these results.

A static relationship should preserve a symbolic source identity such as:

`terraform:aws_iam_role.lambda`

plus projection metadata such as `arn`, rather than inventing an apply-time ARN, email or Entra GUID.

This baseline is the immutable pre-fix comparison point for the next v0.11 iteration.
