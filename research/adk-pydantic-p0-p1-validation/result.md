# HorusTrace Real-World Agent Security 2026 — Frozen Baseline

- Frozen scanner SHA: \`85e009198895d25f878ce96d215c5d5b74148389\`
- Cohort: 20 exact-SHA repositories
- Successful scans: 20
- Execution/fetch failures: 0
- Analysis-incomplete cases: 7
- Target applications were not installed, imported, or executed.
- Runtime effectiveness remains not verified.

## Structural and authority metrics

| Dimension | Precision* | Recall | Truth | Predicted |
| --- | ---: | ---: | ---: | ---: |
| Agent/workflow entities | 0.875 | 0.974 | 38 | 43 |
| Tools | 0.660 | 0.756 | 90 | 103 |
| MCP servers | 0.500 | 1.000 | 1 | 5 |
| Delegation edges | 0.500 | 0.870 | 23 | 23 |
| Explicit effective authority | 0.348 | 0.774 | 31 | 73 |

\* Precision is computed only on cases where the independent reference explicitly marks the relevant dimension complete. Extra predictions on incomplete cases remain unadjudicated, not false positives.

## Attack paths

- Tier-B reported paths: 3
- Source-adjudicable reported paths: 3
- Source-supported: 1
- Structural support precision: 0.3333
- Known-path recall: not measured; the automated reference does not establish an exhaustive valid-path catalogue.

## Findings

- Findings: 39
- By severity: \`{"high": 7, "medium": 32}\`
- By rule: \`{"ADK001": 4, "AGT021": 1, "AGT022": 4, "AGT040": 14, "AGT054": 1, "CAP005": 6, "NET001": 3, "NET002": 1, "PATH002": 2, "PATH010": 1, "PATH011": 2}\`
- By OWASP Agentic category: \`{"ASI01": 5, "ASI02": 35}\`
- Runtime OWASP-mapped findings: \`{"ASI01": 5, "ASI02": 35}\`
- By source context: \`{"runtime": 39}\`
- Finding assertion precision/recall are not claimed from this automated reference.

## Tier C

- Defensible Tier-C cases: 0 / target 25
- Repository-declared identity recall: None
- Runtime deployment effectiveness is not verified.

## Pre-registered threshold checks available from this reference

| Metric | Value | Threshold | Meets |
| --- | ---: | ---: | --- |
| agent_root_precision | 0.875 | 0.95 | no |
| agent_root_recall | 0.974 | 0.90 | yes |
| authority_edge_precision | 0.348 | 0.90 | no |
| authority_edge_recall | 0.774 | 0.80 | no |
| attack_path_structural_support_precision | 0.333 | 0.80 | no |

## Reference limitation

Ground truth was built by an independent automated dual-pass source reference (structural parser plus lexical cross-check) before scanner execution. It is not represented as an independent human dual-review panel. Dynamic constructs are unresolved, precision is restricted to completeness-marked cases, and finding semantics / exhaustive attack-path recall remain outside the claims supported by this baseline.

