# HorusTrace Real-World Agent Security 2026 — Frozen Baseline

- Frozen scanner SHA: \`e0639c218867d3f2f4adc315831c48f4a7f59e68\`
- Cohort: 10 exact-SHA repositories
- Successful scans: 10
- Execution/fetch failures: 0
- Analysis-incomplete cases: 4
- Target applications were not installed, imported, or executed.
- Runtime effectiveness remains not verified.

## Structural and authority metrics

| Dimension | Precision* | Recall | Truth | Predicted |
| --- | ---: | ---: | ---: | ---: |
| Agent/workflow entities | 0.824 | 0.952 | 21 | 24 |
| Tools | 1.000 | 0.957 | 47 | 45 |
| MCP servers | 0.000 | n/a | 0 | 2 |
| Delegation edges | 0.000 | 0.500 | 2 | 2 |
| Explicit effective authority | 0.706 | 0.889 | 18 | 22 |

\* Precision is computed only on cases where the independent reference explicitly marks the relevant dimension complete. Extra predictions on incomplete cases remain unadjudicated, not false positives.

## Attack paths

- Tier-B reported paths: 4
- Source-adjudicable reported paths: 2
- Source-supported: 1
- Structural support precision: 0.5
- Known-path recall: not measured; the automated reference does not establish an exhaustive valid-path catalogue.

## Findings

- Findings: 19
- By severity: \`{"critical": 2, "high": 5, "medium": 12}\`
- By rule: \`{"ADK001": 2, "AGT020": 2, "AGT021": 1, "AGT040": 5, "AGT053": 2, "CAP005": 3, "PATH001": 2, "PATH002": 2}\`
- By OWASP Agentic category: \`{"ASI01": 4, "ASI02": 15, "ASI05": 4}\`
- Runtime OWASP-mapped findings: \`{"ASI01": 4, "ASI02": 15, "ASI05": 4}\`
- By source context: \`{"runtime": 19}\`
- Finding assertion precision/recall are not claimed from this automated reference.

## Tier C

- Defensible Tier-C cases: 0 / target 25
- Repository-declared identity recall: None
- Runtime deployment effectiveness is not verified.

## Pre-registered threshold checks available from this reference

| Metric | Value | Threshold | Meets |
| --- | ---: | ---: | --- |
| agent_root_precision | 0.824 | 0.95 | no |
| agent_root_recall | 0.952 | 0.90 | yes |
| authority_edge_precision | 0.706 | 0.90 | no |
| authority_edge_recall | 0.889 | 0.80 | yes |
| attack_path_structural_support_precision | 0.500 | 0.80 | no |

## Reference limitation

Ground truth was built by an independent automated dual-pass source reference (structural parser plus lexical cross-check) before scanner execution. It is not represented as an independent human dual-review panel. Dynamic constructs are unresolved, precision is restricted to completeness-marked cases, and finding semantics / exhaustive attack-path recall remain outside the claims supported by this baseline.

