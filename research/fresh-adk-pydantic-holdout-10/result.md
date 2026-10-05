# HorusTrace Real-World Agent Security 2026 — Frozen Baseline

- Frozen scanner SHA: \`e0639c218867d3f2f4adc315831c48f4a7f59e68\`
- Cohort: 10 exact-SHA repositories
- Successful scans: 10
- Execution/fetch failures: 0
- Analysis-incomplete cases: 7
- Target applications were not installed, imported, or executed.
- Runtime effectiveness remains not verified.

## Structural and authority metrics

| Dimension | Precision* | Recall | Truth | Predicted |
| --- | ---: | ---: | ---: | ---: |
| Agent/workflow entities | 1.000 | 0.606 | 33 | 26 |
| Tools | 0.480 | 0.935 | 31 | 53 |
| MCP servers | n/a | 1.000 | 1 | 2 |
| Delegation edges | 1.000 | 0.500 | 16 | 9 |
| Explicit effective authority | 0.600 | 0.895 | 19 | 44 |

\* Precision is computed only on cases where the independent reference explicitly marks the relevant dimension complete. Extra predictions on incomplete cases remain unadjudicated, not false positives.

## Attack paths

- Tier-B reported paths: 0
- Source-adjudicable reported paths: 0
- Source-supported: 0
- Structural support precision: None
- Known-path recall: not measured; the automated reference does not establish an exhaustive valid-path catalogue.

## Findings

- Findings: 22
- By severity: \`{"medium": 22}\`
- By rule: \`{"ADK001": 4, "AGT022": 2, "AGT040": 9, "CAP005": 6, "NET002": 1}\`
- By OWASP Agentic category: \`{"ASI02": 21}\`
- Runtime OWASP-mapped findings: \`{"ASI02": 21}\`
- By source context: \`{"runtime": 22}\`
- Finding assertion precision/recall are not claimed from this automated reference.

## Tier C

- Defensible Tier-C cases: 0 / target 25
- Repository-declared identity recall: None
- Runtime deployment effectiveness is not verified.

## Pre-registered threshold checks available from this reference

| Metric | Value | Threshold | Meets |
| --- | ---: | ---: | --- |
| agent_root_precision | 1.000 | 0.95 | yes |
| agent_root_recall | 0.606 | 0.90 | no |
| authority_edge_precision | 0.600 | 0.90 | no |
| authority_edge_recall | 0.895 | 0.80 | yes |
| attack_path_structural_support_precision | n/a | 0.80 | no |

## Reference limitation

Ground truth was built by an independent automated dual-pass source reference (structural parser plus lexical cross-check) before scanner execution. It is not represented as an independent human dual-review panel. Dynamic constructs are unresolved, precision is restricted to completeness-marked cases, and finding semantics / exhaustive attack-path recall remain outside the claims supported by this baseline.

