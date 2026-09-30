# HorusTrace Real-World Agent Security 2026 — Frozen Baseline

- Frozen scanner SHA: \`95885cc341b2900a2ad8eac22db131c700e6701e\`
- Cohort: 5 exact-SHA repositories
- Successful scans: 5
- Execution/fetch failures: 0
- Analysis-incomplete cases: 3
- Target applications were not installed, imported, or executed.
- Runtime effectiveness remains not verified.

## Structural and authority metrics

| Dimension | Precision* | Recall | Truth | Predicted |
| --- | ---: | ---: | ---: | ---: |
| Agent/workflow entities | 1.000 | 1.000 | 13 | 13 |
| Tools | 0.562 | 0.633 | 30 | 28 |
| MCP servers | n/a | n/a | 0 | 2 |
| Delegation edges | 0.500 | 1.000 | 2 | 4 |
| Explicit effective authority | n/a | n/a | 0 | 0 |

\* Precision is computed only on cases where the independent reference explicitly marks the relevant dimension complete. Extra predictions on incomplete cases remain unadjudicated, not false positives.

## Attack paths

- Tier-B reported paths: 0
- Source-adjudicable reported paths: 0
- Source-supported: 0
- Structural support precision: None
- Known-path recall: not measured; the automated reference does not establish an exhaustive valid-path catalogue.

## Findings

- Findings: 11
- By severity: \`{"critical": 1, "high": 4, "medium": 6}\`
- By rule: \`{"ADK001": 1, "AGT020": 2, "AGT040": 3, "CAP005": 2, "PATH001": 1, "PATH006": 1, "PATH008": 1}\`
- By OWASP Agentic category: \`{"ASI01": 3, "ASI02": 8, "ASI05": 3, "ASI07": 1}\`
- Runtime OWASP-mapped findings: \`{"ASI01": 3, "ASI02": 8, "ASI05": 3, "ASI07": 1}\`
- By source context: \`{"runtime": 11}\`
- Finding assertion precision/recall are not claimed from this automated reference.

## Tier C

- Defensible Tier-C cases: 0 / target 25
- Repository-declared identity recall: None
- Runtime deployment effectiveness is not verified.

## Pre-registered threshold checks available from this reference

| Metric | Value | Threshold | Meets |
| --- | ---: | ---: | --- |
| agent_root_precision | 1.000 | 0.95 | yes |
| agent_root_recall | 1.000 | 0.90 | yes |
| authority_edge_precision | n/a | 0.90 | no |
| authority_edge_recall | n/a | 0.80 | no |
| attack_path_structural_support_precision | n/a | 0.80 | no |

## Reference limitation

Ground truth was built by an independent automated dual-pass source reference (structural parser plus lexical cross-check) before scanner execution. It is not represented as an independent human dual-review panel. Dynamic constructs are unresolved, precision is restricted to completeness-marked cases, and finding semantics / exhaustive attack-path recall remain outside the claims supported by this baseline.

