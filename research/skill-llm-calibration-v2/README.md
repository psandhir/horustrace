# Agent Skill LLM calibration v2

This corpus is the **spec-aligned revision** of the frozen v1 study. It exists to
remove prompt-vs-gold inconsistencies discovered during the GPT-5.6 Sol in-chat
adjudication.

It is **not an unseen holdout** and must not be used as an independent estimate of
model generalization.

## Changes from v1

Six missing overlap labels were added because the production prompt explicitly
supports both concepts:

- `exp-secret-harvesting`: add `cross_trust_boundary_data_movement`
- `exp-instruction-override`: add `policy_circumvention`
- `exp-cross-trust`: add `data_exfiltration`
- `sub-secret-harvesting`: add `cross_trust_boundary_data_movement`
- `sub-cross-trust`: add `data_exfiltration`
- `multi-secret-privilege-cross`: add `data_exfiltration`

Two cases were rewritten to make the intended semantic boundary unambiguous:

- `sub-instruction-override` now establishes conflicting **system-level guidance**,
  matching the production definition of instruction override.
- `neg-anonymized-boundary` now keeps anonymous metrics inside the approved internal
  analytics trust zone, making it a clean cross-trust hard negative.

## In-chat consistency check

Using the same production rubric in GPT-5.6 Sol:

| Threshold | Exact cases | TP | FP | FN | Micro precision | Micro recall | Micro F1 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.65 | 44/44 | 56 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| 0.75 | 44/44 | 56 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| 0.85 | 44/44 | 56 | 0 | 0 | 1.000 | 1.000 | 1.000 |

This result confirms **taxonomy/gold consistency only**. Forty-two cases are unchanged
from v1 and reuse the same semantic decisions; only the two rewritten cases required a
fresh in-chat judgment. Therefore the 1.000 score is deliberately not treated as a
holdout-quality metric.

The next meaningful step is a fresh unseen Skill cohort whose gold labels are fixed
before semantic scoring.
