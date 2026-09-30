# Hybrid semantic holdout — deterministic vs targeted LLM

- Scanner commit: b1ac29d9536a536ace88f8cee77051d0eb734207
- Provider/model: copilot / gpt-5.4
- Ground truth: locked #279 blind review
- Scanned: 10/10
- Fresh LLM calls: 16
- Applied semantic resolutions: 0
- Low-confidence rejections: 0
- Semantic resolver errors: 16
- Source chars sent: 28278
- Approx input tokens (@4 chars/token): 7070
- Findings: 10 deterministic -> 10 hybrid
- Attack paths: 1 deterministic -> 1 hybrid

| Case | Baseline A/T/M/F/P | Hybrid A/T/M/F/P | Eligible | Calls | Applied | Input chars |
|---|---|---|---:|---:|---:|---:|
| ho-001 | 1/0/0/0/0 | 1/0/0/0/0 | 0 | 0 | 0 | 0 |
| ho-002 | 0/0/0/0/0 | 0/0/0/0/0 | 0 | 0 | 0 | 0 |
| ho-003 | 1/3/0/2/0 | 1/3/0/2/0 | 3 | 3 | 0 | 4337 |
| ho-004 | 1/1/0/0/0 | 1/1/0/0/0 | 0 | 0 | 0 | 0 |
| ho-005 | 1/7/0/0/0 | 1/7/0/0/0 | 7 | 3 | 0 | 1845 |
| ho-006 | 2/2/0/0/0 | 2/2/0/0/0 | 2 | 2 | 0 | 8569 |
| ho-007 | 1/4/0/0/0 | 1/4/0/0/0 | 4 | 3 | 0 | 8506 |
| ho-008 | 2/2/1/5/1 | 2/2/1/5/1 | 2 | 2 | 0 | 3510 |
| ho-009 | 11/3/0/3/0 | 11/3/0/3/0 | 1 | 1 | 0 | 1063 |
| ho-010 | 3/2/0/0/0 | 3/2/0/0/0 | 2 | 2 | 0 | 448 |
