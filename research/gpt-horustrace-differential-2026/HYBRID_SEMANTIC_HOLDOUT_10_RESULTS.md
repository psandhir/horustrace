# Hybrid semantic holdout — deterministic vs targeted LLM

- Scanner commit: d786faa7f83a9e0173359866aab00380cc401914
- Provider/model: copilot / auto
- Ground truth: locked #279 blind review
- Scanned: 10/10
- Fresh LLM calls: 16
- Applied semantic resolutions: 16
- Low-confidence rejections: 0
- Semantic resolver errors: 0
- Source chars sent: 28278
- Approx input tokens (@4 chars/token): 7070
- Findings: 10 deterministic -> 13 hybrid
- Attack paths: 1 deterministic -> 1 hybrid

| Case | Baseline A/T/M/F/P | Hybrid A/T/M/F/P | Eligible | Calls | Applied | Input chars |
|---|---|---|---:|---:|---:|---:|
| ho-001 | 1/0/0/0/0 | 1/0/0/0/0 | 0 | 0 | 0 | 0 |
| ho-002 | 0/0/0/0/0 | 0/0/0/0/0 | 0 | 0 | 0 | 0 |
| ho-003 | 1/3/0/2/0 | 1/3/0/3/0 | 3 | 3 | 3 | 4337 |
| ho-004 | 1/1/0/0/0 | 1/1/0/0/0 | 0 | 0 | 0 | 0 |
| ho-005 | 1/7/0/0/0 | 1/7/0/0/0 | 7 | 3 | 3 | 1845 |
| ho-006 | 2/2/0/0/0 | 2/2/0/0/0 | 2 | 2 | 2 | 8569 |
| ho-007 | 1/4/0/0/0 | 1/4/0/1/0 | 4 | 3 | 3 | 8506 |
| ho-008 | 2/2/1/5/1 | 2/2/1/6/1 | 2 | 2 | 2 | 3510 |
| ho-009 | 11/3/0/3/0 | 11/3/0/3/0 | 1 | 1 | 1 | 1063 |
| ho-010 | 3/2/0/0/0 | 3/2/0/0/0 | 2 | 2 | 2 | 448 |
