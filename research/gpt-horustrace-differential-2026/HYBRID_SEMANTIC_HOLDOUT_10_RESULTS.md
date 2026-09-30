# Hybrid semantic holdout — deterministic vs targeted LLM

- Scanner commit: 6854723e33fd5eb2139cec61737cc54e5a8615d8
- Provider/model: copilot / auto
- Ground truth: locked #279 blind review
- Scanned: 10/10
- Fresh LLM calls: 20
- Applied semantic resolutions: 19
- Low-confidence rejections: 1
- Semantic resolver errors: 0
- Source chars sent: 59779
- Approx input tokens (@4 chars/token): 14945
- Findings: 10 deterministic -> 20 hybrid
- Attack paths: 1 deterministic -> 1 hybrid

| Case | Baseline A/T/M/F/P | Hybrid A/T/M/F/P | Eligible | Calls | Applied | Input chars |
|---|---|---|---:|---:|---:|---:|
| ho-001 | 1/0/0/0/0 | 1/0/0/0/0 | 0 | 0 | 0 | 0 |
| ho-002 | 0/0/0/0/0 | 0/0/0/0/0 | 0 | 0 | 0 | 0 |
| ho-003 | 1/3/0/2/0 | 1/3/0/3/0 | 3 | 3 | 3 | 4337 |
| ho-004 | 1/1/0/0/0 | 1/1/0/0/0 | 0 | 0 | 0 | 0 |
| ho-005 | 1/7/0/0/0 | 1/7/0/0/0 | 7 | 3 | 3 | 1845 |
| ho-006 | 2/2/0/0/0 | 2/2/0/0/0 | 2 | 2 | 2 | 8569 |
| ho-007 | 1/4/0/0/0 | 1/4/0/0/0 | 4 | 3 | 3 | 8506 |
| ho-008 | 2/2/1/5/1 | 2/3/2/8/1 | 3 | 3 | 3 | 4973 |
| ho-009 | 11/3/0/3/0 | 11/5/0/9/0 | 12 | 3 | 2 | 24000 |
| ho-010 | 3/2/0/0/0 | 3/3/0/0/0 | 3 | 3 | 3 | 7549 |
