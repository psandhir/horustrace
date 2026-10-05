# Fresh ADK + Pydantic AI holdout 10

- Scanner SHA: `e0639c218867d3f2f4adc315831c48f4a7f59e68`
- Successful scans: **10/10**
- Failed scans: **0**
- Analysis incomplete: **7**
- Findings: **22**
- Attack paths: **0**

| Framework | Agent P/R | Tool P/R | MCP P/R | Authority P/R | Findings | Paths |
|---|---:|---:|---:|---:|---:|---:|
| google-adk | 100.0%/88.9% | 40.9%/85.7% | n/a/100.0% | 60.0%/83.3% | 15 | 0 |
| pydantic-ai | 100.0%/26.7% | 100.0%/100.0% | n/a/n/a | n/a/100.0% | 7 | 0 |

## Per-case deltas against locked reference

| Case | Framework | Agent FN/FP | Tool FN/FP | MCP FN/FP | Delegation FN/FP | Authority FN/FP | Findings | Paths |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| rw-008 | google-adk | 0/0 | 0/0 | 0/0 | 0/0 | 1/0 | 0 | 0 |
| rw-028 | google-adk | 1/0 | 2/0 | 0/0 | 2/0 | 1/0 | 0 | 0 |
| rw-034 | google-adk | 0/0 | 0/0 | 0/0 | 2/0 | 0/6 | 12 | 0 |
| rw-023 | google-adk | 1/0 | 0/0 | 0/0 | 4/0 | 0/0 | 0 | 0 |
| rw-026 | google-adk | 0/0 | 0/13 | 0/0 | 0/0 | 0/0 | 3 | 0 |
| rw-172 | pydantic-ai | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0 | 0 |
| rw-174 | pydantic-ai | 11/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0 | 0 |
| rw-177 | pydantic-ai | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 6 | 0 |
| rw-156 | pydantic-ai | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0 | 0 |
| rw-167 | pydantic-ai | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 1 | 0 |
