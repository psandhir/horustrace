# Current Google ADK + Pydantic AI 20-repository study

- Scanner SHA: `eacfd1cdab06939e5fae5f65cd2536e5855ac33f`
- Successful scans: **20/20**
- Failed scans: **0**
- Analysis-incomplete: **8**
- Findings emitted: **67**
- Attack paths emitted: **7**

## Framework scorecard

| Framework | Agent precision | Agent recall | Tool precision | Tool recall | MCP precision | MCP recall | Authority precision | Authority recall | Findings | Paths |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| google-adk | 100.0% | 96.8% | 74.2% | 63.9% | n/a | n/a | 80.0% | 74.1% | 47 | 5 |
| pydantic-ai | 83.3% | 100.0% | 52.2% | 100.0% | 50.0% | 100.0% | 25.0% | 100.0% | 20 | 2 |

## Aggregate structural scorecard

| Dimension | Precision | Recall | Truth | Predicted | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| Agents/workflows | 93.3% | 97.4% | 38 | 42 | 37 | 1 | 1 |
| Tools | 64.8% | 75.6% | 90 | 121 | 68 | 19 | 22 |
| MCP servers | 50.0% | 100.0% | 1 | 5 | 1 | 1 | 0 |
| Delegation | 100.0% | 87.0% | 23 | 20 | 20 | 0 | 3 |
| Effective Authority | 38.1% | 77.4% | 31 | 71 | 24 | 13 | 7 |

## Per-case misses / extras

| Case | Framework | Repo | Agent FN/FP | Tool FN/FP | MCP FN/FP | Authority FN/FP | Findings | Paths |
|---|---|---|---:|---:|---:|---:|---:|---:|
| rw-004 | google-adk | JoanMarinPages/agentGemini | 1/0 | 11/0 | 0/0 | 0/0 | 8 | 0 |
| rw-005 | google-adk | Ojas-Patil26/VeriQ | 0/0 | 0/0 | 0/0 | 0/0 | 0 | 0 |
| rw-007 | google-adk | joshnaim1/ocr-test | 0/0 | 0/0 | 0/0 | 0/0 | 1 | 1 |
| rw-009 | google-adk | vivekcommit/Cloud_Architecture_Review | 0/0 | 6/0 | 0/0 | 6/0 | 18 | 0 |
| rw-010 | google-adk | justsankalp/enterprise-rag-poc | 0/0 | 0/0 | 0/0 | 0/0 | 0 | 0 |
| rw-017 | google-adk | mxyhi/always-on-memory-agent | 0/0 | 0/0 | 0/0 | 0/0 | 19 | 4 |
| rw-021 | google-adk | proflead/how-to-build-ai-agent | 0/0 | 0/3 | 0/0 | 0/0 | 0 | 0 |
| rw-027 | google-adk | google/pubmed-rag | 0/0 | 0/0 | 0/0 | 0/0 | 0 | 0 |
| rw-033 | google-adk | moonpy-a11y/agent_payments | 0/0 | 1/1 | 0/0 | 1/1 | 0 | 0 |
| rw-038 | google-adk | elitepunith/apdm-agent | 0/0 | 4/4 | 0/0 | 0/0 | 1 | 0 |
| rw-147 | pydantic-ai | hope-tatenda-mutema/Pedantic-AI-Deep-Research-Agent | 0/0 | 0/0 | 0/0 | 0/0 | 2 | 1 |
| rw-149 | pydantic-ai | LeonieFreisinger/pydanticai-base-agent | 0/0 | 0/0 | 0/0 | 0/0 | 0 | 0 |
| rw-150 | pydantic-ai | Amar-Ag/project-ideation-tool | 0/0 | 0/0 | 0/0 | 0/0 | 4 | 1 |
| rw-153 | pydantic-ai | abhaybhargav/pydanticai-sec-research-assistant | 0/0 | 0/0 | 0/0 | 0/0 | 3 | 0 |
| rw-155 | pydantic-ai | shotgun-sh/shotgun | 0/0 | 0/10 | 0/1 | 0/11 | 8 | 0 |
| rw-160 | pydantic-ai | lladdy/progressive-disclosure-ai-assistant | 0/0 | 0/0 | 0/0 | 0/0 | 0 | 0 |
| rw-161 | pydantic-ai | mars-mx/portfolio | 0/0 | 0/1 | 0/0 | 0/1 | 0 | 0 |
| rw-168 | pydantic-ai | hypermemory-ai/openrouter_provider_validator | 0/0 | 0/0 | 0/0 | 0/0 | 0 | 0 |
| rw-170 | pydantic-ai | Croups/smart-web-scraper | 0/1 | 0/0 | 0/0 | 0/0 | 0 | 0 |
| rw-175 | pydantic-ai | coleam00/orbit-support-agent | 0/0 | 0/0 | 0/0 | 0/0 | 3 | 0 |

## Findings profile

- By rule: `{"ADK001": 11, "AGT021": 1, "AGT022": 4, "AGT040": 24, "AGT054": 1, "CAP005": 13, "NET001": 4, "NET002": 1, "PATH002": 4, "PATH010": 1, "PATH011": 3}`
- By severity: `{"high": 11, "medium": 56}`
- By source context: `{"runtime": 67}`
- OWASP Agentic mapping: `{"ASI01": 8, "ASI02": 62}`

## Interpretation boundary

These precision figures are only calculated where the locked source reference marks the dimension complete. Finding-level semantic precision is not inferred from structural ground truth; individual findings still require source adjudication before treating them as true/false positives.
