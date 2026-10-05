# ADK + Pydantic P0/P1 validation delta

- Before scanner: `eacfd1cdab06939e5fae5f65cd2536e5855ac33f`
- Candidate scanner: `2f89da39067f9c774ce4a7d96b1afb87c070c4ee`
- Successful scans: 20/20

## Framework delta

| Framework | Metric | Before | After |
|---|---|---:|---:|
| google-adk | Agent precision / recall | 100.0% / 96.8% | 100.0% / 96.8% |
| google-adk | Tool precision / recall | 74.2% / 63.9% | 82.1% / 63.9% |
| google-adk | Authority precision / recall | 80.0% / 74.1% | 80.0% / 74.1% |
| google-adk | Findings | 47 | 21 |
| google-adk | Attack paths | 5 | 3 |
| pydantic-ai | Agent precision / recall | 83.3% / 100.0% | 71.4% / 100.0% |
| pydantic-ai | Tool precision / recall | 52.2% / 100.0% | 48.0% / 100.0% |
| pydantic-ai | Authority precision / recall | 25.0% / 100.0% | 22.2% / 100.0% |
| pydantic-ai | Findings | 20 | 19 |
| pydantic-ai | Attack paths | 2 | 2 |

## Aggregate delta

| Metric | Before | After |
|---|---:|---:|
| Findings | 67 | 40 |
| Attack paths | 7 | 5 |
| Analysis-incomplete cases | 8 | 7 |

## Per-case finding delta

| Case | Framework | Repo | Before | After | Delta |
|---|---|---|---:|---:|---:|
| rw-004 | google-adk | JoanMarinPages/agentGemini | 8 | 8 | +0 |
| rw-005 | google-adk | Ojas-Patil26/VeriQ | 0 | 0 | +0 |
| rw-007 | google-adk | joshnaim1/ocr-test | 1 | 1 | +0 |
| rw-009 | google-adk | vivekcommit/Cloud_Architecture_Review | 18 | 0 | -18 |
| rw-010 | google-adk | justsankalp/enterprise-rag-poc | 0 | 0 | +0 |
| rw-017 | google-adk | mxyhi/always-on-memory-agent | 19 | 11 | -8 |
| rw-021 | google-adk | proflead/how-to-build-ai-agent | 0 | 0 | +0 |
| rw-027 | google-adk | google/pubmed-rag | 0 | 0 | +0 |
| rw-033 | google-adk | moonpy-a11y/agent_payments | 0 | 0 | +0 |
| rw-038 | google-adk | elitepunith/apdm-agent | 1 | 1 | +0 |
| rw-147 | pydantic-ai | hope-tatenda-mutema/Pedantic-AI-Deep-Research-Agent | 2 | 2 | +0 |
| rw-149 | pydantic-ai | LeonieFreisinger/pydanticai-base-agent | 0 | 0 | +0 |
| rw-150 | pydantic-ai | Amar-Ag/project-ideation-tool | 4 | 2 | -2 |
| rw-153 | pydantic-ai | abhaybhargav/pydanticai-sec-research-assistant | 3 | 3 | +0 |
| rw-155 | pydantic-ai | shotgun-sh/shotgun | 8 | 8 | +0 |
| rw-160 | pydantic-ai | lladdy/progressive-disclosure-ai-assistant | 0 | 0 | +0 |
| rw-161 | pydantic-ai | mars-mx/portfolio | 0 | 1 | +1 |
| rw-168 | pydantic-ai | hypermemory-ai/openrouter_provider_validator | 0 | 0 | +0 |
| rw-170 | pydantic-ai | Croups/smart-web-scraper | 0 | 0 | +0 |
| rw-175 | pydantic-ai | coleam00/orbit-support-agent | 3 | 3 | +0 |
