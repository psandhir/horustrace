# Frozen-180 Rule / OWASP Pre-Adjudication Snapshot

## Run identity

- Scanner candidate SHA: `846d9ab08d3a5f68a0a7a123d1cf44c632d5e60f`
- Merged instrumentation PR: #199
- Frozen-180 workflow run: `36333320576`
- Workflow artifact: `10936901533`
- Artifact digest: `sha256:7218526e21d5bdcaca06ac596f4f635057ef8b5f493dfb99427d50eeebe31394`
- Frozen cohort: 180 exact-SHA public repositories
- Successful scans: **180 / 180**
- Execution failures: **0**
- Analysis-incomplete cases: **94**
- Runtime effectiveness: **not_verified**

This is the full-population descriptive snapshot captured before human finding adjudication. Counts below are scanner assertions, **not confirmed vulnerabilities**.

## Headline finding population

- Total findings: **271**
- Runtime-classified findings: **266**
- Test findings: **3**
- Notebook findings: **2**
- Critical: **10**
- High: **69**
- Medium: **192**

## Rule prevalence

| Rule | Findings | Repositories affected | Runtime findings |
| --- | ---: | ---: | ---: |
| AGT040 | 80 | 32 | 79 |
| AGT020 | 57 | 17 | 54 |
| NET002 | 41 | 14 | 41 |
| CAP005 | 33 | 22 | 32 |
| AGT022 | 20 | 10 | 20 |
| ADK001 | 15 | 9 | 15 |
| PATH001 | 10 | 5 | 10 |
| NET001 | 5 | 5 | 5 |
| AGT021 | 3 | 3 | 3 |
| CAP004 | 2 | 1 | 2 |
| AGT032 | 2 | 1 | 2 |
| IDN004 | 1 | 1 | 1 |
| PATH006 | 1 | 1 | 1 |
| AGT050 | 1 | 1 | 1 |

## OWASP Agentic Top 10 prevalence

| OWASP Agentic category | Mapped findings | Repositories affected | Runtime findings |
| --- | ---: | ---: | ---: |
| ASI02 Tool Misuse | 154 | 33 | 152 |
| ASI05 Unexpected Code Execution | 67 | 19 | 64 |
| ASI01 Agent Goal Hijack | 11 | 5 | 11 |
| ASI03 Identity and Privilege Abuse | 1 | 1 | 1 |
| ASI04 Agentic Supply Chain | 1 | 1 | 1 |

No full-population claim is made for ASI06, ASI08, ASI09, or ASI10 because the current static rule catalogue does not establish comprehensive detector coverage for those categories. A category with no mapped finding is not evidence of absence.

## Observed examples requiring human adjudication

Examples from the scanner population include:

- privileged tools without an explicit guardrail or approval (`AGT040`);
- shell/process execution without approval (`AGT020`);
- external network/write capability without a destination allowlist (`NET002`);
- agents combining read and mutation authority (`CAP005`);
- destructive writes without approval (`AGT021`);
- supported untrusted-input-to-process-execution paths (`PATH001`);
- remote MCP servers without explicit tool allowlists (`AGT032`);
- unpinned MCP package execution (`AGT050`);
- a source-observed hardcoded credential case (`IDN004`).

These examples are deliberately not labelled confirmed until the blinded source-review protocol is completed.

## Next validation step

The existing Phase-A source-derived pack must be independently reviewed and locked before scanner reveal.

After Phase-A lock, Phase B will sample **60 scanner findings** using rule/severity stratification and repository diversity caps. Reviewers will see neutral source assertions but not:

- HorusTrace rule ID;
- scanner severity;
- scanner confidence;
- fingerprint;
- OWASP mapping;
- whether the claim originated from HorusTrace.

The final study will publish:

- overall finding assertion precision;
- precision by HorusTrace rule;
- precision by OWASP Agentic category;
- finding recall from the independent Phase-A source assertion pack;
- severity agreement;
- false-positive / false-negative taxonomy;
- unresolved and reviewer-disagreement rates.

This snapshot must remain unchanged when those human verdicts are later added.
