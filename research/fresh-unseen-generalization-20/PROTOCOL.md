# Fresh unseen generalization 20 — protocol

## Question

Does current HorusTrace generalize to previously unseen repositories when measured with the calibrated adjudication framework established in #288?

## Cohort

20 exact-SHA public repositories, frozen before HorusTrace execution:

- 4 Google ADK
- 4 Pydantic AI
- 4 OpenAI Agents SDK
- 4 LangGraph
- 4 MCP/custom

Repositories used in Frozen-180, the retrospective calibration, the unseen ADK/Pydantic holdout, and the earlier hybrid semantic holdout were excluded.

Selection used repository/framework evidence only. HorusTrace output was not used.

## Scanner state

The study executes the scanner from the branch commit under test against each pinned target SHA.

Each case records:

- source pack used for adjudication;
- raw `horustrace scan` JSON;
- raw `horustrace security-graph` JSON;
- normalized findings and attack paths;
- agent/tool/MCP/finding/path counts;
- scanner execution errors.

## Adjudication

The GitHub workflow is intentionally bundle-only. Independent adjudication is performed outside the workflow using the calibrated #285/#288 rules:

- existence != effective authority;
- unbound tools/MCP are not agent-reachable authority;
- co-occurrence != attack path;
- fixed/operator-configured destinations are not model-selected egress;
- runtime/context plumbing is not model-selected input without concrete flow;
- preserve approval, sandbox, allowlist, auth, scope and runtime qualifications.

Finding verdicts: `true_positive`, `partial`, `false_positive`, `unresolved`.

Primary metrics:

- strict precision = TP / resolved claims;
- materially-supported precision = (TP + partial) / resolved claims;
- explicit FP rate;
- partial rate and reason taxonomy;
- findings/paths per framework;
- scanner error rate.

Recall is not inferred from scanner output alone. Fresh blind review is discrepancy discovery; locked source review is required before scanner semantics change.

## Decision rule

The study is evidence for generalization only if the cohort remains frozen and no scanner changes are made after viewing results. Product fixes discovered by this study must be evaluated in a subsequent rerun and labeled as post-hoc.
