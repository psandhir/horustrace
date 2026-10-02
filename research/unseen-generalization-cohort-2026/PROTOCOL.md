# Unseen generalization cohort — protocol

## Question

Does the post-#288 HorusTrace architecture retain high materially-supported precision on repositories that were not part of Frozen-90, Frozen-180, the semantic tuning cases, or retrospective calibration?

## Cohort freeze

The 20 repositories in `cohort.json` were selected and pinned before HorusTrace output was reviewed.

Selection is stratified 4/4/4/4/4 across five discovery families:

- Google ADK
- Pydantic AI
- OpenAI Agents
- LangGraph
- MCP/custom

The family is the discovery stratum, not a claim that every repository contains only that framework. Mixed-framework repositories remain valid generalization cases.

Repositories in the prior 180-repo study and the #288 calibration set were explicitly excluded.

## Scanner

The scanner baseline is the merged post-calibration mainline at `e1689cbae63799efbef67fe6146d39fc9bdab1dc`.

The workflow scans each pinned repository as a whole and exports:

- HorusTrace JSON findings;
- security graph attack paths;
- a bounded source pack for independent adjudication;
- immutable repo/SHA metadata.

## Evaluation

Use the calibrated #288 semantics:

- **strict precision** = TP / (TP + partial + FP)
- **materially-supported precision** = (TP + partial) / (TP + partial + FP)
- explicit FP rate
- partial count and reason taxonomy
- attack-path support separately

A `partial` result is not silently counted as a strict TP. It means the core security fact is source-supported but HorusTrace omitted or overstated a material qualification such as principal, scope, runtime condition, approval, destination provenance, or reachability.

Fresh blind-review findings are discrepancy discovery, not regression truth. They require source adjudication before scanner changes.

## Guardrails

No repository may be replaced because its HorusTrace output is sparse, noisy, or inconvenient. Fetch/scan failures are reported as failures rather than substituted after output review.

No scanner fix is made during the cohort run. Findings from this cohort are converted into a product queue only after the cohort-level result is frozen.
