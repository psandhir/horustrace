# Historical cohort replays — ordered by original cohort registration

This is a **sequential regression programme**, not a fresh independent holdout. The
historical cohorts and their pinned target commits remain unchanged. Changes to
scanner code, study harness, scanner model and selection provenance must be recorded.

## Execution policy

- **One cohort at a time.** Do not start the next until the previous cohort's
  run has concluded and its evidence has been reviewed. A cohort can use bounded
  parallel workers internally; no overlapping cohort runs.
- Use a single explicitly pinned scanner commit for a comparison wave. The first
  scanner commit is `58a2d14ac6456b3f2e2f726484e33763352d6f17` (main immediately
  after evaluation-contract PR #447).
- Retain original fixed repository SHAs, application paths, framework families,
  source/ground-truth reference and original controls. Report cases whose
  repository or source path is no longer retrievable as failures, never silently
  replace them.
- Produce current and baseline metrics: agent coverage, findings, severity,
  attack paths, authority graph, partial or unknown resolution, diagnostics,
  timeouts and framework-specific attribution. Report regressed and improved
  cases with exact references.
- **Separate status labels:** historical execution completed vs accuracy judged.
  Legacy frozen source references are not proof of human-ground-truth or new
  independently blinded LLM adjudication. PR #447 quality gates apply to newly
  registered studies; the historical replays remain labelled as regression.
- Do not mark the next study started, nor report future results, merely because
  it is listed here.

## Audit of recoverable historical studies

| Order | Registered | Historical cohort | Expected scope | Replay handling |
|---:|---|---|---:|---|
| 1 | Sep 25 | `real-world-agent-security-2026` | 180 cases | **Started first:** original runner, locked reference, baseline comparison |
| 2 | Sep 29 | `blind-semantic-cohort-2026` | 11 review cases | Compare existing source reviews; verify runner support |
| 3 | Sep 30 | `gpt-horustrace-differential-2026/unseen-holdout-adk-pydantic-10-v2` | 10 cases | Source/blinding metadata audit before replay |
| 4 | Oct 2 | `fresh-unseen-generalization-20` | 20 cases | Historical standalone runner |
| 5 | Oct 2 | `agent-centric-generalization-12` | 12 cases | Historical standalone runner (overlap with #4) |
| 6 | Oct 2 | `agent-centric-unseen-12-v2` | 12 cases | Historical standalone runner |
| 7 | Oct 2 | `agent-centric-unseen-12-v3` | 12 cases | Historical standalone runner |
| 8 | Oct 2 | `agent-centric-unseen-12-v4` | 12 cases | Historical standalone runner |
| 9 | Oct 3 | `agent-centric-unseen-12-v5` | 12 cases | Historical standalone runner |
| 10 | Oct 3 | `agent-centric-unseen-12-v6` | 12 cases | Historical standalone runner |
| 11 | Oct 3 | `pydantic-fundamentals-15` | 15 cases | Needs fixture-to-runner mapping audit |
| 12 | Oct 3 | `openai-agents-fundamentals-15` | 15 cases | Needs fixture-to-runner mapping audit |
| 13 | Oct 4 | `microsoft-expansion-holdout-16` | 16 cases | Historical standalone runner |
| 14 | Oct 4 | `google-adk-depth-parity-15` | 15 cases | Needs fixture-to-runner mapping audit |
| 15 | Oct 4 | `amazon-sdk-unseen-holdout-10` | 10 cases | Historical standalone runner |
| 16 | Oct 4 | `claude-sdk-generalization-12` | 12 cases | Historical standalone runner |
| 17 | Oct 4 | `anthropic-depth-parity-15` | 15 cases | Needs fixture-to-runner mapping audit |
| 18 | Oct 5–6 | `full-framework-60-20261005` | 60 cases | Historical standalone runner |
| 19 | Oct 6 | `full-framework-60-post-remediation-20261006` | same 60 | Compare against #18; do not count as new holdout |
| 20 | Oct 8 | `independent-20261008-pilot12` (#446) | 12 cases | Final replay only after earlier cohorts; blinded adjudication outstanding |

Other specialized study families (deployment authority/identity, skills LLM
calibration, 15-case depth-parity packs and adjudicator calibration) require
their own semantics and are not omitted from scope: inventory and schedule each
after the corresponding source-scanner cohort family, using separate evaluation
metrics rather than misleading agent/attack-path totals.

The table is a **working execution queue**, not a claim every source cohort or
legacy harness has already been validated against current code. Overlapping
cohorts are retained for regression history but excluded from independent
generalisation denominators.

## First execution record

- Cohort: `research/real-world-agent-security-2026/cohort.json`
- Frozen repositories: 180, exact original pinned source SHAs.
- Frozen original scanner: `418db4e29798a7d25df686dd7bccfd9fefa225bd`.
- Original baseline: 179 successfully executed, 1 failed, 11 attack paths;
  other precision/recall limitations are reported in frozen reference metadata.
- Candidate scanner: `58a2d14ac6456b3f2e2f726484e33763352d6f17`.
- Runner: `scripts/real_world_agent_security_execute.py --mode postfix`.
- Comparison: `scripts/real_world_agent_security_compare.py`.
- Workflow: `.github/workflows/historical-frozen-180-replay.yml`.
- End state: check GitHub Actions, review cases and signed/locked source
  reference before proceeding. **No independent new LLM judge run is claimed.**
