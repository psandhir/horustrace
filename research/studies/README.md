# Registered independent studies

All **new** source-cohort studies go in `research/studies/<study-id>/`.

Each directory must contain:

- `cohort.json`: frozen manifest with exact full repository commit SHAs, unique repositories, source-root scope and selection provenance.
- `study.json`: registry entry pointing to the frozen cohort and the study's GitHub Actions workflow.
- A workflow under `.github/workflows/` that invokes the reusable `./.github/workflows/reusable-study-quality-gate.yml` job after per-case scanner evidence, a study-accurate aggregate summary, independent source-only Phase A and scanner-revealed Phase B evidence have been uploaded.

Example `study.json`:

~~~json
{
  "study": "independent-holdout-example",
  "cohort_path": "research/studies/independent-holdout-example/cohort.json",
  "workflow_path": ".github/workflows/independent-holdout-example.yml",
  "quality_gate_required": true
}
~~~

Do not create new studies outside this convention to bypass the CI guard. Historical studies outside this directory remain archival.

CI runs `python -m scripts.check_study_registry` on changes to this directory. This verifies the cohort contract, manifest identity and explicit quality gate usage. The downstream quality gate validates each completed case, reviewer identities and source evidence, source-blind reviewer agreement, scanner comparison and a stratified independent finding sample.

For complete semantics and limitations, see [the study evaluation contract](../STUDY_EVALUATION_CONTRACT.md).

**A study can execute successfully and still fail its security-quality gate. This is an expected, valuable outcome when supported missing paths or false positives are found.**
