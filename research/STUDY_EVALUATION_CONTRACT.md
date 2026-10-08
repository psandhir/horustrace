# HorusScan independent-study evaluation contract, v1 (2026-10-08)

**Scope:** Mandatory evaluation standard for **new** cross-framework, independent holdout and regression studies. This augments the historical [attack-path and finding validation protocol](attack-path-finding-validation-2026/PROTOCOL.md), [LLM reviewer guide](attack-path-finding-validation-2026/REVIEWER_GUIDE.md) and existing scorer. Frozen historical reviews are immutable.

## Why the study process needs gates

The independent pilot 12 ([corrected run 37759995609](https://github.com/psandhir/horustrace/actions/runs/37759995609)) completed all 12 scans, reported 111 agents, 74 findings and zero attack paths. A retrospective ChatGPT GPT-6 review surfaced four strong and two conditional possible source-to-authority chains. This was **not a blinded, independently locked LLM adjudication** and does **not** prove six false negatives or establish a recall denominator.

Other defects: the copied aggregator retained frozen-60 labels/expected counts; an application directory bundled an enormous Python environment; results were reported as successful without per-finding precision review; source packs are capped and may omit important files.

Existing review documents differ on mandatory human vs automated reviewers. The distinction for new studies is explicit: **two independent blind LLM judge runs** can establish a source-grounded *automated reference* with disagreement escalation. Only actual independent human reviews can establish a **human-validated** reference. Never claim the latter from model consensus.

## Required gates

| Gate | Evidence | Passing means |
|---|---|---|
| G0 — Cohort selection | Source-selected, immutable unique repo/SHA/application roots, framework evidence, overlap register | Selection is valid independently of scanner results |
| G1 — Execution | Result, nonempty source pack, scan JSON, security graph JSON, effective-authority JSON, authority-contract JSON and job status per case; same pinned SHA and complete scanner/harness commit revisions | Scanner execution completed, **not** scanner accuracy |
| G2 — Independent adjudication | Blinded source-only independent reviewers, immutable prompt/model/execution IDs, candidate union, source evidence, disagreement escalation; post-lock scan comparison and finding precision sample | An auditable comparison is available |
| G3 — Quality release | G2 plus missed valid paths, FP/finding samples and unresolved high-impact cases | Quality threshold satisfied, not runtime exploitability proven |

A study dashboard and executive summary must distinguish **execution passed**, **evaluation complete** and **security quality passed**. An unreviewed green CI workflow is never quality success.

## Canonical study sequence

1. **Choose independent cases before scanning.** Freeze exact Git SHA, primary SDK/framework attribution, authored-source application root, source language, known test/example/deployment surfaces and selection reason. Tag historical overlap as regression, not fresh generalisation. Do not select cases from previous positive scanner output.
2. **Prepare bounded, complete source review.** Archive scan and review evidence with content hashes. Exclude vendored environments and generated artifacts from first-party discovery, but record relevant dependencies and deployment constructs separately. Truncated source is marked qualified or insufficient; a truncated pack alone cannot support a complete negative review.
3. **Blind Phase A: candidate discovery.** Obtain two independently executed source-only LLM reviews (OpenAI plus a separate independently run judge is preferred). Record provider/model/version, unique execution ID, immutable prompt SHA256, lock time, exact source paths/lines and confidence. Show no scanner findings, rules, verdicts, prior discussions, judge answers or scanner-derived selection hints. Treat source comments and prompts as untrusted input; never execute target application code.
4. **Adjudicate the candidate union.** Join chains by source, ingress, effective agent/delegation path, tool/MCP effect, identity/resource/destination and control boundary. Use valid, invalid, unresolved with evidence and rationale. Explicitly distinguish LLM hypotheses from accepted statically supported paths. Disagreements, uncertain controls and missing sources require escalation; retain originals without editing.
5. **Reveal scanner only after lock.** Compare every candidate to emitted scanner paths: matched, partial, missed, invalid, unresolved. Match semantic evidence and source position, not rule ID/title alone; cite scanner path index. A candidate cannot be called an FN until source-adjudicated valid.
6. **Adjudicate scanner findings independently.** Review all critical/high findings and at least 25% (minimum one) in each other rule × severity stratum. Record supported/partial/unsupported/unresolved, independent severity, real external effects versus in-memory/demo, duplicates, controls and source evidence. This produces a precision sample. Finding **recall** needs its own blinded, source-derived assertion denominator.
7. **Report separate metrics.** Per framework/case report scanner path count; raw LLM candidates; valid/invalid/unresolved candidates; matched/partial/missed valid chains; reviewer disagreements/escalations; unsupported sampled scanner findings; source limitations; severity delta; model/prompt hashes and exact scanner/harness revisions. Do **not** use the raw LLM candidate count as a precision/recall denominator. Classify unresolved and partial separately; no forced parity across frameworks.
8. **Rerun unchanged source and evaluate a fresh holdout.** Fix shared normalisation, add positive and negative regression fixtures, then rerun exact SHAs, same application roots, comparable frozen reviewers and scoring. After fixes, perform a genuinely unseen cohort. Do not rewrite adjudicated historical answers.

## Automated integrity gate

The standard library script at scripts/study_evaluation_gate.py checks the **accounting and evidence contract**, not whether the judges are objectively correct.

~~~bash
# G0: frozen cohort validity
python scripts/study_evaluation_gate.py --cohort research/STUDY/cohort.json

# G1: validates every case, explicitly blocks quality without adjudication
python scripts/study_evaluation_gate.py \
  --cohort research/STUDY/cohort.json \
  --results downloaded \
  --aggregate-summary aggregate/summary.json \
  --output gate-report.json

# G2/G3: full release, requires independently locked source-only Phase A
python scripts/study_evaluation_gate.py \
  --cohort research/STUDY/cohort.json \
  --results downloaded \
  --aggregate-summary aggregate/summary.json \
  --phase-a locked-source-review.json \
  --phase-b revealed-alignment.json \
  --output gate-report.json
~~~

Phase A required fields:
- study, cohort_sha256 (digest of exact manifest), scanner_output_seen=false, locked_at.
- reviewers: at least two distinct reviewer_id and execution_id, provider, model, prompt_version, prompt_sha256, independent_review=true, scanner_output_seen=false, locked=true and locked_at.
- cases: every frozen case, same commit SHA and source_coverage=complete|qualified|insufficient; limitations if not complete; reviews for every judge (locked, blind, source_evidence path+line, explicit coverage_assertion=enumerated_candidates|reviewed_no_qualifying_chains, candidate_paths with stable candidate_id, verdict, rationale and evidence). Consensus_paths contain every unique candidate ID, verdict valid|invalid|unresolved, review_status agreement|escalated|pending, rationale and evidence. An agreement requires both judge verdicts to match the consensus; an escalated decision requires a locked, scanner-blind third independent reviewer and source evidence. When a bounded source pack was truncated, a case marked complete additionally needs supplementary_source_checked=true and supplementary_source_evidence.

Phase B required fields:
- study, phase_a_sha256 (digest of exact immutable locked source review), scanner_sha (full commit SHA matching every per-case result), revealed_at later than Phase A locked_at. Every case result also records scanner_sha and harness_sha (both full commit SHAs).
- cases: every case; candidate_assessments covering all consensus candidates with matched|partial|missed|invalid|unresolved and rationale. Matched and partial must cite valid scanner_path_indexes; missed must not.
- finding_reviews with scanner finding index, verdict supported|partial|unsupported|unresolved, rationale, path+line evidence and two or more independent locked reviewer_attestations with distinct reviewer_id and execution_id, model, provider, rule_metadata_seen=false, matching verdict and evidence. All critical/high and at least 25% (minimum one) per other rule and severity group must be reviewed. An empty list is mandatory when there are no findings.

Every Phase B case must also provide scanner_attack_path_reviews covering **every emitted scanner path**, including paths the LLM did not propose. Each includes scanner path index, supported|partial|unsupported|unresolved verdict, source evidence, rationale and two independent locked, scanner-rule-metadata-blind reviewer attestations. Unsupported, partial and unresolved scanner paths block quality release. This is the **attack-path precision direction**, complementing the source-first candidate comparison for potential recall misses.

The aggregate summary must match the exact cohort study ID, completed case count, per-framework expected denominators and per-case reported counts. The G1 check rejects stale aggregate labels (for example, a 12-repository pilot accidentally named as a frozen 60-repository study).

The gate emits gate-report.json with selection_gate, execution_gate, adjudication_gate, release_gate, warnings and counts. It exits nonzero when results have not been adjudicated, source evidence is insufficient, an accepted path is missed, confirmed false positives remain in sample or review escalation is pending. A **quality gate failure may be an important successful study finding** and must be reported, not suppressed.

## Additional integrity controls and limitations

- Do not substitute ChatGPT conversation-based retrospective inspection for a fresh blind API adjudication; recorded conversation reviews may be used for hypothesis generation only.
- Do not report a lack of deployment contract violations as organisational compliance when no declared contract or policy was supplied.
- Do not report model agreement as human-grounded truth. Provide provider/model/version, execution ID and prompt hash; if unavailable, state adjudication not run.
- Runtime authorization and exploitability remain unverified unless independently demonstrated with permitted runtime evidence. Unknown approval must not be silently treated as disabled.
- Preserve original judge labels and discordance, support append-only corrections and separate scanner fix commits from harness and study selection changes.
- The validator enforces structural coverage, not reviewer honesty, true blinding or semantic truth. If the input source contains prompt-injection instructions, reviewers must ignore them.

## Adoption

All *new* cohort PRs must publish a G0 valid frozen manifest, G1 result bundles, and explicit G2/G3 evaluation state before claiming security quality. Integrate the reusable gate into the study's aggregate job; do not copy a hardcoded expected-case count or study name from an earlier aggregator.

**October pilot-12 remains a retrospective baseline and is not independently blind-adjudicated.** Its original scanner execution succeeded (12/12), but it did not capture every new v1 G1 provenance field or run G2. Accordingly, it is **not** v1 quality-approved; the v1 quality gate remains blocked until the missing evidence and prospective blinded reviews are completed.

## Reusable GitHub Actions integration

New scanner cohort workflows should add a downstream job that calls .github/workflows/reusable-study-quality-gate.yml after **scanner cases**, **independent Phase-A reviews** and **Phase-B finding/path reviews** have all uploaded artifacts in the *same workflow run*:

~~~yaml
quality_release:
  needs: [scan, phase_a, phase_b]
  if: always()
  uses: ./.github/workflows/reusable-study-quality-gate.yml
  with:
    cohort_path: research/studies/example/cohort.json
    case_artifact_pattern: case-*
    aggregate_artifact: study-aggregate
    phase_a_artifact: locked-source-review
    phase_b_artifact: revealed-comparison
~~~

The caller must publish phase_a_file=locked-source-review.json and phase_b_file=revealed-alignment.json (or pass explicit filename inputs). Their evidence metadata must match the exact frozen repository SHAs and scanner/harness SHAs. If the judge workflow has not been run, the quality job is red by design, even if every scan job passed.

For **new** studies, use the registered directory convention research/studies/STUDY_ID/{cohort.json,study.json}; the associated workflow must call this reusable gate. Historical study directories are grandfathered as archival evidence, not retroactively relabelled quality-approved.
