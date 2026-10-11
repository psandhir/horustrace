# Source-supported finding regression gate (P1)

Use `scripts/source_claim_regression_gate.py` to compare the **same frozen repository SHAs** across scanner revisions. This gate identifies previously adjudicated, source-supported findings that disappeared. It does not assert that earlier findings were correct or that the latest scanner has lower recall.

Prepare a directory containing one `result.json` per case for each scanner revision (extract historical archives without changing the source manifest). The original Fresh-16 adjudication is `research/fresh-unseen-generalization-20/adjudication-second-pass.csv`; it is **single-reviewer source adjudication, not ground truth**.

```bash
python scripts/source_claim_regression_gate.py \\
  --baseline /path/to/old-fresh16-case-results \\
  --candidate /path/to/new-fresh16-case-results \\
  --review-csv research/fresh-unseen-generalization-20/adjudication-second-pass.csv \\
  --decisions research/source-claim-regression/decisions.json \\
  --output /path/to/semantic-delta.json
```

A lost claim with prior verdict `true_positive`, `partial` or `unresolved` fails the gate until an explicit, case/index-scoped decision supplies a concrete source file, line and rationale. Decisions may classify legitimate scope narrowing, a corrected false positive, consolidation or preservation in inventory. No blanket count-based suppressions are accepted.

The comparison uses the rule, source-relative path, original source line and agent for matching; it preserves duplicate multiplicity. This is conservative: refactored finding identity or a corrected agent projection may require review. A report with `passed=true` demonstrates that all identified losses were accounted for, **not** that precision/recall improved.

**Promotion criterion:** review the missing Fresh-16 claims against the pinned source packs, complete source-backed decisions, and only then wire this gate into the post-fix study workflow. Do not pre-approve missing claims or alter frozen source revisions to produce a green report.


## P1a reproducible historical claim-lineage audit

Use the original frozen Fresh-20 manifest with `--exclude-framework langgraph`
to reproduce the *same pinned Fresh-16 source repositories* on old/current
scanner output. Local folders may contain one GitHub Actions case ZIP per
repository or extracted per-case directories, each with `result.json` and
`source-pack.txt`.

```bash
python scripts/audit_frozen_claim_lineage.py \
  --cohort research/fresh-unseen-generalization-20/cohort.json \
  --exclude-framework langgraph \
  --old-dir /path/to/original-20261002-case-bundles \
  --new-dir /path/to/main-20261011-case-bundles \
  --historical-csv research/fresh-unseen-generalization-20/adjudication-second-pass.csv \
  --output /path/to/fresh16-claim-lineage.json
```

This validates every pinned repository and SHA, rejects source-pack digest
mismatch, and retains exact source-identity matching with duplicate
multiplicity. Old FP/TP/partial labels are explicitly
`historical_scanner_visible_single_reviewer`. These are prioritization
signals, never current scanner precision/recall.

Optionally provide `--source-first-review /path/to/blind-review.json` with
an array of independently source-inspected *scanner-blind* claims to calculate
an explicitly qualified calibration table via #512. Each claim requires all of:
`claim_id,case_id,rule_id,agent,source_path,source_line,claim_kind,framework,
language,family,reference,reviewer_id,independent,scanner_blinded,partition`.
Both independence and scanner blinding must be attested `true`; the script
cannot itself verify a reviewer's independence. Include scanner-negative
source candidates to measure false negatives and true negatives. Do not
substitute current scanner findings as the reviewer universe.

#513's immutable adversarial runtime ledger is **not** a surrogate for a
source-code truth set; it remains the appropriate evidence store for
scope-approved execution attempts and later offline rescoring.
