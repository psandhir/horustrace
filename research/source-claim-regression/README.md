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
