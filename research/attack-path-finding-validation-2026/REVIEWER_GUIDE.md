# Reviewer Guide — Attack Path and Finding Validation

This packet is designed to keep reviewers independent from HorusTrace output.

## What reviewers receive

For each case:

- a pinned public repository and exact commit SHA;
- a bounded source scope;
- a neutral factual/security question;
- source-review hints that identify where to inspect;
- an empty reviewer slot.

Do **not** use HorusTrace output, generated findings, attack-path reports, issue discussions that reveal scanner results, or the study's later scoring artifacts while reviewing.

## Required review fields

Each reviewer must independently record:

- `reviewer_id`;
- `verdict`;
- independently assigned `severity` where relevant;
- exact source evidence;
- concise rationale;
- `independent_human: true`;
- `horustrace_output_seen: false`;
- `locked: true` when complete.

Reviewer 1 and Reviewer 2 must be different people.

## Attack-path verdicts

Use:

- `valid` — the claimed relationship/security path is statically supported by the pinned source;
- `invalid` — the claim is contradicted or unsupported despite sufficient bounded source evidence;
- `unresolved` — static source is insufficient without runtime assumptions.

For `invalid_near_miss` cases, repository co-presence is not evidence of authority. Require an actual binding, delegation, dispatch, or other source-proven reachability relationship.

For `dynamic_unresolved` cases, do not infer runtime behavior from naming or likely framework semantics.

## Phase-A finding verdicts

The current finding cases are **source-blind recall-reference assertions**, not HorusTrace finding precision samples.

Use:

- `supported`;
- `unsupported`;
- `unresolved`.

Assign severity based on the security consequence visible in source, not on any external scanner label.

## Lock procedure

1. Reviewer A completes their copy independently.
2. Reviewer B completes their copy independently.
3. Neither reviewer sees the other's review before both are locked.
4. Run `scripts/attack_path_finding_review.py` against the completed review directory.
5. Disagreements remain disagreements; do not rewrite either original review.
6. Only after the relevant review phase is locked may scanner scoring metadata be compared.

## Phase B

Phase B is separate.

After Phase A is locked, the study coordinator will sample actual HorusTrace findings by rule ID and reported severity. Those records will be transformed into neutral factual claims before reviewers see them. Reviewers must not be shown the originating rule ID, scanner severity, finding ID, confidence, or other HorusTrace metadata.

Phase B provides finding precision and severity-agreement evidence; Phase A provides the source-derived recall reference.

## Integrity check

The frozen Phase-A packet is identified in `packet-lock.json`.

Before review, verify the generated `review-packet.yaml` SHA-256 matches the locked digest. If it does not, stop and regenerate from the locked generator commit.


## Phase-B tooling

Do not run Phase B until the completed Phase-A packet has been validated and its summary contains:

```json
"scanner_reveal_allowed": true
```

The coordinator may then build a rule/severity-stratified finding precision packet:

```bash
python scripts/build_finding_precision_review_packet.py \
  --phase-a-summary phase-a-summary.json \
  --findings scanner-findings.json \
  --review-packet phase-b-review-packet.yaml \
  --hidden-map phase-b-hidden-map.json
```

**Never give `phase-b-hidden-map.json` to reviewers.** It contains the hidden HorusTrace rule ID, scanner severity, confidence, fingerprint and title used for later scoring.

Reviewers receive only `phase-b-review-packet.yaml`, complete it independently, and validate the completed packet with:

```bash
python scripts/attack_path_finding_review.py \
  phase-b-review-packet.yaml \
  --output phase-b-summary.json
```

After both phases are locked and scanner observation mappings have been produced, the coordinator can calculate the final metrics:

```bash
python scripts/score_attack_path_finding_validation.py \
  --phase-a-summary phase-a-summary.json \
  --attack-observations attack-observations.json \
  --finding-recall-observations finding-recall-observations.json \
  --phase-b-summary phase-b-summary.json \
  --phase-b-hidden-map phase-b-hidden-map.json \
  --output validation-report.json
```

The scorer reports attack-path precision/recall, finding recall, finding precision, exact severity agreement, one-level severity agreement, and scanner-over/under-severity taxonomy. Unresolved cases and reviewer disagreements are reported separately rather than forced into accuracy denominators.
