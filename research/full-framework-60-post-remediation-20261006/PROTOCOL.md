# Full-framework 60 post-remediation rerun

This rerun validates the ordered remediation work derived from PR #391 against the
original frozen 60-repository cohort.

## Integrity constraints

- Frozen cohort blob SHA: `1ea88dbb611cb7c0a81d5b8717553ef539cbdd49`
- Original scanner baseline: `bf02b7e831973ff733b6fab369094ce784e1a1bd`
- Post-remediation scanner code: `487bc856d26d072d2c0cc07489ec54cfdd477a7c`
- Original workflow run: `37381193593`
- Original aggregate artifact: `11375510742`
- Original aggregate digest:
  `sha256:7796d2b126ed00f2a6296d55184ebb0e8f0062caa65f96f9b30c4264bf122d43`

The cohort file is copied byte-for-byte from PR #391. Repository selection,
upstream SHAs, application paths, evidence paths and source signals are unchanged.

## Comparison

The rerun retains the original result bundle and aggregate format, then adds a
post-remediation comparison that reports:

- per-case and per-framework count deltas;
- zero-agent changes;
- strict/detail Effective Authority resolution;
- the new core Effective Authority resolution signal;
- relationship and finding source-context distribution;
- attack-path basis distribution;
- destination restriction evidence.

Count changes are triage signals, not correctness claims. Material changes must be
source-adjudicated against the retained source packs before being called an
improvement or regression.
