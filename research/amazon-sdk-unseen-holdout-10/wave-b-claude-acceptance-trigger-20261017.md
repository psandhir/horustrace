# Wave B: Claude SDK integrated PR acceptance — Amazon unseen-10 holdout

Research-only workflow trigger on draft PR #578, **not a scanner semantics or source-manifest change**.

- Candidate branch: `fix/wave-b-anthropic-integrated-20261017`.
- Frozen target: existing ten Amazon unseen holdout case IDs and SHA pins, unchanged.
- Motivation: #578 changes Claude SDK runtime-default candidate authority, version-gated Workflow, and effective-authority resolution; the separate Amazon 15-case parity workflow is not the unseen ten-case release acceptance.
- Acceptance: pinned 10/10 artifacts, integrity, no unexpected regressions, same synthetic tested merge/PR candidate provenance. Aggregate PASS is diagnostic only, not independent source truth.
- Keep #540, #551, #568, #575, #576 and #558 signoffs separate; do not merge this draft or claim Wave C GO on green checks alone.
