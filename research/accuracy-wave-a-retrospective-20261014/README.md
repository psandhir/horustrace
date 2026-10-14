# Wave A historical source baseline (14 October 2026)

**Purpose:** compare *existing* source-frozen HorusScan cases before and after the
planned evidence-first redesign. This is a retrospective diagnostic set, not a
prospectively selected blind cohort and not independent accuracy ground truth.

**30 pinned cases:** all 16 active-framework cases from the October 2
Fresh-20 (four ADK, Pydantic, OpenAI Agents, MCP/custom each), plus 14 targeted
cases selected from the existing Full-60 across ADK, Pydantic, OpenAI,
Amazon, Anthropic and Microsoft. They retain their original repository SHA
and application roots. Original full-study manifests are referenced by their
actual Git *blob* SHAs and are never mutated here.

**What is known:** previous scanners and reviewer-visible source signals were
considered when selecting the 14 diagnostic cases. These are intentionally
*not blind*, and their selection cannot support a fresh generalization claim.

**Validation:**

```sh
python -m scripts.verify_accuracy_wave_a_baseline
pytest -q tests/test_accuracy_wave_a_baseline.py
```

**Wave A continuation:** source-anchored assertions must distinguish reviewed
historical labels from adjudicated source truth; the passive stage trace will
measure losses from parsed observations through binding and authority.
A separate truly prospective study under `research/studies/` must follow the
registry's G0–G3 contract, including blind Phase A, independent review and
the reusable quality gate. Do not retrofit this retrospective file into it.

**Non-goals:** no extra findings, no true-positive percentages, no inferred
MCP runtime authority, no source-code execution, no ChatGPT Plus API calls.
