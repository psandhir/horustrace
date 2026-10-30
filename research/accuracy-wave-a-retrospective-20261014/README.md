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

## First source observation panel (A02)

`source-assertions.json` adds 11 explicitly source-checked observations across
six pinned Fresh cases. Each row records a relative file/line, original Git
file blob, exact source-text anchor, semantic claim, expected supported /
unsupported / unresolved state and review rationale. Includes positive
agent-to-MCP invocation and handoff, and hard negatives for fixed PyPI/Maven
hosts, test-only CI MCP destinations, in-memory seat changes and interpolated
credential placeholders.

```sh
python -m scripts.verify_accuracy_wave_a_assertions
pytest -q tests/test_accuracy_wave_a_assertions.py
```

These observations were inspected in an assistant session against pinned
source; the ledger **does not contain two independent locked source-blind
reviewers** and cannot yield production precision or recall. They are
diagnostic initial assertions; blind G0–G3 review remains separate.

## Expanded Wave A diagnostic coverage

The diagnostic ledger now includes **35 source-anchored observations covering
all 30 pinned cases**, with original file blob IDs, source lines, expected
claim scopes and named construct categories. This is a **minimum seed set**
(one or more reviewed source snippets per case), not exhaustive enumeration of
all agents, tools, MCP servers, identities, Skills, edges, sinks or paths.

The baseline validator now rejects missing case coverage; it must not be used
to calculate entity or relationship recall. Those require a separately
enumerated source reference universe and independent source-only adjudication
under the G0–G3 research contract.
