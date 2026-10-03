# Reviewer Guide — Attack Path and Finding Validation

This study uses **two independent blinded LLM judges by default**, with targeted
human escalation for disagreements, low-confidence/unresolved cases, and optional
high-severity spot checks. The original frozen Phase-A source packet remains
unchanged.

## Integrity and blinding

Each judge receives only:

- a pinned public repository and exact commit SHA;
- a bounded source scope;
- a neutral factual/security question;
- source-review hints where present; and
- its own reviewer slot.

Before a judge locks its review, do **not** expose:

- HorusTrace findings or attack-path output;
- scanner rule IDs, severity, confidence, fingerprint or title;
- the Phase-B hidden map;
- the other judge's answer;
- issue/PR discussions that reveal scanner output; or
- later scoring artifacts.

For new adjudication runs, the canonical evaluator prompt is\n`LLM_REVIEW_PROMPT_V2.md`. Record its version as `llm-review-v2`. The v1 prompt\nremains unchanged for reproducibility of already-locked historical reviews.

## Automated Phase-A runner

The preferred execution path is the GitHub Actions workflow
`.github/workflows/llm-adjudication-phase-a.yml`. It performs the full blinded
Phase-A run in isolated API calls:

1. rebuilds the source-only packet from the locked generator;
2. verifies its SHA-256 against the immutable published digest;
3. fetches only the source paths named by each case at the exact pinned commit;
4. strips selection labels such as `proven_authority` / `invalid_near_miss`
   before model evaluation;
5. runs the OpenAI and Gemini judges independently;
6. records model, prompt, provider response/run ID, source-file hashes and
   confidence;
7. validates the locked review packet and emits the escalation queue.

The workflow requires these repository Actions secrets:

- `OPENAI_API_KEY`;
- `GEMINI_API_KEY`.

Its default models are `gpt-5.6-sol` and `gemini-3.8-flash`, but both are
workflow inputs so the exact evaluator versions remain explicit in every run.

Repository source is treated as untrusted input. The runner instructs evaluators to
ignore instructions embedded in source comments, documentation, notebooks, strings,
prompts or links, and never executes reviewed source.

## Prepare the frozen packet for LLM judges

Do not modify or regenerate the locked source packet merely to switch reviewer type.
Verify the original packet digest first, then create a working copy with versioned
judge identities:

```bash
python scripts/prepare_llm_review_packet.py \
  review-packet.yaml \
  --output phase-a-llm-review-packet.yaml \
  --judge-a-id openai-run-001 \
  --judge-a-provider openai \
  --judge-a-model <model-name> \
  --judge-b-id second-run-001 \
  --judge-b-provider <provider> \
  --judge-b-model <model-name> \
  --prompt-version llm-review-v2
```

Different model families/providers are preferred because they reduce shared-model
blind spots, but the hard requirement is two distinct reviewer run IDs and independent
blinded execution.

Each LLM reviewer must fill **only its assigned slot** and set:

- `reviewer_kind: llm`;
- `independent_review: true`;
- `independent_human: false`;
- `horustrace_output_seen: false`;
- provider/model/prompt metadata;
- verdict, severity, exact source evidence and concise rationale; and
- `locked: true` only when complete.

Legacy human review packets remain valid. Human reviewers still use
`independent_human: true`.

## Verdict semantics

For attack paths:

- `valid` — the claimed relationship/security path is statically supported;
- `invalid` — sufficient bounded source exists and the claim is unsupported or contradicted;
- `unresolved` — static source cannot decide without runtime assumptions.

For Phase-A and Phase-B findings:

- `supported`;
- `unsupported`;
- `unresolved`.

Repository co-presence is never sufficient evidence of effective authority. Require an
actual source-proven construction, binding, delegation, dispatch, runtime invocation,
or equivalent relationship.

Severity must be assigned from the source-proven consequence, independently of any
scanner severity.

## Phase A lock and escalation

After both LLM judges finish independently:

```bash
python scripts/attack_path_finding_review.py \
  phase-a-llm-review-packet.yaml \
  --output phase-a-summary.json
```

The summary reports consensus rate and `escalation_cases`. Once both blinded reviews
are locked, scanner reveal is permitted even if some cases disagree. Disagreements are
**not silently reconciled**: they stay outside accuracy denominators and go to a
targeted escalation queue.

Recommended escalation order:

1. third independent LLM/model;
2. human review if the third judge does not resolve the case;
3. preserve `unresolved` when source evidence genuinely cannot decide.

Do not rewrite the original judge outputs to manufacture consensus.

## Phase B — finding precision

After Phase A is locked, build the deterministic rule/severity-stratified scanner
finding sample:

```bash
python scripts/build_finding_precision_review_packet.py \
  --phase-a-summary phase-a-summary.json \
  --findings scanner-findings.json \
  --review-packet phase-b-review-packet.yaml \
  --hidden-map phase-b-hidden-map.json
```

**Never give `phase-b-hidden-map.json` to either judge.**

Prepare the public Phase-B packet for the same or another independent judge pair:

```bash
python scripts/prepare_llm_review_packet.py \
  phase-b-review-packet.yaml \
  --output phase-b-llm-review-packet.yaml \
  --judge-a-id openai-phase-b-001 \
  --judge-a-provider openai \
  --judge-a-model <model-name> \
  --judge-b-id second-phase-b-001 \
  --judge-b-provider <provider> \
  --judge-b-model <model-name> \
  --prompt-version llm-review-v2
```

Then validate the completed packet:

```bash
python scripts/attack_path_finding_review.py \
  phase-b-llm-review-packet.yaml \
  --output phase-b-summary.json
```

## Final scoring

After both phases are locked and scanner observation mappings exist:

```bash
python scripts/score_attack_path_finding_validation.py \
  --phase-a-summary phase-a-summary.json \
  --attack-observations attack-observations.json \
  --finding-recall-observations finding-recall-observations.json \
  --phase-b-summary phase-b-summary.json \
  --phase-b-hidden-map phase-b-hidden-map.json \
  --output validation-report.json
```

The scorer reports attack-path precision/recall, finding recall, finding precision,
exact and within-one-level severity agreement, rule/OWASP precision, and
scanner-over/under-severity taxonomy. Unresolved cases and judge disagreements are
reported separately rather than forced into accuracy denominators.

## Frozen Phase-A packet

The original Phase-A packet is still identified by `packet-lock.json` and its
published SHA-256. Switching to LLM adjudication changes the **review protocol**, not
the source cases, selection process, or immutable frozen truth artifacts.
