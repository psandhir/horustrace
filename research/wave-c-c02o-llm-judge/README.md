# Wave C C02o — use an LLM as a **provisional** source judge

Parent: [#606](https://github.com/psandhir/horustrace/issues/606) and
[#543](https://github.com/psandhir/horustrace/issues/543).

## What changed

This adds a **provider-neutral, offline source-first review handoff** under
`horustrace.source_truth_llm_judge`. It is explicitly not the scanner,
does not run source targets, and does not require a paid LLM API key.
A ChatGPT session or any LLM can inspect the generated JSON packet
and return structured answers for separate offline validation.

- The `prepare` command validates a source-first ledger and emits a
  deterministic `packet_sha256`, pinned repository commit, source Git blob
  SHA, source path, inclusive line ranges and source snippets.
- The packet strips reviewer hint questions, prior model answers, candidate
  truth and scanner predictions; excerpts remain untrusted code, never
  instructions.
- `adjudicate` accepts only bounded JSON decisions
  (`candidate_id`, `claim_id`, `construct`, `positive|negative|unknown`,
  rationale). Invalid or invented citations, conflicting IDs, stale packets,
  unapproved source roles, self-declared independent human attestations,
  and unsupported runtime-authority positive/negative claims **fail closed**.
- Every model verdict is converted into existing versioned C02a
  `source_truth_oracle` records with forced
  `review_method=model_reviewed`, `scanner_blind=false`,
  `positive_complete=false` and `negative_complete=false`.
  It cannot generate certified precision/recall or C03/C04 GO.
- `adjudicate-ledger` supports model decisions prepared during a ChatGPT
  source review: it validates the exact source ledger's **Git blob SHA-1**,
  builds a packet and binds decisions deterministically without inventing
  a hash that the model never saw.

## Real LLM judge case completed in this slice

Pinned source case `rw-006` `manojlds/adk-deepagents` at
`11a15d7c935061c50e1ef626df2445103b91c931`, recorded ledger Git blob
`8ba4e22c0fbd97104ecbfcdde847e36978f1e3b2`.

The single ChatGPT model-reviewed response contains **24 claim-specific
opinions: 13 source positives, 7 selected source hard-negatives and 4
effective-authority UNKNOWNs**. Its principal source-level distinctions:

- A `create_deep_agent` *function definition* and
  `GENERAL_PURPOSE_SUBAGENT` *spec* do not establish deployed instances.
  Existing agents wrapped in `AgentTool` are not new LlmAgent constructors.
- `static` and `both` can take the static
  `build_subagent_tools` branch; `dynamic` and `both` can add registration
  and dynamic-task tools. A default of `static` is not evidence of a
  deployed config. Neither branch implies the other branch ran.
- A general-purpose name in prompt descriptions in dynamic-only mode is
  not proof of a static built `AgentTool`. Dynamic factory/tool definitions
  do not prove that dynamic runtime subagents were instantiated.
- `interrupt_on` callback source, runtime effective tool authority,
  actual dynamic registrations and selected deployment mode remain UNKNOWN
  absent installed SDK, configuration and runtime witnesses.

This is one **unblinded model review**, not a blind independent reviewer,
second independent model adjudication or exhaustive candidate universe.
The reference is never used as release ground truth. No scanner-prediction
TP/FP/FN/TN or precision/recall is claimed.

## Running the offline handoff

No target execution and no network/LLM API calls are made.

```bash
python -m horustrace.source_truth_llm_judge prepare \
  --ledger research/wave-c-c02l-rw006/rw-006-delegation-mode-candidates.json \
  > /tmp/rw006-packet.json
```

Review the generated packet with an LLM and request JSON with these fields:

```json
{
  "schema_version": 1,
  "packet_sha256": "<copy exact digest from the packet>",
  "judge_model": "record actual model and version used",
  "judge_run_id": "review-session-id",
  "source_visibility": "source_packet_only",
  "decisions": [
    {
      "candidate_id": "rw006-static-branch",
      "claim_id": "source_mode:static_builder_only_static_or_both",
      "construct": "typed_edge",
      "truth": "positive",
      "reason": "The source branch is explicitly guarded by static or both; deployment remains unknown."
    }
  ]
}
```

Then run:

```bash
python -m horustrace.source_truth_llm_judge adjudicate \
  --packet /tmp/rw006-packet.json \
  --response /tmp/rw006-model-response.json > /tmp/rw006-unscored-oracle.json

# Reproduce this PR's real model review from its original pinned ledger:
python -m horustrace.source_truth_llm_judge adjudicate-ledger \
  --ledger research/wave-c-c02l-rw006/rw-006-delegation-mode-candidates.json \
  --opinions research/wave-c-c02o-llm-judge/rw-006-model-opinions.json \
  > /tmp/rw006-reviewed-provisional.json
```

The output always reports `release_accuracy_assessable=false`,
`source_oracle_status.aggregate=null`, and a C02a reference whose positive
and negative universe completeness flags are false. A source excerpt only
binds a claimed Git object and line; a local exact Git checkout or a
source retrieval replay is still needed to verify its actual content.
Model judgments should only be used for review triage and identifying
candidate scanner errors before targeted source-verified corrections.

## Decision rules to retain

1. Keep scanner output hidden from the initial source-first judge packet.
   Source context must be sampled independently from real pinned cases,
   including negatives rather than only scanner hits. A ChatGPT model with
   prior conversational context must *not* be represented as blind.
2. Use a challenge/contradiction review or a second independent process on
   disputed or high-risk opinions. Two models agreeing is still not
   independent human ground truth and cannot prove absence over an
   incomplete source tree.
3. Build full positive AND hard-negative universes for selected strata;
   resolve conflicting labels, source roles, framework version and
   source-to-instance mapping. Only then compare exact same-case scanner
   predictions and reconcile additions/removals. Keep UNKNOWN unresolved.
4. Use a **genuinely unseen** sealed D01 holdout, not any of rw004–006,
   rw080, rw149 or previously exposed Amazon cases. Honor owner access,
   privacy and source-license constraints before sending code externally.
5. Keep original Frozen180/active145 (excluding LangGraph), existing
   Fresh16/Full60/CodeQL/regression quality gates, 12 Amazon UNKNOWNs,
   administrator branch-protection blocker [#558](https://github.com/psandhir/horustrace/issues/558),
   and **C03/C04 production NO-GO** unchanged.

The next productive milestone is comparison of these provisional decisions
to same-source scanner claims, targeted regression tests and independent
review—not reclassifying model opinions as certified source truth.
