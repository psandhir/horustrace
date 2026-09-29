# GPT ↔ HorusTrace Differential Evaluation Protocol

## Purpose

This study measures the semantic gap between HorusTrace's deterministic static
analysis and an independent GPT source review over the **same pinned repository
commit**.

GPT is a **differential oracle, not ground truth**. Agreement is useful evidence.
Disagreement is a source-adjudication task. Scanner behavior must never be changed
merely to make it agree with GPT.

No external model API or repository API secret is required for this protocol. The
GPT source-review phase can be performed directly in the HorusScan ChatGPT project
using GitHub source access, then committed as a locked review artifact.

## Two-phase blinding

### Phase 1 — source-only GPT review

1. Choose cases before inspecting their case-specific HorusTrace output.
2. Generate/export a packet containing only:
   - case ID;
   - repository;
   - pinned commit SHA;
   - framework stratum.
3. Review the repository source independently.
4. Record:
   - agent principals and delegation;
   - actual tool/MCP bindings and effective authority;
   - ingress and trust/authentication controls;
   - process/data/network/file/cloud capabilities;
   - approval and guardrail boundaries;
   - source-supported attack paths;
   - runtime viability, blockers, and unresolved dynamic behavior;
   - exact source evidence.
5. Commit the GPT review before revealing the corresponding HorusTrace findings.

The source-review artifact must state whether the reviewer had previously seen
case-specific HorusTrace output. General familiarity with HorusTrace does not make a
review fully blind and must be disclosed.

### Phase 2 — reveal, align, adjudicate

Only after the GPT review is locked:

1. Reveal the HorusTrace result from the frozen scanner SHA.
2. Align each GPT semantic finding as:
   - `covered` — HorusTrace represents the material security semantics;
   - `partial` — HorusTrace detects part of the chain/capability but loses a
     meaningful predicate, binding, ingress, destination, sink, or severity context;
   - `missed` — no materially equivalent HorusTrace finding/path exists.
3. Review every HorusTrace finding, including those with no GPT counterpart.
4. Classify HorusTrace-only findings as:
   - `source_supported`;
   - `semantic_duplicate`;
   - `policy_semantics_review`;
   - `effective_authority_review`;
   - `unsupported`;
   - `unresolved`.
5. Record attack-path differences separately.
6. Source-adjudicate disagreements before creating scanner changes.

## Important semantic rules

### Entity existence is not effective authority

A tool, MCP server, network client, database helper, or dangerous function merely
existing in the repository is insufficient. Require a source-proven binding from the
effective agent/model/tool loop before treating it as agent authority.

### Application authority is not automatically agent authority

Direct REST endpoints, background jobs, administration routes, and application helper
functions must be separated from model-reachable authority unless source proves the
connection.

### Declared authority is not necessarily live authority

Import errors, disabled configurations, unresolved dynamic dispatch, overwritten
objects, optional integrations, and deployment conditions can make dangerous declared
authority conditional. Preserve that distinction rather than upgrading it to proven
runtime reachability.

### Managed services need rule-contract review

A provider-managed search or retrieval tool is not automatically equivalent to an
arbitrary model-selected network destination. When the security rule's semantics are
unclear, classify the disagreement as `policy_semantics_review` instead of forcing a
false-positive/false-negative verdict.

## Reproducibility

The scanner side must be pinned by:

- HorusTrace scanner commit SHA;
- Frozen-180 workflow run/artifact ID and artifact digest where applicable;
- repository commit SHA for every reviewed case.

The GPT side must be pinned by:

- model family/configuration;
- source files reviewed;
- case-specific scanner-output exposure state;
- committed review artifact.

The explicit alignment artifact is separate from both source-review and raw scanner
output.

## Metrics

The study reports **differential coverage**, not product precision/recall:

- full semantic coverage rate;
- covered-or-partial rate;
- missed semantic findings;
- attack-path differential;
- severity disagreements on aligned findings;
- HorusTrace-only adjudication taxonomy;
- finding fingerprint collisions;
- recurring parser/dataflow/binding gap categories.

Formal product precision/recall still requires an independently adjudicated,
sufficiently exhaustive truth set.

## Batch 001

Batch 001 deliberately selected five Frozen-180 cases that were not marked
`previously_studied` and were not the recent hand-tuned scanner exemplars:

- `rw-017` — Google ADK;
- `rw-065` — LangGraph;
- `rw-112` — custom OpenAI Responses + MCP;
- `rw-139` — OpenAI Agents SDK;
- `rw-152` — Pydantic AI.

The GPT source review was committed before the five case-specific HorusTrace findings
were revealed. The reviewer was already familiar with HorusTrace's general concepts
and rule vocabulary, so this is accurately described as **case-blind**, not globally
blind.

## Commands

Export a source-review packet:

```bash
python scripts/gpt_differential_evaluation.py export frozen-result.json \
  --case rw-017 \
  --case rw-065 \
  --case rw-112 \
  --case rw-139 \
  --case rw-152 \
  --output review-packet.json
```

After the GPT review is locked and the alignment has been source-adjudicated:

```bash
python scripts/gpt_differential_evaluation.py compare \
  --gpt-review research/gpt-horustrace-differential-2026/batch-001-gpt-source-review.json \
  --scanner-result frozen-result.json \
  --alignment research/gpt-horustrace-differential-2026/batch-001-alignment.json \
  --output batch-001-summary.json
```

Do not expose `frozen-result.json` or the alignment artifact during the Phase-1
source review.
