# HorusTrace Semantic Parity Benchmark v1

This directory is a post-hoc semantic validation layer for the frozen 2026 real-world agent-security study.

It exists because the preregistered source reference is intentionally lexical/structural and automated. After the Frozen-180 post-fix run, seven high-value repositories were independently re-reviewed with a HorusTrace-policy-aligned LLM prompt and direct source verification. That review found both scanner errors and reference-model limitations: duplicate lexical tool assertions, documentation/example constructors counted as agent roots, workflow nodes counted as principals, custom model/tool loops omitted from truth, and object-lifetime effects that raw constructor counts cannot express.

## Methodology boundary

The original ground-truth/rw-*.json files remain immutable. This benchmark does not rewrite them and must not be substituted for the preregistered broad-cohort metrics.

Instead it records a second layer:

1. semantic model — source-supported effective principals, workflows, tools, MCP construction/effective instances, authority facts and evidence state;
2. policy expectations — required, forbidden and candidate HorusTrace rule outcomes;
3. regression assertions — machine-checkable expectations for future scanner changes.

Evidence states are observed, inferred, and unresolved. Inferred evidence is explicitly retained as such rather than promoted to an observed runtime fact.

## Cases

The v1 benchmark contains seven exact-SHA cases selected during the LLM-parity exercise:

- rw-022 — iwasnothing/agentic-insight — Google ADK cross-file closure and repeated MCP construction/binding provenance;
- rw-085 — openlegion-ai/openlegion — framework-neutral model/tool loop, custom tool registry and conditional authority;
- rw-129 — ALPHAbilal/test3 — config-driven OpenAI Agents registry, custom orchestration and persistent-memory authority;
- rw-158 — newsbubbles/matplotlib_mcp — MCP object lifetime/deduplication and input-to-destructive-tool trust propagation;
- rw-058 — Tunnello/ChatBI — LangGraph SQL capability classification and untrusted-input-to-database-mutation path;
- rw-003 — angrysky56/ai_writers_workshop — FastAgent decorators/workflows plus generated conditional MCP bindings;
- rw-096 — jakie528/mcp-oauth — custom OAuth MCP loop, remote tool-surface allowlisting and dynamic destination scope.

## Reproducibility

llm-review-prompt.md preserves the policy-aligned review prompt. The LLM review is performed against pinned source before viewing HorusTrace output. Conclusions must then be source-verified and classified by evidence state.

Validate the benchmark:

    python scripts/real_world_semantic_benchmark.py \
      research/real-world-agent-security-2026/semantic-benchmark/benchmark-v1.json

Score a Frozen-180/post-fix result:

    python scripts/real_world_semantic_benchmark.py \
      research/real-world-agent-security-2026/semantic-benchmark/benchmark-v1.json \
      --result result.json

Use --strict in a future gating workflow only after the intended scanner fixes have landed. v1 starts as a measurement benchmark, not as a blocking CI gate.

## Initial PR #203 score

The PR #203 Frozen-180 post-fix artifact (scanner_sha=d8f9043525208991ae69ea45c9b694b3288aa36e) passes 3/23 assertions (13.0%). That low score is expected: the seven cases were selected specifically because source review exposed semantic gaps. The checked-in score is the before-state for the next scanner build phase, not a claim about overall HorusTrace quality.
