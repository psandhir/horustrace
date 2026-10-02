# Agent-centric unseen 12 v2 protocol

## Objective

Measure post-#295 generalization on a genuinely fresh cohort limited to the three active HorusTrace agent frameworks: Google ADK, Pydantic AI, and OpenAI Agents.

## Blind selection

- Freeze 12 repositories before any HorusTrace execution: four per framework.
- Exclude every repository already present in prior HorusTrace research cohorts. The exclusion set contains 232 unique repositories.
- Candidate discovery uses live GitHub source search for framework imports in Python code.
- Source screening is allowed only to confirm framework usage and composition signals such as tools, MCP, delegation, network/write authority, or a deliberate negative-control pattern.
- HorusTrace findings, attack paths, and scanner diagnostics are not used for repository selection.
- Freeze the exact commit SHA returned by source discovery; do not replace a case after seeing scanner output unless the repository cannot be fetched at the preregistered SHA. Any replacement must be documented before execution.

## Evaluation

1. Run HorusTrace unchanged from the merged #295 baseline.
2. Persist scan JSON, security graph, source pack, and exact findings/attack paths per case.
3. Adjudicate every emitted semantic claim against source.
4. Separately review likely false negatives by comparing source-visible agent/tool/MCP/delegation authority against HorusTrace output. Do not treat precision-only adjudication as recall evidence.
5. Classify each finding/path as supported, partial/qualified, false positive, or unresolved with source evidence.
6. Any scanner change discovered from this cohort requires a new holdout; do not report the patched rerun as blind generalization.

## Success criteria

Primary: no systematic framework-level false-positive class and no unsupported attack path on the untouched #295 scanner.

Secondary: identify source-visible missed authority/delegation/MCP/tool semantics that should shape the next product iteration without case-specific exceptions.
