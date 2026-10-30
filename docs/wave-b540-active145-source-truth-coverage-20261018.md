# Wave B source-truth coverage audit — active 145 (18 October 2026)

## Why historical scan completion cannot prove accuracy

The immutable real-world study has 180 source-pinned cases, of which **35
LangGraph cases are excluded only from the active 145-case cohort**. The
original ground-truth summary counts **72/180** cases with a complete
agent-entity reference; joining the frozen cohort and reference case IDs
shows **56/145 agent-complete**, **89/145 agent-incomplete** in the active
non-LangGraph panel. These are **source reference completeness flags**, not
scanner success/failure, measured recall, or exact V2 ontology truth.

The reference was locked before the baseline scanner and records two automated
source-review passes. The truth files explicitly state
`human_dual_review=false` and do not establish an independently blinded
V2 closed-world or hard-negative oracle for every entity and typed edge.
`complete_agents=false` means unseen agents are **not** verified negatives.

`scripts/audit_wave_b540_active_truth_coverage.py` independently joins
all 180 immutable case IDs, source repositories and 40-character pins
with the corresponding truth file, checks every locked review flag,
and reports each dimension's existing `reference_completeness`:
`agent_entities`, `tools`, `mcp_servers`, `delegation_edges`.
It archives all explicit present/absent/unresolved claim counts per case
rather than claiming absence when no assertion exists. It fails closed
on any missing reference, wrong SHA, changed exclusion, absent completeness
flag or unsupported evidence assertion. It changes **no** original truth.

## Release and measurement policy

- Cases labelled complete may offer a historical bounded closed-world
  comparison of the *original reference ontology*; the set of absent
  assertions and the source scope must still be respected. Never turn the
  89 incomplete agent cases into false negatives or verified true negatives.
- Legacy root-agent and newer V2 source agent instance/workflow-node
  ontologies differ. A source comparison is not a new independently
  blind ground truth or production precision/recall.
- Precision, recall, authority, findings and paths require independently
  reviewed positive and negative labelled objects/typed relationships,
  explicit unknown counts and scoped denominators.
- Machine-readable output has all accuracy metrics **null**, and
  `wave_b_go=false`, `wave_c_go=false` until the remaining independent
  source-labelled coverage and protected release gates are completed.
- Original Frozen180 inputs, active145 exclusion, Fresh16/Full60 thresholds
  and historical results are unchanged.

This script tells the release owner **exactly which source gaps must be
adjudicated** before claiming exhaustive active145 precision/recall;
it is not a workaround that relabels incomplete source references as
complete to make a dashboard green.
