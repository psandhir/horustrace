# Cross-framework fresh holdout 70 — protocol

## Objective

Measure current HorusTrace generalisation and accuracy on **70 source-screened repositories not present in the frozen full-framework 60**. The scanner is frozen at `a8988e997d0a1c2a016f627adde9d51c331b4e22` (the merge of #428). Study-only commits may add harness files, but must not change `src/horustrace/**`.

## Cohort

Ten exact-SHA repositories each for:

- Google ADK
- Pydantic AI
- OpenAI Agents SDK
- Amazon Strands / AgentCore
- Anthropic Claude Agent SDK
- Microsoft Agent Framework
- FastAgent

Selection was performed from source-code search and then manually source-screened for an actual framework construct. The scanner output was not used to choose cases.

## Evidence captured per case

The harness records the normal JSON scan, Agent Security Graph, Effective Authority, Authority Contract, HorusTrace AI-BOM, source pack, agent/tool/MCP/skill inventory, coverage diagnostics, findings and attack paths.

The study specifically inspects model provenance, data/resource provenance, approval/control metadata, delegation/composition, runtime ingress, AI-BOM lineage and cross-framework semantic normalization introduced after the previous frozen-60 study.

## Adjudication

Security-relevant source constructs and scanner outputs are classified as:

- **correct** — scanner representation materially matches source evidence;
- **partial** — relevant construct is found but important source-proven semantics are missing;
- **false_positive** — scanner asserts security-relevant semantics not supported by source;
- **false_negative** — source contains a supported security-relevant construct that scanner misses;
- **source_not_exposed** — framework/source genuinely does not expose the dimension;
- **adapter_gap** — source exposes the dimension but the adapter does not extract it.

Unknown, dynamic and unresolved evidence are valid outcomes when supported by source; they must not be upgraded to resolved merely to improve completeness.

## Regression pairing

This holdout is interpreted alongside the unchanged frozen-60 rerun triggered from `a8988e997d0a1c2a016f627adde9d51c331b4e22`. The frozen-60 is the longitudinal regression control; this fresh-70 is the generalisation/accuracy holdout.

## Fix discipline

The research PR contains **no scanner behavior changes**. Any P0/P1 product gap discovered by adjudication is fixed in a separate PR, then both the affected holdout case and relevant regression cohort are rerun.
