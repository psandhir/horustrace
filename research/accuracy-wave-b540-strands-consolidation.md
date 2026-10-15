# Issue #540 — WAB-04 Strands agent-instance consolidation

## Primary source and original trace

Pinned original source: aws-samples/sample-multi-agent-region-expansion-planner
at 30d03d7c9f6512e5bf10601879382fac9c3a16b1. Original Wave A
30-case trace, artifact wave-a-semantic-trace-ff60-amazon-04 from
https://github.com/psandhir/horustrace/actions/runs/38599092779.

The original trace records 10 source agent observations at discovery.
Exactly eight Agent observations are removed at
initial_instances_consolidated (and zero further Agent observations are
removed in the later source or delegation stages). The remaining two
agents correspond to analysis_writer and orchestrator.

| Source constructor | Wave A discovered | Initial consolidation |
|---|---|---|
| main.py:56 — orchestrator | present | retained |
| agents/analysis_writer.py:72 | present | retained |
| agents/cfn_explorer.py:92 | present | removed |
| agents/cloudtrail_explorer.py:68 | present | removed |
| agents/multi_region_expansion_planner.py:104 | present | removed |
| agents/planning_report_generator.py:102 | present | removed |
| agents/pricing_explorer.py:89 | present | removed |
| agents/report_writer.py:74 | present | removed |
| agents/tech_analysis.py:140 | present | removed |
| agents/waypoint_explorer.py:78 | present | removed |

The source explains the loss: scanner._consolidate_agents used
(name, instance_key or None). All nine specialist local variables are
named agent, and have no instance_key, so eight source-distinct
constructors incorrectly coalesce into one source object. This is a
specific static source-identity defect, not a justified common-agent
declaration merge.

## Remediation and remaining proof

This draft PR qualifies **Strands-only** agents with a real source
location by source file plus constructor line when instance_key is
absent. The qualifier exists only during consolidation, so no checkout-
specific paths are serialized. Explicit instance keys, same-site
duplicate observations, manifest overlays and non-Strands graph
consolidation keep existing behavior.

The pinned-source CI witness runs the production scanner on the exact
original source and compares the ten expected distinct constructor
locations to the final normalized Agent inventory. It does not install
the third-party repo or claim those instances all executed.

This change affects production scanner inventory; it is **not** the
same passive-only slice as PRs #541–#547. Before merging, review
per-instance capabilities, controls, relationships, finding witnesses,
attack paths, and possible new false positives. Passing scanner CI
and 60/16 cohort integrity is necessary but does not certify those
security decisions. Do not equate the historical 8 removed source
instances with 8 independently adjudicated false negatives.

Further B03 work is needed to validate the Strands tool wrapper
delegation paths and effective runtime authority. Full independent
source-edge adjudication is still an issue #540 closure requirement.
