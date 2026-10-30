# Wave B — Agent entity precision V2 methodology contract

**Stage:** scoring methodology, not an accepted corrected precision number. **Active scope:** 145 source-pinned non-LangGraph repositories. The original Frozen-180 and #581 diagnostic artifacts and thresholds remain immutable.

## Root cause

The historical `agent_entities` precision scorer includes both Graph `agent` and `workflow_node`, while reference cases labelled exhaustive often list only root agents. #581 exposed 31 unmatched predictions: 12 actually workflow nodes, 17 source-supported agents missing/differently identified in the reference, and 2 unresolved custom model/tool-loop clients. The post-hoc review is not independent blind truth.

## Canonical ontology

1. An **agent entity** is a source-identified agent constructor, binding or agent subclass instance whose semantics include LLM/model-mediated task execution, or a framework's explicit agent class. Distinct source bindings remain distinct only when their construction/identity is supported; a shared factory definition alone is not evidence of multiple deployed instances.
2. A **workflow node** is a control-flow/step/edge participant, not an additional agent. A workflow root instantiated as an agent-like orchestrator can count as an agent **once** if canonical source identity supports it, but its additional edge nodes are never counted again.
3. **Delegation and authority are separate relationships**. Neither source agent inventory nor call-graph membership proves runtime tool callability, effective authority or an exploit path.
4. **Custom tool-loop clients** require explicit source-reviewed category decisions; uncertain cases stay unresolved and cannot inflate TP or FP.
5. Source identity includes **repository SHA, path, source line, canonical name and binding cardinality**. Same name across files is not automatically the same agent. Aliasing and factory indirection need positive source witnesses, not a guessed ±6 line tolerance.

## Conservative comparison

The new opt-in `scripts/real_world_agent_ontology_v2.py` rejects missing per-node Graph witnesses, unexpected kinds, duplicate source identities, mismatched frozen source pins, missing V2 case reviews and incomplete candidate runs. It excludes `workflow_node` from precision completely. Only explicitly source-reviewed negative witnesses can count as confirmed FP; unpaired predictions without negative labels remain **unresolved**. Every V2 positive must have a source-anchored declaration, and confirmed missing positives count as FN.

Both historical and candidate scanner versions must have **full 145-case, exact-SHA, per-node evidence** and be evaluated with **the same V2 reference**. Recompute a common-success panel; do not hide failed scans behind that denominator. Any failure, unresolved agent, incomplete review or non-independent source review blocks a release-certified aggregate. Even if a provisional ratio improves, the unchanged **95% agent precision gate** stays in effect.

## Deliverables still required

- Re-execute historical scanner commit `418db4e29798a7d25df686dd7bccfd9fefa225bd` in isolation with the same scanner CLI inputs and pinned sources, exporting exact node kinds and source locations. The existing historical summary does *not* contain these per-node witnesses.
- Produce a separate V2 source-anchored, negative-labelled reference across all 145 in-scope cases. Record incomplete evidence, agent binding multiplicity, and the two custom-client taxonomy decisions. Do not mutate locked V1 labels.
- Run the V2 scorer against both scanners and inspect per-case/stratum TP/FP/FN, including recall regressions and the two existing timeouts. A source-posthoc overlay alone is **not** an independent production-grade precision measurement.
- Preserve the other active non-LangGraph gates (MCP agent recall, delegation precision, scanner success and semantic policy assertions). No Wave C cutover based on diagnostic percentage increases.

This PR changes a study utility, tests, and documentation only. It does not alter production agent inventory, Graph/ADG, findings, attack paths or the original #581 scores.

## Explicitly unresolved SDK imports — `rw-004`

The pinned `rw-004` source declares `root_agent = Agent(name="AgroAsesorIA")`
at `agentGemini/agent.py:38`, but imports `Agent` from
`google.genai.adk`. The inspected `googleapis/python-genai` v0.1.0 and
v1.0.0 tagged trees do not export this module. The target's declared
`google-genai>=0.1.0` requirement is not a locked running environment;
absence in two inspected tags does not rule out local/third-party namespace
providers. Constructability and actual tool authority therefore remain
**unresolved**, rather than automatically true or false.

The source-pinned, post-hoc `rw004-agent-import-resolution-v2.json`
preserves the declaration under `expected: null` with an explicit
`unresolved_sdk_import` reason. The V2 scoring contract excludes it from
both TP/FP and FN counts **on both historical and candidate scans**, reports
the unresolved source site explicitly, and blocks certified precision or
recall while it remains unresolved. Source-positive `FunnelAgent` remains
included and the YAML display name `agentGemini` is source-negative.
No frozen V1 labels, non-LangGraph quality thresholds, Graph authority,
findings or attack paths are changed. This is not independent/blinded truth.
