# Agent-centric unseen 12 v5 — final post-#317 regression

## Scope

This is the final **regression/calibration rerun** of the frozen v5 cohort. It is not a fresh generalization result.

The exact 12 repositories and pinned target SHAs frozen for #309 are unchanged.

- final scanner baseline: `f2e284ed6c1719d1a55f15371116c06247afa5f1` (#317)
- frozen cohort commit: `7757d09d7f03ca86dc31febf4dfc2e2823c2bda1`
- original v5 scanner baseline: `86145932dce3895406f9e57b6783ad6eb706a107`
- final regression workflow run: **37116999361**
- cases: **12/12**
- target repository SHAs changed: **0**

## Final raw result

| Metric | #309 fresh v5 | #314 post-#313 | post-#317 final | Final delta vs #314 |
|---|---:|---:|---:|---:|
| Agents | 24 | 24 | 24 | 0 |
| Effective-authority relationships | 118 | 118 | 119 | +1 |
| Findings | 73 | 109 | 121 | +12 |
| Attack paths | 9 | 19 | 23 | +4 |
| ADK findings | 25 | 35 | 47 | +12 |
| Pydantic AI findings | 11 | 13 | 13 | 0 |
| OpenAI Agents findings | 37 | 61 | 61 | 0 |

The post-#314 delta is isolated to two v5 cases:

- `unseen5-adk-001` (BinCodeQL): +12 findings, +4 attack paths, authority count unchanged.
- `unseen5-adk-004` (GitLab incident agent): +1 effective-authority relationship, no new findings or paths.

All other ten cases are count-stable relative to #314.

## #313-schema adjudication of the post-#317 delta

All **109 findings recorded by #314 remain present by rule / agent / source-location identity**. The final delta therefore consists of exactly 12 newly recovered findings.

| New finding class | Count | Verdict | Source basis |
|---|---:|---|---|
| AGT020 process execution without approval | 2 | supported | `tool_extract_facts_batch` and `tool_find_loop_functions` delegate through function-local repository imports to `bn_utils.run_bn_script -> subprocess.run`; no approval is configured. |
| AGT040 privileged tool lacks guardrail/approval | 3 | supported | The same two process tools plus `tool_resolve_calls` now recover their source-backed process/write authority; no approval/guardrail is configured. |
| AGT021 destructive action without approval | 3 | supported | `tool_run_souffle`, `tool_run_taint_pipeline`, and `tool_run_bn_extra_rules` delete/replace source-proven files under caller/model-selectable output/facts directories without approval. |
| PATH002 potential untrusted-input path to destructive action | 3 | supported | The agent exposes the three destructive tools to untrusted input; the finding explicitly labels the basis as capability co-occurrence and states that executable data flow/runtime exploitability are not proven. |
| PATH006 multiple high-risk capabilities | 1 | supported | The same agent is exposed to untrusted input and has both source-backed `process.execute` and `destructive.write`; the finding is explicitly a potential co-occurrence risk. |

Canonical verdict totals for the new findings:

- supported: **12**
- partial: **0**
- unsupported: **0**
- unresolved: **0**
- strict precision on the post-#314 delta: **12/12 = 100%**
- materially-supported precision on the post-#314 delta: **12/12 = 100%**

No `partial_reasons` are assigned because the new findings already carry the relevant qualification in their claim/limitations instead of overstating reachability, resource scope, or runtime exploitability.

The three new PATH002 attack paths and the new PATH006 path are **4/4 valid within their stated potential-risk semantics**. They are capability-cooccurrence paths, not proof of executable source-to-sink data flow; that limitation is explicit in the emitted path metadata.

## Source checks for the new BinCodeQL semantics

### Function-local process effects

`tool_extract_facts_batch` imports `extract_facts_batch` inside the tool body. The repository helper calls `run_bn_script`, which executes a fixed Binary Ninja Python/script command through `subprocess.run`.

`tool_find_loop_functions` similarly imports the repository helper locally and reaches `run_bn_script -> subprocess.run`.

The process capability is therefore real. The scanner does **not** claim arbitrary shell-string execution for these two findings.

### Function-local pathlib write

`tool_resolve_calls` imports `resolve_call_targets` inside the tool body. That repository helper derives `Path` objects from the supplied facts directory and rewrites `Call.facts` and `FunctionAddr.facts` using `Path.write_text`.

The recovered `data.write` capability is source-backed.

### Destructive output/facts replacement

`tool_run_souffle` converts the exposed `output_dir` argument into a Path and unlinks stale `*.csv` outputs before execution.

`tool_run_taint_pipeline` delegates to `pipeline.run_taint_pipeline`, which clears stale `*.csv` files under the supplied output directory and stages/replaces fixed facts files.

`tool_run_bn_extra_rules` delegates to the shared pipeline, whose staging helper unlinks existing destination facts before replacing them with symlinks. The facts directory is supplied through the tool boundary.

These are caller/model-selectable directory scopes, not the scanner-owned temporary-file cleanup suppressed by #317. Retaining `destructive.write` is therefore source-supported.

## ADK MCP authority closure

The GitLab case now reconstructs the factory-local ADK MCPToolset end-to-end:

| MCP metric | #314 | post-#317 |
|---|---:|---:|
| MCP servers | 2 declarations / duplicated wrapper view | 1 normalized server |
| Bound relationships | 0 | **1** |
| Unbound servers | 2 | **0** |
| Effective-authority relationships | 5 | **6** |

The recovered authority is:

`gitlab_incident_responder -> gitlab_mcp -> mcp.local`

The relationship remains partially resolved for authentication, destination and tool catalogue, which is correct: binding is source-proven while those dimensions are not.

## Original v5 false positives

All **6/6** clear false positives identified in #309 remain closed after #315-#317:

1. local collection mutation is not promoted to persistent write authority;
2. GitLab operator-configured destination provenance is preserved;
3. both Trunks workspace-containment PATH012 false positives remain absent;
4. Alpaca `allow_trading` remains recognized as a runtime guard;
5. Alpaca `ALPACA_URL` remains operator-configured through `AlpacaConfig.base_url`.

No original v5 false positive reappeared.

## Final v5 interpretation

Relative to the fresh #309 baseline:

- findings: **73 -> 121**
- attack paths: **9 -> 23**
- authority relationships: **118 -> 119**
- known clear false positives: **6 -> 0**
- original fresh-v5 materially-supported precision: **67/73 = 91.8%**
- final frozen-regression materially-supported findings: **121/121**

The **121/121 figure is regression/calibration evidence**, not an estimate of unseen-repository precision. #312-#317 were influenced by v5 source review.

Known recall hypotheses that were not pursued further on v5 include module-level object/client effect propagation, some Pydantic outbound/command/config mutation chains, Tavily/web-search helper propagation, and delegated-child authority projection. These should be tested on fresh evidence rather than tuned further against this cohort.

## Build decision

**Freeze v5 now. Do not make additional scanner changes from this cohort.**

The next evidence gate is a fresh pre-frozen **v6 unseen cohort** using only Google ADK, Pydantic AI and OpenAI Agents, excluding every prior research repository. Cohort selection must be completed and committed before HorusScan execution.
