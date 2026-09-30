# ADK + Pydantic AI 10-repo controlled differential

## Purpose

Measure HorusTrace improvement against an unchanged, locked LLM source review by
re-running the exact same pinned **5 Google ADK + 5 Pydantic AI** repositories
through three scanner states:

1. the pre-fix baseline;
2. the P0/P1 framework fixes merged in PR #271;
3. the final rw-152 resource/destination provenance closure merged in PR #275.

This is a controlled A/B/C comparison. The target repository SHAs and LLM review
are unchanged, so semantic deltas can be attributed to scanner changes rather
than cohort drift.

## Locked inputs

- Original scanner baseline: `36c48f88da2106c367e3a96e2f94432e8ef595ca`
- PR #271 head: `58042934515a6aeafaa0c745c95c8e1d60db1a44`
- PR #271 merge: `f42a05025e5c1a13fab8bc1cd4bd73dc0131b5b7`
- PR #275 head: `2ed6a5d304a42661ceabdff91d7987edd6f532cd`
- Final merged main: `55f0da3d5231eb3c63591a643f338942ad1983d2`
- PR #275 head and merged main Git tree: `d76763799916d084d23c0ca762d3853fbf435888`
- Final exact litmus run: `36731150082`
- Final artifact: `framework-litmus-adk-pydantic-10-postfix`
- Final artifact id: `11104227996`

## Three-stage result

| Metric | Baseline | After #271 | After #275 |
|---|---:|---:|---:|
| Repositories scanned | 10/10 | 10/10 | **10/10** |
| Scan errors | 0 | 0 | **0** |
| HorusTrace findings | 62 | 39 | **40** |
| HorusTrace attack paths | 9 | 9 | **10** |
| Full semantic matches | 6/12 (50.0%) | 10/12 (83.3%) | **12/12 (100%)** |
| Partial semantic matches | 4/12 (33.3%) | 2/12 (16.7%) | **0/12 (0%)** |
| Missed semantic findings | 2/12 (16.7%) | 0/12 | **0/12** |
| Full source-supported path matches | 5/9 (55.6%) | 8/9 (88.9%) | **9/9 (100%)** |
| Partial source-supported path matches | 2/9 | 0/9 | **0/9** |
| Missed source-supported paths | 2/9 | 1/9 | **0/9** |
| Known source-unsupported HorusTrace paths | 1 | 0 | **0** |

The raw finding count falls from **62 to 40** while semantic coverage increases
from 83.3% full-or-partial to **100% full alignment**. This is primarily a
precision improvement combined with targeted recall gains, not reduced scanner
coverage.

## Final per-case scanner result

| Case | Framework | Baseline findings | Final findings | Baseline paths | Final paths | Final state |
|---|---|---:|---:|---:|---:|---|
| rw-009 | Google ADK | 3 | 0 | 1 | 0 | False unrestricted GitHub egress removed; fixed provider scope preserved |
| rw-017 | Google ADK | 11 | 11 | 2 | 2 | Persistent-write paths retain optional-public-default authentication predicate |
| rw-004 | Google ADK | 13 | 13 | 0 | 0 | Declared authority retained with source initialization/import blocker qualification |
| rw-007 | Google ADK | 2 | 2 | 1 | 1 | Model-selected local file -> Document AI path retained |
| rw-012 | Google ADK | 0 | 0 | 0 | 0 | Negative precision control remains clean |
| rw-155 | Pydantic AI | 23 | 1 | 0 | 0 | Dynamic configured MCP detected; native shell/file/internal-plan noise removed |
| rw-152 | Pydantic AI | 7 | 8 | 3 | 4 | URL-loader path and model-selected output path scope now explicit |
| rw-147 | Pydantic AI | 0 | 2 | 0 | 1 | Search-result-derived destination provenance detected |
| rw-150 | Pydantic AI | 2 | 2 | 1 | 1 | Direct dynamic URL path retained |
| rw-164 | Pydantic AI | 1 | 1 | 1 | 1 | RAG directory exposure path retained |

## What #271 fixed

PR #271 closed the primary P0/P1 gaps identified by the locked LLM review:

- **rw-009:** fixed-provider destination evidence now survives helper and
  delegation propagation, eliminating false `NET002/PATH009`.
- **rw-017:** ingress authentication state, including public-default behavior,
  is retained in composed paths.
- **rw-004 / rw-152:** source/runtime initialization blockers qualify declared
  authority without erasing it.
- **rw-155:** dynamically configured Pydantic MCP toolsets are represented
  without inventing a concrete catalogue; source-visible shell/path/internal
  state controls remove generic noise.
- **rw-147:** provider-search-result URLs dereferenced by server-side HTTP are
  modeled as second-order destination provenance.

After #271, no locked semantic finding was completely missed, but two rw-152
semantics remained partial and one source-supported path remained absent.

## What #275 closed

### 1. Model-selected URL -> WebBaseLoader

The final scanner now reconstructs a supported static data-flow path:

`web_scraper.urls -> agent_tools.web_scraper -> WebBaseLoader`

The resulting `PATH011` records:

- `basis=static_dataflow`
- `source_kind=agent_tool_input`
- `sink_kind=server_side_url_fetch`
- `destination_provenance=model_selected_url_argument`
- `network_abstraction=url_loader`
- runtime blocker qualification from the pinned source

This closes the final LLM source-supported attack-path miss.

### 2. Model-controlled output filename/path

The effective `generate_and_save_image` authority now carries an explicit
file resource scope:

- `resource_scope=<model-selected-path>`
- `path_parameters=filename`
- `path_containment=not_detected`
- access: `data.write`

The scope is surfaced directly in `AGT022` and `AGT040` evidence, rather than
remaining hidden as generic write capability.

The provenance pass also binds filesystem scope to the **actual path-controlling
parameter**, avoiding the earlier over-approximation where unrelated tool inputs
could be treated as path selectors.

## Final locked-LLM adjudication

The original source review contains **12 semantic findings** and **9
source-supported semantic attack paths**.

Against final merged main:

- **12/12 semantic findings are fully represented**
- **0 partial semantic findings remain**
- **0 semantic findings are missed**
- **9/9 source-supported attack paths are fully represented**
- **0 known source-unsupported HorusTrace paths remain in this cohort**

This does **not** establish universal precision or recall. It establishes complete
alignment against this particular locked 10-repository framework litmus and is
therefore a strong regression baseline.

## Next step

Do not continue tuning against these ten repositories immediately.

Use this set as a **frozen regression suite**, then select a fresh unseen
ADK/Pydantic holdout cohort. The next study should answer whether the semantic
gains generalize to repositories that did not drive the implementation changes.

If the holdout uncovers new gaps, source-adjudicate them before changing scanner
semantics and then ensure this locked 10-repo suite remains green.
