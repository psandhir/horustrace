# ADK + Pydantic AI 10-repo P0/P1 before/after differential

## Purpose

Re-run the exact pinned 5 Google ADK + 5 Pydantic AI framework litmus after PR #271 and compare it against the original locked LLM source review and pre-fix HorusTrace reveal.

This is a controlled A/B comparison:

- target repositories and SHAs are unchanged;
- the LLM source review is unchanged;
- the original scanner baseline is `36c48f88da2106c367e3a96e2f94432e8ef595ca`;
- PR #271 head is `58042934515a6aeafaa0c745c95c8e1d60db1a44`;
- merged `main` is `f42a05025e5c1a13fab8bc1cd4bd73dc0131b5b7`;
- the PR head and merged `main` have the same Git tree: `c41bf160a2dd700eb230923856ce55bb2c150118`.

The exact post-fix workflow was replayed as GitHub Actions run `36722966258`, attempt 2. The fresh artifact is `framework-litmus-adk-pydantic-10-postfix`, artifact id `11103457455`.

## Scanner replay

- Scanned: **10/10**
- Scan errors: **0**
- Findings: **39**
- Attack paths: **9**
- Replay conclusion: **success**

| Case | Framework | Before findings | After findings | Before paths | After paths | Material delta |
|---|---|---:|---:|---:|---:|---|
| rw-009 | Google ADK | 3 | 0 | 1 | 0 | False unrestricted-egress findings/path removed; fixed `api.github.com` scope preserved |
| rw-017 | Google ADK | 11 | 11 | 2 | 2 | Same paths, now carrying optional-public-default authentication predicate |
| rw-004 | Google ADK | 13 | 13 | 0 | 0 | Declared authority now qualified by source initialization/import blockers |
| rw-007 | Google ADK | 2 | 2 | 1 | 1 | Correct local-file -> Document AI path retained |
| rw-012 | Google ADK | 0 | 0 | 0 | 0 | Negative precision control remains clean |
| rw-155 | Pydantic AI | 23 | 1 | 0 | 0 | Dynamic configured MCP authority detected; native shell/file/internal-plan noise removed |
| rw-152 | Pydantic AI | 7 | 7 | 3 | 3 | Runtime blocker qualification added; URL-flow and filename-scope precision remain partial |
| rw-147 | Pydantic AI | 0 | 2 | 0 | 1 | Search-result-derived destination now detected as NET001 + PATH011 |
| rw-150 | Pydantic AI | 2 | 2 | 1 | 1 | Direct dynamic URL detection retained |
| rw-164 | Pydantic AI | 1 | 1 | 1 | 1 | RAG directory exposure path retained |

The raw finding count falls from **62 to 39** while two previously missed semantic authorities are added. The reduction is therefore primarily a precision improvement, not reduced coverage.

## Locked LLM semantic comparison

The original LLM review contains **12 source-supported semantic findings**.

| Metric | Before | After |
|---|---:|---:|
| Full semantic matches | 6 / 12 (50.0%) | **10 / 12 (83.3%)** |
| Partial semantic matches | 4 / 12 (33.3%) | **2 / 12 (16.7%)** |
| Missed semantic findings | 2 / 12 (16.7%) | **0 / 12 (0%)** |
| Full + partial coverage | 10 / 12 (83.3%) | **12 / 12 (100%)** |

Changes against the locked review:

- `rw-009`: source-unsupported fixed-provider egress claim eliminated.
- `rw-017`: partial -> full; both persistent-write paths now retain the public-default authentication predicate.
- `rw-004`: partial -> full; runtime/source blockers now qualify declared authority.
- `rw-155`: missed -> full; dynamically configured Pydantic MCP toolsets are represented without inventing a concrete catalogue.
- `rw-147`: missed -> full; search-result-derived destination provenance is represented.
- `rw-152`: two original partial semantics remain partial:
  1. model-selected URL -> `WebBaseLoader` is recognized as outbound authority but is not reconstructed as a dedicated source-to-destination path;
  2. model-controlled output filename/path scope is still represented as generic write authority rather than precise resource scope.

## Locked LLM attack-path comparison

The original LLM review contains **9 source-supported semantic attack paths**.

| Metric | Before | After |
|---|---:|---:|
| Full path matches | 5 / 9 (55.6%) | **8 / 9 (88.9%)** |
| Partial path matches | 2 / 9 (22.2%) | **0 / 9 (0%)** |
| Missed paths | 2 / 9 (22.2%) | **1 / 9 (11.1%)** |
| Full + partial path coverage | 7 / 9 (77.8%) | **8 / 9 (88.9%)** |
| Known source-unsupported HorusTrace paths | 1 | **0** |

The remaining LLM path miss is `rw-152`:

`model-selected URL -> WebBaseLoader -> outbound fetch`

HorusTrace still reports three source-supported code-execution `PATH001` variants in that repository, so the unchanged aggregate count of nine attack paths should not be read as complete path equivalence. The semantic mapping is the important metric.

## Interpretation

PR #271 materially improved both recall and precision on the exact cases that motivated the work:

1. **No locked LLM semantic finding is now completely missed.**
2. **Full semantic alignment improved by 33.3 percentage points**: 50.0% -> 83.3%.
3. **Full path alignment improved by 33.3 percentage points**: 55.6% -> 88.9%.
4. The known false `rw-009` egress path is gone.
5. `rw-155` changed from 23 noisy findings and no MCP detection to one targeted dynamic-MCP finding.
6. The replay reproduced the same post-fix result, providing a determinism check for this cohort.

## Next build target

The controlled replay leaves one concentrated framework gap: **`rw-152` resource/destination provenance**.

The next small build should focus on:

- reconstructing model-controlled URL -> loader/fetch flows for abstractions such as `WebBaseLoader`;
- preserving model-controlled filename/path scope for write tools;
- retaining the new runtime-viability qualification while doing so.

After that targeted change, rerun this same locked 10-repo litmus. If the remaining two partial semantics and one path miss close without regressing the negative controls, move to a fresh unseen ADK/Pydantic holdout cohort.
