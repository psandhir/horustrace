# HorusScan Wave B→C shared engineering scratchpad

**Live handover file; not a release sign-off.** Update this file at every substantive engineering checkpoint on the working branch, and preserve it when integrating into `main`.

## Ownership and restart procedure

- Repository: `psandhir/horustrace`.
- Active branch: `accuracy/wave-b540-model-judge-handoff-20261015`.
- Base: `main@1ab391e1513c01ec6fa122c6f29953652fe8df76` (PR #552 and #553 both merged).
- Workstreams: Wave B issue [#540](https://github.com/psandhir/horustrace/issues/540), acceptance [PR #551](https://github.com/psandhir/horustrace/pull/551), then Wave C [#543](https://github.com/psandhir/horustrace/issues/543) **C01→C05, not C01 alone**.
- Every agent: **read this scratchpad, #540/#543 latest checkpoint, current main SHA and PR states before touching files**. Never assume a scheduled task has actually run; check its GitHub evidence. Never concurrently edit a branch owned by another active worker.
- At the end of each run: append verified delta (claim IDs, source witnesses, commit SHA, CI links), precise blocker, one next actionable task, and timestamp. Do not overwrite another agent's decisions without a documented contradiction and original source support.
- If CI/GitHub is blocked: inspect failing job/source, fix once; pivot to source review/negative fixtures/standalone docs while waiting; avoid duplicate CI fan-out. Do not bypass branch protections.
- Model adjudication is **OpenAI-model-as-judge** with exact source SHA, Git blob, path/line, positive/negative witnesses, confidence, source-only or conditional classification and reviewer identity. It is **NOT independent human review**, runtime verification, or exhaustive truth. Keep genuinely unverifiable effective authority as UNKNOWN.

## Current verified engineering state (15 Oct 2026, ~23:15 Europe/London)

- `main@1ab391e`: P0 #552 AGT022 lost-finding regression and #553 same-source Strands duplicate tool/phantom authority edge merged.
- Fresh16 [38811906529](https://github.com/psandhir/horustrace/actions/runs/38811906529), Full60 [38811906774](https://github.com/psandhir/horustrace/actions/runs/38811906774), CI [38811906473](https://github.com/psandhir/horustrace/actions/runs/38811906473) and CodeQL [38811906471](https://github.com/psandhir/horustrace/actions/runs/38811906471) all succeeded at that SHA.
- PR #551 head `6bdd3b210018167d293da905bd1c5e236fbbd3b4` is DRAFT and all latest checks passed: [pinned differential 38812764105](https://github.com/psandhir/horustrace/actions/runs/38812764105), [Wave-A-30 38812764084](https://github.com/psandhir/horustrace/actions/runs/38812764084), [unseen Amazon holdout 38812764156](https://github.com/psandhir/horustrace/actions/runs/38812764156), CI 38812763920 and CodeQL 38812764251.
- Acceptance differential: Fresh16 has 0 changed finding keys; Full60 57 added and 16 removed = **73 changed finding claim keys, all in `ff60-amazon-04`, 20 high severity**. Counts are changed claims, **not** verified TP/FP/FN. The current after scan has 10 distinct Agent source sites vs historical 2, 52 authority relationships (all runtime effectiveness unverified), 68 findings (65 lacking raw structured provenance), 0 attack paths.
- Read full case archive from GitHub [run 38811906774](https://github.com/psandhir/horustrace/actions/runs/38811906774); the 73-claim review queue is exported from [run 38812764105](https://github.com/psandhir/horustrace/actions/runs/38812764105) as `evaluation/full60.json` under `cases[].changed_claim_details`. Local working attachments may not persist across scheduled sessions: use the GitHub artifact, not `/mnt/data` paths, as system of record.
- Acceptance PR has detailed `docs/wave-b540-acceptance-dossier-20261015.md` describing WAB-01 through WAB-05 and NO-GO. Do not close #540 or start unsafe production Wave C cutover on green CI alone.

## Source-first judge review now underway

Original target repo: `aws-samples/sample-multi-agent-region-expansion-planner@30d03d7c9f6512e5bf10601879382fac9c3a16b1`. Pinned Git blob IDs and original, **non-executed source**:

- `src/main.py` blob `e9f374cf99d80460602c633de8470a043c991c9a`: imports `shell` and `use_aws` at 16, invokes `Constants.set_tool_configurations()` at 47, defines common tool list at 53, and instantiates orchestrator Agent at 56–60.
- `src/agents/analysis_writer.py` blob `7ff9f80928c741eb46519df84d8c8c71e2d9f97b`: `@tool` wrapper at 35–36, imports `shell` at 18, tools=[...shell] at 59, sets tool config at 62, nested Agent constructor 72–76. Function returns failure if Strands unavailable (54–56): **conditional/deferred**.
- `src/agents/report_writer.py` blob `9c2fa791fb3641ed787b56357a28869287c79e9c`: `@tool` wrapper at 37–38, imports `shell` at 17, tools list at 61, config call 64, nested Agent 74–78; conditional availability at 56–58.
- `src/agents/tech_analysis.py` blob `46080c13371aa2015b08de38d8517663cb2d4b42`: `@tool` wrapper 71–72, imports `shell` at 44, tools 118–124, config 128, nested Agent 140–144, availability guard at 111–114.
- `src/agents/pricing_explorer.py` blob `2c7c942b22ba50e857b4b75a1c38c7a8ef8f2cc2`: `@tool` wrapper 43–44, imports `python_repl` at 26, remote `list_tools_sync` plus standard tools at 83–84, config at 86, nested Agent 89–93 inside per-region loop; remote tools are dynamically UNKNOWN.
- `src/agents/__init__.py` blob `5f7114f83152fc73ee0b84cd5a4c56a550d5ceb1`: imports `compare_regional_pricing` from pricing module at 9, but **does not export a callable `pricing_explorer`**; `main.py:15,54` attempts to include `pricing_explorer`. This may resolve as Python module rather than callable and is a potential **hard-negative for confirmed orchestrator→pricing-explorer callable reachability**. Needs import semantics verification; no invented guaranteed runtime delegation.
- `src/utils/config.py` blob `f8ef81efe8af9a932f14808f9de91c5c80f9e93d`, lines **43–46**: `set_tool_configurations` explicitly sets `STRANDS_TOOL_CONSOLE_MODE=enabled` and `BYPASS_TOOL_CONSENT=true`. Many wrappers call this before Agent construction. The source therefore has **explicit consent-bypass configuration**, stronger evidence than a mere `approval=None` inference, but it does not prove successful runtime access or backend approval semantics.

### Model reviewer classification discipline

For each claim, state what is proven by original pinned source: **source-configured potential capability**, **conditional nested Agent**, **unknown runtime-effective permission**, and whether the original finding's source location is valid. A moved old line-1 finding can be a *location/provenance correction*, **not** removal of an underlying security risk. A standalone Agent variable erroneously named `agent` as a privileged callable should be treated as a potential bogus tool classification and verified against direct source.

Do NOT call any finding a true positive as runtime exploit evidence. Do NOT infer 52 actual reachable authority edges from source observation. Do NOT claim exhaustive recall before reviewing missing source structures/negative controls.

## Overnight plan (restartable milestones)

1. **B truth ledger**: use source-only OpenAI judge to review all 20 high-severity changed claim keys in `ff60-amazon-04`, then the remaining 53, with pinned source witnesses and distinct `model_as_judge` reviewer field; treat tricky cases as unresolved instead of guessing. Commit adjudication JSON, negative tests, and any source-supported remediation on focused PR.
2. **B proof & validation**: WAB-01–05 per-instance positive/hard-negative source objects, conditional MCP catalogs, deferred Strands wrappers, test/provider-only partitions; per-case stage and finding/authority reconciliation; run pinned regression suites at meaningful checkpoints. Complete issue #540 only after its *actual* original acceptance criteria, with human independence limitation disclosed.
3. **Wave C full scope if B gate passes**: C01 typed canonical entities/edges and source context; C02 independent/methodologically isolated D01 blind source holdout; C03 reversible flag-guarded Graph/ADG framework cutover; C04 effective authority, policy findings and attack-path evidence; C05 security UX drilldowns, provenance and rollback/release dossier. Preserve per-phase tests and source truth. If B cannot pass, perform only non-cutover preparation and do not fake an accepted Wave C release.
4. Final morning handoff at 08:00 Europe/London documents DONE/PARTIAL/BLOCKED for Wave B and **all C01–C05**.

## Next safe action

Create `research/accuracy-wave-b540-model-judge-20261015/high-severity-adjudication.json` keyed by all 20 high-severity claim keys, each with pinned blob/path/lines, source-only conditional review, category/confidence/rationale, and second-pass negative witness. Add a test checking queue coverage/unique IDs/no missing witnesses and rejecting invented human reviewer status. Then validate review artifacts and open a dedicated PR; the overnight worker can pick up the remaining 53 without repeating the first 20.

## Active execution checkpoint — 15 October 2026, current session

- Opened draft [PR #554](https://github.com/psandhir/horustrace/pull/554), commit `9806fceb7db353463a70f72a4328e15e3ad9ab75`.
- Source-first OpenAI-model review of all 20 high-severity changes: 10 source-confirmed conditional/potential, 6 obsolete source identity/line-1 claim false positives, 4 unresolved third-party/effect assertions. `high-severity-adjudication.json` includes pinned witness evidence and the test checks exact key coverage. **No verified runtime authority or human-independent review.**
- This checkpoint adds **53 medium-severity review rows**: 35 source-confirmed local/conditional configuration warnings, 10 obsolete or phantom old source claims, 8 unresolved third-party semantics or effective network destination controls. Together 73/73 changed claim keys are model-reviewed; classification must be independently checked by pinned source/negative controls before GO.
- Source discoveries to investigate: package `__init__.py` does not export callable pricing_explorer, config sets BYPASS_TOOL_CONSENT=true, remote MCP `list_tools_sync` outputs dynamic unresolved. All model-reviewed observations are **source-only**.
- Next agent actions: inspect CI on latest #554 SHA; fix failing tests; test accuracy of source path and claim uniqueness against `evaluation/full60.json` and hard negative candidates; assess whether AGT040 exact approval semantics and NET002 potential overclaims justify scanner fix. Build independent source-negative/positive truth for WAB-01–05; pursue safe Wave C preparatory work when Wave B GO remains blocked.
