# Unseen ADK + Pydantic AI holdout — first differential

## Method

This is a true external holdout relative to the frozen 180.

The cohort was selected and pinned before scanner reveal. The independent source
review was committed at `5c6ac0f74bfb584d5f627e0b35063fd60a0860d9`.
Only after that lock was the HorusTrace workflow added and executed.

Scanner workflow:
- run: `36736972394`
- artifact: `11107378157`
- scanned: **10/10**
- scan errors: **0**
- HorusTrace findings: **23**
- HorusTrace attack paths: **2**

The scanner source is the current merged-main implementation; the research
branch adds only study files and the non-mutating workflow.

## Scanner result by case

| Case | Framework | Findings | Paths | Source-review outcome |
|---|---|---:|---:|---|
| hold-adk-001 | Google ADK | 2 | 0 | Partial: write/no-control detected, but GCS bucket/object semantics lost |
| hold-adk-002 | Google ADK | 0 | 0 | Agreement / negative control |
| hold-adk-003 | Google ADK | 5 | 0 | Mixed: dynamic MCP covered; URL-context destination authority missed |
| hold-adk-004 | Google ADK | 0 | 0 | Agreement / negative control |
| hold-adk-005 | Google ADK | 5 | 0 | Partial: CRUD/write surface detected; DELETE, fixed origins and bearer-auth semantics lost |
| hold-pyd-001 | Pydantic AI | 3 | 1 | Partial: bash execution found; wrapped PythonREPL execution missed |
| hold-pyd-002 | Pydantic AI | 3 | 1 | Strong MCP semantic match; path is capability-level rather than exact delete call |
| hold-pyd-003 | Pydantic AI | 0 | 0 | Scanner correctly reports source parse failure/no targets |
| hold-pyd-004 | Pydantic AI | 5 | 0 | Mutation authority covered; cross-file CLI ingress/path is missed |
| hold-pyd-005 | Pydantic AI | 0 | 0 | Agreement / negative control |

## Locked semantic-finding alignment

The blind source review contains **7 material semantic findings**.

| Metric | Result |
|---|---:|
| Full semantic matches | **3 / 7 (42.9%)** |
| Partial semantic matches | **3 / 7 (42.9%)** |
| Missed semantic findings | **1 / 7 (14.3%)** |
| Full + partial coverage | **6 / 7 (85.7%)** |

### Full

1. **hold-adk-003 — dynamic remote MCP authority**
   - HorusTrace binds the remote MCP server and reports missing tool allowlist /
     unresolved authority scope.
   - The scanner also records the dynamic endpoint diagnostic.
   - Separate precision issues are discussed below.

2. **hold-pyd-002 — YouTube MCP mutation/delete**
   - The local stdio MCP implementation is resolved.
   - Exact discovered MCP tools include `update_video_details` and
     `delete_video`.
   - `delete_video` is classified as destructive write.

3. **hold-pyd-004 — local budget state mutation**
   - `add_transaction` is data.write.
   - `delete_transaction` is destructive.write.
   - Lack of technical approval is represented.

### Partial

1. **hold-adk-001 — GCS object write**
   - HorusTrace correctly reports model-bound state-changing write without
     approval/control.
   - It reduces `store_pdf` to generic `data.write`; it does not preserve:
     - Google Cloud Storage as the external sink;
     - deployment-selected bucket;
     - fixed object name `proposal_document_for_user.pdf`.

2. **hold-adk-005 — OpenAPI account CRUD**
   - HorusTrace detects broad read/write/external-network toolset authority.
   - It does not preserve operation-level semantics:
     - POST create/update;
     - DELETE permanent account deletion;
     - fixed production/staging server origins;
     - bearer-auth requirement.
   - Consequently the scanner emits `NET002` despite source-visible fixed
     OpenAPI server origins.

3. **hold-pyd-001 — arbitrary execution**
   - HorusTrace fully reconstructs
     `bash.command -> subprocess.run` as `PATH001`.
   - It discovers `tool_from_langchain` but assigns it no capabilities, so
     the bound `PythonREPLTool` execution half of the source finding is missed.

### Missed

1. **hold-adk-003 — delegated model-selected URL retrieval**
   - Source binds a URL-context specialist through `AgentTool`.
   - The child is explicitly intended to retrieve content from supplied URLs.
   - HorusTrace currently marks `UrlContextTool` / `url_context` as
     `network_scope=fixed_managed_service`.
   - That models the provider service rather than the *target URL authority* and
     therefore fails to represent arbitrary/model-selected retrieval targets.

## Locked source-supported path alignment

The blind review contains **5 semantic attack/authority paths**.

| Metric | Result |
|---|---:|
| Full path matches | **1 / 5 (20.0%)** |
| Partial path matches | **1 / 5 (20.0%)** |
| Missed paths | **3 / 5 (60.0%)** |
| Full + partial path coverage | **2 / 5 (40.0%)** |

### Full

- **hold-pyd-001 bash**
  - source: web-facing agent -> `bash(command)` -> `subprocess.run(shell=True)`
  - scanner: supported `PATH001` from model tool input to `subprocess.run`.

### Partial

- **hold-pyd-002 YouTube delete**
  - scanner: `cli-input -> agent -> mcp -> destructive.write` (`PATH002`)
  - MCP metadata independently proves the exact `delete_video` implementation.
  - Path basis remains `capability_cooccurrence`; the path itself does not
    carry the exact MCP tool/sink edge.

### Missed

1. **hold-pyd-001 PythonREPL**
   - `tool_from_langchain(PythonREPLTool())` has no inferred process/code
     execution capability.

2. **hold-adk-003 URL context**
   - delegated target-URL retrieval is collapsed into fixed-managed-service
     network semantics.

3. **hold-pyd-004 budget delete path**
   - source proves CLI `user_input` -> imported `run_budget_conversation` ->
     `budget_agent.run_sync` -> destructive tool authority.
   - Scanner does not attach CLI ingress to `budget_agent`, so no composed
     path is emitted.

## Precision / qualification findings from adjudication

### ADK remote MCP destination provenance

For the dynamic MCP instance in hold-adk-003, the endpoint comes from
`MCP_SERVER_URL`: it is **operator/deployment configured**, not caller/model
selected. `NET001` currently says the server accepts a “caller-selected
destination.” That wording/semantic classification overstates the source.

The repository also contains an alternate agent file with a literal placeholder
governance URL. HorusTrace reports unauthenticated remote MCP authority against
that placeholder without qualifying that the literal is non-deployable as
written.

### OpenAPI fixed destination loss

hold-adk-005 has explicit fixed server origins in `account_api_spec.json`:
`https://api.accountservice.com/v1` and
`https://staging.api.accountservice.com/v1`.

HorusTrace emits `NET002` “no destination constraint.” This is
source-unsupported and is the clearest precision defect in the holdout.

### Source parse blocker

The locked reviewer described hold-pyd-003 as blocked by missing imported local
modules. Post-reveal adjudication found an even earlier blocker: the pinned
`agent.py` is syntactically incomplete at the result dictionary near line 112.
HorusTrace correctly emits a parse-error coverage diagnostic and no targets.
The locked review's exact blocker rationale was therefore imperfect, but both
sides agree that the declared agent is not source-proven runnable.

### Dual miss discovered during adjudication

hold-pyd-004's `analyze_budget` tool can write a derived PNG via
`plt.savefig(filename)`. The filename is derived from a parsed month/year and
is not an arbitrary path. This fixed-pattern artifact write was omitted by the
blind source review **and** by HorusTrace, so it is not included in the locked
7-finding score. It should be retained as a reviewer+scanner dual-miss for
future coverage work.

## What generalised well

- ADK direct FunctionTool state-change recognition.
- Pydantic direct function-tool process execution.
- Local stdio Pydantic MCP implementation resolution.
- Exact MCP destructive-tool discovery.
- Negative precision controls with side-effect-free tools.
- Basic Pydantic local data-write/destructive-write classification.
- Syntax-error coverage diagnostics.

## Build queue from the holdout

### P0 — wrapped execution authority

Recognize execution semantics through Pydantic/LangChain wrappers such as:

`tool_from_langchain(PythonREPLTool())`

The effective Pydantic tool should retain the wrapped tool's code-execution
authority and controls.

### P0 — ADK URL-context target provenance

Separate **provider transport/service destination** from the **model-selected
content URL** for `UrlContextTool` and equivalent ADK URL-context bindings.
Propagate that authority through `AgentTool` delegation and build the
source-supported URL-fetch path.

### P1 — OpenAPI operation semantics

For ADK/OpenAPI toolsets, preserve:
- server origins;
- authentication schemes;
- HTTP operation/method;
- state-change/destructive semantics for POST/PATCH/PUT/DELETE;
- operation-level effective authority.

This should eliminate the hold-adk-005 false `NET002` while strengthening
DELETE detection.

### P1 — cross-file Pydantic ingress

Resolve public/CLI wrapper flow across imports:

`main.py input -> imported run_budget_conversation -> budget_agent.run_sync`

Then compose that ingress with bound mutation/destructive tools.

### P1 — cloud-object sink semantics

Recognize common cloud SDK object writes such as GCS
`bucket(...).blob(...).upload_from_file`, preserving:
- cloud provider;
- bucket provenance (fixed/config/model selected);
- object-key provenance;
- external-write authority.

### P2 — source-backed side effects beyond names

Infer `set_budget_limit` and fixed-pattern `plt.savefig` writes from source
operations rather than tool-name heuristics alone.

## Bottom line

The holdout validates that the #271/#275 work substantially improved the exact
patterns it targeted, but **complete alignment did not generalize** to unseen
framework composition.

The most important product lesson is that the remaining gap is no longer basic
agent/tool discovery. It is **semantic projection through wrappers and
abstractions**:

- wrapped third-party tools;
- delegated built-in URL tools;
- generated OpenAPI toolsets;
- cross-file ingress wrappers;
- cloud SDK resource sinks.

These are high-value next targets because they recur across frameworks rather
than being repository-specific special cases.
