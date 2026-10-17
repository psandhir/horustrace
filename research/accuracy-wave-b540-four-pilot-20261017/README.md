# Wave B #540 — four-pilot pinned source-edge adjudication

**Reviewed 17 October 2026. Source-mechanism review completed; Wave B release NO-GO.**
Source reviewer: OpenAI/ChatGPT model-assisted analysis, **not an independent human**.
No scanned application or third-party dependency was executed. Runtime identities,
approval enforcement, successful tool calls, network outcomes and attack-path
reachability are not verified.

The machine-readable [source-edge-ledger.json](./source-edge-ledger.json) records
every named candidate in the four frozen pilot scopes with immutable upstream
commit/source blob, positive edge semantics and explicit hard negatives.
`tests/test_wave_b540_four_pilot_source_ledger.py` fails closed on dropped
case entries, catalogue inflation, missing source anchors, duplicated instance
sites or accidental promotion to effective authority. Earlier producer-level
positive and hard-negative tests under `tests/test_source_native_mcp.py`,
`tests/test_source_native_dynamic_mcp.py`,
`tests/test_source_native_toolsets.py` and source-native Strands tests
remain separately required.

## Claim classes and source witnesses

| Pilot | What exact source supports | Explicit negative or unknown | Result |
| --- | --- | --- | --- |
| WAB-01 / `gen-pyd-001` | `newsbubbles/pharmiq@c699497`: `agent.py:54,73` binds literal `python mcp_server.py` to Pydantic Agent; `mcp_server.py` provides **22 individually named `@mcp.tool()` registrations**, each tied to decorator and definition lines plus blob. | `EXPOSES_TOOL` is not `AGENT_CAN_CALL`; no startup, session, authorization, approval or execution proof. | **Source-positive registrations: 22/22. Runtime callable authority: unresolved.** |
| WAB-02 / `ff60-microsoft-04` | `qmatteoq/agent365-demos@937f8c`, teammate `ToolingManifest.json` declares exactly **mcp_MailTools and mcp_CalendarTools**; `WorkIqToolProvider.cs:96–109,137–154` exchanges token, constructs authenticated `McpClient` and awaits remote `ListToolsAsync`. | Missing token, timeout or connection failure skips enumeration. This is neither an empty catalogue nor proof of any named remote callable; service class is not an Agent by itself. | **2 manifest-declared endpoints, 0 source-known remote tool names, unresolved runtime catalogue.** |
| WAB-03 / `gen-mcp-003` | `couchbase/mcp-server-couchbase@df5d9c`: operational **28 read-only-bucket + 12 write-bucket** functions and insights **11 + 2**, for **53 server-qualified source candidates**. Every candidate has ToolSet declaration line, import line, function definition line and immutable blob. `tool_registration.py` prepares and filters; `core/app.py:104–115` uses `FunctionTool.from_function` then `mcp.add_tool`. | Read-only mode excludes write-bucket registration; disabled-tool, confirmation and auth-scope gates are runtime-dependent. Some read-only-bucket SQL/query functions can write, subject to their own runtime checks. No local Agent in provider-only scope; no `AGENT_CAN_CALL` proven. | **53/53 source candidates linked, active catalogue/effective authority unresolved.** |
| WAB-04 / `ff60-amazon-04` | `aws-samples/sample-multi-agent-region-expansion-planner@30d03d`: `src/main.py:52–60` builds `common_tools + agents`; **10 source-distinct Agent constructor sites** are individually pinned to immutable blob/line. | Nine specialist constructors are function-local and deferred; this is not proof of nine live delegated agents. `agents.__init__` exports `compare_regional_pricing`, not an equivalently named decorated `pricing_explorer` callable. Imports of unpinned third-party tools and `@latest` MCP processes cannot establish exact effects, permission, network destinations or unconditional `DELEGATES_TO`. | **10/10 source constructor sites preserved; runtime instances, wrapper invocation and delegated authority unresolved.** |

For WAB-01 the 22 source registrations are the exact source function name
universe, not a blanket *effective-authority* claim. For WAB-03 the 53
registrations count **server-qualified candidate edges** rather than 53
distinct deployed tools. `get_server_configuration_status` is deliberately
shared across both servers, while some names also belong to distinct
implementations; server-qualified identity must survive deduplication.

## Source and scan-stage reconciliation

- WAB-01 historic scanner: one bound MCP server, 22 unbound tools. Source
  supports a local script/declared registrations chain but not automatic
  production Graph `AGENT_CAN_CALL`. Current scanner shadow/prod parity for
  each of the 22 edges still needs artifact-level comparison.
- WAB-02 historic scanner: two MCP servers, zero statically discovered tools.
  The two names are source-declared **server endpoints**; zero scanner tools is
  not a confirmed empty remote catalogue. Keep UNKNOWN remote targets until
  runtime listings are supplied.
- WAB-03 historic scanner: seven unbound MCP server observations and zero
  tools. The two `ServerSpec` sets contain 53 conditional source candidates;
  the static evidence does not imply seven deployable servers or 53 callable
  registrations. Exact inventory-source-context stage reconciliation remains
  separately required.
- WAB-04 original Wave-A trace discovered ten Agent constructors; the
  historical name-only consolidation kept two and collapsed eight distinct
  constructor sites. Strands-specific source identity preservation now retains
  ten sites. Pinned draft #551/#578 Amazon holdout reports **10 constructor
  sites / 52 relationship records / 68 conditional findings / 0 potential
  paths**; **all 52 relationship records retain runtime-not-verified**.
  The recovered source site count is not proof of eight live agents or new
  verified vulnerabilities. Production/current-head finding identity parity
  and authoritatively negative source labels are not completed here.

## No authority inflation contract

`AGENT_BINDS_CLIENT`, `CLIENT_CONNECTS_TO_SERVER` and
`EXPOSES_TOOL` are different edge classes with separate evidence.

A source function declaration, a provider registration loop, an MCP manifest,
a client cataloguing call or an Agent constructor may be retained as
`observed_source`, `conditional_source_candidate` or `unresolved`.
**None of them alone may be emitted as verified `AGENT_CAN_CALL`, live
delegation, applied approval, granted identity or reachable destination.**
Absence of static tool names must be represented as *unresolved*, never
`proven_absent`, unless there is explicit exhaustive evidence of absence.

## Exit assessment and remaining blockers

**For these four pilots, named source-candidate records are enumerated and
assigned source-positive or explicitly unresolved status.** This satisfies the
*ledger-level classification* task, not a final scanner-accuracy release gate.

The strict #540 exit condition is **not yet signed off**: the ledger has not
been independently matched to all latest-main Graph/ADG output and negative
source universe per case; dynamic per-deployment facts cannot be recovered
from source alone. WAB-05 test/example/provider-only source partition is an
additional #540 obligation. The 12 historical unresolved Amazon effect/control
claim keys remain appropriately UNKNOWN without installed third-party package
version and runtime evidence. Review of all current finding/authority/path
deltas and blinded negative labels also remains outstanding. Historical model
review on 73 changed finding claim keys was **45 conditional, 16 invalid
historical anchors, 12 unresolved**, not independent TP/FP/FN truth.

**Decision:** #540 open, #551 draft, #543 Wave C production cutover NO-GO.
Preserve full latest-head CI, CodeQL, Fresh-16, Full-60, Wave-A-30 and unseen
holdout gates where applicable; no path-count floors or downgraded checks.
The new proof ledger itself changes no scanner Graph, findings or paths.
