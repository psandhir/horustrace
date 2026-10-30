# Wave B01 — source-native Pydantic local MCP pilot

Scope: opt-in, Python source **AST only**, no import, network call, target execution
or runtime tool enumeration. It extends the canonical `semantic_discovery`
v2 seam merged in #541. Run:

```sh
horustrace scan ./checkout --shadow-observation-output /tmp/semantic-shadow.json
```

The sidecar retains the existing `entities` / `bindings` from legacy Graph
projection and now includes a separate `source_native` v2 discovery. Its
source-native proof chain is:

- An explicit `from pydantic_ai import Agent` constructor whose
  `mcp_servers=` list is statically resolvable.
- A `from pydantic_ai.mcp import MCPServerStdio` with literal
  `python ["mcp_server.py"]`, bound from that Agent.
- A local script within the declaring source directory, containing exactly
  one identifiable FastMCP object that registers `@mcp.tool()` functions.
- `AGENT_BINDS_CLIENT`, `CLIENT_CONNECTS_TO_SERVER` and
  `EXPOSES_TOOL` edges with line-specific source evidence. **None** is
  `AGENT_CAN_CALL`, an effective permission, a runtime-observed invocation,
  or an attack-path finding.

A missing local script, dynamic argv, nondecorated registration, multiple
FastMCP objects, unrelated decorators, traversal outside the scan root,
server-only inventory and unsupported aliases must never be promoted to
agent-callable authority. Dynamic tool registration is explicitly outside this
pilot and needs the B02/B03 source-symbol/factory linker. The current pilot
does not attempt all Pydantic styles or remote MCP client catalogs.

**Reference:** pinned `newsbubbles/pharmiq@c69949739647a47ec8339b473bdf578c8cf8bfd9`
uses `agent.py:53–73` and `mcp_server.py` decorated registrations,
as originally recorded in Wave A. A test-repository fixture exercises the
same source shape without executing the external repository. The original
Wave A ledger was authored source-visible and is **not independent blind
ground truth**. Exact repository reruns and independent per-tool adjudication
are required before claiming fixed recall.

**Quality gate:** Normal scan Graph/findings remain identical with the optional
sidecar enabled or disabled. CLI and v2 contracts remain backwards compatible.
The native source registry is source-scope only. No production linker cutover
until independent source-backed before/after edge precision/recall and
ambiguous/negative cases have been reviewed.
