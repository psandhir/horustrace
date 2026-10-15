# Wave B02/B03 — bounded dynamic MCP source evidence

This opt-in shadow sidecar extends canonical SemanticDiscovery v2 with
source_native_dynamic. It **does not modify** the production Graph, findings,
ADG, effective authority or attack paths. It does not import/execute target code,
call remote endpoints, inspect credentials, or enumerate live tool catalogues.

## Source-supported shapes

- **Provider-side FastMCP factory:** From fastmcp import FastMCP plus
  from fastmcp.tools import FunctionTool, a unique returned server local to a
  function, and a direct for tool in tools loop wrapping each parameter
  with FunctionTool.from_function(tool) and mcp.add_tool(tool_obj).
  Output contains one MCP server and one **unresolved** selected-tool catalogue
  for the source factory, with a PARTIAL CONTAINS registration-flow edge.
  This shape occurs in couchbase/mcp-server-couchbase, pinned
  df5d9ceb013f57143171f65ec3ba033ace06aa9a, at
  src/cb_mcp/core/app.py:102–117. This proves the registration *mechanism*,
  not the set of tools actually selected. read_only_mode, disabled tools,
  per-user scopes and provider/runtime configuration determine the final
  catalogue. Until those conditions can be source-linked and adjudicated,
  do **not** emit per-tool EXPOSES_TOOL or AGENT_CAN_CALL edges.

- **Remote .NET MCP client:** a source-visible McpClient.CreateAsync,
  HttpClientTransport, and client.ListToolsAsync call with
  using ModelContextProtocol.Client. A per-source MCP client points to an
  **unresolved remote catalogue** through an UNRESOLVED DISPATCHES_TO.
  This occurs in qmatteoq/agent365-demos, pinned
  937f8c12421b6eebfbff764dbafbdbe13cc72f68, in
  dotnet-agent-no-teams/Agent365/WorkIqToolProvider.cs.
  Token exchange and a manifest-derived server URL are not static proof of
  a returned set of tool names, approval controls or tool availability.
  Runtime enumeration is deliberately **not** reported as zero tools.

The source facts above are reviewer-visible diagnostic anchors, **not blind
independent adjudication** or accuracy/recall gains. The engine is bounded by
source counts/bytes and rejects shadowed imported Python constructors,
unrelated factory/server methods, absent return paths, and C# comments.

## Next gates

1. Independently verify the two pinned blobs and negative fixtures.
2. Extend host-configuration and cross-module symbol linkage to expose only
   tools whose registration is statically established for the selected mode.
3. Compare before/after claim identity, unresolved status and stage deltas on
   the exact pinned cases. Do not declare zero FNs from unresolved catalogues.
4. Run current-head CI, CodeQL, Fresh-16 and Full-60; then proceed to WAB-04
   Strands agent-instance and @tool wrapper reconciliation.
