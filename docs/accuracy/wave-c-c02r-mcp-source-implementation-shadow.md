# Wave C C02r — recover local MCP implementation provenance in shadow

Parent: [Wave C #543](https://github.com/psandhir/horustrace/issues/543),
[Independent V2 #606](https://github.com/psandhir/horustrace/issues/606).
Depends conceptually on scanner-vs-judge differential
[#628](https://github.com/psandhir/horustrace/pull/628), but does not
enable a production C03 projection.

## Verified gap

The pinned `rw-080` `Amlan66/SSEEnabledMCPAgent@11531239e71b123f25b3c6103ee36a9d614d0032`
has **four** source FastMCP declarations. A source-first read-only adapter
diagnostic verified all four. The first three local stdio implementation
objects are removed from `graph.unbound_mcp_servers` by
`resolve_local_stdio_implementations()` in `mcp_context.py` once a
separate agent-bound client MCPServer resolves their local script. All 25
statically decorated tools remain in `graph.unbound_tools`, tagged
`bound_via_mcp`. The Telegram FastMCP implementation remains as an
unbound source server with three `EXPOSES_TOOL` ADG edges.

This distinction is **not** a claim of 17 live servers, model permissions,
false positives or false negatives. It explains why the current ADG misses
the source `mcp_server_1`/`mcp_server_2`/`mcp_server_3` constructor
sites and their source exposure relationships despite having detected
their tool symbols. Two of these sites have the same displayed server
name, `Calculator`, but distinct exact source paths.

## Shadow representation

`horustrace.mcp_source_implementation_shadow.project_bound_source_mcp_implementations`
takes an already-normalized scanner Graph and its scan root. It:

- Selects only **locally and uniquely source-resolved stdio implementations**
  supported by existing `implementation_path`, `implementation_line`,
  `implementation_name` and `discovered_tools` metadata.
- Assigns portable shadow source identities by **repository-relative path +
  exact line**. Multiple `Calculator` instances in different files remain
  separate.
- Separates a `mcp_client_configuration` node from a
  `mcp_source_implementation` node. A
  `CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION` source edge expresses
  source-level file correlation, not a successful MCP connection.
- Produces `EXPOSES_TOOL` only when one existing source MCP Tool matches
  the discovered entry by **exact source file, line and tool symbol**.
  A `@mcp.resource` non-tool, tool-name collision or missing source
  witness is not silently promoted.
- Marks every node/edge `source_only`, every callability as null/unknown,
  and certified precision/recall and production cutover as null/false.
- Does not modify the input Graph, production ADG node/edge counts, runtime
  scanner detection, findings or attack paths.

## Real pinned integration validation

A dedicated workflow runs the unchanged production scanner source-first
against the exact `rw-080` Git SHA. It checks four source-constructor Git
blobs and pinned lines and asserts:

- The *shadow* contains **3 distinct source FastMCP implementation nodes**
  for local stdio: `mcp_server_1.py`, `mcp_server_2.py`,
  `mcp_server_3.py`; the separate Telegram source server remains in the
  existing production ADG and is not duplicated in this projection.
- The *shadow* expresses **25 source EXPOSES_TOOL relationships**
  originating in those three files, and three client-config-to-implementation
  source correlations. These are original decorator declarations, not a
  discovered runtime tool catalogue.
- The existing Graph/ADG and all rule, policy, finding, path and authority
  decisions stay unchanged. Exact-source evidence and shadow JSON are
  retained as Actions artifacts.

Run with a pinned, clean source checkout:

```bash
python -m scripts.wave_c_c02r_pinned_mcp_shadow_study \
  --checkout /path/to/SSEEnabledMCPAgent-at-the-exact-SHA \
  --output /tmp/rw080-source-shadow
```

The workflow and tests are a **shadow-stage engineering acceptance** only.
Before any production use or UX cutover: externally verified source-positive
AND exhaustive hard-negative V2 ontology review, a genuinely unseen D01,
actual runtime control/connection evidence or bounded UNKNOWNs, comparable
source-role strata and manual latest-head Fresh16/Full60 plus required accuracy
gate enforcement by repository administrator [#558](https://github.com/psandhir/horustrace/issues/558).
Do not alter Frozen180, active145 non-LangGraph exclusion or the 12 unresolved
Amazon tool-authority claims. **C03/C04 production GO remains blocked.**
