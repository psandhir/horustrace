# Wave C C02i — source-first MCP and agent binding candidate: rw-080

Parent #606; alongside C02h rw-004 import evidence #615.
This is a **second real pinned source cohort case**, rather than another
synthetic scanner fixture.

- Case: \`rw-080\`, within active-145 non-LangGraph MCP-custom stratum.
- Repository: \`Amlan66/SSEEnabledMCPAgent\`
- Source Git commit: \`11531239e71b123f25b3c6103ee36a9d614d0032\`
- Commit tree: \`e93ba494131547f45f2b975fa99dd9121702fee0\`.
- GitHub source tree: 27 nontruncated entries, archived as
  \`pinned-source-tree.json\`.
- Source candidate evidence: 47 exact line excerpts from eight source blobs,
  each anchored to its pinned Git blob SHA in
  \`mcp-source-candidates.json\`. Read from source-first GitHub
  blob/file APIs; **not reverified with local C02b Git checkouts**.
- No model or target agent/MCP code was executed.

## Grounded source distinctions

| Boundary | Source observation | Must NOT claim |
| --- | --- | --- |
| Configuration | \`config/profiles.yaml:27–42\` declares three stdio scripts and one SSE endpoint. | That all servers are deployed, connected or serving their catalogues. The stdio cwd values are environment-specific. |
| Instance identity | \`mcp_server_1.py:33\` and \`mcp_server_2.py:28\` each instantiate \`FastMCP("Calculator")\`. | One merged MCP server purely because the display name is identical. |
| Source exports | Each of four server Python files has at least one \`@mcp.tool()\` site. | That a given tool is bound to the application agent, available in the runtime registry, or permitted to execute. |
| Client initialization | \`agent.py:66–68\` constructs \`MultiMCP\` from YAML and initializes it. | A successful connection or static list of runtime available tools. |
| Dynamic enumeration | \`core/session.py:81\` and \`:111\` call \`session.list_tools()\` after opening SSE/stdio sessions. | That the returned tool names and tool schemas can be determined from the source alone. |
| Tool mapping | \`core/session.py:84\` and \`:114\` write \`self.tool_map[tool.name]\`. | That duplicate runtime tool names cannot override previous entries; actual collisions have not been observed. |
| Agent loop | \`agent.py:100\` and \`:128\` construct \`AgentLoop\` in different branches, and \`core/loop.py:17\` retrieves discovered tools. | Two simultaneously deployed agents or a verified effective call edge. |
| Dispatch | \`core/loop.py:121\` calls the dispatcher, and \`core/session.py:124–148\` routes by dynamic mapping and transport. | A source-certified \`AGENT_CAN_CALL\` per concrete MCP-exported tool. |

A source graph may represent the observed configuration and candidate
client/server and export links, but **\`EXPOSES_TOOL\` does not imply
\`AGENT_CAN_CALL\`**. The app uses runtime MCP enumeration and a name-keyed
map; there is no complete source-only proof of which tools are actually
available after initialization. Shared display names and conditional
CLI/Telegram constructors must remain distinct source identities until
context and installed-runtime evidence resolve them.

## Replay/checklist

Source manifest and tests pin the 27-entry tree, the eight Git blobs,
the four declared configs, the different MCP source declaration sites,
the conditional AgentLoop constructor sites, the call dispatch and runtime
enumeration anchor lines.

\`\`\`bash
pytest -q tests/test_wave_c_rw080_mcp_source_candidates.py
\`\`\`

To move toward an actual C02 independently adjudicated reference, acquire
an exact full pinned checkout, inspect relevant framework/installed MCP SDK
versions, enumerate positive **and** hard-negative source sites in explicit
runtime/test/provider roles, get independently blinded reviewer agreement,
and keep unresolved runtime-only facts UNKNOWN. D01 must use *new* unseen
cases, not rw-080 or previously disclosed Amazon-10.

This dossier explicitly contains no trusted source-truth positive/negative
labels, independently verified source review, runtime MCP enumeration,
certified precision/recall or production Graph/authority/finding/path cutover
permission. #558's administrator-required accuracy gate is still open;
Frozen-180 and the active non-LangGraph cohort remain unchanged.
