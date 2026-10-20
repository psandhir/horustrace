# Wave C C02j — Pydantic AI source-configured tool sets, rw-149

Parent source-truth issue #606. This is a **third real source-pinned active145 case**
after Google ADK rw-004 and MCP-custom rw-080. It is not independent or
scanner-blind V2 truth; C03/C04 production remains NO-GO.

## Source and reproducibility

- \`rw-149\`: \`LeonieFreisinger/pydanticai-base-agent\`
- Exact archived revision \`0cf88a4caf2b5da29ff7af8364d4db14ac9e50b4\`
- Exact Git commit tree \`672f992626f1d06f45e8effcb0756059171c9a2c\`
- 22-entry complete, nontruncated Git tree; four Python source blobs and 37
  line-level source syntax witnesses read against the pinned revision.
- \`conditional-tool-source-candidates.json\` is a source-first review seed
  with no inferred runtime tool permissions, deployment role or true labels.
- No external scanned-target code or tools were executed. The C02b full
  offline pinned-Git checkout verification and independent reviewers remain
  outstanding.

## Conditional source-level registered tool symbols

\`agent/tools.py:408–433\` implements \`get_tools_for_level(level)\`:

| Selected level | Source-selected tool functions | Count |
| --- | --- | ---: |
| 1 | None, \`return []\` | 0 |
| 2 | \`list_tables\`, \`describe_table\` | 2 |
| 3 | Level 2 functions plus \`execute_query\`, \`get_current_date\`, \`get_stock_query_template\` | 5 |
| 4 | Same five functions as level 3 | 5 |

This describes **conditional source registration**, not observed runtime
callability or deployed identity. \`agent/agent.py:83\` selects the list,
passes \`tools=tools\` at line 99 to \`BaseAgent\`, then
\`agent/base_agent.py:131–135\` constructs the Pydantic AI \`Agent\`
and registers each selected source function with \`self._agent.tool(tool)\`.

The level is not known for a deployed agent: \`DEMO_LEVEL\` defaults to
\`4\` in source (\`agent/agent.py:35\`) but is environment-configurable;
the constructor also accepts an explicit \`demo_level\` override
(\`agent/agent.py:60–74\`). \`app.py:32–43\` calls \`SQLQueryAgent()\`
within a Chainlit start handler; source visibility does not prove it ran.

**Hard-negative review target:** Any rule inferring *all five* effective tool
permissions for level 1 or level 2 solely because five tool functions are
defined is wrong for the source registration branch. But the code's
level-dependent symbolic return values cannot by themselves prove source
ontology completeness, installed framework contract, actual import success,
database/credential access or run-time availability.

Level 4 uses instrumentation and retry features; these must not be promoted
to approval enforcement or least-privilege controls. No agent-to-MCP graph
edge is supported by this source alone.

## Tests and future adjudication

\`\`\`bash
pytest -q tests/test_wave_c_rw149_pydantic_tool_selection.py
\`\`\`

Tests cross-check the active145 archive ID/commit/framework, all 37 site
anchors against their pinned Git blob entries, the four selected source
sets and the \`BaseAgent\` registration chain, and guard every release
certification flag as false. They do not constitute independent reviewers
or an exhaustive positive/negative universe.

To score Pydantic agent/tool precision, collect source-first positive and
explicit hard-negative sites across all source roles, reconcile unknown
environment levels and installed SDK behavior, independently blind-adjudicate
the relevant candidate universe, and pair exact old/current scanner
predictions in C02e. These disclosed cases are not eligible as the new D01
blind holdout. Preserve Frozen-180 and six original numeric floors; #558's
protected-main administrator status enforcement remains required.
