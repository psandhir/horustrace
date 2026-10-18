# Wave B: rw-003 conditional FastAgent agent/workflow node ontology

**Target:** `angrysky56/ai_writers_workshop@c160a299706dd0cd1dc9ae114b97aba905e9261d`,
file `mcp_server/components/fast_agent_integration.py` (Git blob
`6e092dc8083c45b99b4908125c181bd88637eeaf`).

The merged #586 current/historic 145-case source-witness artifact (current
scanner at `4880625c`) described **10 FastAgent agent-kind source nodes**:
eight `@fast.agent` decorators at lines 56, 65, 76, 87, 97, 107,
119, 138; plus `@fast.chain` at line 153 and
`@fast.evaluator_optimizer` at line 169, both counted as agents.

These last two are **composite workflow declarations, not distinct individual
model agents**. The original 180 truth for `rw-003` labels ten source
constructs as agents but explicitly marks agent/tool/MCP/delegation source
coverage INCOMPLETE. It was an earlier ontology, not independent, exhaustive
V2 ground truth. The 8/2 correction must **not** be scored as two old-study
false negatives or automatic new-study precision improvement.

## Bounded production correction

- `Graph.workflow_nodes` holds source-qualified `WorkflowDeclaration`
  objects independently of `Graph.agents`. Classifier treats only
  `chain` and `evaluator_optimizer` decorators as workflow-only.
  Router, parallel, orchestrator and other decorator semantics remain
  unchanged until separate source adjudication.
- FastAgent `@fast.chain` and `@fast.evaluator_optimizer` source
  declarations contribute **ADG `workflow_node` entities**, not ordinary
  `agent` nodes, and `WORKFLOW_FLOWS_TO` edges to uniquely resolved
  source agent participants, never an `AGENT_CAN_CALL` permission or
  effective authority claim. Unknown/ambiguous workflow members are not
  invented as agents.
- Workflow sources are conditionally registered under
  `FAST_AGENT_AVAILABLE and fast` in this pinned case. Nothing proves
  that `mcp_agent` was installed, registered or invoked in a deployed
  session. All workflow runtime-effectiveness fields stay `not_verified`.
- Local `FastAgentScript`/`AgentSession` abstractions from
  `mcp_server/fastagent_integration/fastagent_tools.py` and the
  `FastMCP` server in `mcp_server/server.py` do not automatically
  imply separately instantiated FastAgent LLM agents or available MCP
  tool permissions. These source roles need their own evidence.

`.github/workflows/wave-b540-rw003-fastagent-ontology.yml` checks the
exact SHA and blob (never imports/executes target dependencies) and requires
**8 agent declaration sites + 2 workflow declaration sites**. New hard
negative tests preserve arbitrary/unknown workflow member ambiguity and
existing routed/parallel behavior. Full original Fresh16/Full60, CodeQL,
Python 3.11/3.12 and same-head accuracy remain mandatory for this product
change, with thresholds unchanged.

**Scope and decision:** this is a post-hoc bounded source-backed ontology
correction, *not* independent whole-cohort V2 precision/recall or proof of
deployed workflow reachability. `rw-003` original reference stays
INCOMPLETE. Wave B NO-GO and Wave C cutover BLOCKED pending the
remaining 89-incomplete reference coverage, 12 unverified third-party
runtime effects and #558 required branch protection.
