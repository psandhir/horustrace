# Wave C C02l — rw-006 mode-sensitive ADK source evidence

This is a **third real Google ADK case** in the C02 source-first review set,
not scanner-derived truth. It studies a materially different class of agent
identity risk: factory-created vs static/dynamic sub-agent representations.

- Case: **rw-006** in immutable Frozen-180 and active-145 (LangGraph excluded).
- Repository: \`manojlds/adk-deepagents\`.
- Exact pinned commit: \`11a15d7c935061c50e1ef626df2445103b91c931\`.
- Artifact: \`rw-006-delegation-mode-candidates.json\`, **30** GitHub-read
  source-line witnesses across **5** precise Git blobs.
- Source role: **unknown**. Installed SDK, runnable deployment and target
  imports were not executed or verified.

## Source-mode discriminators

| Construct | Pinned source observation | Only legitimate interpretation |
|---|---|---|
| Default | \`types.py:231\` | \`DeepAgentConfig.delegation_mode\` defaults to \`"static"\` when caller does not override it |
| Static | \`graph.py:213–225\` | \`build_subagent_tools(...,include_general_purpose=True)\` is called only for \`static\` and \`both\` |
| Dynamic | \`graph.py:228–249\` | Register-subagent tool and dynamic-task tool added to *core tools* only in \`dynamic\` or \`both\`; not a list of already instantiated dynamic agents |
| Parent factory | \`graph.py:414,471,493,526–539\` | \`create_deep_agent()\` assembles \`core_tools + subagent_tools\`, returns one \`LlmAgent\` **when invoked**, not when its source is merely imported |
| General-purpose default | \`task.py:130–134\` | In static builder, default spec added unless an existing sanitized name matches; do **not** count duplicate default agents |
| Prebuilt vs constructor | \`task.py:141–169\` | \`AgentTool(agent=agent)\` wraps an existing agent; \`LlmAgent(...)\` creates from a spec then wraps it. Wrapper is not an extra agent |
| Dynamic agent factory | \`task_dynamic_execution.py:319–363\` | \`_build_spec_agent\` may return \`LlmAgent\` on a dynamic task path, but does not prove a task occurred |
| General-purpose prompt | \`graph.py:275–281\` | The general-purpose **description** is included even for dynamic-only mode; describing an agent to an LLM is not proof a static \`AgentTool\` exists |

The \`mode_candidates\` matrix is derived from pinned source branch
conditions; the record is explicitly provisional. In the dynamic-only
configuration the static builder does not run, even though a
\`general_purpose\` prompt description appears. Conversely, static mode
does not add the dynamic registration/task tools through the dynamic branch.
Neither condition proves runtime effective tool authority.

## Pinned Git blob witnesses

\`\`\`text
adk_deepagents/types.py                         7476bbad8eaf9b72e847614c902d59328b97a546
adk_deepagents/graph.py                         6016c01a60b4df00cf91a1df6ad73aabdf9fb0ee
adk_deepagents/tools/task.py                    03d9a3f35a3f3b2362f5276ada6ba066000407b1
adk_deepagents/tools/task_dynamic_execution.py  d0b6a5f333886f0e697aecbc6b93546a32e18ae2
adk_deepagents/tools/task_dynamic.py            32e1e8080336d2dfd58c6cebe969d02863e23b12
\`\`\`

The GitHub file service returned blob identifiers for these exact pinned
source paths, but **no full independent local C02b Git checkout replay** has
yet been performed. This work did not run the scanned repository, call the
model, inspect any scanner predictions or establish independent/blind source
labels. Hard-negative *questions* about false source instances are not an
adjudicated complete hard-negative universe.

## Decision and follow-on

Treat all candidates as **source syntax candidates** with source_role
\`unknown\`, never as certified runtime agent instances, executed
\`AGENT_CAN_CALL\` edges or effective-approval controls. Independent reviewers
must enumerate each source context in a complete positive/negative
construct universe, replay the exact source, compare to scanner results only
after source labels are frozen, and certify any real D01 unseen holdout
separately. Preserve Frozen-180, active145 exclusion, six numerical
thresholds, 12 Amazon UNKNOWN third-party runtime claims and C03/C04 NO-GO.
