# Wave C C02h — real pinned rw-004 source tree/import closure

Parent #606. Extends the source-only seven-observation C02g PR #614 with
**four pinned Python modules and a complete commit-specific Git tree**.
This is actual source evidence, **not** model-as-judge truth.

## Exact Git evidence

- Active non-LangGraph source case: \`rw-004\`
- Repository: \`JoanMarinPages/agentGemini\`
- Archived commit: \`0160690bb47cca17e70ceb8486209d7b1cacaf76\`
- Commit's Git tree: \`002a3a94c6d6652c185cfbe73911aaccc633a0d0\`
- Full recursive tree at that revision: 41 entries; GitHub \`truncated=false\`
- Four observed source blob SHA-1 values and 14 exact relative-import
  anchor lines in \`relative-import-anchors.json\`; the full tree is frozen
  in \`pinned-source-tree.json\`.

The offline import-closure evaluator uses **only the complete source tree**
and the source-anchored import sites; it never runs the scanned project,
installs its dependencies, executes its tools, accesses credentials or assumes
network/runtime availability.

## Source facts observed

| Source paths | Exact pinned Git tree resolution | Count |
| --- | --- | ---: |
| \`agentGemini/config.py\`, \`agentGemini/models.py\`, \`agentGemini/prompts.py\`, \`agentGemini/tools/conversion_tools.py\`, \`agentGemini/services/firestore_service.py\` and repeat imports | Tracked Python module | 7 |
| \`agentGemini/tools/__init__.py\` | Tracked package initializer | 1 |
| \`tools/\` for root-level \`agent.py:8\` | Directory, but no tracked \`tools/__init__.py\` or module implementation of the requested symbol | 1 |
| \`prompt.py\`, \`agentGemini/tools/customer_tools.py\`, \`catalog_tools.py\`, \`cart_tools.py\`, \`agentGemini/services/email_service.py\` | No tracked matching Python module in this complete commit tree | 5 |

This is a **source-tree closure mismatch**, not a claim that imports actually
failed at runtime. Editable installs, environment-specific imports,
dynamically provided modules, partial deployment/source-role context and
unverified SDK versions could affect actual availability. Source absence
must not automatically become \`runtime_import_available=false\` or a
semantic source-negative label. It does motivate checking the declared
agent-tool chain before claiming \`AGENT_CAN_CALL\`.

The C02g constructor/callback observations remain unreviewed: two distinct
file-local constructor expressions do not prove two deployed instances;
\`tools=[...]\` is not a proven usable tool catalogue; logging callbacks
are not approval enforcement.

## Offline replay

\`\`\`bash
python -m horustrace.source_truth_imports \
  --tree research/wave-c-c02h-rw004/pinned-source-tree.json \
  --imports research/wave-c-c02h-rw004/relative-import-anchors.json \
  > /tmp/rw004-import-closure.json
\`\`\`

With a **full local checkout at the exact HEAD** of the pinned commit,
optionally add \`--checkout /path/to/pinned/repo\`. That enforces the
source blob actually exists in the pinned tree and checks the exact import
text at every claimed line; wrong HEAD, blob, line or import fail closed.
No such local checkout is available in the committed evidence: until it
is independently replayed, \`local_git_source_lines_verified=false\`.
The captured source lines and tree were separately obtained via connected
GitHub files/tree APIs, but the local C02b verifier was not run.

The evaluator rejects truncated source trees before making absence claims,
wrong source SHA, duplicate/malformed tree entries, invalid imports and
manifest/commit drift. Tests include synthetic *real local Git* fixture
checkout verification as well as the immutable rw-004 tree ledger.

## What this does not complete

- **No independent blind source review or certified negative universe**
- **No runtime tool resolution, callable edges, effective authority or path**
- **No D01 unseen holdout** — rw-004 was already exposed and is in active145
- **No certified precision or recall**, no production cutover permission
- #558 administrator-enforced same-head accuracy status remains required
- 12 unresolved Amazon third-party runtime/approval claims remain UNKNOWN

**Next:** independently adjudicate these exact source observations against
the declared runtime/example contexts, check the installed SDK contracts
and partial external/imported modules, then extend the same protocol
across ADK/MCP/Strands/Pydantic source strata with explicit positive and
hard-negative completeness. Keep original Frozen-180 archive unchanged.
