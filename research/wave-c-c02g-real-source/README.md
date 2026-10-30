# Wave C C02g: first pinned source-review candidate, rw-004

This is a **source-visible, preliminary reviewer seed**, not an independently
blinded or semantically certified source-truth oracle. It is based on the
Frozen-180 archived source case `rw-004`, included in active-145, from
`JoanMarinPages/agentGemini` at exact commit
`0160690bb47cca17e70ceb8486209d7b1cacaf76`.

The JSON ledger `rw-004-source-candidates.json` records seven source syntax
anchors fetched at the exact Git revision using GitHub, with observed path,
Git blob ID and inclusive lines. The source role remains **unknown**.

Source-review questions worth adjudicating independently:

1. `agent.py:98` constructs `funnel_agent = LlmAgent(...)`, and
   `agent.py:124` assigns `root_agent = funnel_agent`. This is a
   same-file Python variable alias, **not another constructor**.
2. `agentGemini/agent.py:38` contains a **separate module-local**
   `root_agent = Agent(...)`. The identical symbol name in two different
   files is not sufficient evidence to merge their agent identities or
   that both are successfully deployed.
3. Both construction sites contain `tools=[...]` arguments. The
   presence of a list alone does not prove successful tool imports, effective
   runtime invocation authority, or MCP relationships.
4. `agentGemini/agent.py:67` declares
   `@root_agent.on_tool_call`, but the nearby callback body logs activity.
   It is **not** source proof of an approval or permission guardrail.
5. `agentGemini/tools/__init__.py:5` begins a relative import whose
   module and operational availability require source-tree resolution and
   separate runtime/context review.

## Evidence limits

The paths, blob identities and excerpts were read against the exact pinned
public GitHub revision, but the existing C02b local-checkout verifier has
**not** been run against a full local pinned checkout in this PR. No target
imports or code execution were attempted. This case is already exposed, so
it **must not** become part of the genuinely unseen D01 holdout.

There are no independent reviewer attestations, negative-universe completeness
claims, source-positive/negative semantic verdicts, certified precision/recall
scores, or authorization for production Graph/ADG/authority cutover. The
purpose is to prevent future reviewers from conflating constructors, aliases,
module namespaces and invocation permissions, and to seed an independently
reviewed, source-backed V2 adjudication workflow.

Keep all 12 unresolved Amazon third-party runtime/control claims UNKNOWN.
Preserve the immutable Frozen-180 and the active-145 non-LangGraph policy.
