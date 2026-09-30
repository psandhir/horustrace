# GPT ↔ HorusTrace differential — Batch 004

## Integrity

Batch selection was locked at `88159d680e6cf2e455077a6194d8865ce7f8809a`.
The source-only GPT review was locked at `c6ac4d468f7a4048e1a1265fcf04caf84a5c4c39` before scanner reveal.

Scanner reveal uses pinned Frozen-180 artifact `11058625749` from scanner SHA `6cff0bbab343dcfd9de9c7ecb7763f0d50423c06`.

## Result

- 5 fresh cases
- 2 GPT semantic findings
- 0 full matches / 0 partial / 2 misses
- 2/2 precision controls passed
- 1 GPT source-supported attack path / 0 HorusTrace paths
- 44 HorusTrace scanner-only findings concentrated in rw-042

## High-value result: rw-042 precision defect

The repository contains many LangGraph StateGraph workflows. HorusTrace promotes deterministic orchestration graphs to agent principals and, in at least zad18/zad23, treats workflow state as untrusted ingress into subprocess execution even though the graph is invoked from a fixed empty state. The top-level agent.py also constructs an LLM/tool graph but discards the compiled graph and routes REPL input through a manual command parser.

This creates a large false-positive/qualification problem and is the first repair target.

## Recall gaps

### rw-164 — Streamlit folder → server filesystem → RAG

An unauthenticated Streamlit user selects an arbitrary existing directory. The app recursively loads supported files under that directory into LanceDB, and user chat reaches a PydanticAI search tool that can return indexed file content. HorusTrace emits no equivalent finding or path.

### rw-138 — dynamic remote MCP without approval

The OpenAI Agents example can import an operator-configured remote MCP catalogue and expose the tools without per-call approval. The pinned entrypoint has a fixed prompt, so this is authority semantics rather than an untrusted attack path. HorusTrace emits no equivalent claim.

## Precision controls

rw-012 and rw-104 both pass: scoped/fixed-destination ADK authority and a read-only local MCP dataset loop remain quiet.

## Next build order

1. Deterministic LangGraph workflow vs model-agent qualification.
2. User-selected server directory → recursive file ingestion → RAG retrieval.
3. Dynamic remote MCP catalogue / approval semantics.
4. Targeted repaired-case + negative regressions, then Batch 005.

## Repair closure

The Batch-004 gaps were repaired as a single tranche before starting Batch 005:

- rw-042 deterministic LangGraph workflow qualification: PR #256.
- rw-164 user-selected server directory → recursive RAG retrieval: PR #257.
- rw-138 dynamic remote MCP catalogue without per-call approval: PR #258 (`AGT054`).

The comparison above remains the locked pre-repair scanner reveal. These follow-up PRs are recorded separately so the original differential result is not rewritten after remediation.
