# Agent-centric unseen 12 v3 — adjudicated result

## Executive result

This is the first untouched holdout after the merged post-LangGraph precision boundary work (#297) and bound-dynamic-authority work (#298).

- Scanner baseline: `c2c2a929f25356a8e0c76f66cb55ed76efa6cbc8`
- Workflow run: `37067753054`
- Cases completed: **12/12**
- Findings: **43**
- Attack paths: **5**
- Effective-authority relationships: **85**
- Materially supported findings (including qualified/partial): **28/43 = 65.1%**
- False-positive findings: **15/43 = 34.9%**
- Materially supported attack paths: **5/5**, all qualified rather than proof of exploitability

This is an improvement over unseen v2 (16/29 = 55.2% supported precision, 0/1 supported attack paths), but it is still below the product target and does not justify further case-by-case detector patching.

## Adjudication by case

| Case | Findings | Supported / qualified | FP | Attack paths | Notes |
|---|---:|---:|---:|---:|---|
| unseen3-adk-001 | 13 | 12 | 1 | 2/2 qualified | Real GCS/RAG mutation/destructive authority; prompt asks for confirmation but no hard callback/per-tool enforcement. NET002 loses fixed Google-provider destination. |
| unseen3-adk-002 | 8 | 6 | 2 | 0 | A2A auth/approval findings source-supported (loopback-qualified). NET002 incorrectly loses fixed localhost agent-card destinations. |
| unseen3-adk-003 | 4 | 3 | 1 | 0 | Real Firestore/read-write pipeline. NET001 treats operator-configured MCP base URL as arbitrary destination. |
| unseen3-adk-004 | 2 | 0 | 2 | 0 | Discovery Engine uses POST for a read/query operation to a fixed Google endpoint; HTTP verb is incorrectly promoted to external-write privilege. |
| unseen3-pyd-001 | 5 | 1 | 4 | 0 | CAP005 is descriptive and supported; write tools call `gate.arequire(...)` before mutation, so “no guardrail/approval” claims are false. |
| unseen3-pyd-002 | 0 | 0 | 0 | 0 | Registrar library accepts a caller-owned Agent; no concrete Agent instance exists in-repo. Treat as composition/control, not a scanner FN. |
| unseen3-pyd-003 | 0 | 0 | 0 | 0 | Relationships survive, but post-construction registrar tools collapse to generic `tool_fn` semantics; recall/authority-fidelity gap. |
| unseen3-pyd-004 | 0 | 0 | 0 | 0 | Source function returns a concrete Pydantic `Agent(...)`; scanner reports zero agents. Factory-return normalization gap. |
| unseen3-oai-001 | 0 | 0 | 0 | 0 | Two agents discovered, but function-parameter MCP binding yields zero authority relationships. Binding recall gap. |
| unseen3-oai-002 | 7 | 3 | 4 | 0 | Persistent memory write findings supported; pure arithmetic `add(a,b)` is incorrectly classified as state-changing by name. |
| unseen3-oai-003 | 4 | 3 | 1 | 3/3 qualified | Fixed Python script receives model-derived argv; paths are real source-to-process dependencies but not shell/command-selection proof. Destination finding loses operator-configured voice-service base URL. |
| unseen3-oai-004 | 0 | 0 | 0 | 0 | Two read/planning relationships; no source-visible high-confidence policy violation in the selected surface. |

## Systematic precision defects

### 1. HTTP method is being confused with authority semantics

A POST to a fixed search/query API is not necessarily an external write. In the ADK Space Hub case the agent calls Google Discovery Engine `streamAssist` with POST, but the operation is retrieval/querying. This promotes a read operation into `external.write`, which then triggers ADK001/AGT040.

**Invariant:** HTTP verb is transport evidence, not sufficient proof of mutation semantics. Endpoint/function semantics and response purpose must corroborate write authority.

### 2. Source-visible authorization guards are not represented as tool controls

The Typesec Pydantic tools call `await ctx.deps.gate.arequire(...)` immediately before graph mutation. HorusTrace correctly recognizes the write capability but reports the tools as having no guardrail.

**Invariant:** source-visible mandatory authorization/policy gates that dominate the side effect count as a guardrail/control even when they are not human approval.

### 3. Name hints still promote pure computation to persistent state change

OpenAI course examples define `add(a, b): return a + b`. The name `add` is enough to produce `data.write`, AGT022 and AGT040.

**Invariant:** generic mutation-like names (`add`, `set`, `update`) are hints only; persistent/external write authority requires body-side-effect evidence or a known mutating API.

## Remaining recall / authority-composition gaps

1. **Factory-return agents:** a function returning `Agent(...)` can still disappear (unseen3-pyd-004).
2. **Function-parameter MCP binding:** OpenAI Agents can bind `mcp_servers=[mcp_server]` inside a helper while the concrete server is supplied by a caller/context manager; the agent survives but the authority relationship disappears (unseen3-oai-001).
3. **Post-construction registrars:** `agent.tool_plain(tool_fn)` over dynamically constructed nested tools preserves a relationship but loses the concrete search/ingest semantics (unseen3-pyd-003).
4. **Flow/authority inconsistency:** PaperX static dataflow proves model-controlled inputs reach `subprocess.run`, while the corresponding effective-authority tool relationship has no process-execution capability. Flow and authority normalization should share effect semantics.
5. **Destination provenance:** fixed provider and operator-configured destinations are still lost through some global constants/f-strings/cross-file helpers despite #297.

## Product implication

The LangGraph removal continues to look directionally correct: the failures are now concentrated in authority semantics shared by the three supported frameworks rather than framework sprawl.

The next build should address these invariants as shared semantic layers, then use another genuinely unseen cohort. The v3 repositories are now consumed diagnostic data and must not be used for a new generalization claim.
