# GPT ↔ HorusTrace differential — Batch 002

## Integrity

Selection was locked before source review at `70f0c4a93fd85f2b1199079eb571a46493f42d2e`.
The source-only GPT review was locked before scanner reveal at `91539e908c0b246fe9198e36e49e1d9a20fd8dbd`.

Scanner reveal uses the post-#244 Frozen-180 artifact from `cc167bb4a5236ce6b25c66a8fdc24190670ea226` (workflow `36595899208`, artifact `11046496598`).

## Result

Six fresh cases covered FastAgent, Google ADK, LangGraph, custom MCP, OpenAI Agents and Pydantic AI.

- GPT semantic findings: **4**
- full semantic matches: **0**
- partial matches: **2**
- GPT findings with no equivalent HorusTrace claim: **2**
- precision controls: **2/2 passed**
- GPT source chains: **4**
- HorusTrace attack paths: **0**

The raw finding count is not a precision/recall metric; the comparison is semantic and source-adjudicated.

## Strong precision results

### rw-041 — LangGraph provider-mediated search

HorusTrace correctly keeps DuckDuckGo/Hugging Face read/search authority clean rather than treating provider-mediated query parameters as arbitrary destination control.

### rw-076 — connected MCP is not effective authority

This is the strongest precision result in the batch. The application starts a destructive filesystem MCP and lists its tools, but never gives those tools to the model or dispatches model output to them. HorusTrace reports structural MCP/tool visibility with **zero agent authority/findings**, matching source.

## Gaps

### P0 — rw-116 Flask ingress composition

HorusTrace reconstructs Barney's persistent Firestore write authority (AGT022/AGT040/CAP005) but reports no path from the public Flask chat endpoint.

The missing reusable primitives are:

1. Flask `@app.route` recognition;
2. taint seeded from Flask's global `request` object rather than handler parameters;
3. wrapper-factory resolution: `get_chat_agent() -> FormChatAgent -> inner OpenAI Agent`;
4. wrapper runtime method propagation through `process_message(...)`.

This should be the next build.

### P1 — rw-004 runtime viability

The scanner correctly sees declared ADK privileged authority but does not qualify that the pinned entrypoints are import-blocked by missing tool modules. Static authority and runtime viability need to remain separate dimensions.

### P1 — rw-147 second-order network destination

A model-selected research angle drives DuckDuckGo search; returned result URLs then flow to `requests.get(url)` without an allowlist. This is weaker than direct arbitrary URL control but broader than a fixed provider endpoint. HorusTrace currently emits no network finding.

### P2 — rw-003 generated FastAgent MCP config

Source can generate four semantic MCP aliases that all point at one broad mutating server implementation, but the active config is absent from the pinned tree and runtime reload is uncertain. Treat as conditional until live loading can be source-proven.

## Next build order

1. Flask/global-request + wrapper-factory runtime ingress.
2. Runtime viability/import-blocker qualification.
3. Search-result-derived destination provenance.
4. Runtime-generated FastAgent MCP binding when source proves the generated config is consumed.

After each change, rerun Batch 002 precision controls and Frozen-180 gates.
