# GPT ↔ HorusTrace differential — Batch 003

## Integrity

Batch selection was locked before source review. The source-only GPT review was locked at `1adf51eb69b54de8060bef4039bce61060e039fb` before scanner reveal.

Scanner reveal uses the post-#248 Frozen-180 artifact from `6cff0bbab343dcfd9de9c7ecb7763f0d50423c06` (workflow `36620578672`, artifact `11058625749`).

## Result

Five fresh cases cover Google ADK, LangGraph + MCP, custom MCP, OpenAI Agents and Pydantic AI.

- GPT semantic findings: **4**
- full semantic matches: **0**
- partial semantic matches: **2**
- GPT findings with no equivalent HorusTrace claim: **2**
- precision controls: **1/1 passed**
- GPT source-supported attack paths: **3**
- HorusTrace attack paths: **0**

The scanner generally discovers the principals and tool bindings. The residual gap is semantic composition rather than basic discovery.

## Strong precision result

### rw-084 — authenticated Redmine MCP remains read-only

The custom MCP agent accepts CLI input and has authenticated Redmine access, but its effective model-callable catalogue contains only read operations against a configured Redmine base URL. HorusTrace emits no security findings or attack paths, matching source.

## Gaps

### P0 — rw-007 model-selected local file → external Document AI

HorusTrace discovers the ADK agent and both tools but misses that the model can select a local file path outside the intended sample directory, the tool opens that path, and the bytes are submitted to Google Document AI. Missing primitives: model-selected path provenance, filesystem containment, and file-read → external-service composition.

### P0 — rw-131 filesystem containment + indirect untrusted source

HorusTrace emits generic AGT022/AGT040/CAP005 authority findings. It does not preserve the intended path boundaries for SCAN_DIR/REPORT_PATH, nor treat repository source returned through a tool as indirect untrusted model input that can influence later path-bearing tool calls.

### P0 — rw-150 authenticated user URL → server-side fetch

HorusTrace emits NET002 but no attack path. Source proves authenticated Streamlit input reaches the Pydantic agent, which can invoke `fetch_curriculum(url)`; the tool performs `httpx.get(url)` with redirects and no destination restriction.

### P1 — rw-049 Firecrawl URL authority

The agent receives Firecrawl MCP tools that accept arbitrary URL or URL-list parameters without an allowlist. HorusTrace discovers the MCP/tool surface but does not express that destination authority. The pinned entrypoint has no untrusted ingress, so this is authority semantics rather than a proven attack path.

## Next build order

1. Model-selected filesystem path + containment semantics, including file-read → external-service composition.
2. User/model URL provenance → server-side HTTP destination and attack-path composition.
3. Indirect untrusted content from tool/repository results → model context.
4. MCP tool URL-parameter destination authority without requiring untrusted ingress.
