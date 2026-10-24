# Wave C C02p — cross-framework LLM source judge

Extends merged [C02o #626](https://github.com/psandhir/horustrace/pull/626)
without changing scanner detections, authority decisions or release gates.

## Source packet compatibility

The offline `horustrace.source_truth_llm_judge` now accepts all three
versioned, immutable source ledger shapes already merged:

- `rw-006`, Google ADK, source `kind`, `line_start`/`line_end`
  and `source_expression`. Existing C02o sample and regression tests
  remain unchanged.
- `rw-080`, MCP, `line`, `source_expression`,
  `source_only_candidate=true`, and
  `scanner_predictions_consulted=false`. The unchanged 47 original
  Git blob/line observations become 47 source-only candidate packet rows.
- `rw-149`, Pydantic AI, `line`, `expression`,
  `source_syntax_only=true`, with no scanner-prediction flag in this
  pre-existing archive. All **37** observations must explicitly mark
  `source_syntax_only`; this is an archive data-contract eligibility rule,
  not proof that reviewer blindness is independently verified.

The converter does not enrich source evidence or infer missing line content.
A conflicting `line` versus `line_start`, conflicting excerpt, invalid
Git blob SHA, missing source-only declaration, or any exposed scanner
predictions fails closed. The emitted packet strips source-review hints,
scanner results and previous model opinions. Positive/negative universes
always remain incomplete unless a **separate independent** process proves
otherwise.

## MCP case model judge, exact pinned Git evidence

- Case `rw-080`: `Amlan66/SSEEnabledMCPAgent`
  at `11531239e71b123f25b3c6103ee36a9d614d0032`.
- Original archived ledger Git blob:
  `f950abc4d38fffdf5537861459c0ff9b0fccc2c1`.
- **28** unblinded source-only ChatGPT model opinions:
  **16 source positives**, **8 selected hard negatives**, and
  **4 effective-authority UNKNOWN**. These are **not TP/FP/FN/TN**.
- Source-visible facts from eight pinned blobs: four distinct FastMCP
  constructor sites, `MultiMCP(server_configs=...)`, configured stdio
  and SSE transports, source-declared tool decorators, dynamic
  `ClientSession.list_tools`, dictionary `self.tool_map[tool.name]`,
  source AgentLoop constructor sites, and MCP dispatch call.

Important hard negatives and unknowns:

- `mcp_server_1.py` and `mcp_server_2.py` both name their FastMCP
  object `Calculator`, but source-file identity is distinct.
  **Do not merge the two servers solely by display name.**
- A server-side `@mcp.tool()` is **EXPOSES_TOOL source intent**, not
  verified `AGENT_CAN_CALL` or effective authority.
  `@mcp.resource` is not a tool-export decorator.
- A `list_tools` source expression is not a complete remote tool
  catalogue. Tool-map keyed by unqualified tool names **could** overwrite
  collisions if two servers return identical tool names; collisions
  are not demonstrated by the source alone.
- `AgentLoop` source constructors and dispatch branches do not
  prove live sessions or successful tool calls.
- Actual connected stdio/SSE servers, returned remote catalogue,
  duplicate-name collisions, runtime SDK compatibility,
  and effective tool permissions are **UNKNOWN**, not negative.

## Replay

```bash
python -m horustrace.source_truth_llm_judge prepare \
 --ledger research/wave-c-c02i-rw080/mcp-source-candidates.json \
 > /tmp/rw080-mcp-packet.json

python -m horustrace.source_truth_llm_judge adjudicate-ledger \
 --ledger research/wave-c-c02i-rw080/mcp-source-candidates.json \
 --opinions research/wave-c-c02p-mcp-judge/rw-080-model-opinions.json \
 > /tmp/rw080-mcp-provisional.json

python -m horustrace.source_truth_llm_judge prepare \
 --ledger research/wave-c-c02j-rw149/conditional-tool-source-candidates.json \
 > /tmp/rw149-pydantic-packet.json
```

No external LLM/API calls, target imports, code execution, runtime MCP
enumeration, new unseen D01 holdout or manual source-truth
certification took place. The rw080 and rw149 cases were previously exposed;
they cannot be relabelled as truly blinded holdouts. All source opinions
are an unblinded single model review; model self-consistency is not a
substitute for complete source positives and explicit hard-negative
universes with external reviewer attestation. The reference remains
`review_method=model_reviewed` with `scanner_blind=false` and
`certified_precision/recall=null` (where applicable).

The next actual **accuracy** milestone still requires mapping current
scanner predictions to these exact source claim identities, replaying
full pinned Git witness/source role/installed runtime where needed,
adjudicating disagreements, and comparing frozen Old vs Current with
methodologically complete source universes. Preserve Frozen180,
active145 LangGraph exclusion, Amazon12 UNKNOWNs and #558 administrator
branch accuracy-gate requirement. C03/C04 production authority
cutover remains **NO-GO**.
