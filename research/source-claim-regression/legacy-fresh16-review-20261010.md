# Fresh-16 original-claim reconciliation — 10 October 2026

## Scope and evidence

This is a claim-level audit of the original October 2 Fresh-16 (76 findings) against the October 10 merged P0/P1 rerun (49 findings), excluding LangGraph cohort cases. The machine-readable ledger in `legacy-fresh16-adjudication-20261010.json` contains **all 32 exact source-identity unmatched claims**, with their original source-relative file and line, historical verdict, and review state. The original source-adjudication CSV was single-reviewer and is **not ground truth**. Historical 76→49 is a net count, not a direct false-negative count.

| Previously adjudicated category | Claims missing at exact identity | Required action |
|---|---:|---|
| False positive | 16 | Preserve absence unless source evidence changes |
| Partial | 14 | Validate narrowed scope independently, avoid count restoration |
| True positive | 2 | Recover correct source binding or explicitly scope as unbound |
| **Total** | **32** | |

The mismatch includes claims whose source location / agent relationship moved. There are five nonidentical new claims; the net loss is 27.

## Two historical true-positive claims

- **`gen-oai-003`, old NET001 `client.py:25`**: source proves `sse_client(url=server_url)` then `ClientSession`, `list_tools` and model-selected `call_tool` in one custom loop. The October 10 scan now binds that dynamic MCP session to `m_c_p_client` and emits a more accurately attributed NET001. **Recovered with stronger provenance**, not an outstanding missing agent authority.
- **`gen-mcp-001`, old AGT032 `.mcp.json:1`**: repo/IDE Greptile configuration declares HTTPS and an environment-supplied authorization placeholder, without an explicit tool allowlist. The declaration was unbound to a runtime agent. **Inventory/configuration gap requires policy scoping**; historical true-positive rating is not sufficient evidence of *effective agent* authority. Do not reinstate an agent-risk finding without an agent relationship. The old AGT051 embedded-secret alert is correctly excluded because `Bearer ${GREPTILE_API_KEY}` is a variable reference, not a literal credential.

## Partial-claim adjudication queue (14)

| Cases and original indices | Prior claim(s) | Investigation status |
|---|---|---|
| `gen-adk-003:7` | NET001 on an agent calling package/version checks | **Source-specific destination review:** fixed PyPI/Maven hosts should not be described as model-selected destinations |
| `gen-mcp-003:0,1,2,3` | NET001 ×2; AGT032 ×2 | **Test/operator configuration:** locations are `tests/integration/conftest.py:160,184`; verify inventory applicability independently, not as agent reachability |
| `gen-oai-004:4,5,10,11` | AGT022 ×2; AGT040 ×2 | **Run-context mutation:** `Seat Booking Agent` writes `context.context.seat_number` in example code, not a source-proven external airline write. Context mutation remains a semantic effect |
| `gen-oai-004:12,13,16,17` | AGT040 ×2; CAP005 ×2 | **Delegation/source-context:** `Triage Agent` handoff exists in example source; verify inventory/delegation without promoting sample-only or run-context effects to external authority |
| `gen-pyd-002:15` | NET002 | **Test-only context:** `examples/testing_examples/test_agent_patterns.py:38` is not enough to assert live unconstrained outbound egress |

Other Pydantic `gen-pyd-002:0,1,6,12,13,14` were historically adjudicated false positives from capability/source-scope inference; these should not be restored by default.

**Decision discipline:** unresolved partial claims are not yet recorded as approved `scope_narrowed` or `corrected_false_positive` dispositions in the enforced reference. A source-pack excerpt may be truncated; inspect full pinned source when a claim needs code-level adjudication. The claim-level gate from P0 protects *current* reported claims independently.

## Evidence and next verification

- Run the enforced postmerge Fresh-16 gate after P1 classifier changes. A count reduction should require a case/index-scoped source-backed decision.
- Inspect real **runtime** agent invocation and effective authority for the test/example claims before classifying them as false negatives.
- For Greptile IDE-only MCP configuration, consider an optional *configuration hygiene* observation, clearly separated from effective agent control findings. Never equate no explicit allowlist in a configuration snippet with proven unrestricted runtime tool access.

No security findings, attack paths or severity thresholds are modified by this audit.
