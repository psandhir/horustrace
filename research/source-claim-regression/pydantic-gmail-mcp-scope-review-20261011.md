# P1a source-scope review: Pydantic Gmail and unbound MCP configuration

Date: 2026-10-11. Basis: pinned Fresh16 source bundles from run
[38177972382](https://github.com/psandhir/horustrace/actions/runs/38177972382);
scanner commit `268978d994578643315f83efc740496d902b2051`.
This is an **informed single-pass source inspection of scanner-visible claims**,
not scanner-blind ground truth or proof of runtime exploitation.

## gen-pyd-002: newly generated findings

The post-merge run reports twelve findings. Among the three new source-identity
claims, the following source effects must be distinguished:

| Source / scanner claim | Pinned-source observation | Adjudication and product action |
|---|---|---|
| `agents/email_agent.py:57`, `AGT022` on `authenticate_gmail` | Agent-bound tool delegates to `tools.gmail_tools.authenticate_gmail_service`; helper loads, refreshes and writes a **local OAuth token** at configured `token_path`, or returns a mock with `TESTING=true` | **Partial / scope-qualified**, not unsupported. Local credential-state mutation and auth flow are not Gmail message sending. Preserve local-token side effect and approval uncertainty; do not call it external data write |
| `agents/email_agent.py:49`, `CAP005` on `email_agent` | Agent binds both the authentication tool and `create_gmail_draft`; latter calls `service.users().drafts().create(userId='me', body=...)` in `tools/gmail_tools.py` | **Source-supported combined authority**, with a provider-scoped Gmail draft resource and no demonstrated send/delete access. Distinguish local auth persistence from remote draft mutation |
| `agents/research_agent.py:52`, `CAP005` on `research_agent` | Source-bound research/search and `create_email_draft` delegate to the Email Agent in `agents/research_agent.py:94` | **Partial / delegation-scoped**: preserve handoff as indirect authority, not a direct Gmail API call by the research agent; approval enforcement not established |

**Near-miss qualifications:** `create_gmail_draft` is a draft operation, not
`messages.send`; example-local `research_agent` variants remain explicitly
non-runtime, and one carries a static module-import blocker. An alert about
`authenticate_gmail` must not silently inherit all capabilities of sibling
`create_gmail_draft` merely because both are bound to `email_agent`.

These are source-level adjudication **proposals**, awaiting a second independent
reviewer; the status is not a confirmed FP/TP verdict. The audit pipeline must
retain these distinction labels and unresolved provenance rather than restoring
historical totals or suppressing the whole rule family.

## gen-mcp-001: Greptile configuration

The scanner already records its MCP server inventory as **unbound**:
`mcp_authority.summary.bound_relationships == 0` and a
`declaration_not_agent_bound` resolution for configuration-only declarations.
For the `.mcp.json` Greptile entry, the
`Bearer ${GREPTILE_API_KEY}` expression is an environment placeholder, **not**
a hard-coded credential. No configured tool allowlist is demonstrable from
that declaration, but no running agent binding is established.

**P1a behaviour:** retain an *informational inventory/configuration-hygiene*
signal (server, source, declared auth reference, tool-scope unknown, binding
unresolved). Do not raise an AGT051 embedded secret or an AGT032 *effective
agent-access* violation without stronger evidence. Treat production reachability
as unknown, not a security denial or an assumed allowed tool catalogue.

## Independent follow-up and limits

A trustworthy precision/recall claim requires a **locked scanner-blind source
review** that includes scanner-negative cases, separate finding and path labels,
frameworks, source SHAs and reviewers. `scripts/audit_frozen_claim_lineage.py`
produces identity-level loss/recovery and provides an optional strict source-first
reference input. It does not perform live attack execution or judge the source
without independent reviewers. Historical `adjudication-second-pass.csv`
remains *single-reviewer, scanner-visible calibration*.
