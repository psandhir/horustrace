# Residual fidelity validation — PR #295

## Scope

This records the post-fix rerun of the exact frozen 12-repository agent-centric cohort from #294:

- Google ADK: 4
- Pydantic AI: 4
- OpenAI Agents SDK: 4

Repositories and SHAs are unchanged. LangGraph and MCP/custom strata remain outside this product-scope metric.

## Scanner state

- PR: #295 `fix: close agent-centric residual fidelity gaps`
- Validated head: `ca90a487a2f388104e4d79c8a344d0118e310a83`
- Workflow run: `37050030151`
- Execution: **12/12 cases + aggregate succeeded**

## Raw result

| Framework | #294 findings | Post-#295 findings | Attack paths |
|---|---:|---:|---:|
| Google ADK | 24 | **23** | 4 |
| Pydantic AI | 17 | **12** | 1 |
| OpenAI Agents | 20 | **18** | 0 |
| **Total** | **61** | **53** | **5** |

No attack path was removed or added.

## Exact claim delta

Stable claim comparison found **8 removed findings and no new semantic finding**.

### Removed prior false positives — 7

Google ADK:
- Pipeline Reviewer `NET001`: fixed PyPI/Maven hosts were previously represented as `<dynamic-url>`.

Pydantic AI:
- three `NET002` claims that lost fixed/provider destination provenance;
- one `AGT040` claim on the pure in-process `compose_email_content` helper.

OpenAI Agents mixed repository:
- two `AGT020` claims from unbound LangGraph/LangChain `calculate` tools in Python/notebook examples.

### Removed prior partial — 1

Pydantic testing example:
- `NET002` on `test_agent` was previously marked partial solely because it occurred in test context.
- Source review shows the apparent API call is `ctx.deps.api_client.post(...)` where the dependency is a test Mock/AsyncMock. The pinned source does not prove real external network egress.
- Suppressing this claim is therefore treated as a semantic correction, not a meaningful recall loss.

## Carried-forward adjudication

Starting from #294:
- TP: 22
- partial: 32
- FP: 7
- materially supported: 54/61 = 88.5%

Post-#295:
- TP: **22**
- partial: **31**
- FP: **0**
- materially supported: **53/53 = 100%**
- explicit FP rate: **0%**

The five retained attack paths remain the same five previously adjudicated qualified/partial paths:
- four Google ADK Pipeline Reviewer fixed-command paths;
- one Pydantic MCP state-changing data path.

Materially-supported path rate remains **5/5 = 100%**. This does not mean five unrestricted arbitrary-impact paths; all retain the qualifications recorded in #290/#294.

## What changed architecturally

The fixes are invariant-level rather than repository-name exceptions:

1. **Unbound inventory is not effective authority.**
   Generic/LangChain tools can remain discoverable without emitting agent-risk findings until a supported/source-proven binding exists.

2. **Function names do not prove external authority.**
   Pydantic function-name hints no longer manufacture `network.external` or `external.write` without source-visible sinks.

3. **Fixed destination provenance survives composition.**
   Repository-local helpers, HTTP client wrappers and Pydantic `Agent.run*` delegation retain fixed/provider destination constraints.

4. **ADK imported helper chains preserve network scope.**
   `urllib.request.Request`, `urlopen` and same-module helper chains preserve fixed PyPI/Maven origins; `urllib.parse` is not treated as network I/O.

5. **Pydantic instances remain distinct authority principals.**
   Delegation propagation resolves source-proven agent instances without collapsing unrelated same-framework objects.

## Interpretation

This frozen cohort now has no known unsupported finding under the calibrated #290/#294 claim-adjudication rubric.

That is **regression evidence on an iterated cohort**, not proof of generalization. The correct next step is a new unseen cohort restricted to Google ADK, Pydantic AI and OpenAI Agents, frozen before HorusTrace execution and evaluated with blind source review plus claim precision adjudication.
