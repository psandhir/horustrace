# Post-#307 frozen-v4 validation

## Executive result

The frozen `agent-centric-unseen-12-v4` cohort was rerun on the post-#307 scanner using commit `17eddad62090a22ccac2efde00c3c61b2dc45f73` (parent: merged #307, `86145932dce3895406f9e57b6783ad6eb706a107`).

- Workflow run: **37078177790**
- Cases completed: **12/12**
- Findings: **45** (down from 48)
- Attack paths: **2** (down from 4)
- Effective-authority relationships: **51** (up from 48)
- Materially supported findings: **44/45 = 97.8%**
- False-positive findings: **1/45 = 2.2%**
- Materially supported attack paths: **2/2**, both qualified rather than proof of exploitability

This clears the working >=90% materially-supported precision target on the frozen v4 cohort.

## Framework result

| Framework | Findings | Supported / qualified | FP | Supported precision | Authority relationships |
|---|---:|---:|---:|---:|---:|
| Google ADK | 19 | 19 | 0 | 100.0% | 24 |
| Pydantic AI | 20 | 19 | 1 | 95.0% | 18 |
| OpenAI Agents | 6 | 6 | 0 | 100.0% | 9 |
| **Total** | **45** | **44** | **1** | **97.8%** | **51** |

## What changed

### Precision

The post-v4 semantic fixes removed the previously adjudicated false positives caused by:

- ADK `send_email` name-only mutation inference.
- ADK loss of operator-configured destination provenance through aliases/delegation.
- OpenAI `create_escalation_summary` name-only mutation inference.

The largest case delta is `unseen4-adk-001`: **13 -> 5 findings** and **2 -> 0 attack paths**, while retaining the source-supported GCS write/read authority.

### Recall / authority composition

The rerun also closes the highest-priority v4 recall gaps:

- `unseen4-oai-001`: MCP factory binding now survives as an authority relationship (**0 -> 1**).
- `unseen4-oai-002`: awaited/composed tool collection now survives binding (**0 -> 2** relationships).
- `unseen4-pyd-001`: imported `Tool(...)` wrappers now inherit source-visible NATS control semantics; three privileged-control findings are surfaced.
- `unseen4-pyd-002`: imported SMS helper effects now propagate to `send_alert`; the transitive local debug-file write in `get_price` is also source-supported.

## Residual known gap

One previously known Pydantic `NET002` false positive remains in `unseen4-pyd-003`: the database connection is sourced from operator configuration (`DATABASE_URL`) but one relationship still loses that destination provenance and is treated as unconstrained external network authority.

The separate `scrape_url` authority remains legitimately broad because the URL is supplied as tool/application input.

## Decision

Do **not** spend another iteration tuning this frozen cohort before testing generalization.

The next step is a fresh, pre-frozen unseen cohort covering only the current product scope:

- Google ADK
- Pydantic AI
- OpenAI Agents

Selection must be completed and committed before HorusTrace is run. The v5 study should continue to score precision and authority recall separately, with particular attention to provider/destination provenance and composed tool/MCP collections.
