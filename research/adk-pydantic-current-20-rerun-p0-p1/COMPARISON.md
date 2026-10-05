# ADK + Pydantic AI frozen-20 rerun comparison

Baseline scanner: `eacfd1cdab06939e5fae5f65cd2536e5855ac33f`  
P0/P1 rerun scanner: `37b433a1141fdc398ec2a003eaa8c394896d70a0`  
Rerun workflow: `37288186549`

## Overall

| Metric | Before | After | Delta |
| --- | ---: | ---: | ---: |
| Successful scans | 20/20 | 20/20 | unchanged |
| Analysis incomplete | 8 | 7 | -1 |
| Findings | 67 | 39 | -28 (-41.8%) |
| Attack paths | 7 | 5 | -2 |
| Google ADK findings | 47 | 21 | -26 |
| Pydantic AI findings | 20 | 18 | -2 |

No locked-reference recall dimension regressed. Raw precision figures that decline for
Pydantic are driven by newly discovered source-supported objects absent from the old
reference, not by newly invented source objects.

## P0 validation

### HTTP transport vs semantic mutation

`rw-009 Cloud_Architecture_Review` falls from **18 findings to 0**.

The Microsoft Docs MCP helper uses HTTP POST as JSON-RPC transport for a read/search
operation. The old scanner promoted POST to `external.write`, then propagated that
capability through delegation. The rerun removes that amplification cluster.

### SQLite read vs write semantics

`rw-017 always-on-memory-agent` falls from **19 findings to 11**, and attack paths
fall from **4 to 2**.

The removed paths/findings were driven by read-only SELECT helpers being promoted to
write authority through their shared idempotent schema initializer. The remaining
write findings are attached to actual mutation functions (`store_memory`,
`store_consolidation`) and delegation to those write-capable agents.

## P1 validation

### Finding deduplication

`rw-150 project-ideation-tool` falls from **4 findings to 2** while retaining its
single source-supported URL-fetch attack path. This is the intended duplicate removal.

### ADK topology taxonomy

ADK tool precision improves from **74.2% to 82.1%** in the raw locked-reference
scorecard. In `rw-021`, the three delegated-agent helper projections are no longer
counted as ordinary tool false positives.

### ADK imported sub-agents

`rw-027 google/pubmed-rag` now reconstructs all three imported sub-agent bindings.
The raw scorer reports 3 FP + 3 FN because the locked reference names the Python
variables (`librarian_agent`, `analyst_agent`, `reporter_agent`) while the scanner
uses the agents' runtime names (`clinical_librarian`, `evidence_analyst`,
`reporter`). Source inspection confirms the three delegations are real. This is a
benchmark normalization issue, not a product miss.

### Pydantic conditional capability

`rw-161 mars-mx/portfolio` is no longer analysis-incomplete. Conditional
`WebSearch()` is represented as a typed, conditionally available capability instead
of an unresolved dynamic placeholder.

The old reference does not include WebSearch, so raw precision treats it as an extra;
source inspection confirms the capability is explicitly configured.

### Pydantic factory composition

`rw-170 smart-web-scraper` now discovers the two concrete factory-created agents
(`_agent`, `_agent_custom`) and the later `_scrape_tool` registration on both.
The old reference records none of those objects, so raw agent/tool/authority precision
moves down even though discovery has improved.

One semantic follow-up remains: the tool calls a fixed Massive Unblocker endpoint but
passes caller-controlled `target_url` as a proxy-fetch parameter. The binding is now
correctly discovered, but indirect/proxy destination semantics are not yet represented
as caller-selected downstream reachability.

## Raw framework scorecard

| Framework | Metric | Before | After |
| --- | --- | ---: | ---: |
| Google ADK | Agent P/R | 100.0% / 96.8% | 100.0% / 96.8% |
| Google ADK | Tool P/R | 74.2% / 63.9% | 82.1% / 63.9% |
| Google ADK | Authority P/R | 80.0% / 74.1% | 80.0% / 74.1% |
| Pydantic AI | Agent P/R | 83.3% / 100.0% | 71.4% / 100.0% |
| Pydantic AI | Tool P/R | 52.2% / 100.0% | 48.0% / 100.0% |
| Pydantic AI | Authority P/R | 25.0% / 100.0% | 22.2% / 100.0% |

The Pydantic precision decrease is an expected artifact of stale/incomplete locked
ground truth: the newly counted factory agents/tools and conditional WebSearch are all
source-supported.

## Decision

The P0 semantic fixes are validated by the frozen cohort. The P1 changes also improve
inventory/composition fidelity without losing locked-reference recall.

The next validation step should be a fresh unseen **5 ADK + 5 Pydantic** holdout.
Separately, indirect/proxy-fetch semantics should be added to the shared semantic
backlog rather than treated as another Pydantic parser fix.
