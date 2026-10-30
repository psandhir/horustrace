# Wave B rw-001 — complete-flagged original reference contains six app factories

**Frozen source:** `Klavis-AI/klavis@45c9f7da83d1cf43f7429b96f9c8e8153542ea1e`,
six files below `mcp_servers/hugging_face/packages/e2e-python`.

**Critical acceptance distinction:** the locked 2026-09-26 `rw-001` source
reference marks `agent_entities` **complete**, but six of its 14
`explicit_agent_entity` positives are the `fast = FastAgent(...)`
**application factory**, not an individual agent construct. The two-pass
automated historical reference was source-locked before the older scanner,
but it used a different agent ontology. `reference_completeness=true`
therefore does NOT independently certify V2 accuracy or a closed-world
negative universe.

The exact immutable source shows **eight decorated agent configurations**:
three stacked `@fast.agent` declarations in `agent.py`; one each in
`gradio-files.py`, `jobs-testing/agent.py`, `prompts.py`,
`qwen-test/qwen-test.py`, and `skybridge1.py`. The six distinct
`fast = FastAgent("...")` assignment sites are **source-supported hard
negatives for the *individual agent entity* type**. The two commented-out
`@fast.agent(...)` lines in the Gradio/Qwen examples are source text but
**not Python decorators or deployed registrations**. Source declarations
are not runtime instances or verified MCP access.

## Reproducible crosscheck

`scripts/verify_wave_b540_rw001_fastagent_negatives.py` verifies six Git
blob hashes, independently parses Python AST for decorated source identities
and factory assignments, crosschecks each with the FastAgent adapter, and
requires the *unchanged* historic locked reference to contain its six
factory-as-agent records. It emits a per-site mismatch report with separate
labels and explicit `agent_precision=null`, `agent_recall=null`,
`wave_b_go=false`, `wave_c_go=false`.

A dedicated isolated GitHub Actions workflow retrieves **only the six SHA
pinned source files** over their immutable raw URLs, never installs target
dependencies or executes target source. Hard-negative tests detect source
drift, missing cases, wrong factories, commented declarations becoming active,
and historical reference/positive conflict suppression.

**Do not edit the original 180 reference** to force better scanner metrics.
That archive describes its initial ontology. The present facts are a
**post-hoc, bounded six-file evidence correction**, not independently
blinded V2 source truth. The exact source identity labels may inform the
later independently adjudicated new V2 oracle with reviewers kept blind to
scanner candidates. This case should be flagged as reference-ontology
incompatible in Wave B certification, not treated as a measured scanner
false-positive rate. Active145 excludes archived LangGraph 35 only from
active reports. #558 branch accuracy protection and other Wave B #540
release blockers remain open.
