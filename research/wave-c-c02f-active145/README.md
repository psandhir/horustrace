# Wave C C02f: active-145 source-review population (seed, not oracle)

Derived mechanically from the immutable source-case registry
[\`research/real-world-agent-security-2026/cohort.json\`](../real-world-agent-security-2026/cohort.json),
whose exact Git blob is recorded in \`manifest_ref\`.

- Archived 180 exact-SHA cases: **unaltered**.
- Active review population: **145 cases**, excluding the 35 LangGraph
  cases from *active* evaluation only.
- Source-cohort strata: FastAgent 3, Google ADK 37, MCP custom 40,
  OpenAI Agents 31, Pydantic AI 34.
- Each record fixes \`case_id\`, \`repository\`, \`commit_sha\` and
  framework exactly as archived, but marks \`source_role=unknown\`.
- \`construct=agent\` indicates the **agent-ontology review domain**,
  not an assertion that the repository contains an agent. This is
  crucial for negative cases such as an application factory or a
  passive MCP server.

This file is an **expected population**, not source truth. It contains
no invented source-positive labels, reviewer credentials, negative
labels, derived scanner findings or fabricated Git blob witnesses.
It can be submitted to C02f's offline coverage matrix with an
empty versioned source-oracle reference to reproduce the 145 still
unadjudicated **C02a source-oracle scopes**. That is not the claim that
there are zero useful historical assertions: legacy ground truth
has source-positive references, but the independently reviewed V2
positive-and-negative universe remains incomplete.

Only after source review can the case population be expanded into
subscopes by construct (agent instance/tool/MCP/edge/identity/
capability/control/finding/path) and source role
(runtime/test/example/provider_only etc). Never silently change the
case IDs or source SHAs while converting that scope seed.

## Actual review plan

For each case, enumerate **all** candidate sites within the declared
source-root and ontology scope, independently of scanner output;
inspect imports/constructors/application factories/test-only roles and
MCP tool binding vs deployed call authority, and give explicit
source-anchored positive, hard-negative or unknown labels.
\`source_truth_review\` permits provisional separate review opinions,
while C02b requires Git blob/line witnesses. The D01 independent
unseen holdout must be **new cases**, not these disclosed 145 cases.

Do not treat the 145-case seed or self-declared reviewer fields
as release certification. The source-accuracy and C03/C04
production-cutover gate remain NO-GO pending an externally auditable
independent reference and #558 required CI status enforcement.
