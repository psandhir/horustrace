# Wave B rw-004 — validate ADK source provenance before accepting a recall claim

**Status: source construct detected in old Graph but supported SDK identity unresolved.** This is not clearance of any release gate.

Exact frozen source: `JoanMarinPages/agentGemini@0160690bb47cca17e70ceb8486209d7b1cacaf76`. Framework stratum: Google ADK; active non-LangGraph 145 case `rw-004`.

## Findings

1. `agent.py:98` instantiates `LlmAgent(name="FunnelAgent", ...)` from `google.adk.agents`. This has the Google ADK import provenance required by HorusTrace, and was present in both historical/current Graphs.
2. `agentGemini/agent.py:38` declares `root_agent = Agent(name="AgroAsesorIA", ...)`, but the source import is **`from google.genai.adk import Agent`**. The pinned `requirements.txt` and `pyproject.toml` declare `google-genai` without `google-adk`. The repository's own `README.md` and separate `agent.py` correctly use `google.adk.agents`. These statements are internally inconsistent. `google.genai.adk` must not be assumed to be a functioning Google ADK SDK export from the syntax alone.
3. `adk.yaml:name=agentGemini` is **application display metadata**, not a distinct third agent construct.
4. The historical scanner counted `AgroAsesorIA` plus the `adk.yaml` name; latest scanner's Google ADK detectors require `google.adk` source evidence to prevent incidental third-party `Agent()` calls from masquerading as Google ADK principals.

Official Google documentation independently shows the supported import `from google.adk.agents import Agent` ([Python ADK quickstart](https://adk.dev/get-started/python/)). This document does **not** claim that the pinned repository was ever executed, nor that its `google.genai.adk` import failed at runtime.

## Ontology / correctness boundary

`AgroAsesorIA` is a **source-declared Agent-shaped call**. It is not yet a verified constructable Google ADK agent instance. Treat it as `unresolved_sdk_import` during independent adjudication; do not count it as a confirmed *runtime* agent false negative and do not create effective tool authority from unverified import provenance. Conversely, do not erase this declaration from a source-fact inventory or claim its absence proves the source has no agent intent.

The strict fixtures `tests/test_wave_b_rw004_agent_import_provenance.py` enforce supported ADK recognition, unverified-import and unrelated-SDK hard negatives, and prevent `adk.yaml` display-name duplication. They do not change scanner behaviour or historical truth.

## Further acceptance

- Establish the versioned `google-genai` package's actual export surface using a trusted wheel/package manifest without installing or executing the target source.
- Introduce an explicit `source_declaration_unresolved` fact in the inventory (distinct from `Agent` with proven authority), if the benchmark needs source-intent inventory independent of SDK constructability.
- Verify frozen rw-004 missing-agent classification against the new declared-vs-effective ontology and apply the same rule to baseline and current.
- Keep 95% agent precision, six active release gates, other ADK source-claim assertions and original frozen source truth unchanged.
