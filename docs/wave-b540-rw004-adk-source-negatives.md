# Wave B source-positive/negative ADK review: rw-004

Target: `JoanMarinPages/agentGemini@0160690bb47cca17e70ceb8486209d7b1cacaf76`.
This is a **bounded, post-hoc, six-file source review** of an old
agent-complete reference; it is not a new independently blinded V2 oracle.

Exactly pinned Git blobs in `scripts/verify_wave_b540_rw004_adk_negatives.py`
establish:

- `agent.py`: `funnel_agent = LlmAgent(name="FunnelAgent")` is a
  source-declared ADK agent. `root_agent = funnel_agent` is **only an alias**,
  and `Runner(agent=root_agent)` is a session orchestration runner, not
  a separate agent or a verified runtime session.
- `agentGemini/agent.py`: `root_agent = Agent(name="AgroAsesorIA")` is
  a *second source-declared constructor*. Its imported symbol is
  `google.genai.adk.Agent`, not the usual `google.adk.agents.Agent`.
  The pinned dependency declarations list `google-genai` but **no separate
  `google-adk` package**. Without installed package/SDK facts, treat
  executable import binding as **unresolved**, not an observed live agent,
  an automatic false positive, or evidence of an exploitable tool grant.
- `example_simple_agent.py`: `google.genai.Client` model API calls and
  `GenerateContentConfig` are **not** separate ADK agents.
- `agentGemini/models.py`: Pydantic `BaseModel` domain classes are
  **not** LLM agents.
- The pinned `requirements.txt` and `pyproject.toml` describe source
  package declarations only. Neither asserts an installed SDK version,
  runtime import success, deployed tool catalogue or effective control.

The new CI test executes **only HorusScan's static parser** against immutable
source data; it does not import, install or run the target repo, or make
claims about Cloud credentials. It writes exact positive/negative
witnesses and scanner projection in
`evaluation/rw004-adk-source-negatives.json`.

The historical rw-004 agent reference marks two agent entities complete,
but supplies **no explicit hard-negative universe**, and an unresolved
SDK binding cannot become a runtime-certified agent without environment
proof. Do not edit original Frozen180 truth or compute full-cohort
precision/recall from this targeted crosscheck.

Wave B release remains NO-GO until independent/methodologically isolated
positive AND negative V2 source labels, finding/attack-path adjudication,
12 Amazon runtime unknown dispositions, and required protected-main
accuracy status gate (#558) are addressed. Wave C cutover is blocked.
