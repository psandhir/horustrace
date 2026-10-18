# Wave B — pinned rw-002 FastAgent source-positive and negative roles

Target: `omnigentx/jarvis@90d1eb1620912e752be2e6fe8156923a0394216d`.
Source files (verified by Git Git blob SHA): `backend/agent.py` at
`97f5e0fd49193dc66fa3f080ff5759ed8f2ddf1a`, and
`backend/services/context_compaction.py` at
`27b57b5bd590093fac04e7b6d10f938ce360bbb1`.

## Positives, negatives and runtime unknowns

- **Eight source-declared FastAgent decorators** in `backend/agent.py`:
  `PersonalAgent`, `IoTAgent`, `ResearchAgent`, `FinanceAgent`,
  `CrawlStoriesAgent`, `Jarvis` (`@fast.agent`); `MusicAgent` and
  `AudioReaderAgent` (`@fast.custom(TagRelayAgent, ...)`). These are
  source-visible registration declarations. They are not eight observed
  running agents.
- **Explicit negative:** `fast = FastAgent("Jarvis",...)` at line 71
  creates a framework *application object*. It is NOT another individual
  agent. The historical locked reference identified `fast` as a positive
  agent. That is a **bounded source-ontology conflict**, not permission to
  overwrite the original reference or manufacture a new precision score.
- **Explicit negative:** `class TagRelayAgent(McpAgent)` at line 63 is a
  subclass/type definition, NOT a separately instantiated agent. The two
  `@fast.custom` registrations still ARE source-declared agent entries.
- **Additional source-positive, runtime unresolved:** a distinct
  `LlmAgent(AgentConfig(name="context-compactor"), ...)` construction in
  `backend/services/context_compaction.py` at line 536. It occurs inside
  conditional helper execution. A source-visible constructor does not mean
  its branch executed or created a runtime instance.
- `servers=[...]`, skill names, tool allowlists, dynamic list expansions,
  decorator registration and Jarvis delegation configuration DO NOT prove
  deployed MCP service/tool catalogues, effective grants, actual delegations
  or successful remote calls.

The frozen `rw-002` source reference reports all four original truth
dimensions INCOMPLETE and contains eight positive records including the
`fast` application object and `shell` compactor. It omits the two custom
decorator registrations. No explicit negative universe is provided.
The new evidence is a **post-hoc, scoped two-file AST crosscheck** with its
own separate identities and never represented as human-independent blind
truth. The source-only results MUST NOT be reported as `rw-002` or
active145 precision/recall, independent exhaustive negatives, effective
runtime security accuracy, Wave B release GO or Wave C cutover approval.

`.github/workflows/wave-b540-rw002-fastagent-negatives.yml` fetches the
original SHA without executing or installing target code, verifies both
immutable blob witnesses, independently counts eight decorator positives and
the two constructor/class negatives, and compares the scanner's scoped
FastAgent adapter output. Changes to the original historical frozen truth,
active145 LangGraph exclusion, current numeric quality thresholds, and
release gates are prohibited.

Other files within this ~1,200-file repository and other framework-specific
constructs remain *unreviewed*. This result is a bounded reference improvement,
not an assertion that there are exactly eight deployed or source-positive
agents in the whole repository. #540 remains open and the release is NO-GO
pending complete labelled positives/negatives and required branch protection
under #558.
