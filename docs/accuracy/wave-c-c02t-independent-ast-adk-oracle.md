# Wave C C02t — independent bounded Google ADK AST source oracle

Parent [#606](https://github.com/psandhir/horustrace/issues/606) / [#543](https://github.com/psandhir/horustrace/issues/543). Implements a **mechanical second parser** over exact pinned ADK source, independent of HorusScan's adapter and source-truth LLM judge. Complements MCP declaration oracle C02s (#630).

## Exact frozen study

- Repository: `Ojas-Patil26/VeriQ@067cb330ab943279b4b8ea13c91c9042bdd9f421`, active145 `rw-005`.
- Scope: two complete Git blob-backed files `agent.py` (`89ce05579a18e8e09822d4157cace7121a5d7c99`) and `api.py` (`bfed9d84fd977eb20a4e7f8453aebff675ac9faf`). Git tree, object SHA1, commit HEAD and source digests are rechecked before parsing.
- Separate standard-library `ast` traversal with **no SDK execution**, no LLM invocation, no import of scanner for parsing source.
- Literal top-level `LlmAgent(name=...)` construction census: **5 unique source constructor sites**.
- Literal `sub_agents=[...]` listing: **4 declared direct child relationships**, all owned by root coordinator.
- Literal direct `tools=[...]` listing: **8 tool-to-owner source declaration entries**, owned by three child agents. Incident report explicitly has an empty tool list, and root has **no direct tool list**.
- The API dynamic import alias and `Runner(agent=_root_agent)` do **not** create new source agent constructors. API aliases, prompt text and comments are not agents.
- Unresolved constructs include nested/factory constructors, dynamically selected tools/delegates, nonlocal unresolved child identifiers, missing literal name and reassigned symbols. They are *not* silently counted as absent or runtime non-callable.

The pinned Actions workflow runs current full-repository `horustrace.scanner.scan()` and archives raw ADG/source AST JSON next to the separate mechanical census. The source oracle does not derive its labels from scanner output and does not infer correctness from agreement; the earlier #628 scanner/LLM evidence remains independently traceable.

## Hard negatives / limitations

Synthetic regression cases exercise identical display names at distinct sites, commented-out constructor syntax, imported API aliases, dynamic tool lists, nested factories, unresolved delegation and source alias rebinding. The bounded syntax oracle only establishes these source-visible declarations under a static grammar. It does **not** exhaust imported aliases, nested runtime factories, conditional deployment, callable tools, installed ADK versions, effective authority, or all real-world hard negatives.

Outputs deliberately remain `certified_precision=null`, `certified_recall=null`, `independent_human_review_verified=false`, and `production_cutover_authorized=false`. No Graph/ADG, security findings, paths, controls, UX, OWASP or thresholds change. Preserve Frozen180, active145 non-LangGraph and Amazon12 UNKNOWN. An external unseen D01, complete V2 source evidence and #558 admin-required accuracy gate are still release blockers.

### Required PR acceptance

- Exact pinned Git objects verified, targeted oracle + adversarial tests green, scoped source counts 5/4/8 and API hard negatives intact.
- Current-head Python 3.11/3.12, Ruff, CodeQL, Fresh16, Full60, same-head accuracy gate with preserved evidence artifacts green.
- No auto-promotion to independent completeness or C03/C04 production GO.
