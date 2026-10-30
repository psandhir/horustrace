# Wave B #540 — bounded finding source provenance (18 October 2026)

## Evidence source and release scope

Latest merged #594 exact current-scanner five-pilot study exposed **three**
findings with an attached source location but no structured source provenance:

- Microsoft `ff60-microsoft-04` at
  `qmatteoq/agent365-demos@937f8c12421b6eebfbff764dbafbdbe13cc72f68`
  contains two `AGT032` warnings, for literal manifest endpoints
  `mcp_MailTools` and `mcp_CalendarTools` in
  `dotnet-agent-teammate/ToolingManifest.json`. Both manifest declarations
  share a source location, so location-only fact matching is **not safe**.
- Pharmiq `gen-pyd-001` at
  `newsbubbles/pharmiq@c69949739647a47ec8339b473bdf578c8cf8bfd9`
  contains one `CAP005` combined read/write finding. The existing source
  adjudicator could not attach two independent, located capability facts for
  that agent instance, although a source-bound MCP authority candidate lists
  both capabilities.

## Correction and explicit uncertainty

`src/horustrace/provenance.py` now attaches to each `AGT032` finding
**exactly one** `EvidenceFact` for its own source-declared configured URL
when source location AND URL match **one** server uniquely. Different
servers in the same manifest cannot share the fact. This is a *positive*
declaration only: absence of an observed tool allowlist is not proof the
deployed server lacks tool filtering. The finding retains its rule and
severity, but now explicitly says deployed tool catalogue and filters
remain unverified. An ambiguous/missing source URL gives **zero** facts,
not a guess; arbitrary unrelated tool facts on that same line are excluded.

The existing `CAP005` finding is not suppressed. If it has no independent
read+write source-fact pair, it is now `heuristic_risk` with
`confidence=potential` and a clear limitation. All cases with the already
implemented **two located capability facts** retain the original
static-configuration assessment and original facts unchanged. Neither the
candidate authority relationship nor a package-defined capability creates a
fabricated executed/write effect.

This is a **claim-confidence correction**, not a new independent truth set,
production deployed permission discovery, or automatic reclassification of
the historical 12 unresolved Amazon third-party claims. No LangGraph is
introduced to the active 145. Numerical accuracy thresholds are unchanged.

## Reproducible targeted verification

`.github/workflows/wave-b540-bounded-finding-source.yml` checks out only
the two immutable target SHAs (not their target dependencies), runs the
real scanner in static mode, and enforces exactly two unique Microsoft
configured-URL source witnesses and one Pharmiq CAP005 potential,
unverified source combination. The checker emits a per-claim JSON artifact
with `source_precision=null`, `source_recall=null`,
`deployed_controls_verified=false` and `wave_b_go=false`.
Hard-negative tests cover mixed servers on the same manifest line, a
missing/mismatched URL, duplicate ambiguous servers, an unrelated located
source tool, an absent read/write witness, and a genuine two-leg supported
finding retaining its original assessment.

The scanner changes must pass original full Fresh-16/Full-60 gates,
same-head accuracy, CI Python 3.11/3.12, CodeQL, plus this pinned
three-claim test before merging. This report is scoped to exact source
configuration and **does not certify** overall Wave B precision,
attack-path exploitability or runtime authority. #558 required accuracy
check enforcement and complete blinded/negative-labelled truth remain
release NO-GO blockers.
