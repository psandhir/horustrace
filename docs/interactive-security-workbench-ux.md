# Interactive Security Workbench — UX upgrade plan

Status: design and implementation backlog (not yet shipped)

Branch: `ux/interactive-security-workbench`

## Intent

Upgrade the existing **offline, self-contained HTML scan report** into a clear, evidence-driven security investigation workbench. The product must remain useful for application developers, security engineers and security leaders, without conflating missing detections with improved security posture.

This is a **presentation-layer programme**, not a rewrite of the scanner, framework adapters, policy engine, Effective Authority, Authority Contract, or Agent Security Graph.

## Verified baseline

The existing `src/horustrace/visual_report.py` already implements:

- A versioned `horustrace.visual_report` schema (v1), embedding the assurance summary and existing Agent Security Graph.
- Drillable assessment metrics, a prioritised review queue, agent profiles, findings, policy/OWASP/contract sections and coverage.
- A searchable, filterable agent inventory and findings list.
- Per-agent SVG agency maps with grouped collapse/expand, zoom, pan, search, focus, full-screen and evidence inspection.
- Attack-path presentation that distinguishes source-supported static flows (solid edges) from potential capability co-occurrence (dashed edges).
- Standalone HTML rendering without CDNs, remote resources, telemetry or network requests.
- HTML/JSON escaping and tests for report data, keyboard access and self-containment.

Existing report capabilities must be preserved and **not reimplemented in parallel**.

## UX design principles

1. **Investigate first**: every chart segment, metric and risk indicator navigates to the exact filtered evidence.
2. **Separate risk, confidence and completeness**: severity, assessment class, source support, authority resolution and scan coverage are separate dimensions. Never render an absence of findings as proof of safety.
3. **Data provenance over decoration**: retain source path/line, relationship ID, contract clause, rule ID and evidence-strength labels.
4. **Consistent interaction grammar**: keyboard-accessible click targets, focus styles, Escape behavior for modal/sheet surfaces, responsive layout, tooltips/labels and reduced-motion support.
5. **Offline by default**: report stays a portable HTML artifact with no remote JavaScript, fonts, images or telemetry.
6. **Presentation only**: no findings, attack paths, policy decisions, security semantics or historical conclusions are inferred by browser JavaScript.
7. **Honest comparisons**: counts are diagnostics, not a risk score. Decreased findings or attack paths may indicate regression, source-context correction or true remediation; label as unadjudicated until reconciled.

## Phases and deliverables

### UX-01 — Design system and interaction foundations (P0)

- Create reusable visual primitives for card, severity display, status indicator, filter chip, detail panel and empty/loading state. Keep generated report a single standalone HTML file.
- Define separate display states:
  - **Scan execution**: pending, running, complete, incomplete, failed.
  - **Security assessment**: critical/high/medium/low/informational, policy violation, contract violation, no mapped finding, not assessed.
  - **Evidence confidence**: supported static data flow, potential capability co-occurrence, unresolved/unknown authority, source context.
  - **Comparative classification**: new, resolved, changed, unchanged, unmatched/unadjudicated.
- Preserve existing labels and scanner values; map into presentation labels without changing scanner schemas.
- Check responsive layouts and screen-reader/keyboard behavior.

Acceptance: same scan projection, finding counts and report semantics before/after UX-only changes; offline/CSP tests pass; keyboard interaction test coverage increases.

### UX-02 — Clickable analytics (P0)

- Add compact, accessible interactive visualizations for severity distribution, agent/framework coverage, authority resolution, policy/contract posture and OWASP assessed-vs-unassessed.
- Chart events apply the existing view filter/drill action, rather than establishing a second navigation model.
- Show denominators, definitions and informative no-data states.
- Do not use colours alone for semantics.

Acceptance: chart segments and existing metric cards link to equivalent filtered data; totals equal report projection; zero-count and incomplete scans render accurately.

### UX-03 — Finding investigation panel (P0)

- Provide a dedicated investigation surface with severity, assessment class, rule ID, source context, evidence and provenance, effective authority, linked path and remediation where available.
- Support navigation from chart -> finding -> agent -> relationship -> underlying evidence, with breadcrumbs/back navigation.
- Avoid claiming runtime exploitability; distinguish static path evidence and potential capability co-occurrence.

Acceptance: a selected finding resolves to the same identifying rule, agent and source evidence as the machine-readable output; missing evidence is represented explicitly.

### UX-04 — Before/after scan comparison (P0)

- Reuse existing `change_analysis.py`, `authority_delta.py` and contract comparison semantics as data producers; expose a versioned *comparison projection* separate from a single-scan report.
- Show before/after findings, attack paths, agent inventory, effective-authority changes and source-context deltas.
- Provide drill-through lists for new, removed and changed findings/relationships and distinguish potential false-negative regressions from source-context corrections.
- Never automatically interpret reduced finding counts as risk reduction.

Acceptance: comparator counters match existing diff JSON; unmatched/reordered findings do not silently disappear; snapshot identifiers and source/context exclusion assumptions are visible; baseline absent -> clear no-comparison state.

### UX-05 — Multi-agent impact exploration (P1)

- Extend existing agency map interactions rather than introducing a second graph model.
- Expose selected-agent neighbors, delegation/communication edges, reachable identities/resources and upstream/downstream impact as *supported by existing graph evidence*.
- Visually distinguish supported vs potential paths and missing provenance.

Acceptance: graph nodes and edges link to existing evidence IDs; no invented edges; large/complex graph remains usable.

### UX-06 — Scan execution states (P1)

- Propose a versioned execution-event contract for a future CLI/hosted execution surface. An offline report produced at scan completion cannot truthfully show live progress without an execution host and event transport.
- Keep execution-stage status distinct from security assessment and evidence-resolution status.

Acceptance: deterministic event/state tests; canceled/failed/incomplete scans are not represented as clean security passes.

## Technical boundaries

- Keep scan-level `horustrace.visual_report` v1 consumers backward-compatible. Add only optional fields with explicit schema versioning if required.
- Continue using the existing Agent Security Graph as the topology source; **do not create another security graph in JavaScript**.
- Report can be refactored into Python-packaged CSS/JS template modules and bundled into the final single-file HTML. Packaging tests must validate wheel/sdist output.
- Do not add runtime frontend dependencies or CDN assets without explicit architecture review.
- Respect the Content Security Policy and escape any source-controlled text for HTML, attributes, URLs and SVG.
- Avoid touching scanner adapters/rule interpretation in UX PRs; isolated interface changes can run alongside ongoing P0/P1 scanner work.

## Delivery sequence and review gates

- Land UX-01 first, then UX-02/03/04 as independently reviewable changes. UX-05 and UX-06 follow once evidence/transport contracts are agreed.
- Run `tests/test_visual_report.py`, schema/serialization tests, offline/CSP/XSS regression checks and repository CI on each UX change.
- Compare a pinned representative scan fixture's machine-readable security projection before/after UX changes. Scanner output and finding/attack-path counts must be identical for UX-only changes.
- Avoid automatic merges to `main`; keep draft until actual UI implementation and validation pass.
- Regularly update this branch from `main` after scanner fixes, resolving template-level conflicts intentionally.

## Current stage

The branch includes an initial UX-02 thin slice: a keyboard-operable finding-severity bar chart that routes into the existing findings filters, includes the informational category, and uses static scan counts without backend inference. The existing machine-readable report projection is unchanged by this feature.

This is a first implementation step, not completion of UX-01–UX-06. CI and runtime accessibility validation remain release gates.
