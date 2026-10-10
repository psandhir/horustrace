# HorusScan security workbench — visual system

## External references and lessons

We draw on recognizable information architecture patterns, not copy vendor branding or assets.

- [Wiz Security Graph](https://www.wiz.io/platform): make risk a navigable relationship across agent, tool/MCP, identity, resource, destination and attack path. Do not imply live exploitability from static analysis.
- [Snyk UI design system](https://snyk.io/blog/introducing-new-snyk-ui/): a small, consistent library of component patterns with typography, iconography and contrast discipline.
- [Semgrep interactive reporting](https://semgrep.dev/assets/release-marketing/spring-2025-semgrep-release-marketing-kit.pdf): actionable findings, priority review and linked chart-to-detail investigation.
- [GitHub Security Overview](https://docs.github.com/en/code-security/concepts/security-at-scale/security-overview): distinct risk, coverage and remediation dimensions. Absence of alerts must not be presented as secure or compliant.

## Adopted design principles

1. **Calm by default:** cool-white canvas, white surfaces, slate/navy text, subtle blue selection, no brown/ochre headlines and no rainbow KPI wall.
2. **Colour has one job:** rose/red = active critical risk; restrained peach = warning / partial context; sage = informational good / resolved; grey = unknown / not assessed. Numbers retain navy text unless highlighting genuine violations.
3. **Icon = construct:** source-local line icons for agents, findings, policy, OWASP mapping, attack paths, contracts, tools, skills, MCP, identities, resources and scan evidence. The icons are *not* security ratings.
4. **Text accompanies colour:** categories, count, severity, and scan completeness always remain textual. Zero-count categories have empty bars, never fake green progress.
5. **Follow the evidence:** high-level tiles drill into real scanned agents/findings; source locations and provenance remain accessible.
6. **Offline & secure:** static bundled SVG paths, no CDN, web fonts, remote icon service, telemetry, or HTML built from untrusted scanner data. CSP and embedded report JSON behaviour remain unchanged.
7. **Both audiences:** security executives can read the assessment and priority queue; engineers can pivot into authority, underlying findings and agent relationships.

## First implementation increment

- [x] Semantic navigation icons and clearer selected state.
- [x] Icons in KPIs and key section headings.
- [x] Consistent card number, label and detail hierarchy.
- [x] Compact, clearly differentiated assessment banner with discreet risk stripe.
- [x] Neutral light palette (dark mode remains available).
- [x] Offline/icon and scanner-projection regression tests.

## Next recommended increments (separate PRs)

**P0 — Finding investigation:** finding detail should show `source -> agent -> tool/MCP -> capability -> identity -> resource/destination -> control -> path`, with known/unknown context and source-backed evidence links; distinguish scanner observations from hypotheses.

**P0 — Risk overview and scan completeness:** separate risk severity, policy breach, authority resolution, and scan coverage so no colour visually implies a scan is safe, compliant, or fully assessed. Risk comparison needs a signed baseline and stable rule set rather than comparing unqualified finding counts.

**P1 — Graph investigation:** visual relationship legend, fit-to-view, search, focus/expand, selected-path highlight, and source trace controls. Never display capability co-occurrence as proved data flow.

**P1 — Multi-agent impact:** change impact from agent to delegated agents and reachable tools/resources, with authority-binding uncertainty.

**P1 — Keyboard/mobile:** automated focus order, screen-reader label, keyboard drilldown, horizontal table overflow and small viewport audits.

## Acceptance gates

- Python 3.11 and 3.12 tests, JavaScript syntax check where Node is available, packaging, self-scan and security actions all green.
- Existing ADK vulnerable fixture: agent/MCP/tool discovery, 37 findings, eight attack paths and OWASP mapping must remain source-backed (counts treated as baseline, not hardcoded into the UI).
- Static report JSON projection byte/semantic equivalence before and after rendering changes.
- Browser review of dashboard, finding list, agent profile, attack graph, dark mode and narrow viewport using the archived ADK demo HTML.
