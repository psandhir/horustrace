# Wave C C02v — opt-in MCP source supply-chain HTML explorer

Parent: Wave C #543, C02 evidence #606 and source MCP implementation shadow #629.

This addition presents already-built, **source-only** local stdio MCP
configuration → implementation → declared-tool edges from the existing
`project_bound_source_mcp_implementations` output as a single, offline
HTML artifact. It does **not** change the production security workbench,
canonical Graph/ADG, findings, controls, OWASP mappings, authority or paths.

## What is now visible

- Three separate columns for MCP client configurations, original source
  implementation sites and statically decorated source tools.
- Same-display-name servers (for example the two rw080 `Calculator` modules)
  remain distinct by their **repository-relative file and line**.
- Select any node to emphasize its connected source component. Unrelated
  nodes **remain rendered** but are visually de-emphasized, matching the
  previously requested drill-down behavior. Click the same node or
  **Show all** to restore the complete view.
- Source-site locations, declaration-kind counts and unresolved witness
  reasons stay visible without raw credentials, target source text or
  deployment assumptions.
- Clearly visible **source only / runtime unknown** banners avoid
  misleading consumers into believing `EXPOSES_TOOL` implies
  `AGENT_CAN_CALL`, credential reachability or an exploitable attack path.

## How to view

The existing `Wave C C02r MCP Source Implementation Shadow` Actions
workflow now publishes `mcp-source-supply-chain.html` inside its preserved
`wave-c-c02r-rw080-source-shadow` artifact after scanning the exact pinned
rw080 source. To regenerate from any valid source-only C02r JSON:

```sh
python -m horustrace.source_shadow_html \
  --input artifacts/source-shadow.json \
  --output artifacts/mcp-source-supply-chain.html
```

Open the resulting HTML file locally in a browser (no external network
assets required). No default report mode is changed.

## Fail-closed evidence contract

Rendering rejects unknown schema/mode, authority/promoted runtime flags,
`AGENT_CAN_CALL` edges, unsupported kinds, wrong edge endpoint types,
duplicate/missing nodes, source escaping paths, invalid source line
witnesses and mismatched edge counts.

Every source name, path and unresolved reason is escaped in HTML. The
serialized source-node script payload escapes HTML metacharacters, so
source labels cannot inject HTML/script elements. Offline CSP blocks all
network/file resource loads and no secrets are injected.

## Acceptance and boundaries

The pinned rw080 study still expects exactly 3 local stdio implementation
source sites and 25 `EXPOSES_TOOL` declarations. Tests cover distinct
same-name nodes, opt-in click focus/dimming, real Chromium click/keyboard drilldowns, malformed graphs,
untrusted script strings, unresolved claims, absent witnesses and zero-tool
scopes. No source study result is an independent human V2 reference or
certified TP/FP/FN/TN.

Existing exact-head Python 3.11/3.12/Ruff, CodeQL, Fresh16, Full60,
source-shadow study and same-head accuracy gates remain fully required.
#558 administrator-required main gate, complete #606 independent source
truth, unseen external D01 custody and runtime authority verification
remain NO-GO prerequisites for C03/C04 cutover.

A dedicated Playwright Chromium smoke in the source-shadow workflow checks all
three server sites, 25 tool cards, same-name distinct instances, per-node
connected-component focus, unrelated-node defocus without removal, keyboard
Enter activation, Show all reset, and mobile viewport retention. Any browser
JavaScript error fails the study. The HTML remains offline and source-only.

Client configuration cards now explicitly display the **source agent context**;
selecting any linked server or tool includes connected source agent names in
the inspection panel. These are source-discovered ownership contexts, **not**
proof the named agent can invoke the MCP server in a deployed environment.
