# Wave C C02w — opt-in source-only MCP evidence inside the standard Workbench

Parent: [#543](https://github.com/psandhir/horustrace/issues/543) / [#606](https://github.com/psandhir/horustrace/issues/606). Depends on merged C02r #629, mechanical MCP AST C02s #630 and offline evidence explorer C02v #633.

## User-facing feature (experimental only)

The standard `horustrace report` now accepts an **explicit opt-in**:

```sh
horustrace report /path/to/the/exact/scanned-repository \
  --mcp-source-shadow /path/to/source-shadow.json \
  --output workbench-mcp-evidence.html
```

The JSON must be the **C02r source-only MCP shadow artifact** from the
*same checkout*. The pinned `rw080` CI study publishes a runnable example:
`workbench-with-mcp-source-evidence.html` alongside the original
`source-shadow.json` and standalone `mcp-source-supply-chain.html`, inside
the workflow artifact `wave-c-c02r-rw080-source-shadow`.

When the flag is set, an extra **MCP source evidence · Experimental** tab
appears next to the canonical **Supply chain** tab. The additional tab shows:

- Three clearly separated columns of source-configured MCP clients (with
  **source agent context**), distinct original server implementation sites,
  and decorated source tool declarations.
- Exact repository-relative source path and line, including preserving
  multiple servers with the same displayed name.
- Clicking a card highlights the *source-declared* connected component;
  unrelated cards remain visible, **defocused**. Click the same card or
  **Show all** to restore the full view. Keyboard Enter works; source names
  and edge counts are visible in an inspector.
- Full explanatory labels that a declared tool exposure is **not**
  deployed/credentialed/runtime-callable authority or a proven attack path.

It is an entirely separate presentation model: neither the shadow artifact
nor the view is injected into the canonical Graph, ASG/ADG, authority
reconstruction, contract engine, findings, OWASP policies or attack paths.

## Validation and defensible scope

The loader refuses an absent, oversized, malformed or non-source-only
artifact, any `AGENT_CAN_CALL`/promoted edge or invalid endpoint, a missing
client source-agent context, duplicate identities, unsafe source path,
out-of-repository symlink, a witness line beyond a source file, or
inconsistent source-edge counts. Input is limited to 4 MiB; each cited
source file is bounded to 2 MiB and only a limited number of nodes/edges
is presented. All input metadata not needed by the UI is discarded.
Dynamic HTML labels are escaped and the inert JSON script payload uses
HTML-safe serialization. No external JavaScript, styles or network calls.

**Crucial limit:** This checks that the supplied source witness file and line
exist inside the checkout; it does **not** compare source blob hashes to a
pinned manifest because this prior C02r artifact schema does not contain
those hashes. It does not establish semantic freshness, independent source
truth, or SDK execution. To use the result as stronger source evidence,
compare the original pinned Git SHA/blob evidence in the C02r study. This
limitation is stated in the Workbench warning.

If the flag is omitted, the experimental tab and all source-shadow data
are **absent**. Default report metrics, all canonical evidence and the
standard Workbench navigation are unchanged.

## Tests and merge gates

- Unit: flag absent/present; canonical `build_visual_report` and ADG
  unchanged; valid scoped artifact; invalid source witness and source
  escape fail closed; HTML/script injection escaping; CLI rejects invalid
  evidence without writing a report.
- Real pinned repo `Amlan66/SSEEnabledMCPAgent@11531239e71b123f25b3c6103ee36a9d614d0032`:
  static scanning, original C02r source-shadow generation, opt-in standard
  report generation and **real Chromium navigation/focus/reset tests**.
  Assert three local stdio server implementations, 25 decorated tools,
  duplicate-name distinct sources, source agent contexts, unchanged
  canonical supply-chain tab and no browser JavaScript errors.
- Preserve **all** full latest-head CI (Python 3.11 / 3.12, Ruff,
  browser-report smoke), CodeQL, Fresh-16, Full-60 and same-head accuracy
  gate. No reduced cohort or relaxed threshold.

## Release status

C02w is a **safe opt-in, source-only Workbench integration**, not a production
C03/C04 graph/authority/attack-path cutover or independently certified
precision/recall. The independent complete V2 source oracle and genuine
unseen D01 in #606 are still missing. #558 still needs an administrator to
make `accuracy-regression-gate` mandatory in main branch protection.
Runtime contracts, including the 12 unresolved Amazon claims, remain
UNKNOWN. All existing release NO-GO conditions remain in effect.
