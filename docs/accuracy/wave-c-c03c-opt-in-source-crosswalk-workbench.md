# Wave C C03c — opt-in source/canonical witness correlations in Security Workbench

This slice follows C03a #640 and C03b #642. No independent adjudicator
is available. **Engineering-only, not C03 production rollout.**

## Usage

```sh
horustrace report /exact/checkout \
  --mcp-source-shadow /path/to/v2/source-shadow.json \
  --mcp-c03-crosswalk-preview \
  --output workbench-with-crosswalk.html
```

The C03 flag requires the already opt-in, v2 **Git revision/blob/worktree
attested** source-shadow input. By itself the C03 flag fails closed. If
absent, the existing default Workbench and source-evidence tab are unchanged.

The CLI recomputes a C03a quarantined candidate and C03b source-site
crosswalk **from the current scan's canonical ADG** and the same attested
source. It never accepts user-supplied correspondence labels as ground truth.

In the **MCP source evidence · Experimental** tab, each source declaration
now optionally carries one of three statuses:

- No exact canonical source-site match (does NOT imply the scanner missed a
  deployed runtime entity).
- Matching canonical source site, requiring exact path + line + name
  (does NOT prove semantic identity).
- Ambiguous canonical source-site matches, with no arbitrary winner.

A summary shows the matched, unmatched and ambiguous counts, while all
original source nodes and edges remain visible and focus/defocus still works.
Every status explicitly says semantic identity and runtime authority are
unverified. `EXPOSES_TOOL` is never promoted to `AGENT_CAN_CALL`.

## Controls / quality gates

- The C03c presentation model is a deep copy of the already verified source
  overlay. It checks exact witness site/name, same Git commit, versioned
  crosswalk digest, node-set completeness and unmodified baseline ADG.
- Stale or wrong source SHA, absent nodes, altered site/name, promoted runtime
  flags or non-attested source files cannot become an overlay.
- The pinned rw080 study additionally generates
  `workbench-with-c03-source-crosswalk.html`, and Chromium verifies that
  every source card displays a correlation and a clear non-authority warning.
- Existing baseline, source-only workbench, browser drills, CI 3.11/3.12,
  CodeQL, Fresh16, Full60, and same-head accuracy gate remain required.

Release GO is **not** established: correspondence is mechanical source-site
corroboration, not independently complete V2 positives/hard negatives, a
sealed externally unseen D01, installed runtime MCP catalogue or identity,
or independently certified precision/recall. C03 production and C04
effective authority/findings/path cutover remain NO-GO. #558 GitHub admin
required accuracy check is still outstanding.
