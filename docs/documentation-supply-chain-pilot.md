# Documentation-backed agent supply-chain benchmark — isolated pilot

**Status:** Experimental, diagnostic only. **Does not modify or depend on Wave C C02.**

## Objective

Determine whether HorusScan recovers concrete, independently published
agent-supply-chain architecture from a repository at an immutable commit.
Use documented structures to find **possible scanner coverage gaps** before
commissioning a full independent source or runtime adjudication.

The first case is
[aws-samples/sample-cloudops-multi-agent-system](https://github.com/aws-samples/sample-cloudops-multi-agent-system)
at commit `143dbbcdca91ca5ba7dd7c118e384bb0878314c2`.
Its own `docs/architecture.md` describes `src/agents/hierarchy.json`
as the source of truth for agent roles, children and allowed tool groups.
Both source document Git blob IDs are frozen in
`research/documentation-supply-chain-pilot/aws-cloudops-reference.json`.

The reference has **11 configured named agents, 10 directed child links
and 13 agent-to-tool-group assignments** (12 distinct group labels).
It was curated from the published architecture and configuration without
reading HorusScan's scan output. The workflow verifies source and documentation
identities and exact bounded claims before invoking the scanner.

## Execution

GitHub Actions: **Documentation-Backed Agent Supply Chain Pilot**

Trigger via **Actions → Documentation-Backed Agent Supply Chain Pilot → Run workflow**
or by a PR changing the experiment files. It deliberately does not run on every
push or alter the default quality gates.

The workflow checks out HorusScan, installs the local scanner, runs isolated
unit tests, fetches the exact upstream Git commit, verifies the frozen
source documents and reference, runs a static scan **without importing or
executing target application code**, and compares the emitted ADG against
the reference's typed hierarchy claims.

Results:

- `summary.md`: readable per-dimension result in the Actions job summary.
- `comparison.json`: documented/matched/unmatched/scanner-only evidence.
- `scanner-adg.json`: actual scanner graph for audit.
- `reference.json`: exact reviewed pilot reference used by the run.

The files are uploaded as the
`documentation-supply-chain-aws-cloudops` artifact.

To reproduce locally after checking out the exact target SHA:

```bash
python -m pip install -e . 'pytest>=8.3,<9'
python -m pytest -q tests/test_documentation_supply_chain_pilot.py
python -m scripts.documentation_supply_chain_pilot \
  --checkout ./study-target \
  --reference research/documentation-supply-chain-pilot/aws-cloudops-reference.json \
  --output ./documented-supply-chain-report
```

## Interpretation and limitations

**CI success means evidence integrity, tests and scanner execution succeeded,
not that inventory accuracy passed.** The first run should expose missing or
misclassified elements without blocking engineering on an arbitrary count floor.

- A source-configured named agent is not necessarily a runtime-created agent
  instance; compare this reference to the scanner's ADG `agent` entities as
  a possible *ontology disagreement* until reconciled.
- An explicit `children` entry is a declared delegation configuration.
  Only the typed `DELEGATES_TO` edge satisfies the initial exact-edge check.
  Runtime reachability, transport authentication and actual calls are not proved.
- A configured gateway **tool group** is not an individual MCP tool export.
  Exact-label `INVOKES` links are candidates, never accepted authority
  or tool recall measurements.
- Source documents can omit real features. A scanner-only entity is a review
  candidate, **not a verified false positive**.
- There is no exhaustively labelled negative universe, no independent human
  reviewer, no full security finding or attack-path validation, and no
  deployment/runtime evidence. Precision, recall, certified FP/FN and
  production cutover stay `null` / false.
- This case has been examined in the conversation, so it is a development
  pilot, **not a new blind holdout**.
- If the pinned upstream SHA or Git blobs are unavailable, fail the integrity
  run; never silently fall back to `main` or relabel a changed source.

## Next experiment decision

After the first comparison, inspect each unmatched identity, delegation
and binding against its exact source site. Distinguish **detector gap**,
**scope/ontology difference**, **expected non-runtime configuration** and
**unresolved dependency/runtime effect**. Add a second framework with equally
rich authored documentation and a genuinely untouched reference before
expanding to a larger cohort.

This workflow remains isolated from the existing C02 oracle, active-145
measurement denominators, protected release gates and Wave C GO/NO-GO rules.

## Independent source-only diagnostic (research update)

The pilot also exports `configured-source-shadow.json` from an **explicitly selected** `src/agents/hierarchy.json` manifest, verified against exact Git HEAD, tracked blob and current worktree SHA-256. This parallel parser records configured agents, declared child links and **gateway tool-group labels** by JSON pointer. These are not runtime instances, callable tools or an authoritative canonical graph. The original scanner's 0/11, 0/10 and 0/13 comparison remains visible, unchanged, alongside source declaration alignment.

Because the published reference and source-only reader are both derived from the same configuration, source alignment is mechanical corroboration, **not** independent accuracy adjudication or proof of improved canonical scanner recovery. Subsequent C03 work must reconcile source declarations with the scanner's typed Graph through explicit role-preserving adapters and hard negatives, before any production projection decision.
