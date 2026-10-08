# HorusScan / independent-LLM comparison contract v1

This report format is a **static source evidence reference**, not a clone of
HorusScan's detector logic and not a source of automatically true findings.

## Same meaning and field-level matching

| Question | HorusScan source | Independent LLM v1 | Comparison |
|---|---|---|---|
| What are the agents? | `security-graph.json.topology.nodes[kind=agent]` | `entities[kind=agent]` | Framework, real agent instance name, construction path/line and runtime context |
| Which models? | AI BOM, agent model attributes | `entities[kind=model]` and agent references | Model/provider identifier only when source explicit |
| Which tools/MCP/skills? | `topology.nodes/edges`, `scan.skills` | `entities` + `relationships` | Agent-to-tool/MCP/skill binding, transport, allow/deny, provenance |
| Effective authority | `security_graph.effective_authority.relationships` | `relationships` | Agent, target, actual capabilities, identity, resources, destinations, approval, guards, resolution |
| Declared authority contract | `scan.authority_contract` | `authority_contracts` | Only compare to explicitly source-declared allow/deny/require clauses, not an invented org policy |
| Security findings | `scan.findings` | `findings` | Independent issue_type → optional rule-family compatibility, agent, source location, control, severity, effect |
| Attack paths | `security_graph.attack_paths` | `attack_paths` | Ingress, reachable agent/delegate/tool chain, sink effect, control boundary, affected destination/resource |
| OWASP | `scan.owasp_agentic`, finding standards | `findings[].owasp_agentic` | Map only supported assertions; never treat zero findings as safe |
| Incomplete coverage | `security_graph.resolution` | `coverage`, `limitations` | Distinguish unknown source from proven absence |

### Why Phase A never sees rule IDs

The reviewer knows what a source-derived approval gap, cross-owner write, shell
sink, privileged MCP call, untrusted URL, data exfiltration route and delegated
authority are. It does **not** see HorusScan output, `PATH001`, other scanner
rule IDs, scanner severity or a prior answer. The mapping from independently
named `issue_type` to possible rule IDs occurs only in the post-lock
coordinator tool. That avoids artificially boosting agreement by showing the
reviewer exactly what HorusScan detects.

### What the comparison can and cannot automatically decide

The provisional comparator ranks source anchor agreement, line proximity,
agent identity and compatible rule/sink types. **No word matching or rule ID
alone establishes a TP.** It outputs a side-by-side review queue, not FP/FN
metrics. Two model outputs may describe the same underlying chain and must be
deduplicated by the coordinator, preserving the original reviewer attestations.

Every source-first candidate receives manual adjudication:
- `valid` (source-supported), `invalid`, `unresolved`;
- then `matched`, `partial`, `missed`, `invalid` or `unresolved`
  versus the scanner, with source evidence and scanner index.
- A **complete miss** is a valid source-backed condition with no corresponding
  scanner detection, including missing agent bindings or whole trust-boundary
  chains. An LLM candidate not yet accepted is NOT a false negative.
- For **precision**, assess every one of the 45 scanner paths in Phase B,
  whether a model proposed it or not, and independently assess all critical/
  high plus a rule-by-severity sample of other findings. A candidate LLM
  finding is NOT automatically a true positive.
- Treat partial/conditional/unresolved and coverage-incomplete cases as
  separate, not positives or negatives.
- `exploitability=not_verified` for any static-only proof.

## Quality requirements

1. Two separately executed reviewer calls, preferably distinct providers.
2. Same exact source pack digest and prompt SHA; SHA/version/case identity
   recorded in each locked reviewer envelope.
3. Every referenced path/line must be present in the immutable source pack;
   validation rejects invented anchors and omitted declared entrypoints.
4. Source packs from the original recovery job were corrected: seven
   application entrypoints had been omitted by file ordering or unhandled
   notebook/MDX extensions. The corrected source-only artifact is the **only**
   admissible packet for prospective model review.
5. Bounded packs have `source_coverage=qualified`. For 31 original cases
   with truncation and all other qualified scopes, an absence conclusion needs
   extra source inspection; validation rejects “reviewed no candidate” as a
   definitive negative when coverage is only qualified.
6. Human-verified ground truth is **not** claimed from two LLM reviewers.
   Escalations and important FP/FN judgments may require independent human
   source review before release.
7. Do not alter the frozen 180 source SHAs, and exclude 35 deprecated
   LangGraph cases from all active-framework denominators.

## Commands

Source-only Phase A, one bounded pilot case (requires connected provider
credentials when using the API runner):

```bash
python scripts/run_frozen180_source_llm_review.py \
  --source-root evidence/source-only \
  --case-id rw-038 \
  --judge-a-model <supported-openai-model> \
  --judge-b-model <supported-gemini-model> \
  --output evidence/independent-phase-a
```

Source-only record validation (can also validate a ChatGPT-authored draft, but
a retrospective draft is **not** an independent locked judge):

```bash
python scripts/frozen180_llm_review.py \
  --review evidence/independent-phase-a/source-judge-a/rw-038.json \
  --source-manifest evidence/source-only/rw-038/source-manifest.json \
  --source evidence/source-only/rw-038/source-only.txt
```

After two real reviewer locks, the coordinator can request provisional
comparison using saved scanner artifacts:

```bash
python scripts/frozen180_llm_provisional_compare.py \
  --source-root evidence/source-only \
  --review-root evidence/independent-phase-a \
  --scanner-findings evidence/scanner_findings_pending_review.json \
  --scanner-paths evidence/path_review_packets.json \
  --case-id rw-038 \
  --output evidence/provisional-comparison.json
```

**None of these scripts declares a final accuracy rate.** Phase-B independent
source adjudication, agreement/escalation and the PR #447 study gates remain
mandatory before reporting security TP/FP/FN/complete-miss accuracy.

## Cost and data handling

Every two-judge review produces **two separately billed provider calls per
case** and sends the case's public GitHub source packet to those providers.
The runner defaults to a maximum three cases and cannot review a larger batch
without an explicit confirmation flag. Repo secrets are not required merely
to prepare the packets or compare supplied review results. They are required
only for the opt-in API execution. Model IDs and prompt hashes are retained;
no API keys enter review artifacts.
