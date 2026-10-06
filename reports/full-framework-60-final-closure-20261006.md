# Full-Framework 60 Final Closure — 2026-10-06

## Decision

The P0/P1 remediation cycle opened by the original full-framework 60-repository study is **closed**.

The final scanner was executed against the exact frozen 60-repository cohort: 10 pinned repositories each for Google ADK, Pydantic AI, OpenAI Agents SDK, Amazon Strands / AgentCore, Anthropic Claude / Managed Agents, and the Microsoft agentic stack.

Final execution completed **60/60 repository scans with 0 scan errors and 0 zero-agent cases**.

This report is an auditable closure baseline, not a claim of perfect recall or uniformly complete authority resolution.

## Integrity

- Original study PR: #391
- Original scanner baseline: `bf02b7e831973ff733b6fab369094ce784e1a1bd`
- Frozen cohort blob: `1ea88dbb611cb7c0a81d5b8717553ef539cbdd49`
- Final scanner on merged `main`: `586d95c66c8fe3e98e86b8f2aeb4601feddf4b8b`
- Final study harness revision: `eeec7592971ac5e222b808bd152cffd5e50e27cb`
- Final workflow run: `37529141432`
- Frozen repositories present: **60/60**
- Scan errors: **0**
- Zero-agent cases: **0**

## Final aggregate

| Framework | Repos | Agents | Findings | Attack paths | Effective Authority relationships | Diagnostics | Zero-agent |
|---|---:|---:|---:|---:|---:|---:|---:|
| Amazon | 10 | 28 | 65 | 0 | 144 | 54 | 0 |
| Anthropic | 10 | 31 | 115 | 5 | 145 | 40 | 0 |
| Google ADK | 10 | 74 | 47 | 4 | 102 | 18 | 0 |
| Microsoft | 10 | 21 | 76 | 0 | 38 | 8 | 0 |
| OpenAI Agents | 10 | 82 | 71 | 1 | 143 | 27 | 0 |
| Pydantic AI | 10 | 14 | 34 | 4 | 34 | 9 | 0 |
| **Total** | **60** | **250** | **408** | **14** | **606** | **156** | **0** |

### Change from the original #391 baseline

| Signal | Original | Final | Delta |
|---|---:|---:|---:|
| Agents | 246 | 250 | +4 |
| Findings | 430 | 408 | -22 |
| Attack paths | 24 | 14 | -10 |
| Effective Authority relationships | 591 | 606 | +15 |
| Diagnostics | 161 | 156 | -5 |
| Zero-agent cases | 2 | 0 | -2 |

The reduction in findings and attack paths is primarily precision improvement, not loss of scanning breadth: unsupported transport/name-derived effects, non-runtime paths and over-projected tool surfaces were removed while repository composition and explicit unresolved authority were strengthened.

## Effective Authority resolution

Final core-resolution signal:

- **479 / 606 (79.0%) core fully resolved**
- **127 / 606 core partially resolved**
- **0 core unknown**
- strict/detail resolution remains partial for all 606 relationships when dimensions such as identity, resource, destination or approval detail are unresolved

The 79.0% figure is a **resolution/completeness metric**, not an accuracy score.

Relationship source contexts:

- runtime: 451
- test: 59
- example: 56
- notebook: 22
- CLI: 12
- application-support: 6

Network destination signal:

- restricted / source-bounded destinations: **72 / 107**

## Attack-path signal

Final attack paths: **14**

- source-bound ingress authority: 6
- capability co-occurrence: 5
- static dataflow: 3

Attack-path count reduction from the original baseline reflects removal of unsupported/non-runtime path construction, especially in OpenAI mixed conformance/test surfaces.

## Ordered remediation completed

The seven remediation areas identified by #391 were implemented and validated:

1. **Source-grounded effect semantics** — #395
   - request transport no longer manufactures mutation authority;
   - body/effect semantics dominate names and transport;
   - transitive effects are bounded.

2. **Anthropic explicit tool-surface semantics** — #396
   - explicit allowed/empty/restricted surfaces preserved;
   - Managed Agent construction and allowed-host provenance improved.

3. **Repository and dynamic composition** — #397
   - Google ADK MCP/A2A composition;
   - Pydantic MCP/registrar composition;
   - OpenAI wrappers;
   - Amazon Graph/Swarm;
   - Microsoft workflow topology.

4. **Destination/resource provenance** — #398
   - fixed/provider/localhost/operator-configured destinations retain provenance rather than becoming arbitrary egress.

5. **Framework-neutral attack-path ingress** — #399
   - source-bound ingress is reconstructed beyond the original framework subset.

6. **Source-context classification** — #400
   - test/spec/conformance/example/generated surfaces no longer automatically become live runtime authority or live attack paths.

7. **Effective Authority resolution UX** — #401
   - core authority resolution is separated from detail completeness.

The exact frozen cohort was then rerun in #402.

## Residuals found by #402 and closed

### Anthropic composed option controls — #403, #406, #407

#403 preserved composed TypeScript allow/deny/control semantics through typed bindings, imported option builders and object spreads.

The targeted frozen-case rerun exposed a real parser defect: an apostrophe inside a TypeScript `//` comment could confuse delimiter balancing and prevent imported option-builder reconstruction. #406 made balancing comment-aware and added the real-world regression shape.

Final closure review then found a normalization mismatch:

- Claude TypeScript adapter emitted `enforcing_tool_control`;
- shared Effective Authority and rule evaluation consume `tool_control_enforcing`.

#407 normalized the metadata contract and records the concrete mechanism (`canUseTool`, `PreToolUse`, or both). It also fixed the framework-specific CI path filters so TypeScript Claude changes automatically trigger Anthropic Depth Parity and Claude Generalization suites.

Real-world merged-main validation on `ff60-anthropic-06` proves:

- source-proven controlled agents are detected;
- affected tool approval dimensions resolve through inherited control;
- `inherited_control=true`;
- AGT040 is not emitted on source-proven controlled agents.

Compared with the immediately preceding pre-#407 full cohort, #407 removed **15 false AGT040 control-gap findings**:
- Anthropic-06: -8
- Anthropic-07: -6
- OpenAI-labeled mixed-repository case 09: -1 Claude SDK test-surface finding

The OpenAI-labeled delta is not nondeterminism: that frozen repository contains Claude SDK test code, and the removed finding is a Claude `AGT040` finding.

### Amazon literal MCP operation effects — #404

Literal MCP operations such as `call_tool_sync(name="create_branch")` are source-classified at the actual MCP invocation boundary and propagate through repository-local callers.

Validated behavior:
- direct create-branch helper obtains `external.write`;
- local caller inherits the mutation effect;
- instructions-only helper remains non-mutating;
- read-only literal MCP operations remain reads.

### Dynamic Managed Agent tool catalogues — #405

A source-visible but non-enumerable Managed Agent `tools=` expression is now represented as first-class unresolved authority rather than disappearing from the authority graph.

The scanner:
- records an explicit dynamic tool collection;
- retains the source binding expression;
- does not invent catalogue members or capabilities;
- exposes unresolved catalogue/capability dimensions.

## Targeted frozen residual closure

After #403–#406, the exact residual cases were rerun with semantic assertions:

- `ff60-anthropic-06`
- `ff60-anthropic-07`
- `ff60-anthropic-09`
- `ff60-amazon-10`

All four passed.

After #407, `ff60-anthropic-06` was rerun again from merged `main` with explicit assertions for Effective Authority inherited control and AGT040 suppression. It passed.

## Validation on the final product head

#407 merge candidate passed:

- Python 3.11 full CI
- Python 3.12 full CI
- package
- self-scan
- reconciliation
- PR security delta
- CodeQL
- Anthropic Depth Parity 15
- Claude SDK Generalization 12

The final merged scanner was then replayed across the complete frozen 60-repository cohort. All repository scans and final aggregation/comparison passed.

## Known non-blocking limitations

These are not closure blockers for this P0/P1 cycle:

- 127 core relationships remain partially resolved because some source dimensions remain dynamic or unavailable.
- Strict/detail authority completeness remains partial where identity, approval detail, resource or destination evidence is unavailable.
- Amazon and Microsoft emit no attack paths in this specific frozen ten-repository subset. This is a future breadth/calibration topic, not evidence that authority discovery failed.
- Static analysis does not verify runtime authorization or control effectiveness.
- Repository examples/tests remain visible in inventory and findings where appropriate, but are explicitly source-context classified.
- Existing research scripts still contain some Python invalid-escape warnings; these are hygiene issues, not scanner correctness blockers.

## Closure decision

The architecture and remediation approach are sufficiently validated to close this study cycle.

There is no known material P0/P1 correctness defect from the #391 full-framework study left open.

Future framework improvements should use this frozen cohort and final scanner state as a regression reference rather than modifying the cohort to fit new behavior.
