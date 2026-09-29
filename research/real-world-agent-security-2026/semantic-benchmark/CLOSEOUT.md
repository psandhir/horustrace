# Semantic parity benchmark closeout

## Decision

The seven-case LLM-assisted semantic parity exercise is closed on benchmark v1.1.

The scanner was not changed to satisfy the final rw-085 discrepancy. Source review established that the v1 OpenLegion lower bound of 140 tools was reference noise: seven entries represented duplicate lexical/decorator assertions or example/tool-authoring names rather than effective runtime tools.

The corrected lower bound is 133.

## Evidence trail

- PR #203 baseline: 3/23 semantic assertions.
- PR #206: OpenLegion AgentLoop and custom tool registry became structurally visible; scanner reported 133 effective tools and documented the 140-count reference problem.
- PRs #209–#213: closed web/CLI ingress, persistent-memory, destructive MCP and dynamic remote-MCP policy gaps.
- PR #214: closed the final genuine scanner gap in scoped Google ADK construction identity and validated 22/23 against v1.
- v1.1 changes only rw-085 `summary.tools >= 140` to `summary.tools >= 133`.

Therefore the PR #214 validated scanner state satisfies all 23 v1.1 assertions.

## Boundaries

This is a post-hoc semantic benchmark, not a replacement for the preregistered Frozen-180 metrics.

The original frozen ground truth and benchmark-v1.json remain unchanged. No product-quality claim about attack-path or finding precision/recall is inferred from this closeout; those claims remain gated by the independent-human protocol in Issue #157.
