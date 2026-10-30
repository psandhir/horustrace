# Wave B #540 / #551 — third-party dependency resolution boundary

**Date: 18 October 2026. Source-only conclusion: 12 outstanding model-reviewed
effect/control claims stay unresolved. Wave B and Wave C remain NO-GO.**

The immutable case `aws-samples/sample-multi-agent-region-expansion-planner
@30d03d7c9f6512e5bf10601879382fac9c3a16b1` does not supply a
reproducible installed dependency closure. GitHub's full pinned tree contains
**29 records**, including `requirements.txt`, and **no Python/npm lockfile
or captured install manifest**. The requirements are literally
`strands-agents-tools`, `mcp[cli]`, `boto3`, `botocore`, all without pins.

## Source-positive vs effective authority

The separate immutable file witnesses, each checked by its **Git blob SHA**,
show five runtime-enumerating MCP clients:

| Source constructor | Launcher/source argument | What remains unresolved |
|---|---|---|
| `src/agents/pricing_explorer.py:69-84` | `uvx awslabs.aws-pricing-mcp-server@latest` | Resolved package digest, tool names, execution and permissions |
| `src/agents/cfn_explorer.py:67-81` | `uvx awslabs.cfn-mcp-server@latest` | Resolved package digest, tool names, execution and permissions |
| `src/agents/planning_report_generator.py:78-91` | `npx mcp-remote https://knowledge-mcp.global.api.aws` | npm proxy version/content, remote catalogue, network/session rights |
| `src/agents/multi_region_expansion_planner.py:80-93` | Same dynamic npx proxy and endpoint | Same |
| `src/agents/waypoint_explorer.py:54-68` | Same dynamic npx proxy and endpoint | Same |

All five dynamically call `MCPClient.list_tools_sync()`, rather than
declaring an immutable result catalogue. The endpoint URL is a **source-
declared configuration**, not proof a connection succeeds, any returned tool
executes, or a data-write destination is authorized. In
`src/utils/config.py:43-46`, the code requests
`BYPASS_TOOL_CONSENT=true`; it cannot prove the installed SDK implements
or honors that request.

The previous upstream source review of `strands-agents/tools@1dd0465...`
establishes that *that specific upstream revision* contains Python execution,
AWS dispatch and conditional approval implementations. It is **not evidence**
that the pinned Amazon application installed that revision. Nor would merely
pinning the *declared* source dependency prove those installed bytes were
executed or that a particular agent actually called a tool.

## Claim-specific disposition (unchanged source labels)

| Group | Historical keys | Source-only disposition |
|---|---|---|
| CAP004, AGT020, CAP003 ×2 | `0de03732933c171d96b4`, `34e0345cd816a7b394f5`, `391d0a5e8be35376802b`, `e9eccd96b25d7aac2746` | Precise per-instance capability conjunction and tool approval unverified |
| AGT040 | `d3388fd929c8794bfce6` | Imported `python_repl` source-visible, installed effect/control unverified |
| NET002 ×7 | `1cd6188f31f7ae6ae9ae`, `2ad096fe63994b320f70`, `36830b3ae86117942e1e`, `84724ebc1b42818721ea`, `9a644fee027e44fe2bd5`, `ae7e4aadfa7c31e34044`, `f37bdf0d899c7565a374` | Configured tool names/endpoints are not actual external/write effects or observed control bypass |

These exact **73 frozen historical claim keys** retain their prior
source-review status partition: 45 conditional source-supported, 16 invalid
historical claim/anchor, **12 unresolved** (4 high, 8 medium). The ledger is
model-reviewed, not independent human truth. The newer `arg-v1` scanner
fingerprints are a different identity space and must not be silently joined
to these older claim hashes.

## Repeatable evidence test / next authoritative input

`.github/workflows/wave-b540-third-party-resolution.yml` downloads
**only** exact immutable source blobs and Git tree metadata from the frozen
repository, checks Git blob hashes, inspects Python AST literal spawn arguments
and dynamic catalogue calls, enforces the 73-claim ledger, and uploads
`evaluation/amazon-third-party-resolution-boundary.json` showing the
missing attestation. Target application dependencies are **never installed
or executed**, no customer credentials are requested, and the test is not
a runtime exploit.

To genuinely resolve actual effects, an explicitly authorized deployed
environment would need to provide: (1) **same-environment installed package
names, versions and wheel/package SHA-256 digests**; (2) `uvx` and `npx`
resolved package identities and artifact digests; (3) runtime MCP catalogue
snapshots *per server, identity and session*, with tool schema/provenance; and
(4) permission/consent configuration and actual tool invocation evidence,
if the claim concerns executed/effective authority. Collect redacted metadata
without secrets or AWS credentials in the artifact. Such runtime evidence
must be evaluated separately by the source/authority verifier with
explicit positive and negative labels and negative-case denominators.

**Immutable repository-only source cannot provide this deployed-environment
evidence.** The research verdict is a bounded **unresolvable-under-source-only
scope**, never a false positive, a confirmed vulnerability, an empty MCP tool
catalogue, or a GO certificate.

#540 remains open. #558 administrator enforcement remains a separate blocker;
LangGraph is excluded only from the active 145-case evaluation.
