# Authority Contract v1

Authority Contract v1 is the v0.6 repository-local policy model for constraining an
agent's effective authority.

It extends the existing `horustrace.manifest.yaml` agent policy. Existing v0.5 policy
fields remain valid and retain their current semantics.

## Manifest syntax

```yaml
version: 1
agents:
  - name: support-agent
    policy:
      authority:
        allow:
          capabilities:
            - data.read
            - external.write
          identities:
            - support-bot
          resources:
            - tickets/*
          destinations:
            - https://support.example.test
          iam_roles:
            - roles/viewer
          permissions:
            - tickets.read
          oauth_scopes:
            - issues:read
          mcp_servers:
            - github

        deny:
          capabilities:
            - process.execute
            - destructive.write
          iam_roles:
            - roles/owner
          mcp_servers:
            - filesystem

        require_approval_for:
          - external.write

        mcp_tools:
          - server: github
            allow:
              - issues_read
              - issues_update
            deny:
              - repo_delete
```

## Normalized dimensions

The contract separates authority into framework-neutral dimensions:

- capabilities;
- identities;
- resources;
- destinations;
- IAM roles;
- permissions;
- OAuth scopes;
- MCP servers;
- per-server MCP tool scope;
- capabilities that require explicit approval.

String-or-list syntax is accepted for leaf sets. Normalization removes ordering as a
security semantic and emits deterministic sorted values.

## Safety semantics

Authority Contract v1 is static and local-first.

The contract does not make unresolved authority safe. Missing identity, destination,
resource, approval, IAM, OAuth or MCP evidence remains unresolved until the effective
authority evaluator has enough supported evidence to assess the clause.

Unknown fields, invalid nested shapes and non-string authority values fail the manifest
closed rather than being ignored.

## Compatibility

The existing policy fields remain supported:

```yaml
policy:
  required: [data.read]
  deny: [process.execute]
  allowed_resources: [records/*]
  allowed_destinations: [api.example.test]
  require_approval_for: [data.write]
  max_privileged_capabilities: 2
```

Authority Contract v1 is additive to these fields. Evaluation of the new contract
against Effective Authority Relationship v1 is implemented separately so schema
parsing does not silently change legacy finding behavior.


## Evaluation semantics

Authority Contract v1 is evaluated against Effective Authority Relationship v1.

Each relationship with an attached contract receives one of three outcomes:

- `compliant` — supported static evidence satisfies every applicable contract clause;
- `violation` — supported static evidence contradicts at least one contract clause;
- `unresolved` — no violation is proven, but one or more constrained dimensions lack
  sufficient static evidence.

Violation and unresolved records link back to the stable
`authority_relationship_id` and identify the exact contract clause, expected policy
values and observed evidence. Runtime effectiveness remains `not_verified`.

Examples of high-confidence violations include:

- an observed capability explicitly denied by the contract;
- a resource or destination outside an explicit allowlist;
- an observed IAM role, permission or OAuth scope denied by policy;
- an explicitly disabled approval for a capability that requires approval;
- an MCP server outside the allowed server set;
- an MCP server exposing tools outside an explicit contract allowlist.

An unspecified approval state is not treated as approval. It remains unresolved.
Likewise, missing identity/resource/destination evidence does not become a clean policy
result.

### MCP tool scope

Per-server MCP tool contracts distinguish explicit scope from incomplete evidence.

An explicit server allowlist that exposes tools outside the contract is a violation.
A contract requiring an MCP allowlist is also violated when the relationship is known
to be unrestricted or denylist-only. Dynamic filters remain unresolved unless their
effective tool scope can be reconstructed.

For deny-only MCP clauses, HorusTrace reports unresolved when the server catalogue is
unknown and cannot prove whether the denied tool is reachable.


## Scan-time evaluation

A normal scan evaluates any repository Authority Contract alongside the built-in
HorusTrace security rules:

```bash
horustrace scan . --format json --fail-on none
```

The JSON report keeps the channels separate:

- `findings` contains built-in HorusTrace security findings;
- `authority_contract` contains relationship-level contract outcomes, violations and
  unresolved clauses.

Console output renders a separate Authority Contract assessment, and SARIF includes the
same contract report in run properties. Contract evaluation is automatic when a contract
is present; repositories without a contract continue to receive the built-in security
assessment.

CI can enforce current contract violations independently of finding severity:

```bash
horustrace scan . --fail-on none --fail-on-policy-violation
```

This gate fails only on proven `violation` results. `unresolved` remains visible and
non-failing because incomplete evidence is neither proof of compliance nor proof of a
violation.

## Change-aware policy gate

HorusTrace can compare Authority Contract results independently at two Git revisions:

```bash
horustrace diff origin/main..HEAD --fail-on-policy-violation
```

The policy delta keeps four categories separate:

- introduced violations;
- resolved violations;
- introduced unresolved assessments;
- resolved unresolved assessments.

The gate fails only when `introduced_violations` is non-empty. A violation already
present in the base revision is historical policy debt and does not fail a pull request
unless the change introduces a distinct relationship/clause/reason violation.

Violation identity deliberately excludes observed and expected authority values. This
keeps potentially sensitive principals, tokens, destinations, or policy evidence out of
fingerprint inputs and gives the gate a stable structural identity.

Unresolved assessments remain non-failing. They are rendered separately because missing
static evidence is not proof of compliance and is not proof of a violation.

The security-delta report includes base/head violation counts, introduced/resolved
violations, introduced unresolved assessments, the stable authority relationship ID,
contract clause and reason, expected/observed evidence, source context, and trust-boundary
crossings when the effective relationship changed.

In GitHub Actions (v0.6+), enable the same behavior with:

```yaml
with:
  mode: diff
  fail-on-policy-violation: "true"
```

The input defaults to `"false"`, preserving existing Action behavior.
