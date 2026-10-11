# Adversarial evaluation evidence v1

Status: **data contracts and offline test target only** (issue #510). This does **not**
add runtime validation to normal scans, network requests, or a red-team execution engine.
Planning, importers, scorers, and Workbench integration belong to #512–#518.

## Boundaries

1. A static finding or attack path establishes a source-evidence claim, **not** exploitation.
2. External test attempts are explicitly configured and scoped. No repository, MCP server,
   agent, source URL or credential discovered by scanning becomes an executable target.
3. A completed, observed tool action, a denied attempt, a textual answer, an
   infrastructure error and an unexecuted case have **different** meanings.
4. Lack of an observed violation cannot prove absent authority or general runtime safety.
5. The versioned API is deliberately data-only: inputs cannot auto-load plugins.

## Canonical records

- **EvaluationCase:** identity, test family, scope (static scanner, semantic compiler or
  external agent), objective, exact source/scanner revisions, ASG digest, optional Authority
  Contract digest, referenced graph asset IDs, declared assertion IDs, partition and
  transformation lineage. An external-agent case must supply an explicit target reference.
- **Observation:** immutable evidence ID, turn index, event type, attempted / denied /
  completed / informational effect and optional content-addressed artifact digest.
- **Assertion:** exact ID, supported / refuted / unresolved, scorer ID/version, rationale
  and references to observations from the **same attempt**. A decisive assertion without
  evidence is rejected.
- **Attempt:** attempt ID, run case ID, execution status, scoped outcome, evidence,
  assertions and errors. Timed-out, failed or skipped attempts cannot claim control
  enforcement or a policy violation.
- **EvaluationResult:** one pinned case plus uniquely identified attempts. Assertions
  not declared by the case and cross-case observations are rejected.

Schema: docs/schemas/adversarial-evaluation-v1.schema.json. The Python parser is also
a strict semantic validator; a JSON Schema pass alone does not validate relationships.
The on-wire format is JSON and every object carries the v1 contract where applicable.
All values are bounded. Duplicate JSON keys, unknown fields/versions, ambiguous IDs,
stale ASG/contract pins and dangling references fail with explicit diagnostics.

## Scoped outcomes

| Outcome | Meaning |
| --- | --- |
| not_executed | No valid completed evaluation. **Not** evidence of protection. |
| unresolved | Evidence or validation conditions insufficient. |
| policy_violation | A supported assertion and completed observed action in the tested environment. |
| control_enforced | A supported assertion and observed denial in the tested environment. |
| no_violation_observed | A completed valid attempt with supported, explicitly scoped assertion. |

A free-text refusal without tool events cannot prove a control blocked a tool. A
completed unsafe action cannot be negated by a text refusal. The contract checks
basic evidence integrity; #512 adds policy-specific event-ordering and effect scorers.

## ASG binding

Call validate_case_bindings(case, agent_security_graph.as_dict(), ...) before use.
It recomputes the canonical ASG v1 digest, checks the optional authority-contract
digest and validates references against ADG node/edge IDs, flow IDs, attack-path
IDs and effective-authority relationship IDs. The ASG schema and graph semantics
remain unchanged. Source/check-out commit pins remain caller-verifiable evidence;
the ASG itself does not attest to the historical scanner checkout.

## Reproducibility, adoption and migration

The offline FakeEvaluationTarget replays only synthetic observations; it cannot
contact a target, execute subprocesses or read credentials. Protocols provide
minimal generator, transformer, target, scorer and evidence-storage boundaries
for later optional implementations.

Existing benchmark v1 manifests, ASG v1, study G0–G3 packets, runtime evidence
and source adjudications are **not migrated, rewritten or invalidated**. A future
explicit adapter may reference their immutable IDs and translate to v1 cases.
Historical truth and qualification status must not be rewritten by an importer.
New schema versions require a separate reader/migration and explicit version pin;
unknown versions must fail rather than silently fall back.

Example static case (the SHA and digest values shown are dummy fixtures, not attestations):

    {
      "schema_version": 1,
      "case_id": "static.path001.1",
      "family": "flow",
      "scope": "static_scanner",
      "objective": "Check source-backed path to command execution",
      "source_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "scanner_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "asg_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "assertion_ids": ["flow.to.process"],
      "asset_ids": [],
      "partition": "regression"
    }

Programmatic use: EvaluationCase.from_dict(case_json), EvaluationResult.from_json(json_text)
and validate_case_bindings(case, asg). Planning/export and optional runtime execution
are intentionally deferred to their respective issues.
