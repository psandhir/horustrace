"""Adversarial evaluation v1 is data-only, strict and evidence scoped."""
import json
from dataclasses import replace
from pathlib import Path

import pytest

from horustrace.evaluation import (
    EvaluationCase,
    EvaluationContractError,
    EvaluationResult,
    Observation,
    validate_case_bindings,
)
from horustrace.evaluation.validation import FakeEvaluationTarget, _canonical_digest


def _asg():
    document = {
        "schema_version": 1,
        "model": "horustrace.agent_security_graph",
        "topology": {
            "nodes": [{"id": "adg-v1:agent", "kind": "agent"}],
            "edges": [{"id": "edge-v1:invoke", "source": "adg-v1:agent", "target": "adg-v1:tool"}],
        },
        "effective_authority": {"relationships": [{"relationship_id": "authority-v1:tool"}]},
        "attack_paths": [{"path_id": "PATH001"}],
        "flows": [{"flow_id": "flow-v1:1"}],
    }
    document["digest"] = _canonical_digest(document)
    return document


def _case(*, scope="external_agent"):
    return {
        "schema_version": 1,
        "case_id": "eval.shell",
        "family": "command_execution",
        "scope": scope,
        "objective": "Check whether a forbidden process call completes",
        "source_sha": "a" * 40,
        "scanner_sha": "b" * 40,
        "asg_digest": _asg()["digest"],
        "contract_digest": "sha256:" + "c" * 64,
        "target_ref": "fake://explicitly-approved" if scope == "external_agent" else None,
        "assertion_ids": ["forbidden.tool"],
        "asset_ids": ["adg-v1:agent", "edge-v1:invoke", "authority-v1:tool", "flow-v1:1", "PATH001"],
        "partition": "regression",
    }


def _attempt(*, outcome="control_enforced", state="completed", effect="denied"):
    return {
        "attempt_id": "attempt.1",
        "case_id": "eval.shell",
        "execution_state": state,
        "outcome": outcome,
        "observations": [
            {"observation_id": "obs.1", "turn": 0, "kind": "tool_invocation", "effect": effect}
        ],
        "assertions": [
            {"assertion_id": "forbidden.tool", "verdict": "supported", "scorer_id": "event_scoring",
             "scorer_version": "v1", "evidence_ids": ["obs.1"], "rationale": "Observed tool event"}
        ],
        "errors": ["synthetic timeout"] if state == "timed_out" else [],
    }


def _result(case=None, attempts=None):
    return {
        "schema_version": 1,
        "run_id": "eval.run1",
        "case": case or _case(),
        "attempts": attempts if attempts is not None else [_attempt()],
    }


def test_roundtrip_and_pinned_references():
    result = EvaluationResult.from_dict(_result())
    assert EvaluationResult.from_json(result.to_json()) == result
    assert EvaluationResult.from_dict(result.as_dict()) == result
    assert json.loads(result.to_json())["case"]["scope"] == "external_agent"
    validate_case_bindings(
        result.case, _asg(), authority_contract_digest=result.case.contract_digest,
    )


@pytest.mark.parametrize("change", [
    {"schema_version": 3},
    {"scope": "exec_anything"},
    {"source_sha": "a"},
    {"asg_digest": "sha256:untrusted"},
    {"asset_ids": ["adg-v1:agent", "adg-v1:agent"]},
    {"assertion_ids": []},
    {"contract_digest": "unverified"},
    {"unexpected": "ignored?"},
])
def test_invalid_case_fields_rejected(change):
    data = _case()
    data.update(change)
    with pytest.raises(EvaluationContractError):
        EvaluationCase.from_dict(data)


def test_external_case_requires_explicit_target():
    case = _case()
    case["target_ref"] = None
    with pytest.raises(EvaluationContractError, match="target_ref"):
        EvaluationCase.from_dict(case)


def test_stale_or_unbound_graph_and_contract_rejected():
    case = EvaluationCase.from_dict(_case())
    graph = _asg()
    with pytest.raises(EvaluationContractError, match="stale"):
        validate_case_bindings(case, {**graph, "digest": "sha256:" + "f" * 64})
    altered = {**graph, "topology": {"nodes": [], "edges": []}}
    with pytest.raises(EvaluationContractError, match="invalid digest"):
        validate_case_bindings(case, altered)
    with pytest.raises(EvaluationContractError, match="Contract"):
        validate_case_bindings(case, graph)
    broken = replace(case, asset_ids=("adg-v1:unknown",))
    with pytest.raises(EvaluationContractError, match="unknown ASG"):
        validate_case_bindings(
            broken, graph, authority_contract_digest=case.contract_digest,
        )


@pytest.mark.parametrize("state", ["timed_out", "error", "skipped", "started", "not_executed"])
def test_incomplete_attempts_never_claim_control_enforced(state):
    value = _attempt(state=state)
    with pytest.raises(EvaluationContractError, match="incomplete or errored"):
        EvaluationResult.from_dict(_result(attempts=[value]))


def test_policy_violation_requires_observed_completed_effect():
    value = _attempt(outcome="policy_violation")
    with pytest.raises(EvaluationContractError, match="completed effect"):
        EvaluationResult.from_dict(_result(attempts=[value]))
    value["observations"][0]["effect"] = "completed"
    assert EvaluationResult.from_dict(_result(attempts=[value])).attempts[0].outcome == "policy_violation"


def test_control_enforcement_requires_observed_denial():
    value = _attempt(effect="informational")
    with pytest.raises(EvaluationContractError, match="denial"):
        EvaluationResult.from_dict(_result(attempts=[value]))


def test_bare_text_answer_cannot_prove_control():
    value = _attempt(effect="informational")
    value["observations"][0]["kind"] = "final_answer"
    with pytest.raises(EvaluationContractError, match="denial"):
        EvaluationResult.from_dict(_result(attempts=[value]))


def test_static_case_cannot_claim_observed_runtime_outcome():
    with pytest.raises(EvaluationContractError, match="static evaluations"):
        EvaluationResult.from_dict(_result(case=_case(scope="static_scanner")))


def test_missing_and_cross_case_assertion_evidence_rejected():
    value = _attempt()
    value["assertions"][0]["evidence_ids"] = ["foreign.obs"]
    with pytest.raises(EvaluationContractError, match="unknown observation"):
        EvaluationResult.from_dict(_result(attempts=[value]))
    value = _attempt()
    value["assertions"][0]["assertion_id"] = "not_declared"
    with pytest.raises(EvaluationContractError, match="undeclared"):
        EvaluationResult.from_dict(_result(attempts=[value]))


def test_duplicate_attempt_and_observation_identifiers_rejected():
    with pytest.raises(EvaluationContractError, match="duplicate attempt_id"):
        EvaluationResult.from_dict(_result(attempts=[_attempt(), _attempt()]))
    duplicate = _attempt()
    duplicate["observations"].append(dict(duplicate["observations"][0]))
    with pytest.raises(EvaluationContractError, match="duplicate observation_id"):
        EvaluationResult.from_dict(_result(attempts=[duplicate]))


def test_strict_json_disallows_duplicate_keys_and_unknown_version():
    data = EvaluationResult.from_dict(_result()).to_json()
    with pytest.raises(EvaluationContractError, match="duplicate JSON key"):
        EvaluationResult.from_json('{"schema_version":1,"run_id":"a","run_id":"b"}')
    with pytest.raises(EvaluationContractError, match="unsupported schema"):
        EvaluationResult.from_json(data.replace('"schema_version":1', '"schema_version":2'))


def test_synthetic_offline_target_distinguishes_no_decision_from_control():
    case = EvaluationCase.from_dict(_case())
    observation = Observation.from_dict({
        "observation_id": "obs.1", "turn": 0, "kind": "tool_invocation", "effect": "denied",
    })
    attempt = FakeEvaluationTarget((observation,)).execute(case)
    assert attempt.execution_state == "completed"
    assert attempt.outcome == "unresolved"  # a scorer must adjudicate the event
    assert attempt.observations == (observation,)
    for state in ("error", "timed_out", "skipped"):
        attempt = FakeEvaluationTarget((observation,), mode=state).execute(case)
        assert attempt.outcome == "not_executed"
        assert not attempt.observations


def test_documented_json_schema_enumerates_contract_fields():
    path = Path(__file__).resolve().parents[1] / "docs/schemas/adversarial-evaluation-v1.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"] == {"const": 1}
    assert schema["additionalProperties"] is False
    assert "attempt" in schema["$defs"]
    assert "case" in schema["$defs"]
