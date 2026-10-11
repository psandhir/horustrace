"""Append-only evaluation ledger, integrity, redaction and offline rescore."""
import hashlib
import json

import pytest

from horustrace.evaluation.contracts import (
    Attempt,
    EvaluationCase,
    EvaluationContractError,
    Observation,
)
from horustrace.evaluation.ledger import (
    EvaluationLedger,
    digest,
    promote_regression_pair,
)
from horustrace.evaluation.scorers import AssertionSpec
from scripts.replay_adversarial_evaluation import main as replay_main


def _case(partition="regression", objective="synthetic forbidden tool"):
    return EvaluationCase.from_dict({
        "schema_version": 1,
        "case_id": "ledger.case",
        "family": "tool_risk",
        "scope": "external_agent",
        "objective": objective,
        "source_sha": "a" * 40,
        "scanner_sha": "b" * 40,
        "asg_digest": "sha256:" + "c" * 64,
        "contract_digest": "sha256:" + "d" * 64,
        "assertion_ids": ["forbidden"],
        "target_ref": "fake://explicit",
        "transformation_ids": ["import_alias", "parameter_rename"],
        "partition": partition,
    })


def _obs():
    return Observation.from_dict({
        "observation_id": "evt.1", "turn": 0, "kind": "tool_invocation",
        "effect": "completed", "subject_id": "tool.exec",
        "attributes": {"tool_id": "tool.exec", "destination": "unauthorized.test"},
    })


def _attempt(case, *, attempt_id="attempt.1"):
    return Attempt.from_dict({
        "attempt_id": attempt_id, "case_id": case.case_id,
        "execution_state": "completed", "outcome": "unresolved",
        "observations": [_obs().as_dict()], "assertions": [], "errors": [],
    })


def _ledger(tmp_path, *, partition="regression", pins=None):
    return EvaluationLedger.create(
        tmp_path / "bundle", _case(partition), "run.one",
        pins=pins if pins is not None else {
            "harness_version": "v1", "target_model": "local-fake",
            "scorer_version": "v1", "seed": 7,
            "prompt_digest": "sha256:" + "f" * 64,
            "config_digest": "sha256:" + "e" * 64,
        },
    )


def _complete(ledger):
    record = _attempt(ledger.case)
    assert ledger.append("planned", record.attempt_id, {"plan": "synthetic"})
    assert ledger.append("started", record.attempt_id, {"state": "started"})
    assert ledger.append("observed", record.attempt_id,
                         {"observation": _obs().as_dict()})
    assert ledger.append("finished", record.attempt_id, {"attempt": record.as_dict()})
    return record


def test_append_integrity_idempotency_and_sealing(tmp_path):
    ledger = _ledger(tmp_path)
    original = _complete(ledger)
    assert not ledger.append("finished", original.attempt_id,
                             {"attempt": original.as_dict()})
    assert ledger.state("attempt.1") == "completed"
    assert ledger.get_attempt("attempt.1") == original
    data = ledger.validate()
    assert data["events"] == 4
    assert len(data["chain_head"]) == 71
    assert data["incomplete_attempts"] == []
    assert ledger.seal()["chain_head"] == data["chain_head"]
    assert EvaluationLedger(ledger.root).validate() == ledger.seal()
    with pytest.raises(EvaluationContractError, match="sealed"):
        ledger.append("planned", "attempt.2", {"plan": "cannot change sealed history"})


def test_crash_resume_does_not_repeat_uncertain_side_effect(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.append("planned", "attempt.1", {"plan": "synthetic"})
    ledger.append("started", "attempt.1", {"state": "started"})
    assert EvaluationLedger(ledger.root).state("attempt.1") == "unknown"
    with pytest.raises(EvaluationContractError, match="uncertain effect"):
        ledger.append("started", "attempt.1", {"state": "retry"})
    ledger.append("reconciled", "attempt.1", {"disposition": "unknown"})
    assert ledger.state("attempt.1") == "unknown"
    assert ledger.validate()["incomplete_attempts"] == ["attempt.1"]


def test_conflicting_imports_cannot_rewrite_attempt(tmp_path):
    ledger = _ledger(tmp_path)
    _complete(ledger)
    different = _attempt(ledger.case)
    updated = different.as_dict()
    updated["observations"][0]["effect"] = "denied"
    with pytest.raises(EvaluationContractError, match="conflicting finished"):
        ledger.append("finished", "attempt.1", {"attempt": updated})


def test_integrity_detects_tampering_and_truncation(tmp_path):
    ledger = _ledger(tmp_path)
    _complete(ledger)
    path = ledger.root / "events.jsonl"
    data = path.read_bytes()
    path.write_bytes(data.replace(b'"phase":"observed"', b'"phase":"started"', 1))
    with pytest.raises(EvaluationContractError, match="integrity"):
        ledger.validate()
    path.write_bytes(data[:-1])
    with pytest.raises(EvaluationContractError, match="truncated"):
        ledger.validate()


def test_redacted_attachment_preserves_digest_lineage_and_prevents_public_secrets(tmp_path):
    ledger = _ledger(tmp_path)
    text = "Authorization: Bearer testauth999\npassword=topsecret999\nSECRET-privatevalue000"
    result = ledger.attach_text(text)
    assert result["redacted"] is True
    assert result["exact_replay_available"] is False
    file = ledger.root / "attachments" / result["digest"].split(":")[1]
    exposed = file.read_text(encoding="utf-8")
    assert "testauth999" not in exposed and "topsecret999" not in exposed
    assert "privatevalue000" not in exposed
    assert digest(file.read_bytes()) == result["digest"]
    with pytest.raises(EvaluationContractError, match="credential"):
        ledger.append("planned", "attempt.1",
                      {"authorization": "Authorization: Bearer leaksecret999"})


def test_pin_change_requires_distinct_bundle_identity(tmp_path):
    first = _ledger(tmp_path)
    assert first.manifest["pins"]["seed"] == 7
    with pytest.raises(EvaluationContractError, match="already exists"):
        EvaluationLedger.create(first.root, first.case, first.run_id, pins={"seed": 9})
    with pytest.raises(EvaluationContractError, match="credentials"):
        EvaluationLedger.create(
            tmp_path / "other", first.case, "run.two",
            pins={"prompt_digest": "Authorization: Bearer unsafeabc123"},
        )
    assert first.manifest["case"]["transformation_ids"] == [
        "import_alias", "parameter_rename",
    ]


def test_rescore_runs_on_stored_evidence_only_and_append_new_result(tmp_path, capsys):
    ledger = _ledger(tmp_path)
    original = _complete(ledger)
    spec = AssertionSpec("forbidden", "forbidden_tool", tool_id="tool.exec")
    scored = ledger.rescore(
        "attempt.1", (spec,),
        authority_contract_digest=ledger.case.contract_digest,
    )
    assert scored.outcome == "policy_violation"
    assert scored.assertions[0].evidence_ids == ("evt.1",)
    assert ledger.get_attempt("attempt.1") == original  # immutable initial truth
    assert ledger.validate()["events"] == 5
    assert not ledger.append("rescored", "attempt.1", {"attempt": scored.as_dict()})
    with pytest.raises(EvaluationContractError, match="immutable"):
        ledger.append("planned", "attempt.1", {"plan": "retroactively reset attempt"})
    with pytest.raises(EvaluationContractError, match="immutable"):
        ledger.append("reconciled", "attempt.1", {"disposition": "unknown"})
    specs = tmp_path / "specifications.json"
    specs.write_text(json.dumps([{
        "assertion_id": "forbidden", "kind": "forbidden_tool",
        "tool_id": "tool.exec",
    }]), encoding="utf-8")
    assert replay_main(["--bundle", str(ledger.root), "--mode", "validate"]) == 0
    assert "chain_head" in capsys.readouterr().out
    assert replay_main([
        "--bundle", str(ledger.root), "--mode", "replay", "--attempt", "attempt.1",
    ]) == 0
    assert '"target_requests": 0' in capsys.readouterr().out
    assert replay_main([
        "--bundle", str(ledger.root), "--mode", "rescore", "--attempt", "attempt.1",
        "--specifications", str(specs),
        "--authority-contract-digest", ledger.case.contract_digest,
    ]) == 0
    output = capsys.readouterr().out
    assert '"target_requests": 0' in output
    assert '"outcome": "policy_violation"' in output


def test_reviewed_synthetic_pair_promotion_keeps_immutability(tmp_path):
    ledger = _ledger(tmp_path)
    _complete(ledger)
    review = {
        "source_review_status": "independently_source_adjudicated",
        "reviewer": "fixture-author",
        "review_packet_digest": "sha256:" + hashlib.sha256(b"source fixture").hexdigest(),
        "source_anchor": "agent.py:1",
    }
    result = promote_regression_pair(
        ledger, "attempt.1",
        positive_source="def positive():\n    return True\n",
        negative_source="def negative():\n    return False\n",
        adjudication=review,
    )
    assert result["historical_truth_modified"] is False
    assert ledger.validate()["events"] == 4
    with pytest.raises(EvaluationContractError, match="already exists"):
        promote_regression_pair(
            ledger, "attempt.1", positive_source="a",
            negative_source="b", adjudication=review,
        )


def test_promotion_refuses_holdout_and_missing_source_review(tmp_path):
    ledger = _ledger(tmp_path, partition="holdout")
    _complete(ledger)
    with pytest.raises(EvaluationContractError, match="holdout"):
        promote_regression_pair(
            ledger, "attempt.1", positive_source="a", negative_source="b",
            adjudication={},
        )
    other_root = tmp_path / "other"
    other = EvaluationLedger.create(other_root, _case(), "run.second", pins={})
    _complete(other)
    with pytest.raises(EvaluationContractError, match="adjudication"):
        promote_regression_pair(
            other, "attempt.1", positive_source="a", negative_source="b",
            adjudication={},
        )
