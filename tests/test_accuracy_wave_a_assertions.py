"""Wave-A source assertions preserve historical/source-visible review limits."""
import json

import pytest

from scripts.verify_accuracy_wave_a_assertions import DIRECTORY, audit_assertions
from scripts.verify_accuracy_wave_a_baseline import BaselineError


def test_wave_a_source_assertions_validate_without_accuracy_claim():
    report = audit_assertions()
    assert report["source_observations"] == 11
    assert report["independent_blind_review"] is False
    assert report["measured_accuracy"] is None


def test_wave_a_rejects_unreviewed_positive_promotion(tmp_path):
    data = json.loads((DIRECTORY / "source-assertions.json").read_text())
    data["assertions"][0]["review_status"] = "independently_confirmed"
    target = tmp_path / "fake-reviewed.json"
    target.write_text(json.dumps(data))
    with pytest.raises(BaselineError, match="missing reviewer qualification"):
        audit_assertions(ledger_path=target)


def test_wave_a_rejects_claim_without_pinned_code_anchor(tmp_path):
    data = json.loads((DIRECTORY / "source-assertions.json").read_text())
    data["assertions"][0]["evidence"]["source_git_blob_sha"] = "unverified"
    target = tmp_path / "unverified.json"
    target.write_text(json.dumps(data))
    with pytest.raises(BaselineError, match="immutable Git file blob"):
        audit_assertions(ledger_path=target)


def test_wave_a_rejects_fake_blind_truth(tmp_path):
    data = json.loads((DIRECTORY / "source-assertions.json").read_text())
    data["blind_review_completed"] = True
    target = tmp_path / "blind.json"
    target.write_text(json.dumps(data))
    with pytest.raises(BaselineError, match="must not claim"):
        audit_assertions(ledger_path=target)
