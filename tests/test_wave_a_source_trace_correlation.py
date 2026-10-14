"""Wave-A trace/source correlation never manufactures accuracy labels."""
from __future__ import annotations

import json

import pytest

from scripts.verify_accuracy_wave_a_assertions import DIRECTORY
from scripts.verify_accuracy_wave_a_baseline import BaselineError
from scripts.wave_a_correlate_source_traces import (
    _scan_relative_path,
    correlate,
)


def _fixture(tmp_path):
    cases = json.loads((DIRECTORY / "cohort.json").read_text())["cases"]
    claims = json.loads((DIRECTORY / "source-assertions.json").read_text())["assertions"]
    first = claims[0]
    for case in cases:
        directory = tmp_path / case["case_id"]
        directory.mkdir()
        result = {
            **{field: case[field] for field in (
                "case_id", "repo", "sha", "framework", "application_path"
            )}
        }
        (directory / "result.json").write_text(json.dumps(result))
        rows = []
        if case["case_id"] == first["case_id"]:
            rows.append({
                "stage": "discovered",
                "action": "added",
                "observation": {
                    "kind": "agent",
                    "source": {
                        "path": _scan_relative_path(
                            first["evidence"]["path"], case["application_path"]
                        ),
                        "line": first["evidence"]["line"],
                    },
                },
            })
        (directory / "trace.json").write_text(json.dumps({
            "events_truncated": False,
            "stages": [{"stage": str(i)} for i in range(11)],
            "events": rows,
        }))
    return first


def test_correlation_covers_all_pinned_cases_without_tp_fp_fn(tmp_path):
    first = _fixture(tmp_path)
    result = correlate(tmp_path)
    assert result["cases_indexed"] == 30
    assert result["assertions_indexed"] == 35
    assert result["independent_adjudication"] is False
    assert result["accuracy"] is None
    observed = next(row for row in result["correlations"] if
                    row["assertion_id"] == first["assertion_id"])
    assert observed["correlation_status"] == "source_file_event_present_semantics_unverified"
    assert observed["near_line_events"] == 1
    assert all(row["accuracy_verdict"] is None for row in result["correlations"])


def test_correlation_fails_if_one_case_absent(tmp_path):
    _fixture(tmp_path)
    case = json.loads((DIRECTORY / "cohort.json").read_text())["cases"][0]
    (tmp_path / case["case_id"] / "result.json").unlink()
    with pytest.raises(BaselineError, match="missing case traces"):
        correlate(tmp_path)


def test_correlation_does_not_accept_modified_source_sha(tmp_path):
    _fixture(tmp_path)
    case = json.loads((DIRECTORY / "cohort.json").read_text())["cases"][0]
    path = tmp_path / case["case_id"] / "result.json"
    document = json.loads(path.read_text())
    document["sha"] = "0" * 40
    path.write_text(json.dumps(document))
    with pytest.raises(BaselineError, match="frozen identity mismatch"):
        correlate(tmp_path)


def test_correlation_keeps_negative_claim_unadjudicated(tmp_path):
    _fixture(tmp_path)
    report = correlate(tmp_path)
    negatives = [x for x in report["correlations"] if x["expected"] == "not_supported"]
    assert len(negatives) == 5
    assert all(x["accuracy_verdict"] is None for x in negatives)
