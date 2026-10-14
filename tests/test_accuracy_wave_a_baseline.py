"""Wave-A source freeze is a retrospective diagnostic, not blind truth."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.verify_accuracy_wave_a_baseline import ROOT, BaselineError, audit

MANIFEST = ROOT / "research/accuracy-wave-a-retrospective-20261014/cohort.json"


def test_wave_a_baseline_pins_exact_source_cohorts() -> None:
    result = audit(MANIFEST, ROOT)
    assert result["cases"] == 30
    assert result["framework_counts"]["mcp-custom"] == 4
    assert result["independent_blind_reference"] is False
    assert result["accuracy_validated"] is False


def test_wave_a_baseline_rejects_source_sha_drift(tmp_path: Path) -> None:
    payload = json.loads(MANIFEST.read_text())
    payload["cases"][0]["sha"] = "0" * 40
    changed = tmp_path / "cohort.json"
    changed.write_text(json.dumps(payload))
    with pytest.raises(BaselineError, match="pinned sha drift"):
        audit(changed, ROOT)


def test_wave_a_baseline_rejects_false_blind_claim(tmp_path: Path) -> None:
    payload = json.loads(MANIFEST.read_text())
    payload["status"] = "independently_validated"
    changed = tmp_path / "cohort.json"
    changed.write_text(json.dumps(payload))
    with pytest.raises(BaselineError, match="explicitly retrospective"):
        audit(changed, ROOT)


def test_wave_a_baseline_rejects_redefined_repository_root(tmp_path: Path) -> None:
    payload = json.loads(MANIFEST.read_text())
    payload["cases"][0]["application_path"] = "not-the-original-root"
    changed = tmp_path / "cohort.json"
    changed.write_text(json.dumps(payload))
    with pytest.raises(BaselineError, match="application root drift"):
        audit(changed, ROOT)
