"""rw001 six exact source-file positive/negative FastAgent census fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

from scripts import verify_wave_b540_rw001_fastagent_negatives as module


def fixture(tmp_path: Path, monkeypatch):
    files: dict[str, bytes] = {}
    positives = set()
    commented = {}
    factory_lines = {}
    frozen = {
        "case_id": "rw-001",
        "source_reference": {"repo": module.REPO, "sha": module.SHA},
        "truth_lock": {"reviewed": True, "horustrace_output_seen": False},
        "tier_a": {"reference_completeness": {"agent_entities": True}},
        "assertions": [],
    }
    for i, path in enumerate(module.BLOBS):
        name = f"source_agent_{i}"
        code = ["from fast_agent import FastAgent", "", "", "",
                "fast = FastAgent('fixture')"]
        if i < 2:
            code.append("# @fast.agent(name='not_registered')")
            commented[path] = 1
        else:
            code.append("# ordinary comment")
        code += [f"@fast.agent(name='{name}')", "async def demo(): pass"]
        raw = ("\n".join(code) + "\n").encode()
        full = tmp_path / module.ROOT / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(raw)
        files[path] = raw
        factory_lines[path] = 5
        positives.add((path, name, 7))
        frozen["assertions"].append({
            "expected_state": "present", "predicate": "explicit_agent_entity",
            "subject": "fast", "evidence": [
                {"path": f"{module.ROOT}/{path}", "line": 5}
            ],
        })
    monkeypatch.setattr(module, "BLOBS", {
        path: module.git_blob(raw) for path, raw in files.items()
    })
    monkeypatch.setattr(module, "FACTORY_LINES", factory_lines)
    monkeypatch.setattr(module, "AGENT_LINES", positives)
    monkeypatch.setattr(module, "COMMENTED_DECORATORS", commented)
    return files, frozen


def test_positive_and_negative_census_does_not_certify_v2(tmp_path, monkeypatch):
    files, original = fixture(tmp_path, monkeypatch)
    result = module.prove(files, tmp_path, original)
    assert result["source_positive_agent_count"] == 6
    assert result["source_hard_negative_factory_count"] == 6
    assert result["historical_agent_positive_factory_conflicts"] == 6
    assert result["commented_decorators_not_active"] == 2
    assert result["original_reference_agent_complete_flag"] is True
    assert result["historical_reference_rewritten"] is False
    assert result["independent_blind_v2_source_truth"] is False
    assert result["agent_precision"] is None and result["agent_recall"] is None
    assert result["wave_b_go"] is False and result["wave_c_go"] is False


def test_mutated_blob_fails_closed(tmp_path, monkeypatch):
    files, original = fixture(tmp_path, monkeypatch)
    first = next(iter(files))
    files[first] += b"# added\n"
    with pytest.raises(ValueError, match="pinned source blob changed"):
        module.prove(files, tmp_path, original)


def test_missing_file_does_not_mean_no_source_agent(tmp_path, monkeypatch):
    files, original = fixture(tmp_path, monkeypatch)
    files.pop(next(iter(files)))
    with pytest.raises(ValueError, match="complete pinned"):
        module.prove(files, tmp_path, original)


def test_missing_factory_can_never_count_as_agent(tmp_path, monkeypatch):
    files, original = fixture(tmp_path, monkeypatch)
    first = next(iter(files))
    changed = files[first].replace(b"FastAgent('fixture')", b"OtherApp('fixture')")
    files[first] = changed
    (tmp_path / module.ROOT / first).write_bytes(changed)
    monkeypatch.setattr(module, "BLOBS", {
        **module.BLOBS, first: module.git_blob(changed)
    })
    with pytest.raises(ValueError, match="app factory role"):
        module.prove(files, tmp_path, original)


def test_commented_out_decorator_does_not_become_agent(tmp_path, monkeypatch):
    files, original = fixture(tmp_path, monkeypatch)
    path = next(iter(module.COMMENTED_DECORATORS))
    raw = files[path].replace(b"# @fast.agent", b"@fast.agent")
    files[path] = raw
    (tmp_path / module.ROOT / path).write_bytes(raw)
    monkeypatch.setattr(module, "BLOBS", {
        **module.BLOBS, path: module.git_blob(raw)
    })
    with pytest.raises(ValueError, match="scanner agent identity|commented source|eight decorated"):
        module.prove(files, tmp_path, original)


def test_historical_reference_false_completeness_not_silently_reclassified(
    tmp_path, monkeypatch,
):
    files, original = fixture(tmp_path, monkeypatch)
    original["tier_a"]["reference_completeness"]["agent_entities"] = False
    with pytest.raises(ValueError, match="original complete-flagged"):
        module.prove(files, tmp_path, original)


def test_historical_source_positive_factory_conflict_must_be_explicit(
    tmp_path, monkeypatch,
):
    files, original = fixture(tmp_path, monkeypatch)
    original["assertions"].pop()
    with pytest.raises(ValueError, match="historical factory-as-agent"):
        module.prove(files, tmp_path, original)


def test_v2_negative_is_not_deployed_permission_assertion(tmp_path, monkeypatch):
    files, original = fixture(tmp_path, monkeypatch)
    report = module.prove(files, tmp_path, original)
    assert all(r["label"] == "source_negative_app_factory_not_agent"
               for r in report["source_hard_negative_factories"])
    assert not report["runtime_instance_verified"]
    assert report["source_negative_panel_limited"]
    assert report["agent_recall"] is None
