"""rw-004 pinned ADK constructor/alias/runner/model-client negative fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

from scripts import verify_wave_b540_rw004_adk_negatives as mod


def _fixture(tmp_path: Path, monkeypatch) -> tuple[dict[str, bytes], Path]:
    def assembled(length: int, placements: dict[int, str]) -> bytes:
        lines = [""] * length
        for number, code in placements.items():
            lines[number - 1] = code
        return ("\n".join(lines) + "\n").encode()
    source = {
        "agent.py": assembled(108, {
            1: "from google.adk.agents import LlmAgent",
            2: "from google.adk.runners import Runner",
            98: "funnel_agent = LlmAgent(name='FunnelAgent')",
            100: "root_agent = funnel_agent",
            102: "runner = Runner(agent=root_agent)",
        }),
        "agentGemini/agent.py": assembled(40, {
            1: "from google.genai.adk import Agent",
            38: "root_agent = Agent(name='AgroAsesorIA')",
        }),
        "example_simple_agent.py": assembled(5, {
            1: "from google.genai import Client",
            5: "client = Client(api_key='dummy')",
        }),
        "agentGemini/models.py": assembled(3, {
            1: "from pydantic import BaseModel",
            3: "class Customer(BaseModel): pass",
        }),
        "requirements.txt": b"google-genai>=0.1.0\n",
        "pyproject.toml": b'[tool.poetry.dependencies]\ngoogle-genai = "^0.1.0"\n',
    }
    for name, body in source.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    monkeypatch.setattr(mod, "BLOBS", {
        name: mod.git_blob(content) for name, content in source.items()
    })
    return source, tmp_path


def test_positive_constructors_and_hard_negatives(tmp_path: Path, monkeypatch) -> None:
    source, root = _fixture(tmp_path, monkeypatch)
    out = mod.audit(source, root)
    assert out["source_agent_declaration_count"] == 2
    assert {x["agent_name"] for x in out["source_agents"]} == {
        "FunnelAgent", "AgroAsesorIA"
    }
    assert {x["kind"] for x in out["source_hard_negatives"]} >= {
        "alias_not_new_agent", "runner_not_agent",
        "model_api_client_not_agent", "pydantic_data_model_not_agent"
    }
    assert out["source_native_scanner"][0]["source_declared_agent_count"] == 1
    assert out["source_native_scanner"][1]["source_declared_agent_count"] == 1
    assert out["source_import_resolution"]["google.genai.adk.Agent"].endswith(
        "unresolved"
    )
    assert out["agent_precision"] is None and out["agent_recall"] is None
    assert not out["independent_exhaustive_negative_truth"]
    assert not out["wave_b_go"] and not out["wave_c_go"]


def test_source_blob_modification_fails_closed(tmp_path: Path, monkeypatch) -> None:
    source, root = _fixture(tmp_path, monkeypatch)
    source["agent.py"] += b"# changed\n"
    with pytest.raises(ValueError, match="Git blob source mismatch"):
        mod.audit(source, root)


def test_missing_source_file_does_not_imply_no_agent(tmp_path: Path, monkeypatch) -> None:
    source, root = _fixture(tmp_path, monkeypatch)
    del source["agentGemini/agent.py"]
    with pytest.raises(ValueError, match="six exact"):
        mod.audit(source, root)


def test_alias_cannot_be_mislabeled_as_third_agent(tmp_path: Path, monkeypatch) -> None:
    source, root = _fixture(tmp_path, monkeypatch)
    modified = source["agent.py"].replace(
        b"root_agent = funnel_agent", b"root_agent = other"
    )
    source["agent.py"] = modified
    (root / "agent.py").write_bytes(modified)
    monkeypatch.setattr(mod, "BLOBS", {
        **mod.BLOBS, "agent.py": mod.git_blob(modified)
    })
    with pytest.raises(ValueError, match="root_agent alias missing"):
        mod.audit(source, root)


def test_direct_model_client_must_not_become_agent(tmp_path: Path, monkeypatch) -> None:
    source, root = _fixture(tmp_path, monkeypatch)
    modified = source["example_simple_agent.py"].replace(
        b"Client(", b"SomeAgent("
    )
    source["example_simple_agent.py"] = modified
    (root / "example_simple_agent.py").write_bytes(modified)
    monkeypatch.setattr(mod, "BLOBS", {
        **mod.BLOBS,
        "example_simple_agent.py": mod.git_blob(modified)
    })
    with pytest.raises(ValueError, match="model_api_client_not_agent"):
        mod.audit(source, root)


def test_google_genai_adk_import_is_not_proved_installed(tmp_path: Path, monkeypatch) -> None:
    source, root = _fixture(tmp_path, monkeypatch)
    report = mod.audit(source, root)
    assert report["standalone_google_adk_dependency_declared"] is False
    assert report["installed_sdk_version_verified"] is False
    assert not report["effective_tool_authority_verified"]


def test_missing_pydantic_non_agent_control_rejected(tmp_path: Path, monkeypatch) -> None:
    source, root = _fixture(tmp_path, monkeypatch)
    changed = source["agentGemini/models.py"].replace(
        b"BaseModel):", b"Unknown):"
    )
    source["agentGemini/models.py"] = changed
    (root / "agentGemini/models.py").write_bytes(changed)
    monkeypatch.setattr(mod, "BLOBS", {
        **mod.BLOBS, "agentGemini/models.py": mod.git_blob(changed)
    })
    with pytest.raises(ValueError, match="pydantic_data_model_not_agent"):
        mod.audit(source, root)


def test_new_declared_google_adk_package_changes_version_truth(
    tmp_path: Path, monkeypatch,
) -> None:
    source, root = _fixture(tmp_path, monkeypatch)
    changed = source["requirements.txt"] + b"google-adk==1.0\n"
    source["requirements.txt"] = changed
    (root / "requirements.txt").write_bytes(changed)
    monkeypatch.setattr(mod, "BLOBS", {
        **mod.BLOBS, "requirements.txt": mod.git_blob(changed)
    })
    with pytest.raises(ValueError, match="standalone google-adk"):
        mod.audit(source, root)


def test_frozen_pinned_case_identity_and_metrics(tmp_path: Path, monkeypatch) -> None:
    source, root = _fixture(tmp_path, monkeypatch)
    v = mod.audit(source, root)
    assert v["source_sha"] == mod.SHA
    assert v["original_frozen_truth_modified"] is False
    assert v["scope"] == "six_pinned_source_files_not_installed_runtime"
    assert len(v["blob_witnesses"]) == 6
