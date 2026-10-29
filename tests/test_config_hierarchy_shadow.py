"""Hard negatives for opt-in configured JSON hierarchy declarations."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from horustrace.config_hierarchy_shadow import (
    build_configured_hierarchy_source_shadow as build,
)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True,
        check=True, text=True,
    ).stdout.strip()


def _repo(root: Path, data: dict | str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    source = root / "config.json"
    source.write_text(
        data if isinstance(data, str) else json.dumps(data), encoding="utf-8",
    )
    _git(root, "init", "-q")
    _git(root, "add", "config.json")
    _git(root, "-c", "user.name=Fixture", "-c",
         "user.email=fixture@example.invalid", "commit", "-qm", "fixture")


def _sample() -> dict:
    return {
        "supervisor": {
            "type": "frontend", "dir": "agents/frontend",
            "children": ["finops-agent"],
        },
        "finops-agent": {
            "type": "worker", "dir": "agents/worker",
            "tools": ["cost-explorer", "billing"],
        },
    }


def test_source_only_hierarchy_declared_relationships_and_reproducibility(
    tmp_path: Path,
) -> None:
    _repo(tmp_path, _sample())
    one = build(tmp_path, "config.json")
    two = build(tmp_path, "config.json")
    assert one == two
    assert one["mode"].endswith("not_production_adg")
    assert len([n for n in one["nodes"] if n["kind"] == "configured_agent"]) == 2
    assert len([n for n in one["nodes"] if n["kind"] == "declared_tool_group"]) == 2
    assert one["edge_kinds"] == {
        "CONFIG_DECLARES_CHILD": 1,
        "CONFIG_DECLARES_TOOL_GROUP": 2,
    }
    assert any(e["source"] == "config-agent:supervisor"
               and e["target"] == "config-agent:finops-agent"
               and e["json_pointer"] == "/supervisor/children/0"
               for e in one["edges"])
    assert all(e["kind"] not in {"DELEGATES_TO", "AGENT_CAN_CALL", "INVOKES"}
               for e in one["edges"])
    assert all(e["source_only"] for e in one["edges"])
    assert one["certified_precision"] is None
    assert one["certified_recall"] is None
    assert one["runtime_authority_verified"] is False
    assert one["production_cutover_authorized"] is False


@pytest.mark.parametrize("bad", [
    {},
    {"a": {"type": "tool", "dir": "agents/worker"}},
    {"a": {"type": "worker"}},
    {"a": {"type": "worker", "dir": "../escape"}},
    {"a": {"type": "worker", "dir": "agents/worker", "children": ["missing"]}},
    {"a": {"type": "worker", "dir": "agents/worker", "children": ["a"]}},
    {"a": {"type": "worker", "dir": "agents/worker", "tools": ["x", "x"]}},
    {"a": {"type": "worker", "dir": "agents/worker", "children": "x"}},
])
def test_unsupported_or_invalid_hierarchy_fails_closed(
    tmp_path: Path, bad: dict,
) -> None:
    _repo(tmp_path, bad)
    with pytest.raises(ValueError):
        build(tmp_path, "config.json")


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    _repo(tmp_path,
          '{"a":{"type":"worker","dir":"agents/worker"},'
          '"a":{"type":"worker","dir":"agents/worker"}}')
    with pytest.raises(ValueError, match="duplicate JSON"):
        build(tmp_path, "config.json")


def test_dirty_source_and_stale_revision_do_not_generate_candidate(
    tmp_path: Path,
) -> None:
    _repo(tmp_path, _sample())
    (tmp_path / "config.json").write_text(
        json.dumps({"other": {
            "type": "worker", "dir": "agents/worker",
        }}), encoding="utf-8",
    )
    with pytest.raises(ValueError, match="differs"):
        build(tmp_path, "config.json")


@pytest.mark.parametrize("path", [
    "../config.json", "/config.json", "./config.json",
    "nested/../../config.json", "config.yaml",
])
def test_unsafe_paths_are_not_read(tmp_path: Path, path: str) -> None:
    _repo(tmp_path, _sample())
    with pytest.raises(ValueError, match="unsafe"):
        build(tmp_path, path)


def test_untracked_or_symlinked_json_not_attested(tmp_path: Path) -> None:
    _repo(tmp_path, _sample())
    (tmp_path / "untracked.json").write_text(
        json.dumps(_sample()), encoding="utf-8",
    )
    with pytest.raises(ValueError, match="untracked"):
        build(tmp_path, "untracked.json")
    (tmp_path / "linked.json").symlink_to(tmp_path / "config.json")
    with pytest.raises(ValueError, match="untracked"):
        build(tmp_path, "linked.json")


def test_configured_names_are_not_runtime_permissions(tmp_path: Path) -> None:
    _repo(tmp_path, _sample())
    candidate = build(tmp_path, "config.json")
    assert all(n.get("mcp_tool_export_verified") is False
               for n in candidate["nodes"]
               if n["kind"] == "declared_tool_group")
    assert all(e.get("effective_agent_can_call") is None
               for e in candidate["edges"]
               if e["kind"] == "CONFIG_DECLARES_TOOL_GROUP")
