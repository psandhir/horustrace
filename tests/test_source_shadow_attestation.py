"""C02x exact-source SHA-256 and Git blob/HEAD attestation hard negatives."""
from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.source_shadow_attestation import (
    seal_mcp_source_shadow,
    verify_mcp_source_shadow,
)
from horustrace.source_shadow_workbench import project_mcp_source_overlay


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _checkout(root: Path) -> None:
    root.mkdir(exist_ok=True)
    (root / "agent.py").write_text("agent client source\n", encoding="utf-8")
    (root / "server.py").write_text(
        'mcp = FastMCP("Calculator")\n'
        '@mcp.tool()\n'
        'def add(a, b): return a + b\n',
        encoding="utf-8",
    )
    _git(root, "init", "-q")
    _git(root, "add", "agent.py", "server.py")
    _git(root, "-c", "user.name=C02x Test",
         "-c", "user.email=c02x@example.test", "commit", "-qm", "source")


def _source() -> dict:
    nodes = [
        {
            "id": "shadow-mcp:client", "kind": "mcp_client_configuration",
            "name": "configured", "agent": "agent_1",
            "location": {"path": "agent.py", "line": 1},
            "source_only": True, "deployment_verified": False,
            "effective_authority": "unknown",
        },
        {
            "id": "shadow-mcp:server", "kind": "mcp_source_implementation",
            "name": "Calculator", "location": {"path": "server.py", "line": 1},
            "source_only": True, "deployment_verified": False,
            "effective_authority": "unknown",
        },
        {
            "id": "shadow-mcp:tool", "kind": "mcp_source_tool",
            "name": "add", "location": {"path": "server.py", "line": 3},
            "source_only": True, "deployment_verified": False,
            "effective_authority": "unknown",
        },
    ]
    edges = [
        {
            "id": "a", "kind": "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION",
            "source": nodes[0]["id"], "target": nodes[1]["id"],
            "source_only": True, "effective_agent_can_call": None,
        },
        {
            "id": "b", "kind": "EXPOSES_TOOL",
            "source": nodes[1]["id"], "target": nodes[2]["id"],
            "source_only": True, "effective_agent_can_call": None,
        },
    ]
    return {
        "schema_version": 1,
        "mode": "local_stdio_source_implementation_shadow_not_production_adg",
        "nodes": nodes, "edges": edges,
        "edge_kinds": {
            "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION": 1, "EXPOSES_TOOL": 1,
        },
        "unresolved": [],
        "production_cutover_authorized": False,
        "effective_authority_verified": False,
        "runtime_tool_catalogue_verified": False,
    }


def test_c02x_exact_git_sources_roundtrip_deterministic_and_source_only(
    tmp_path: Path,
) -> None:
    _checkout(tmp_path)
    raw = _source()
    saved = deepcopy(raw)
    sealed = seal_mcp_source_shadow(raw, tmp_path)
    assert raw == saved
    assert sealed == seal_mcp_source_shadow(raw, tmp_path)
    assert sealed["schema_version"] == 2
    manifest = sealed["source_revision"]
    assert len(manifest["commit_sha"]) == 40
    assert [x["path"] for x in manifest["files"]] == ["agent.py", "server.py"]
    assert all(len(x["sha256"]) == 64 and len(x["git_blob_sha"]) == 40
               and x["git_mode"] == "100644" for x in manifest["files"])
    assert manifest["runtime_effective_authority_verified"] is False
    assert manifest["independently_adjudicated"] is False
    verify_mcp_source_shadow(json.loads(json.dumps(sealed)), tmp_path)
    overlay = project_mcp_source_overlay(sealed, tmp_path)
    assert len(overlay["nodes"]) == 3
    assert len(overlay["edges"]) == 2
    assert overlay["runtime_authority_verified"] is False


def test_c02x_legacy_v1_is_not_valid_workbench_evidence(tmp_path: Path) -> None:
    _checkout(tmp_path)
    with pytest.raises(ValueError, match="legacy/unsealed"):
        project_mcp_source_overlay(_source(), tmp_path)


def test_c02x_dirty_file_same_lines_and_size_is_rejected(tmp_path: Path) -> None:
    _checkout(tmp_path)
    evidence = seal_mcp_source_shadow(_source(), tmp_path)
    path = tmp_path / "server.py"
    path.write_text(path.read_text().replace("Calculator", "CalculatoR"))
    with pytest.raises(ValueError, match="changed MCP source"):
        project_mcp_source_overlay(evidence, tmp_path)


def test_c02x_pinned_commit_change_fails_even_if_files_equal(tmp_path: Path) -> None:
    _checkout(tmp_path)
    evidence = seal_mcp_source_shadow(_source(), tmp_path)
    (tmp_path / "README.md").write_text("new unrelated readme\n")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "-c", "user.name=C02x Test",
         "-c", "user.email=c02x@example.test", "commit", "-qm", "new commit")
    with pytest.raises(ValueError, match="checked-out commit"):
        verify_mcp_source_shadow(evidence, tmp_path)


@pytest.mark.parametrize("mutation", [
    lambda d: d["source_revision"].pop("files"),
    lambda d: d["source_revision"].update({"files": []}),
    lambda d: d["source_revision"]["files"].append(
        deepcopy(d["source_revision"]["files"][0])
    ),
    lambda d: d["source_revision"]["files"][0].update({
        "sha256": "0" * 64,
    }),
    lambda d: d["source_revision"]["files"][1].update({
        "git_blob_sha": "f" * 40,
    }),
    lambda d: d["source_revision"]["files"][0].update({
        "size_bytes": 0,
    }),
    lambda d: d["source_revision"]["files"][0].update({
        "git_mode": "120000",
    }),
    lambda d: d["source_revision"].update({
        "independently_adjudicated": True,
    }),
    lambda d: d["source_revision"].update({
        "runtime_effective_authority_verified": True,
    }),
    lambda d: d["source_revision"].update({
        "commit_sha": "a" * 40,
    }),
    lambda d: d["nodes"][1]["location"].update({
        "path": "new-untracked.py",
    }),
    lambda d: d["nodes"][1]["location"].update({
        "path": "agent.py",
    }),
])
def test_c02x_tampered_or_partial_manifest_fails_closed(
    tmp_path: Path, mutation,
) -> None:
    _checkout(tmp_path)
    sealed = seal_mcp_source_shadow(_source(), tmp_path)
    mutation(sealed)
    with pytest.raises(ValueError):
        verify_mcp_source_shadow(sealed, tmp_path)


def test_c02x_uncommitted_and_symlink_sources_cannot_be_attested(
    tmp_path: Path,
) -> None:
    _checkout(tmp_path)
    evidence = seal_mcp_source_shadow(_source(), tmp_path)
    outside = tmp_path.parent / (tmp_path.name + "-outside.py")
    outside.write_text("shadow source\n")
    path = tmp_path / "server.py"
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(ValueError):
        verify_mcp_source_shadow(evidence, tmp_path)


def test_c02x_sealing_untracked_or_missing_git_checkout_is_forbidden(
    tmp_path: Path,
) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "agent.py").write_text("source\n")
    (plain / "server.py").write_text("source\n" * 4)
    with pytest.raises(ValueError, match="Git checkout"):
        seal_mcp_source_shadow(_source(), plain)
    tracked = tmp_path / "tracked"
    _checkout(tracked)
    (tracked / "server.py").unlink()
    with pytest.raises(FileNotFoundError):
        seal_mcp_source_shadow(_source(), tracked)


def test_c02x_clean_source_with_unrelated_uncommitted_file_still_matches(
    tmp_path: Path,
) -> None:
    _checkout(tmp_path)
    sealed = seal_mcp_source_shadow(_source(), tmp_path)
    (tmp_path / "unrelated.txt").write_text("not in declared source universe")
    verify_mcp_source_shadow(sealed, tmp_path)
