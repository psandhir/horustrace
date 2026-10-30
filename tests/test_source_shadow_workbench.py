"""Opt-in source-only MCP Workbench overlay: no canonical security changes."""

from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.adg import build_adg
from horustrace.cli import main
from horustrace.models import Agent, Graph
from horustrace.source_shadow_attestation import seal_mcp_source_shadow
from horustrace.source_shadow_workbench import (
    load_mcp_source_overlay,
    project_mcp_source_overlay,
)
from horustrace.visual_report import build_visual_report, render_visual_report_html


def shadow_fixture() -> dict:
    nodes = [
        {
            "id": "shadow-mcp:config",
            "kind": "mcp_client_configuration",
            "name": "configured-calculator",
            "agent": "example_agent",
            "location": {"path": "agent.py", "line": 1},
            "source_only": True,
            "deployment_verified": False,
            "effective_authority": "unknown",
        },
        {
            "id": "shadow-mcp:server",
            "kind": "mcp_source_implementation",
            "name": "Calculator",
            "location": {"path": "mcp_server.py", "line": 2},
            "source_only": True,
            "deployment_verified": False,
            "effective_authority": "unknown",
        },
        {
            "id": "shadow-mcp:tool",
            "kind": "mcp_source_tool",
            "name": "add",
            "location": {"path": "mcp_server.py", "line": 4},
            "source_only": True,
            "deployment_verified": False,
            "effective_authority": "unknown",
        },
    ]
    edges = [
        {
            "id": "config-server",
            "kind": "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION",
            "source": nodes[0]["id"],
            "target": nodes[1]["id"],
            "source_only": True,
            "effective_agent_can_call": None,
        },
        {
            "id": "server-tool",
            "kind": "EXPOSES_TOOL",
            "source": nodes[1]["id"],
            "target": nodes[2]["id"],
            "source_only": True,
            "effective_agent_can_call": None,
        },
    ]
    return {
        "schema_version": 1,
        "mode": "local_stdio_source_implementation_shadow_not_production_adg",
        "nodes": nodes,
        "edges": edges,
        "edge_kinds": {
            "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION": 1,
            "EXPOSES_TOOL": 1,
        },
        "unresolved": [{"reason": "runtime_catalogue_unknown"}],
        "production_cutover_authorized": False,
        "runtime_tool_catalogue_verified": False,
        "effective_authority_verified": False,
    }


def checkout(root: Path) -> None:
    root.mkdir(exist_ok=True)
    (root / "agent.py").write_text(
        'from google.adk.agents import LlmAgent\n'
        'root_agent = LlmAgent(name="example_agent", model="gemini")\n',
        encoding="utf-8",
    )
    (root / "mcp_server.py").write_text(
        'from mcp.server.fastmcp import FastMCP\n'
        'mcp = FastMCP("Calculator")\n'
        '@mcp.tool()\n'
        'def add(a: int, b: int) -> int: return a + b\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "agent.py", "mcp_server.py"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=C02x Test",
         "-c", "user.email=c02x@example.test", "commit", "-qm", "fixture"],
        check=True,
    )


def _seal(root: Path, data: dict | None = None) -> dict:
    return seal_mcp_source_shadow(data if data is not None else shadow_fixture(), root)


def test_c02w_opt_in_keeps_canonical_projection_and_default_html(tmp_path: Path) -> None:
    checkout(tmp_path)
    graph = Graph(agents=[Agent(name="example_agent")])
    graph.adg = build_adg(graph, tmp_path)
    source = _seal(tmp_path)
    unchanged = deepcopy(source)
    before_model = build_visual_report(graph, [], tmp_path)
    adg_digest = graph.adg.canonical_digest()
    default_html = render_visual_report_html(graph, [], tmp_path)
    overlay = project_mcp_source_overlay(source, tmp_path)
    opt_html = render_visual_report_html(
        graph, [], tmp_path, source_overlay=overlay,
    )
    assert before_model == build_visual_report(graph, [], tmp_path)
    assert source == unchanged
    assert graph.adg.canonical_digest() == adg_digest
    assert len(before_model["findings"]) == 0
    assert "mcp_source_evidence" not in before_model
    assert 'data-view="mcp-source-evidence"' not in default_html
    assert 'horus-mcp-source-data' not in default_html
    assert 'data-view="mcp-source-evidence"' in opt_html
    assert 'id="mcp-source-evidence"' in opt_html
    assert 'id="horus-mcp-source-data"' in opt_html
    assert "renderMcpSourceEvidence()" in opt_html
    assert "No report data leaves this file" in opt_html
    assert "source agent contexts" in opt_html.lower()
    assert "effective AGENT_CAN_CALL" in opt_html
    assert "runtime_authority_verified" in opt_html  # only in inert JSON
    assert "<script src=" not in opt_html


def test_c02w_scoped_witnesses_and_escape_untrusted_labels(tmp_path: Path) -> None:
    checkout(tmp_path)
    data = shadow_fixture()
    data["nodes"][1]["name"] = '</script><script>alert("bad")</script>'
    data["nodes"][0]["agent"] = '<img src=x onerror="bad()">'
    overlay = project_mcp_source_overlay(_seal(tmp_path, data), tmp_path)
    graph = Graph(agents=[Agent(name="example_agent")])
    graph.adg = build_adg(graph, tmp_path)
    html = render_visual_report_html(graph, [], tmp_path, source_overlay=overlay)
    assert '</script><script>alert' not in html
    assert r'\u003c/script\u003e\u003cscript\u003e' in html
    assert '<img src=x onerror=' not in html


@pytest.mark.parametrize("mutate", [
    lambda d: d.update({"mode": "production_adg"}),
    lambda d: d.update({"effective_authority_verified": True}),
    lambda d: d["edges"][1].update({"kind": "AGENT_CAN_CALL"}),
    lambda d: d["nodes"][0].update({"agent": ""}),
    lambda d: d["nodes"][1]["location"].update({"line": 999}),
    lambda d: d["nodes"][1]["location"].update({"path": "../secret.py"}),
    lambda d: d["nodes"][1]["location"].update({"path": "not-in-repo.py"}),
])
def test_c02w_invalid_source_overlay_fails_closed(tmp_path: Path, mutate) -> None:
    checkout(tmp_path)
    fixture = _seal(tmp_path)
    mutate(fixture)
    with pytest.raises((ValueError, FileNotFoundError)):
        project_mcp_source_overlay(fixture, tmp_path)


def test_c02w_symlink_escape_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "project"
    checkout(root)
    outside = tmp_path / "outside.py"
    outside.write_text("external\n" * 9, encoding="utf-8")
    (root / "escape.py").symlink_to(outside)
    data = _seal(root)
    data["nodes"][1]["location"] = {"path": "escape.py", "line": 2}
    with pytest.raises(ValueError):
        project_mcp_source_overlay(data, root)


def test_c02w_overlay_input_file_round_trip_and_cli(tmp_path: Path) -> None:
    root = tmp_path / "target"
    checkout(root)
    evidence = tmp_path / "source-shadow.json"
    evidence.write_text(json.dumps(_seal(root)), encoding="utf-8")
    overlay = load_mcp_source_overlay(evidence, root)
    assert overlay["mode"] == "opt_in_mcp_source_evidence_not_authority"
    assert overlay["runtime_authority_verified"] is False
    assert len(overlay["nodes"]) == 3
    assert len(overlay["edges"]) == 2
    output = tmp_path / "with-overlay.html"
    assert main([
        "report", str(root), "--mcp-source-shadow", str(evidence),
        "--output", str(output),
    ]) == 0
    with_overlay = output.read_text(encoding="utf-8")
    assert 'data-view="mcp-source-evidence"' in with_overlay
    assert "EXPOSES_TOOL" in with_overlay
    assert "Runtime callability and effective authority are unknown." in with_overlay
    default = tmp_path / "default.html"
    assert main(["report", str(root), "--output", str(default)]) == 0
    assert 'data-view="mcp-source-evidence"' not in default.read_text(encoding="utf-8")


def test_c02w_cli_bad_input_does_not_write_report(tmp_path: Path, capsys) -> None:
    root = tmp_path / "target"
    checkout(root)
    evidence = tmp_path / "bad-source.json"
    data = _seal(root)
    data["nodes"][2]["location"]["line"] = 10000
    evidence.write_text(json.dumps(data), encoding="utf-8")
    output = tmp_path / "forbidden.html"
    assert main([
        "report", str(root), "--mcp-source-shadow", str(evidence),
        "--output", str(output),
    ]) == 1
    assert not output.exists()
    assert "invalid MCP source evidence" in capsys.readouterr().err


def test_c02w_reject_unverified_overlay_into_renderer(tmp_path: Path) -> None:
    graph = Graph(agents=[Agent(name="safe")])
    graph.adg = build_adg(graph, tmp_path)
    with pytest.raises(ValueError):
        render_visual_report_html(graph, [], tmp_path, source_overlay={
            "mode": "production_adg", "source_only": False,
            "runtime_authority_verified": True,
        })
