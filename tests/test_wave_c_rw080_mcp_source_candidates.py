"""Real rw-080 MCP source dossier: never infer callable tools from exports."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POP = ROOT / "research/wave-c-c02f-active145/expected-agent-review-scopes.json"
TREE = ROOT / "research/wave-c-c02i-rw080/pinned-source-tree.json"
LEDGER = ROOT / "research/wave-c-c02i-rw080/mcp-source-candidates.json"
_SHA = re.compile(r"[0-9a-f]{40}\Z")


def _documents() -> tuple[dict, dict]:
    return (
        json.loads(TREE.read_text(encoding="utf-8")),
        json.loads(LEDGER.read_text(encoding="utf-8")),
    )


def _expression(ledger: dict, path: str, line: int) -> str:
    found = [
        r["source_expression"] for r in ledger["observations"]
        if r["path"] == path and r["line"] == line
    ]
    assert len(found) == 1, (path, line)
    return found[0]


def test_rw080_is_exact_non_langgraph_archive_case() -> None:
    tree, ledger = _documents()
    expected = json.loads(POP.read_text(encoding="utf-8"))["expected_scopes"]
    row = next(x for x in expected if x["case_id"] == "rw-080")
    assert row["framework"] == "mcp-custom"
    assert row["source_role"] == "unknown"
    assert ledger["cohort_scope_id"] == row["scope_id"]
    assert ledger["repository"] == row["repository"]
    assert ledger["pinned_commit_sha"] == row["commit_sha"]
    assert tree["commit_sha"] == row["commit_sha"]
    assert tree["tree_sha"] == ledger["pinned_tree_sha"]
    assert tree["tree_sha"] == "e93ba494131547f45f2b975fa99dd9121702fee0"
    assert tree["truncated"] is False
    assert len(tree["entries"]) == 27


def test_rw080_bounded_pinned_source_sites_remain_git_tree_anchored() -> None:
    tree, ledger = _documents()
    blobs = {
        entry["path"]: entry["sha"]
        for entry in tree["entries"] if entry["type"] == "blob"
    }
    witnesses = {x["path"]: x["blob_sha"] for x in ledger["source_files"]}
    assert len(witnesses) == 8
    assert len(ledger["observations"]) == 47
    assert len({x["id"] for x in ledger["observations"]}) == 47
    assert all(_SHA.fullmatch(blob) for blob in witnesses.values())
    assert all(blobs[path] == blob for path, blob in witnesses.items())
    assert all(
        site["path"] in witnesses
        and witnesses[site["path"]] == site["blob_sha"]
        and isinstance(site["line"], int) and site["line"] > 0
        and site["source_expression"].strip()
        and site["source_only_candidate"] is True
        for site in ledger["observations"]
    )


def test_rw080_four_distinct_source_server_configs_and_transports() -> None:
    tree, ledger = _documents()
    sources = {
        row["path"] for row in tree["entries"] if row["type"] == "blob"
    }
    rows = ledger["declared_mcp_configs"]
    assert len(rows) == 4
    assert {r["id"] for r in rows} == {
        "math", "documents", "websearch", "telegram",
    }
    assert Counter(r["transport"] for r in rows) == {"stdio": 3, "sse": 1}
    assert all(r["source_path"] == "config/profiles.yaml" for r in rows)
    stdio = [r for r in rows if r["transport"] == "stdio"]
    assert {r["script"] for r in stdio} == {
        "mcp_server_1.py", "mcp_server_2.py", "mcp_server_3.py",
    }
    assert all(r["script"] in sources for r in stdio)
    assert all("url" not in r for r in stdio)
    telegram = next(r for r in rows if r["id"] == "telegram")
    assert "script" not in telegram
    assert telegram["url"] == "http://localhost:8000/sse"
    assert _expression(ledger, "config/profiles.yaml", 27) == "mcp_servers:"
    assert _expression(ledger, "config/profiles.yaml", 29) == (
        "script: mcp_server_1.py"
    )
    assert _expression(ledger, "config/profiles.yaml", 42) == (
        "url: http://localhost:8000/sse"
    )


def test_rw080_duplicate_server_display_name_does_not_merge_instances() -> None:
    _, ledger = _documents()
    assert _expression(ledger, "mcp_server_1.py", 33) == (
        'mcp = FastMCP("Calculator")'
    )
    assert _expression(ledger, "mcp_server_2.py", 28) == (
        'mcp = FastMCP("Calculator")'
    )
    assert _expression(ledger, "mcp_server_3.py", 209) == (
        'mcp = FastMCP("ddg-search")'
    )
    assert _expression(ledger, "mcp_telegram_server.py", 27) == (
        'mcp = FastMCP("telegram-integration")'
    )
    assert _expression(ledger, "mcp_server_1.py", 36) == "@mcp.tool()"
    assert _expression(ledger, "mcp_server_2.py", 98) == "@mcp.tool()"
    assert _expression(ledger, "mcp_server_3.py", 214) == "@mcp.tool()"
    assert _expression(ledger, "mcp_telegram_server.py", 65) == "@mcp.tool()"


def test_rw080_runtime_enumeration_and_unqualified_collision_are_source_only() -> None:
    _, ledger = _documents()
    assert _expression(ledger, "core/session.py", 81) == (
        "tools = await session.list_tools()"
    )
    assert _expression(ledger, "core/session.py", 111) == (
        "tools = await session.list_tools()"
    )
    for line in (84, 114):
        assert _expression(ledger, "core/session.py", line) == (
            "self.tool_map[tool.name] = {"
        )
    assert _expression(ledger, "core/session.py", 124) == (
        "entry = self.tool_map.get(tool_name)"
    )
    assert _expression(ledger, "core/session.py", 137) == (
        "return await session.call_tool(tool_name, arguments)"
    )
    assert _expression(ledger, "core/session.py", 148) == (
        "return await session.call_tool(tool_name, arguments)"
    )
    assert _expression(ledger, "core/loop.py", 17) == (
        "self.tools = dispatcher.get_all_tools()"
    )
    assert _expression(ledger, "core/loop.py", 121) == (
        "response = await self.mcp.call_tool(tool_name, tool_input)"
    )


def test_rw080_two_agent_loop_constructor_sites_are_not_instance_count() -> None:
    _, ledger = _documents()
    assert _expression(ledger, "agent.py", 100) == "agent = AgentLoop("
    assert _expression(ledger, "agent.py", 128) == "agent = AgentLoop("
    assert _expression(ledger, "agent.py", 66) == (
        "multi_mcp = MultiMCP(server_configs=mcp_servers)"
    )
    assert _expression(ledger, "agent.py", 68) == (
        "await multi_mcp.initialize()"
    )


def test_rw080_exposed_tools_never_become_effective_authority_by_fixture() -> None:
    _, ledger = _documents()
    assert ledger["record_type"] == (
        "source_first_mcp_candidate_not_verified_authority"
    )
    for key in (
        "source_witnesses_locally_verified", "scanner_predictions_consulted",
        "source_blindness_externally_verified", "positive_universe_complete",
        "negative_universe_complete", "runtime_mcp_enumeration_verified",
        "effective_authority_verified", "production_cutover_authorized",
    ):
        assert ledger[key] is False
    assert ledger["certified_precision"] is None
    assert ledger["certified_recall"] is None
    assert len(ledger["review_questions"]) >= 7
    assert all("truth" not in r and "expected_label" not in r
               for r in ledger["observations"])
