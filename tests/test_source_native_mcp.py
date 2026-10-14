"""Source-native MCP pilot: exact registrations, uncertainty, and negatives."""
from __future__ import annotations

import json
from pathlib import Path

from horustrace.models import Graph
from horustrace.semantic_shadow import shadow_observation_report
from horustrace.source_native_mcp import inspect_local_pydantic_mcp


def _agent(root: Path, *, server: str = "mcp_server.py") -> None:
    (root / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "from pydantic_ai.mcp import MCPServerStdio\n"
        f"servers = [MCPServerStdio('python', ['{server}'])]\n"
        "agent = Agent('test:model', mcp_servers=servers)\n",
        encoding="utf-8",
    )


def _provider(root: Path) -> None:
    (root / "mcp_server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('records')\n"
        "@mcp.tool()\n"
        "def read_record(record_id: str):\n"
        "    return record_id\n"
        "@mcp.tool(name='write_record')\n"
        "def mutate_record(record_id: str):\n"
        "    return record_id\n"
        "class Decoy:\n"
        "    def tool(self):\n"
        "        return lambda fn: fn\n"
        "unrelated = Decoy()\n"
        "@unrelated.tool()\n"
        "def not_exposed():\n"
        "    return 1\n"
        "if __name__ == '__main__':\n"
        "    mcp.run()\n",
        encoding="utf-8",
    )


def test_pydantic_static_local_mcp_proves_only_source_edges(tmp_path: Path) -> None:
    _agent(tmp_path)
    _provider(tmp_path)
    native = inspect_local_pydantic_mcp(tmp_path)
    report = native.as_dict()
    entities = report["entities"]
    kinds = [entity["kind"] for entity in entities]
    assert kinds.count("agent") == 1
    assert kinds.count("mcp_client") == 1
    assert kinds.count("mcp_server") == 1
    assert kinds.count("tool") == 2
    assert {entry["name"] for entry in entities if entry["kind"] == "tool"} == {
        "read_record", "write_record",
    }
    edges = report["bindings"]
    assert len(edges) == 4
    assert [edge["kind"] for edge in edges].count("exposes_tool") == 2
    assert {edge["kind"] for edge in edges} == {
        "agent_binds_client", "client_connects_to_server", "exposes_tool",
    }
    assert all(edge["resolution"] == "proven" for edge in edges)
    assert all(edge["metadata"]["runtime_verified"] is False for edge in edges)
    assert all(edge["metadata"]["agent_callable"] is False for edge in edges)
    assert all(
        edge["source_id"] in {entity["entity_id"] for entity in entities}
        and edge["target_id"] in {entity["entity_id"] for entity in entities}
        for edge in edges
    )
    assert str(tmp_path) not in json.dumps(report)
    shadow = shadow_observation_report(Graph(), tmp_path)
    assert len(shadow["source_native"]["bindings"]) == 4
    assert shadow["comparison"]["source_recall"] is None


def test_source_native_ids_are_independent_of_checkout_directory(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    for location in (left, right):
        _agent(location)
        _provider(location)
    assert inspect_local_pydantic_mcp(left).as_dict() == (
        inspect_local_pydantic_mcp(right).as_dict()
    )


def test_missing_program_does_not_create_server_or_callable_edge(tmp_path: Path) -> None:
    _agent(tmp_path)
    result = inspect_local_pydantic_mcp(tmp_path).as_dict()
    assert {row["kind"] for row in result["entities"]} == {"agent", "mcp_client"}
    assert [row["kind"] for row in result["bindings"]] == ["agent_binds_client"]
    assert any(item["resolution"] == "unresolved" for item in result["observations"])


def test_nonmatching_provider_or_dynamic_command_never_infers_tool(tmp_path: Path) -> None:
    _agent(tmp_path)
    (tmp_path / "mcp_server.py").write_text(
        "from fastmcp import FastMCP\n"
        "mcp = FastMCP('example')\n"
        "def hidden():\n"
        "    return 1\n"
        "mcp.add_tool(hidden)\n", encoding="utf-8",
    )
    result = inspect_local_pydantic_mcp(tmp_path).as_dict()
    assert not any(row["kind"] == "exposes_tool" for row in result["bindings"])

    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "from pydantic_ai.mcp import MCPServerStdio\n"
        "dynamic = f'{1}.py'\n"
        "servers = [MCPServerStdio('python', [dynamic])]\n"
        "agent = Agent('test:model', mcp_servers=servers)\n", encoding="utf-8",
    )
    result = inspect_local_pydantic_mcp(tmp_path).as_dict()
    assert result["entities"] == []
    assert result["bindings"] == []


def test_near_miss_unrelated_agent_and_script_paths(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "from pydantic_ai.mcp import MCPServerStdio\n"
        "servers = [MCPServerStdio('bash', ['mcp_server.py'])]\n"
        "agent = Agent('test:model', mcp_servers=servers)\n",
        encoding="utf-8",
    )
    _provider(tmp_path)
    assert inspect_local_pydantic_mcp(tmp_path).bindings == []

    _agent(tmp_path, server="../other.py")
    assert inspect_local_pydantic_mcp(tmp_path).bindings == []


def test_file_target_scans_only_its_explicit_program(tmp_path: Path) -> None:
    _agent(tmp_path)
    _provider(tmp_path)
    (tmp_path / "other.py").write_text(
        "from pydantic_ai import Agent\n"
        "from pydantic_ai.mcp import MCPServerStdio\n"
        "agent = Agent('a', mcp_servers=[MCPServerStdio('python', ['missing.py'])])\n",
        encoding="utf-8",
    )
    results = inspect_local_pydantic_mcp(tmp_path / "agent.py").as_dict()
    assert len([e for e in results["entities"] if e["kind"] == "agent"]) == 1


def test_two_fastmcp_objects_in_one_script_do_not_collapse_into_one_server(
    tmp_path: Path,
) -> None:
    _agent(tmp_path)
    (tmp_path / "mcp_server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "first = FastMCP('a')\n"
        "second = FastMCP('b')\n"
        "@first.tool()\n"
        "def tool_one():\n"
        "    return 1\n"
        "@second.tool()\n"
        "def tool_two():\n"
        "    return 2\n", encoding="utf-8",
    )
    report = inspect_local_pydantic_mcp(tmp_path).as_dict()
    assert not any(e["kind"] == "exposes_tool" for e in report["bindings"])
    assert not any(e["kind"] == "client_connects_to_server" for e in report["bindings"])


def test_provider_without_run_entrypoint_does_not_claim_client_connection(
    tmp_path: Path,
) -> None:
    _agent(tmp_path)
    (tmp_path / "mcp_server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('inactive')\n"
        "@mcp.tool()\n"
        "def hidden():\n"
        "    return 1\n", encoding="utf-8",
    )
    report = inspect_local_pydantic_mcp(tmp_path).as_dict()
    assert {edge["kind"] for edge in report["bindings"]} == {"agent_binds_client"}
    assert all(entity["kind"] != "mcp_server" for entity in report["entities"])
