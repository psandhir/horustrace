import json
from pathlib import Path

from horustrace.cli import main
from horustrace.mcp_effective import effective_mcp_authority_report
from horustrace.models import Agent, Graph, Identity, MCPServer
from horustrace.rules.builtin import evaluate
from horustrace.scanner import scan


def _write_bound_fixture(root: Path) -> None:
    (root / "agent.py").write_text(
        """
import os
from agents import Agent
from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter

slack = MCPServerStreamableHttp(
    params={
        "url": "https://mcp.example.test/mcp",
        "headers": {"Authorization": f"Bearer {os.getenv('MCP_TOKEN')}"},
    },
    tool_filter=create_static_tool_filter(
        allowed_tool_names=["search_messages", "read_thread"],
        blocked_tool_names=["send_message"],
    ),
)
agent = Agent(name="agent", mcp_servers=[slack])
""",
        encoding="utf-8",
    )


def test_effective_mcp_authority_exposes_agent_identity_filter_and_destination(
    tmp_path: Path,
) -> None:
    _write_bound_fixture(tmp_path)
    graph, _ = scan(tmp_path)

    report = effective_mcp_authority_report(graph)

    assert report["summary"] == {
        "mcp_servers": 1,
        "bound_relationships": 1,
        "unbound_servers": 0,
        "unresolved_references": 0,
        "unresolved_agent_references": 0,
        "unbound_by_reason": {},
        "unresolved_by_reason": {},
        "unresolved_by_resolution_class": {},
        "fully_resolved_relationships": 1,
        "explicit_tool_scopes": 1,
        "identity_bound_relationships": 1,
        "fixed_destination_relationships": 1,
    }

    authority = report["authorities"][0]
    assert authority["agent"] == "agent"
    assert authority["server"] == "slack"
    assert authority["binding"] == {
        "status": "bound",
        "origin": "framework_agent_configuration",
    }
    assert authority["tools"] == {
        "scope": "explicit_allowlist",
        "catalogue_known": True,
        "effective": ["search_messages", "read_thread"],
        "denied": ["send_message"],
    }
    assert authority["authentication"] == {
        "state": "authenticated",
        "mechanism": "authorization-header",
        "identity": "agent:slack:mcp-auth",
        "provider": "mcp.example.test",
        "credential_source": "env:MCP_TOKEN",
    }
    assert authority["destination"] == {
        "target": "https://mcp.example.test/mcp",
        "constraint": "fixed_remote_endpoint",
        "args": [],
    }
    assert authority["fully_resolved"] is True
    assert authority["unresolved"] == []


def test_effective_mcp_authority_preserves_unknown_tool_catalogue(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStreamableHttp

weather = MCPServerStreamableHttp(
    params={"url": "https://weather.example.test/mcp"}
)
agent = Agent(name="agent", mcp_servers=[weather])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    authority = effective_mcp_authority_report(graph)["authorities"][0]

    assert authority["tools"]["catalogue_known"] is False
    assert authority["tools"]["effective"] == []
    assert authority["destination"]["constraint"] == "fixed_remote_endpoint"
    assert "tool_catalogue" in authority["unresolved"]
    assert authority["fully_resolved"] is False


def test_effective_mcp_authority_reports_unbound_server(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStreamableHttp

weather = MCPServerStreamableHttp(
    params={"url": "https://weather.example.test/mcp"}
)
agent = Agent(name="agent")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    report = effective_mcp_authority_report(graph)

    assert report["summary"]["bound_relationships"] == 0
    assert report["summary"]["unbound_servers"] == 1
    assert report["authorities"] == []
    unresolved = report["unbound"][0]
    assert unresolved["server"] == "weather"
    assert unresolved["reference_kind"] == "server_declaration"
    assert unresolved["reason"] == "declaration_not_agent_bound"
    assert unresolved["resolution_class"] == "resolvable_static"


def test_authority_cli_json_exposes_effective_relationship(
    tmp_path: Path,
    capsys,
) -> None:
    _write_bound_fixture(tmp_path)

    assert main([
        "authority",
        str(tmp_path),
        "--format",
        "json",
    ]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == 1
    assert report["summary"]["relationships"] >= 1
    relationship = next(
        item
        for item in report["relationships"]
        if item["target"] == {"kind": "mcp_server", "name": "slack"}
    )
    assert relationship["agent"] == "agent"
    assert relationship["runtime_effectiveness"] == "not_verified"


def test_authority_cli_console_is_human_readable(
    tmp_path: Path,
    capsys,
) -> None:
    _write_bound_fixture(tmp_path)

    assert main(["authority", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    assert "HorusTrace Effective Authority" in output
    assert "agent -> mcp_server:slack" in output
    assert "allowed=search_messages, read_thread" in output
    assert "identity: agent:slack:mcp-auth" in output
    assert "https://mcp.example.test/mcp" in output
    assert "Runtime effectiveness:          NOT VERIFIED" in output


def test_scan_json_embeds_mcp_authority_report(
    tmp_path: Path,
    capsys,
) -> None:
    _write_bound_fixture(tmp_path)

    assert main([
        "scan",
        str(tmp_path),
        "--format",
        "json",
        "--fail-on",
        "none",
    ]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["mcp_authority"]["summary"]["bound_relationships"] == 1
    assert report["mcp_authority"]["authorities"][0]["server"] == "slack"
    relationship = next(
        item
        for item in report["effective_authority"]["relationships"]
        if item["target"] == {"kind": "mcp_server", "name": "slack"}
    )
    assert relationship["agent"] == "agent"
    assert relationship["runtime_effectiveness"] == "not_verified"

def test_authenticated_relationship_with_generic_configured_auth_is_not_fully_resolved() -> None:
    identity = Identity(
        name="agent:server:mcp-auth",
        provider="mcp",
        credential_source="env:MCP_TOKEN",
    )
    server = MCPServer(
        name="server",
        transport="http",
        url="https://mcp.example.test/mcp",
        authenticated=True,
        allowed_tools=["read"],
        identity=identity.name,
        metadata={
            "auth_mechanism": "configured-auth",
            "binding_origin": "framework_agent_configuration",
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="agent",
                identities=[identity],
                mcp_servers=[server],
            )
        ]
    )

    authority = effective_mcp_authority_report(graph)["authorities"][0]

    assert authority["authentication"]["state"] == "authenticated"
    assert authority["authentication"]["mechanism"] == "configured-auth"
    assert authority["authentication"]["credential_source"] == "env:MCP_TOKEN"
    assert authority["fully_resolved"] is False
    assert authority["unresolved"] == ["authentication_mechanism"]


def test_authenticated_relationship_without_credential_source_is_not_fully_resolved() -> None:
    identity = Identity(
        name="agent:server:mcp-auth",
        provider="mcp.example.test",
    )
    server = MCPServer(
        name="server",
        transport="http",
        url="https://mcp.example.test/mcp",
        authenticated=True,
        allowed_tools=["read"],
        identity=identity.name,
        metadata={
            "auth_mechanism": "authorization-header",
            "binding_origin": "framework_agent_configuration",
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="agent",
                identities=[identity],
                mcp_servers=[server],
            )
        ]
    )

    authority = effective_mcp_authority_report(graph)["authorities"][0]

    assert authority["authentication"]["mechanism"] == "authorization-header"
    assert authority["authentication"]["credential_source"] is None
    assert authority["fully_resolved"] is False
    assert authority["unresolved"] == ["credential_source"]



def test_agt053_requires_effective_agent_mcp_binding() -> None:
    unbound = MCPServer(
        name="privileged",
        transport="stdio",
        command="python",
        metadata={
            "discovered_tool_capabilities": [
                "data.write",
                "process.execute",
            ],
        },
    )
    graph = Graph(unbound_mcp_servers=[unbound])

    assert not any(item.rule_id == "AGT053" for item in evaluate(graph))


def test_agt053_retained_for_bound_privileged_mcp() -> None:
    bound = MCPServer(
        name="privileged",
        transport="stdio",
        command="python",
        metadata={
            "discovered_tool_capabilities": [
                "data.write",
                "process.execute",
            ],
            "binding_origin": "framework_agent_configuration",
        },
    )
    graph = Graph(agents=[Agent(name="worker", mcp_servers=[bound])])

    finding = next(item for item in evaluate(graph) if item.rule_id == "AGT053")
    assert finding.agent == "worker"
    assert finding.authority_relationship_id is not None
