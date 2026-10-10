from pathlib import Path

from horustrace.mcp_context import (
    reconstruct_mcp_context,
    resolve_fast_agent_mcp_references,
    resolve_imported_mcp_placeholders,
)
from horustrace.mcp_effective import effective_mcp_authority_report
from horustrace.mcp_resolution import unresolved_mcp_summary
from horustrace.models import Agent, Graph, MCPServer, SourceLocation


def _server(
    root: Path,
    *,
    name: str = "shared",
    url: str = "https://mcp.example.test",
    source: str = "python_connection_config",
) -> MCPServer:
    return MCPServer(
        name=name,
        transport="streamable-http",
        url=url,
        location=SourceLocation(root / "mcp.py", line=5),
        metadata={"framework": "mcp", "source": source},
    )


def test_unbound_declaration_has_static_reason(tmp_path: Path) -> None:
    graph = Graph(unbound_mcp_servers=[_server(tmp_path)])

    report = unresolved_mcp_summary(graph)

    assert report["summary"] == {
        "unresolved_references": 1,
        "server_declarations": 1,
        "agent_references": 0,
        "by_source_context": {"runtime": 1},
        "by_reason": {"declaration_not_agent_bound": 1},
        "declaration_by_reason": {"declaration_not_agent_bound": 1},
        "agent_reference_by_reason": {},
        "by_resolution_class": {"resolvable_static": 1},
    }
    reference = report["references"][0]
    assert reference["reference_kind"] == "server_declaration"
    assert reference["reason"] == "declaration_not_agent_bound"
    assert reference["evidence_gaps"] == []
    assert reference["runtime_effectiveness"] == "not_verified"


def test_fast_agent_missing_declaration_becomes_reference_not_server(
    tmp_path: Path,
) -> None:
    agent = Agent(
        name="worker",
        location=SourceLocation(tmp_path / "agent.py", line=8),
        metadata={
            "framework": "fast-agent",
            "mcp_server_refs": ["missing"],
        },
    )
    graph = Graph(agents=[agent])

    resolve_fast_agent_mcp_references(graph)

    assert graph.unbound_mcp_servers == []
    assert len(graph.unresolved_mcp_references) == 1
    report = effective_mcp_authority_report(graph)
    assert report["summary"]["mcp_servers"] == 0
    assert report["summary"]["unbound_servers"] == 0
    assert report["summary"]["unresolved_references"] == 1
    assert report["summary"]["unresolved_agent_references"] == 1
    reference = report["unbound"][0]
    assert reference["agent"] == "worker"
    assert reference["server"] == "missing"
    assert reference["reason"] == "server_not_declared"
    assert reference["resolution_class"] == "resolvable_static"
    assert reference["evidence_gaps"] == ["server_declaration"]


def test_fast_agent_ambiguity_preserves_candidates(tmp_path: Path) -> None:
    first = _server(tmp_path / "a")
    second = _server(
        tmp_path / "b",
        url="https://other.example.test",
    )
    agent = Agent(
        name="worker",
        location=SourceLocation(tmp_path / "agent.py"),
        metadata={
            "framework": "fast-agent",
            "mcp_server_refs": ["shared"],
        },
    )
    graph = Graph(
        agents=[agent],
        unbound_mcp_servers=[first, second],
    )

    resolve_fast_agent_mcp_references(graph)
    report = unresolved_mcp_summary(graph)

    assert len(graph.unbound_mcp_servers) == 2
    assert len(graph.unresolved_mcp_references) == 1
    reference = next(
        item
        for item in report["references"]
        if item["reference_kind"] == "agent_reference"
    )
    assert reference["reason"] == "ambiguous_multiple_candidates"
    assert reference["resolution_class"] == "evidence_limited"
    assert len(reference["candidate_declarations"]) == 2
    assert reference["evidence_gaps"] == ["unique_server_binding"]
    assert report["summary"]["by_reason"] == {
        "ambiguous_multiple_candidates": 1,
        "declaration_not_agent_bound": 2,
    }


def test_dynamic_fast_agent_server_selection_remains_unresolved(
    tmp_path: Path,
) -> None:
    agent = Agent(
        name="worker",
        location=SourceLocation(tmp_path / "agent.py", line=12),
        metadata={
            "framework": "fast-agent",
            "dynamic_mcp_servers": True,
        },
    )
    graph = Graph(agents=[agent])

    resolve_fast_agent_mcp_references(graph)
    reference = unresolved_mcp_summary(graph)["references"][0]

    assert reference["server"] == "<dynamic>"
    assert reference["reason"] == "dynamic_server_selection"
    assert reference["resolution_class"] == "evidence_limited"
    assert reference["evidence_gaps"] == ["static_server_name"]


def test_unresolved_import_placeholder_does_not_become_effective_authority(
    tmp_path: Path,
) -> None:
    placeholder = MCPServer(
        name="remote_server",
        transport="configured",
        location=SourceLocation(tmp_path / "agent.py", line=20),
        metadata={
            "framework": "openai-agents",
            "placeholder": True,
            "import_module": "external.servers",
        },
    )
    agent = Agent(name="agent", mcp_servers=[placeholder])
    graph = Graph(agents=[agent])

    resolve_imported_mcp_placeholders(graph, tmp_path)
    reconstruct_mcp_context(graph)

    assert agent.mcp_servers == []
    assert graph.unbound_mcp_servers == []
    assert len(graph.unresolved_mcp_references) == 1

    report = effective_mcp_authority_report(graph)
    assert report["authorities"] == []
    assert report["summary"]["bound_relationships"] == 0
    assert report["unbound"][0]["reason"] == "server_not_declared"


def test_imported_reference_resolves_unique_repository_declaration(
    tmp_path: Path,
) -> None:
    service = tmp_path / "services"
    service.mkdir()
    concrete = MCPServer(
        name="remote_server",
        transport="stdio",
        command="python",
        location=SourceLocation(service / "mcp.py", line=3),
        metadata={"framework": "mcp", "source": "StdioServerParameters"},
    )
    placeholder = MCPServer(
        name="remote_server",
        transport="configured",
        location=SourceLocation(tmp_path / "agent.py", line=20),
        metadata={
            "framework": "openai-agents",
            "placeholder": True,
            "import_module": "services.mcp",
        },
    )
    agent = Agent(name="agent", mcp_servers=[placeholder])
    graph = Graph(
        agents=[agent],
        unbound_mcp_servers=[concrete],
    )

    resolve_imported_mcp_placeholders(graph, tmp_path)
    reconstruct_mcp_context(graph)

    assert graph.unbound_mcp_servers == []
    assert graph.unresolved_mcp_references == []
    assert len(agent.mcp_servers) == 1
    assert agent.mcp_servers[0].metadata["repository_resolved"] is True
    assert (
        agent.mcp_servers[0].metadata["binding_origin"]
        == "repository_import_reference"
    )


def test_same_name_wrong_module_is_cross_file_unlinked(
    tmp_path: Path,
) -> None:
    concrete = MCPServer(
        name="remote_server",
        transport="stdio",
        command="python",
        location=SourceLocation(tmp_path / "other.py"),
        metadata={"framework": "mcp", "source": "StdioServerParameters"},
    )
    placeholder = MCPServer(
        name="remote_server",
        transport="configured",
        location=SourceLocation(tmp_path / "agent.py"),
        metadata={
            "framework": "openai-agents",
            "placeholder": True,
            "import_module": "services.mcp",
        },
    )
    graph = Graph(
        agents=[Agent(name="agent", mcp_servers=[placeholder])],
        unbound_mcp_servers=[concrete],
    )

    resolve_imported_mcp_placeholders(graph, tmp_path)
    references = unresolved_mcp_summary(graph)["references"]
    reference = next(
        item
        for item in references
        if item["reference_kind"] == "agent_reference"
    )

    assert reference["reason"] == "cross_file_reference_unlinked"
    assert len(reference["candidate_declarations"]) == 1
    assert reference["evidence_gaps"] == ["repository_linkage"]


def test_reference_id_excludes_destination_and_checkout_path(
    tmp_path: Path,
) -> None:
    first = Graph(
        unbound_mcp_servers=[
            _server(
                tmp_path / "checkout-a",
                url="https://user:secret-a@example.test/mcp?token=a",
            )
        ]
    )
    second = Graph(
        unbound_mcp_servers=[
            _server(
                tmp_path / "checkout-b",
                url="https://user:secret-b@example.test/mcp?token=b",
            )
        ]
    )

    first_reference = unresolved_mcp_summary(first)["references"][0]
    second_reference = unresolved_mcp_summary(second)["references"][0]

    assert first_reference["destination"] != second_reference["destination"]
    assert first_reference["location"] != second_reference["location"]
    assert first_reference["reference_id"] == second_reference["reference_id"]


def test_repeated_mcp_declarations_have_unique_portable_reference_ids(
    tmp_path: Path,
) -> None:
    """Pinned LinkedIn MCP test fixtures duplicate server names many times."""
    from horustrace.mcp_resolution import unresolved_mcp_references

    def records(root: Path):
        return unresolved_mcp_references(Graph(unbound_mcp_servers=[
            MCPServer(
                name="test",
                transport="server",
                location=SourceLocation(root / "tests" / "test_tools.py", line=22),
                metadata={"framework": "mcp", "source": "FastMCP"},
            ),
            MCPServer(
                name="test",
                transport="server",
                location=SourceLocation(root / "tests" / "test_tools.py", line=77),
                metadata={"framework": "mcp", "source": "FastMCP"},
            ),
            MCPServer(
                name="live",
                transport="server",
                location=SourceLocation(root / "src" / "server.py", line=8),
                metadata={"framework": "mcp", "source": "FastMCP"},
            ),
        ]))

    first = records(tmp_path / "checkout-a")
    second = records(tmp_path / "checkout-b")
    assert len({item.reference_id for item in first}) == 3
    assert [item.reference_id for item in first] == [
        item.reference_id for item in second
    ]
    repeated = [item for item in first if item.server == "test"]
    assert len(repeated) == 2
    assert all(item.source_context == "test" for item in repeated)
    assert next(item for item in first if item.server == "live").source_context == (
        "runtime"
    )
    report = unresolved_mcp_summary(Graph(unbound_mcp_servers=[
        MCPServer(
            name="test", transport="server",
            location=SourceLocation(tmp_path / "tests" / "test_tools.py", line=22),
            metadata={"framework": "mcp", "source": "FastMCP"},
        ),
        MCPServer(
            name="live", transport="server",
            location=SourceLocation(tmp_path / "src" / "server.py", line=8),
            metadata={"framework": "mcp", "source": "FastMCP"},
        ),
    ]))
    assert report["summary"]["by_source_context"] == {
        "runtime": 1, "test": 1
    }
    assert [item["source_context"] for item in report["references"]] == [
        "runtime", "test"
    ] or [item["source_context"] for item in report["references"]] == [
        "test", "runtime"
    ]
