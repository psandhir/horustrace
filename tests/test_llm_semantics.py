from __future__ import annotations

from pathlib import Path

from horustrace.llm_semantics import LLMSemanticConfig, enrich_llm_semantics
from horustrace.models import Agent, Graph, SourceLocation, Tool
from horustrace.scanner import scan


def _config(**overrides):
    values = {
        "provider": "openai",
        "model": "test-model",
        "max_candidates": 4,
        "max_slice_chars": 4000,
        "max_total_chars": 8000,
        "min_confidence": 0.75,
    }
    values.update(overrides)
    return LLMSemanticConfig(**values)


def _empty_result(**overrides):
    result = {
        "capabilities": [],
        "approval": "unknown",
        "guardrails": "unknown",
        "resources": [],
        "destinations": [],
        "mcp": {
            "present": False,
            "name": "",
            "transport": "unknown",
            "url": "",
            "command": "",
            "authenticated": "unknown",
            "approval": "unknown",
            "allowed_tools": [],
        },
        "confidence": 0.95,
        "evidence": [],
        "limitations": [],
    }
    result.update(overrides)
    return result


def test_llm_semantics_adds_facts_without_emitting_findings(tmp_path: Path):
    source = tmp_path / "agent.py"
    source.write_text(
        """
def ambiguous_tool(target):
    return transport(target)
""",
        encoding="utf-8",
    )
    tool = Tool(
        name="ambiguous_tool",
        kind="function",
        location=SourceLocation(source, 2, 1),
        metadata={
            "source_path": str(source),
            "source_function": "ambiguous_tool",
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="ops",
                tools=[tool],
                location=SourceLocation(source, 2, 1),
                metadata={"framework": "pydantic-ai"},
            )
        ]
    )

    def resolver(candidate, source_slice, config):
        assert candidate.agent.name == "ops"
        assert "def ambiguous_tool" in source_slice
        return _empty_result(
            capabilities=["network.external", "data.read"],
            destinations=[
                {
                    "target": "<model-selected-url>",
                    "restricted": False,
                    "provenance": "model_selected",
                }
            ],
            resources=[
                {
                    "kind": "remote-object",
                    "selector": "<model-selected-id>",
                    "access": ["data.read"],
                    "classification": "external",
                    "selector_provenance": "model_selected",
                }
            ],
            evidence=["target parameter controls the remote destination"],
        )

    stats = enrich_llm_semantics(
        graph,
        tmp_path,
        [source],
        _config(),
        resolver=resolver,
    )

    assert stats["eligible_candidates"] == 1
    assert stats["escalated"] == 1
    assert stats["applied"] == 1
    assert {"network.external", "data.read"} <= tool.capabilities
    assert tool.metadata["semantic_origin"] == "llm_inferred"
    assert tool.metadata["semantic_confidence"] == 0.95
    assert tool.destinations[0].target == "<model-selected-url>"
    assert tool.resources[0].selector == "<model-selected-id>"
    assert any(
        item.fact == "semantic_capability=network.external"
        and item.origin == "llm_inferred"
        for item in tool.provenance
    )


def test_llm_semantics_materializes_only_source_backed_unresolved_helper(
    tmp_path: Path,
):
    source = tmp_path / "agent.py"
    source.write_text(
        """
def search_youtube(query):
    def invoke():
        return MCPToolset.from_server(
            StdioServerParameters(command="mcp-youtube-search")
        )
    return invoke

root_agent = object()
""",
        encoding="utf-8",
    )
    agent = Agent(
        name="root",
        location=SourceLocation(source, 8, 1),
        metadata={
            "framework": "google-adk",
            "unresolved_helpers": ["search_youtube", "not_in_source"],
        },
    )
    graph = Graph(agents=[agent])

    def resolver(candidate, source_slice, config):
        assert candidate.name == "search_youtube"
        assert "mcp-youtube-search" in source_slice
        return _empty_result(
            capabilities=["mcp.remote"],
            mcp={
                "present": True,
                "name": "youtube-search",
                "transport": "stdio",
                "url": "",
                "command": "mcp-youtube-search",
                "authenticated": "unknown",
                "approval": "unknown",
                "allowed_tools": [],
            },
            limitations=["package MCP catalogue is outside the repository"],
        )

    stats = enrich_llm_semantics(
        graph,
        tmp_path,
        [source],
        _config(),
        resolver=resolver,
    )

    assert stats["unresolved_helpers_source_resolved"] == 1
    assert [tool.name for tool in agent.tools] == ["search_youtube"]
    assert agent.tools[0].kind == "llm_resolved_helper"
    assert "mcp.remote" in agent.tools[0].capabilities
    assert agent.metadata["llm_resolved_helpers"] == ["search_youtube"]
    assert len(agent.mcp_servers) == 1
    assert agent.mcp_servers[0].transport == "stdio"
    assert agent.mcp_servers[0].command == "mcp-youtube-search"
    assert (
        agent.mcp_servers[0].metadata["catalogue_resolution"]
        == "unresolved_remote_or_package_catalogue"
    )


def test_low_confidence_semantics_do_not_change_graph(tmp_path: Path):
    source = tmp_path / "agent.py"
    source.write_text(
        """
def uncertain_tool(value):
    return opaque(value)
""",
        encoding="utf-8",
    )
    tool = Tool(
        name="uncertain_tool",
        kind="function",
        location=SourceLocation(source, 2, 1),
        metadata={
            "source_path": str(source),
            "source_function": "uncertain_tool",
        },
    )
    graph = Graph(agents=[Agent(name="agent", tools=[tool])])

    def resolver(candidate, source_slice, config):
        return _empty_result(
            capabilities=["process.execute"],
            confidence=0.4,
        )

    stats = enrich_llm_semantics(
        graph,
        tmp_path,
        [source],
        _config(min_confidence=0.8),
        resolver=resolver,
    )

    assert stats["low_confidence"] == 1
    assert stats["applied"] == 0
    assert tool.capabilities == set()
    assert "semantic_origin" not in tool.metadata


def test_structured_cache_avoids_second_model_call(tmp_path: Path):
    source = tmp_path / "agent.py"
    source.write_text(
        """
def opaque_tool(value):
    return opaque(value)
""",
        encoding="utf-8",
    )
    cache = tmp_path / ".cache" / "semantic.json"
    calls = {"count": 0}

    def make_graph():
        tool = Tool(
            name="opaque_tool",
            kind="function",
            location=SourceLocation(source, 2, 1),
            metadata={
                "source_path": str(source),
                "source_function": "opaque_tool",
            },
        )
        return Graph(agents=[Agent(name="agent", tools=[tool])]), tool

    def resolver(candidate, source_slice, config):
        calls["count"] += 1
        return _empty_result(capabilities=["data.read"])

    graph, _ = make_graph()
    first = enrich_llm_semantics(
        graph,
        tmp_path,
        [source],
        _config(cache_path=cache),
        resolver=resolver,
    )
    second_graph, second_tool = make_graph()
    second = enrich_llm_semantics(
        second_graph,
        tmp_path,
        [source],
        _config(cache_path=cache),
        resolver=resolver,
    )

    assert first["escalated"] == 1
    assert second["escalated"] == 0
    assert second["cache_hits"] == 1
    assert calls["count"] == 1
    assert "data.read" in second_tool.capabilities
    cache_text = cache.read_text(encoding="utf-8")
    assert "def opaque_tool" not in cache_text


def test_scanner_integration_is_opt_in_and_reports_resolution_stats(
    tmp_path: Path,
    monkeypatch,
):
    source = tmp_path / "agent.py"
    source.write_text(
        """
from pydantic_ai import Agent

def opaque_capability(payload):
    return custom_library_call(payload)

agent = Agent("test:model", tools=[opaque_capability])
""",
        encoding="utf-8",
    )

    baseline_graph, _ = scan(tmp_path)
    baseline_agent = next(item for item in baseline_graph.agents if item.name == "agent")
    baseline_tool = next(
        item for item in baseline_agent.tools if item.name == "opaque_capability"
    )
    assert "process.execute" not in baseline_tool.capabilities
    assert "semantic_llm" not in baseline_graph.coverage.resolution

    def resolver(candidate, source_slice, config):
        return _empty_result(capabilities=["process.execute"])

    monkeypatch.setattr("horustrace.llm_semantics._api_resolver", resolver)
    semantic_graph, _ = scan(
        tmp_path,
        llm_semantic_config=_config(max_candidates=1),
    )
    semantic_agent = next(item for item in semantic_graph.agents if item.name == "agent")
    semantic_tool = next(
        item for item in semantic_agent.tools if item.name == "opaque_capability"
    )

    assert "process.execute" in semantic_tool.capabilities
    stats = semantic_graph.coverage.resolution["semantic_llm"]
    assert stats["selected_candidates"] == 1
    assert stats["applied"] == 1
    assert stats["input_chars"] > 0


def test_copilot_provider_is_valid_and_json_fences_are_tolerated():
    from horustrace.llm_semantics import _strip_json_fence

    _config(provider="copilot").validate()
    assert _strip_json_fence('```json\n{"confidence": 0.9}\n```') == (
        '{"confidence": 0.9}'
    )


def test_constructor_bound_helper_is_escalated_without_inventing_agent(tmp_path: Path):
    source = tmp_path / "agent.py"
    source.write_text(
        """
def search_youtube(query):
    def invoke():
        return MCPToolset.from_server(
            StdioServerParameters(command="mcp-youtube-search")
        )
    return invoke

agent = Agent(tools=[search_youtube])
""",
        encoding="utf-8",
    )
    agent = Agent(
        name="youtube_assistant",
        location=SourceLocation(source, 9, 1),
        metadata={"framework": "google-adk", "source_alias": "agent"},
    )
    graph = Graph(agents=[agent])

    def resolver(candidate, source_slice, config):
        assert candidate.kind == "bound_unresolved_helper"
        assert candidate.name == "search_youtube"
        assert "mcp-youtube-search" in source_slice
        return _empty_result(
            capabilities=["mcp.remote"],
            mcp={
                "present": True,
                "name": "youtube-search",
                "transport": "stdio",
                "url": "",
                "command": "mcp-youtube-search",
                "authenticated": "unknown",
                "approval": "unknown",
                "allowed_tools": [],
            },
        )

    stats = enrich_llm_semantics(
        graph,
        tmp_path,
        [source],
        _config(max_candidates=1),
        resolver=resolver,
    )

    assert stats["bound_helpers_source_resolved"] == 1
    assert stats["applied"] == 1
    assert [tool.name for tool in agent.tools] == ["search_youtube"]
    assert len(agent.mcp_servers) == 1
    assert agent.mcp_servers[0].command == "mcp-youtube-search"


def test_agent_runtime_context_projects_attached_toolset_semantics(tmp_path: Path):
    source = tmp_path / "agent.py"
    source.write_text(
        """
def create_cli_agent():
    toolset = create_console_toolset(
        include_execute=True,
        require_execute_approval=False,
    )
    agent = Agent()
    return agent.with_toolset(toolset)
""",
        encoding="utf-8",
    )
    agent = Agent(
        name="agent",
        location=SourceLocation(source, 7, 5),
        metadata={
            "framework": "pydantic-ai",
            "instance_key": f"{source}:7:agent",
        },
    )
    graph = Graph(agents=[agent])

    def resolver(candidate, source_slice, config):
        assert candidate.kind == "agent_runtime_context"
        assert "create_console_toolset" in source_slice
        return _empty_result(
            capabilities=["process.execute", "data.write"],
            approval="false",
            resources=[
                {
                    "kind": "filesystem",
                    "selector": "<model-selected-path>",
                    "access": ["data.write"],
                    "classification": "internal",
                    "selector_provenance": "model_selected",
                }
            ],
        )

    stats = enrich_llm_semantics(
        graph,
        tmp_path,
        [source],
        _config(max_candidates=1),
        resolver=resolver,
    )

    assert stats["runtime_contexts_source_resolved"] == 1
    assert stats["applied"] == 1
    assert len(agent.tools) == 1
    tool = agent.tools[0]
    assert tool.kind == "llm_resolved_runtime_context"
    assert {"process.execute", "data.write"} <= tool.capabilities
    assert tool.approval is False


def test_semantic_projection_rejects_ephemeral_write_and_logical_destination(
    tmp_path: Path,
):
    source = tmp_path / "agent.py"
    source.write_text(
        """
def update_state(ctx):
    ctx.deps.state.ready = True
    return ctx.deps.state
""",
        encoding="utf-8",
    )
    tool = Tool(
        name="update_state",
        kind="function",
        location=SourceLocation(source, 2, 1),
        metadata={
            "source_path": str(source),
            "source_function": "update_state",
            "agent_internal_state": True,
        },
    )
    graph = Graph(agents=[Agent(name="agent", tools=[tool])])

    def resolver(candidate, source_slice, config):
        return _empty_result(
            capabilities=["data.read", "data.write"],
            resources=[
                {
                    "kind": "application state",
                    "selector": "ctx.deps.state",
                    "access": ["data.read", "data.write"],
                    "classification": "internal",
                    "selector_provenance": "fixed",
                }
            ],
            destinations=[
                {
                    "target": "Slack channel identified by deps.channel_id",
                    "restricted": False,
                    "provenance": "model_selected",
                }
            ],
        )

    enrich_llm_semantics(
        graph,
        tmp_path,
        [source],
        _config(max_candidates=1),
        resolver=resolver,
    )

    assert "data.read" in tool.capabilities
    assert "data.write" not in tool.capabilities
    assert tool.destinations == []
    assert tool.metadata["semantic_ephemeral_state_write_suppressed"] is True
    assert tool.resources[0].access == {"data.read"}
