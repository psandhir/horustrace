"""Wave B: decorated Strands tool wrappers are not already-instantiated agents."""
from __future__ import annotations

from pathlib import Path

from horustrace.models import Agent, Graph, SourceLocation, Tool
from horustrace.scanner import (
    _consolidate_agents,
    _dedupe_strands_source_tool_projections,
)
from horustrace.strands_repository import (
    _append_tool,
    _build_modules,
    _strands_decorated_function_tool,
    enrich_strands_repository_graph,
)


def _repo(root: Path, decorated: bool = True) -> list[Path]:
    agents = root / "agents"
    agents.mkdir(parents=True)
    main = root / "main.py"
    init = agents / "__init__.py"
    specialist = agents / "specialist.py"
    main.write_text(
        "from strands import Agent\n"
        "from agents import specialist\n"
        "def run():\n"
        "    common_tools = []\n"
        "    agents = [specialist]\n"
        "    orchestrator = Agent(tools=common_tools + agents)\n"
        "    return orchestrator\n",
        encoding="utf-8",
    )
    init.write_text(
        "from .specialist import specialist\n", encoding="utf-8",
    )
    decorator = "@tool\n" if decorated else ""
    specialist.write_text(
        "from strands import Agent, tool\n"
        + decorator
        + "def specialist():\n"
        "    agent = Agent(tools=[])\n"
        "    return agent('a task')\n",
        encoding="utf-8",
    )
    return [main, init, specialist]


def test_decorated_wrapper_is_callable_tool_not_live_delegation(
    tmp_path: Path,
) -> None:
    paths = _repo(tmp_path)
    modules = _build_modules(tmp_path, paths)
    main = modules["main"]
    tool = _strands_decorated_function_tool(modules, main, "specialist")
    assert tool is not None
    assert tool.name == "specialist"
    assert tool.kind == "strands_tool_wrapper"
    assert tool.location is not None
    assert tool.location.path.name == "specialist.py"
    assert tool.metadata["nested_agent_execution"] == (
        "deferred_until_wrapper_invocation"
    )
    assert tool.metadata["delegation_target_resolution"] == (
        "unresolved_runtime_instance"
    )

    graph = Graph()
    enrich_strands_repository_graph(graph, tmp_path, python_paths=paths)
    orchestrators = [x for x in graph.agents if x.name == "orchestrator"]
    assert len(orchestrators) == 1
    parent = orchestrators[0]
    assert any(
        t.kind == "strands_tool_wrapper" and t.name == "specialist"
        for t in parent.tools
    )
    assert not any(t.kind == "delegated_agent" for t in parent.tools)
    assert not parent.metadata.get("delegates_to")


def test_function_without_strands_tool_decorator_is_not_wrapper_proof(
    tmp_path: Path,
) -> None:
    paths = _repo(tmp_path, decorated=False)
    modules = _build_modules(tmp_path, paths)
    assert _strands_decorated_function_tool(
        modules, modules["main"], "specialist",
    ) is None


def test_shadowed_or_unresolved_import_cannot_invent_wrapper(
    tmp_path: Path,
) -> None:
    paths = _repo(tmp_path)
    source = tmp_path / "agents" / "specialist.py"
    source.write_text(
        "from strands import Agent\n"
        "def tool(fn):\n    return fn\n"
        "@tool\n"
        "def specialist():\n"
        "    agent = Agent(tools=[])\n"
        "    return agent('x')\n",
        encoding="utf-8",
    )
    modules = _build_modules(tmp_path, paths)
    assert _strands_decorated_function_tool(
        modules, modules["main"], "specialist",
    ) is None


def test_same_source_decorated_callable_deduplicates_kind_projections(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "weather.py", line=80)
    source_key = "weather.weather_assistant"
    legacy = Tool(
        name="weather_assistant", kind="function",
        location=location, capabilities={"data.read"},
        metadata={"source_function_key": source_key, "binding_origin": "@tool"},
    )
    wrapper = Tool(
        name="weather_assistant", kind="strands_tool_wrapper",
        location=location, capabilities={"network.external"},
        metadata={
            "source_function_key": source_key,
            "source_tool_decorator": "strands.tool",
            "nested_agent_execution": "deferred_until_wrapper_invocation",
        },
    )
    agent = Agent(name="orchestrator", tools=[legacy], location=location)
    _append_tool(agent, wrapper)
    assert len(agent.tools) == 1
    merged = agent.tools[0]
    assert merged.kind == "strands_tool_wrapper"
    assert merged.capabilities == {"data.read", "network.external"}
    assert merged.metadata["source_tool_decorator"] == "strands.tool"
    assert merged.metadata["nested_agent_execution"] == (
        "deferred_until_wrapper_invocation"
    )


def test_same_name_distinct_source_definitions_do_not_merge(
    tmp_path: Path,
) -> None:
    first = SourceLocation(tmp_path / "first.py", line=80)
    second = SourceLocation(tmp_path / "second.py", line=80)
    agent = Agent(name="orchestrator", tools=[Tool(
        name="weather_assistant", kind="function", location=first,
        metadata={"source_function_key": "first.weather_assistant"},
    )])
    _append_tool(agent, Tool(
        name="weather_assistant", kind="strands_tool_wrapper", location=second,
        metadata={"source_function_key": "second.weather_assistant"},
    ))
    assert len(agent.tools) == 2
    assert {t.kind for t in agent.tools} == {
        "function", "strands_tool_wrapper",
    }


def test_unlocated_or_unproven_symbol_cannot_merge_tool_kinds(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "weather.py", line=80)
    agent = Agent(name="orchestrator", tools=[Tool(
        name="weather_assistant", kind="function", location=location,
    )])
    _append_tool(agent, Tool(
        name="weather_assistant", kind="strands_tool_wrapper", location=location,
        metadata={"source_function_key": "weather.weather_assistant"},
    ))
    assert len(agent.tools) == 2


def test_production_consolidation_removes_duplicate_decorated_tool(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "agent_stdio_multi_agent.py", line=80)
    metadata = {
        "framework": "strands-agents",
        "source_function_key": "agent_stdio_multi_agent.weather_assistant",
        "source_path": str(location.path),
        "source_line": 80,
    }
    tools = [
        Tool(name="weather_assistant", kind="function",
             location=location, metadata={**metadata, "binding_origin": "@tool"}),
        Tool(name="weather_assistant", kind="strands_tool_wrapper",
             location=location, metadata={
                 **metadata, "source_tool_decorator": "strands.tool",
                 "nested_agent_execution": "deferred_until_wrapper_invocation",
             }),
    ]
    agent = Agent(
        name="orchestrator_agent", location=SourceLocation(
            location.path, line=116,
        ),
        metadata={"framework": "strands-agents"}, tools=tools,
    )
    graph = Graph(agents=[agent])
    _consolidate_agents(graph)
    assert len(graph.agents) == 1
    assert len(graph.agents[0].tools) == 1
    merged = graph.agents[0].tools[0]
    assert merged.kind == "strands_tool_wrapper"
    assert merged.metadata["source_tool_decorator"] == "strands.tool"
    assert merged.metadata["nested_agent_execution"] == (
        "deferred_until_wrapper_invocation"
    )


def test_production_dedup_keeps_unproved_and_distinct_source_tools(
    tmp_path: Path,
) -> None:
    path = tmp_path / "tools.py"
    location = SourceLocation(path, line=20)
    other = SourceLocation(path, line=23)
    base = {
        "framework": "strands-agents",
        "source_function_key": "tools.same_name",
        "source_path": str(path),
        "source_line": 20,
    }
    agent = Agent(
        name="orchestrator", location=SourceLocation(path, line=40),
        metadata={"framework": "strands-agents"},
        tools=[
            Tool(name="same_name", kind="function", location=location,
                 metadata=base),
            Tool(name="same_name", kind="strands_tool_wrapper",
                 location=other, metadata={**base, "source_line": 23}),
            Tool(name="same_name", kind="strands_tool_wrapper",
                 location=location, metadata={"framework": "strands-agents"}),
        ],
    )
    graph = Graph(agents=[agent])
    _consolidate_agents(graph)
    assert len(graph.agents[0].tools) == 3


def test_late_source_annotation_reconciles_previous_unknown_identity(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "agent_stdio_multi_agent.py", line=80)
    legacy = Tool(
        name="weather_assistant", kind="function",
        location=location, metadata={"framework": "strands-agents"},
    )
    wrapper = Tool(
        name="weather_assistant", kind="strands_tool_wrapper",
        location=location, metadata={
            "framework": "strands-agents",
            "nested_agent_execution": "deferred_until_wrapper_invocation",
        },
    )
    agent = Agent(
        name="orchestrator", location=SourceLocation(location.path, line=120),
        metadata={"framework": "strands-agents"}, tools=[legacy, wrapper],
    )
    graph = Graph(agents=[agent])
    _consolidate_agents(graph)
    assert len(graph.agents[0].tools) == 2

    # This normalized identity is attached after consolidation, when exact
    # source provenance resolves the imported decorated function's symbol.
    for tool in graph.agents[0].tools:
        tool.metadata.update({
            "source_function_key": "agent_stdio_multi_agent.weather_assistant",
            "source_path": str(location.path),
            "source_line": 80,
        })
    _dedupe_strands_source_tool_projections(graph.agents[0])
    assert len(graph.agents[0].tools) == 1
    assert graph.agents[0].tools[0].kind == "strands_tool_wrapper"
    assert graph.agents[0].tools[0].metadata["nested_agent_execution"] == (
        "deferred_until_wrapper_invocation"
    )
