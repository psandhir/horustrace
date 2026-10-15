"""Wave B: decorated Strands tool wrappers are not already-instantiated agents."""
from __future__ import annotations

from pathlib import Path

from horustrace.models import Graph
from horustrace.strands_repository import (
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
