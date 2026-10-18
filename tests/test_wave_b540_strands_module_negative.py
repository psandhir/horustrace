"""WAB-04: source-bound negative: package submodule is not an @tool callable."""
from __future__ import annotations

from pathlib import Path

from horustrace.source_native_strands import inspect_strands_tool_composition


def test_package_module_name_does_not_create_a_false_strands_tool_edge(
    tmp_path: Path,
) -> None:
    package = tmp_path / "agents"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from .pricing_explorer import compare_regional_pricing\n"
        "__all__ = ['pricing_explorer', 'compare_regional_pricing']\n",
        encoding="utf-8",
    )
    (package / "pricing_explorer.py").write_text(
        "from strands import Agent, tool\n"
        "@tool\n"
        "def compare_regional_pricing():\n"
        "    agent = Agent(tools=[])\n"
        "    return agent('price')\n",
        encoding="utf-8",
    )
    main = tmp_path / "main.py"
    main.write_text(
        "from strands import Agent\n"
        "from agents import pricing_explorer\n"
        "def orchestrate():\n"
        "    common_tools = []\n"
        "    agents = [pricing_explorer]\n"
        "    return Agent(tools=common_tools + agents)\n",
        encoding="utf-8",
    )
    module_candidate = inspect_strands_tool_composition(tmp_path)
    assert not module_candidate.bindings
    assert not module_candidate.entities

    # The actual decorated symbol *is* exported and must remain detectable.
    main.write_text(
        "from strands import Agent\n"
        "from agents import compare_regional_pricing\n"
        "def orchestrate():\n"
        "    common_tools = []\n"
        "    agents = [compare_regional_pricing]\n"
        "    return Agent(tools=common_tools + agents)\n",
        encoding="utf-8",
    )
    callable_candidate = inspect_strands_tool_composition(tmp_path)
    assert len(callable_candidate.bindings) == 2
    assert any(entity.name == "compare_regional_pricing"
               for entity in callable_candidate.entities)
    assert all(binding.metadata["runtime_verified"] is False
               for binding in callable_candidate.bindings)
