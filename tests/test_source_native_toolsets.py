"""Evidence-scoped MCP ToolSet source-linking and authority hard negatives."""
from __future__ import annotations

import json
from pathlib import Path

from horustrace.models import Graph
from horustrace.semantic_shadow import shadow_observation_report
from horustrace.source_native_toolsets import inspect_local_toolset_catalogues


def _fixture(root: Path) -> None:
    package = root / "src" / "cb_mcp"
    for directory in (
        package / "core",
        package / "servers" / "operational",
        package / "tools" / "operational",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    (package / "core" / "spec.py").write_text(
        "class ServerSpec:\n    pass\nclass ToolSet:\n    pass\n",
        encoding="utf-8",
    )
    (package / "core" / "app.py").write_text(
        "from fastmcp import FastMCP\n"
        "from fastmcp.tools import FunctionTool\n"
        "def build_app(tools):\n"
        "    mcp = FastMCP('test')\n"
        "    for tool in tools:\n"
        "        obj = FunctionTool.from_function(tool)\n"
        "        mcp.add_tool(obj)\n"
        "    return mcp\n",
        encoding="utf-8",
    )
    (package / "tools" / "operational" / "ops.py").write_text(
        "def read_tool():\n    return 1\n"
        "def write_tool():\n    return 2\n",
        encoding="utf-8",
    )
    (package / "tools" / "operational" / "__init__.py").write_text(
        "from ...core.spec import ToolSet\n"
        "from .ops import read_tool as read_alias, write_tool\n"
        "TOOL_SET = ToolSet(\n"
        "    read_only=(read_alias,),\n"
        "    write=(write_tool,),\n"
        ")\n",
        encoding="utf-8",
    )
    (package / "servers" / "operational" / "spec.py").write_text(
        "from ...core.spec import ServerSpec\n"
        "from ...tools.operational import TOOL_SET\n"
        "SPEC = ServerSpec(tools=TOOL_SET)\n",
        encoding="utf-8",
    )


def test_resolves_local_tool_names_and_preserves_conditions(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    doc = inspect_local_toolset_catalogues(tmp_path).as_dict()
    assert doc["schema_version"] == 2
    assert len(doc["bindings"]) == 2
    kinds = [e["kind"] for e in doc["entities"]]
    assert kinds.count("mcp_server") == 1
    assert kinds.count("tool") == 2
    by_id = {e["entity_id"]: e for e in doc["entities"]}
    assert {by_id[e["target_id"]]["name"] for e in doc["bindings"]} == {
        "read_tool", "write_tool",
    }
    assert all(e["kind"] == "exposes_tool" for e in doc["bindings"])
    assert all(e["resolution"] == "partial" for e in doc["bindings"])
    assert all(
        e["metadata"]["exposure_state"] == "conditional_candidate"
        and e["metadata"]["disabled_tools"] == "unresolved"
        and e["metadata"]["auth_scope"] == "unresolved"
        and e["metadata"]["agent_callability"] == "not_adjudicated"
        for e in doc["bindings"]
    )
    modes = {
        by_id[e["target_id"]]["name"]: e["metadata"]["read_only_mode"]
        for e in doc["bindings"]
    }
    assert modes == {"read_tool": "either", "write_tool": "must_be_false"}
    assert str(tmp_path) not in json.dumps(doc)
    assert not any(e["kind"] == "agent_can_call" for e in doc["bindings"])


def test_checkouts_are_portable_and_shadow_graph_is_unchanged(
    tmp_path: Path,
) -> None:
    first = tmp_path / "a"
    second = tmp_path / "b"
    _fixture(first)
    _fixture(second)
    left = inspect_local_toolset_catalogues(first).as_dict()
    right = inspect_local_toolset_catalogues(second).as_dict()
    assert left == right
    graph = Graph()
    report = shadow_observation_report(graph, first)
    assert report["source_native_toolsets"]["bindings"] == left["bindings"]
    assert report["comparison"]["graph_behavior_changed"] is False
    assert not graph.agents
    assert str(first) not in json.dumps(report)


def test_missing_runtime_registration_factory_does_not_imply_exposure(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    app = tmp_path / "src" / "cb_mcp" / "core" / "app.py"
    app.write_text(
        "from fastmcp import FastMCP\n"
        "def build_app(tools):\n    return FastMCP('test')\n",
        encoding="utf-8",
    )
    assert inspect_local_toolset_catalogues(tmp_path).bindings == []


def test_shadowed_or_unknown_imports_do_not_prove_tools(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    pkg = tmp_path / "src" / "cb_mcp" / "tools" / "operational"
    original = (pkg / "__init__.py").read_text(encoding="utf-8")
    (pkg / "__init__.py").write_text(
        original + "read_alias = lambda: None\n", encoding="utf-8",
    )
    assert inspect_local_toolset_catalogues(tmp_path).bindings == []
    (pkg / "__init__.py").write_text(
        original.replace("write_tool,),", "does_not_exist,),"),
        encoding="utf-8",
    )
    assert inspect_local_toolset_catalogues(tmp_path).bindings == []
    (pkg / "__init__.py").write_text(
        original.replace("read_alias,", "factory(),"), encoding="utf-8",
    )
    assert inspect_local_toolset_catalogues(tmp_path).bindings == []


def test_unknown_server_spec_and_local_toolset_rebinding_are_not_proof(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    spec = tmp_path / "src" / "cb_mcp" / "servers" / "operational" / "spec.py"
    original = spec.read_text(encoding="utf-8")
    spec.write_text(original + "SPEC = ServerSpec(tools=TOOL_SET)\n",
                    encoding="utf-8")
    assert inspect_local_toolset_catalogues(tmp_path).bindings == []
    spec.write_text(original, encoding="utf-8")
    package = tmp_path / "src" / "cb_mcp" / "tools" / "operational" / "__init__.py"
    package.write_text(package.read_text(encoding="utf-8")
                       + "ToolSet = LocalClass\n", encoding="utf-8")
    assert inspect_local_toolset_catalogues(tmp_path).bindings == []


def test_missing_origin_function_does_not_turn_name_into_source_fact(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    impl = tmp_path / "src" / "cb_mcp" / "tools" / "operational" / "ops.py"
    impl.write_text("read_tool = lambda: None\ndef write_tool():\n    pass\n",
                    encoding="utf-8")
    assert inspect_local_toolset_catalogues(tmp_path).bindings == []
