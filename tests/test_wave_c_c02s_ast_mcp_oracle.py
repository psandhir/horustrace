"""C02s independent AST MCP syntax oracle: hard-negative and mutation tests."""

from __future__ import annotations

from copy import deepcopy

import pytest

from horustrace.source_truth_ast_mcp import (
    inspect_mcp_python,
    inspect_mcp_scope,
)
from scripts.wave_c_c02s_independent_ast_mcp_study import compare_scope

BASE = """
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("Calculator")

@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b

@mcp.resource("data://{name}")
def resource(name: str) -> str:
    return name

@mcp.prompt()
def prompt() -> str:
    return "template"
"""


def test_c02s_literal_constructor_and_decorators_only() -> None:
    result = inspect_mcp_python("one.py", BASE)
    assert [(x["name"], x["symbol"]) for x in result["implementations"]] == [
        ("Calculator", "mcp"),
    ]
    assert [(x["function"], x["name"]) for x in result["tools"]] == [
        ("add", "add"),
    ]
    assert {x["kind"] for x in result["excluded_non_tools"]} == {
        "resource", "prompt",
    }
    assert not result["unresolved"]
    assert result["tools"][0]["source_only"] is True


def test_c02s_duplicate_display_names_are_not_one_identity() -> None:
    scope = inspect_mcp_scope({"a.py": BASE, "b.py": BASE})
    assert len(scope["implementations"]) == 2
    assert len({x["id"] for x in scope["implementations"]}) == 2
    assert len(scope["tools"]) == 2
    assert len({x["id"] for x in scope["tools"]}) == 2
    assert scope["certified_precision"] is None
    assert scope["certified_recall"] is None
    assert scope["production_cutover_authorized"] is False


def test_c02s_metamorphic_comments_and_whitespace_not_extra_tools() -> None:
    baseline = inspect_mcp_python("same.py", BASE)
    mutated = inspect_mcp_python(
        "same.py", BASE + "\n# @mcp.tool()\n# def misleading(): pass\n",
    )
    assert [x["name"] for x in mutated["tools"]] == [
        x["name"] for x in baseline["tools"]
    ]
    assert len(mutated["implementations"]) == 1
    assert len(mutated["excluded_non_tools"]) == 2


def test_c02s_dynamic_registration_is_unresolved_not_negative() -> None:
    code = BASE + "\nmcp.add_tool(lambda: 42)\n"
    result = inspect_mcp_python("one.py", code)
    assert any(x["reason"] == "dynamic_registration_not_evaluated"
               for x in result["unresolved"])
    assert inspect_mcp_scope({"one.py": code})["source_scope_complete"] is False


def test_c02s_dynamic_export_name_is_not_inferred() -> None:
    source = """
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("one")
@mcp.tool(name=get_tool_name())
def add(): pass
"""
    result = inspect_mcp_python("one.py", source)
    assert result["tools"] == []
    assert result["unresolved"][0]["reason"] == "dynamic_tool_export_name"


def test_c02s_alias_import_is_supported_but_unknown_owner_not_invented() -> None:
    source = """
from mcp.server.fastmcp import FastMCP as Server
host = Server("a")
@host.tool()
def yes(): pass
@not_host.tool()
def no(): pass
"""
    result = inspect_mcp_python("one.py", source)
    assert [x["name"] for x in result["tools"]] == ["yes"]
    assert any(x["reason"] == "unknown_mcp_decorator_owner"
               for x in result["unresolved"])


def test_c02s_reassigned_server_alias_is_not_certified() -> None:
    source = BASE + "\nmcp = object()\n"
    result = inspect_mcp_python("one.py", source)
    assert result["implementations"] == []
    assert result["tools"] == []
    assert any(x["reason"] == "implementation_symbol_rebound"
               for x in result["unresolved"])


def test_c02s_scope_path_and_syntax_fail_closed() -> None:
    for path in ("../escape.py", "/tmp/root.py", "example.js", "a\\b.py"):
        with pytest.raises(ValueError):
            inspect_mcp_python(path, BASE)
    with pytest.raises(SyntaxError):
        inspect_mcp_python("broken.py", "def x(: pass")
    with pytest.raises(ValueError):
        inspect_mcp_scope({})


def test_c02s_source_shadow_disagreement_is_symmetric_and_unscored() -> None:
    oracle = inspect_mcp_scope({"mcp_server_1.py": BASE})
    implementation = oracle["implementations"][0]
    tool = oracle["tools"][0]
    matching = {
        "nodes": [
            {
                "kind": "mcp_source_implementation",
                "name": implementation["name"],
                "location": {"path": implementation["path"],
                             "line": implementation["line"]},
            },
            {
                "kind": "mcp_source_tool",
                "name": tool["name"],
                "location": {"path": tool["path"], "line": tool["line"]},
            },
        ],
    }
    result = compare_scope(oracle, matching)
    assert result["missing_source_tool_sites_in_shadow"] == []
    assert result["missing_source_implementations_in_shadow"] == []
    missing = deepcopy(matching)
    missing["nodes"] = [matching["nodes"][0]]
    disagreement = compare_scope(oracle, missing)
    assert len(disagreement["missing_source_tool_sites_in_shadow"]) == 1
    assert disagreement["certified_false_negatives"] is None
    assert disagreement["effective_agent_can_call"] is None


def test_c02s_no_false_runtime_or_human_independence_claims() -> None:
    output = inspect_mcp_scope({"a.py": BASE})
    assert output["runtime_server_connected"] is None
    assert output["runtime_tool_catalogue_verified"] is False
    assert output["effective_agent_can_call"] is None
    assert output["independent_human_review_verified"] is False
    assert output["complete_scope_kind"].endswith("decorated_tools_only")
