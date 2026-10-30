"""C02u Pydantic source-only conditional tool set AST hard-negative tests."""

from __future__ import annotations

import pytest

from horustrace.source_truth_ast_pydantic import (
    inspect_pydantic_level_returns,
    inspect_pydantic_tool_plumbing,
)

SOURCE = """
def get_tools_for_level(level: int) -> list:
    if level == 1:
        return []
    elif level == 2:
        return [list_tables, describe_table]
    else:
        return [
            list_tables, describe_table, execute_query,
            get_current_date, get_stock_query_template,
        ]
"""

OUTER = """
class SQLQueryAgent:
    def __init__(self):
        tools = get_tools_for_level(self.demo_level)
        self._agent = BaseAgent(model="x", tools=tools)
"""

INNER = """
class BaseAgent:
    def __init__(self, tools):
        self.tools = tools or []
        for tool in self.tools:
            self._agent.tool(tool)
"""


def test_c02u_literal_level_1_2_else_sets_are_mechanical() -> None:
    result = inspect_pydantic_level_returns("agent/tools.py", SOURCE)
    assert result["level_1"] == []
    assert result["level_2"] == ["list_tables", "describe_table"]
    assert result["else_branch_other_values"] == [
        "list_tables", "describe_table", "execute_query",
        "get_current_date", "get_stock_query_template",
    ]
    assert result["level_3_uses_else"] is True
    assert result["level_4_uses_else"] is True
    assert result["runtime_level_value_known"] is False
    assert result["runtime_tools_registered"] is None
    assert result["certified_precision"] is None
    assert result["production_cutover_authorized"] is False


def test_c02u_whitespace_and_comments_do_not_change_source_selection() -> None:
    first = inspect_pydantic_level_returns("agent/tools.py", SOURCE)
    second = inspect_pydantic_level_returns(
        "agent/tools.py", SOURCE + "\n# return [imaginary_tool]\n"
    )
    for key in ("level_1", "level_2", "else_branch_other_values"):
        assert first[key] == second[key]


def test_c02u_other_levels_not_falsely_described_as_blocked() -> None:
    result = inspect_pydantic_level_returns("agent/tools.py", SOURCE)
    assert "else_branch_other_values" in result
    assert result["level_3_uses_else"] and result["level_4_uses_else"]


def test_c02u_dynamic_branch_or_condition_fails_closed() -> None:
    altered = SOURCE.replace("return [list_tables, describe_table]",
                             "return tool_factory(level)")
    with pytest.raises(ValueError):
        inspect_pydantic_level_returns("agent/tools.py", altered)
    with pytest.raises(ValueError):
        inspect_pydantic_level_returns(
            "agent/tools.py", SOURCE.replace("level == 2", "level >= 2")
        )


def test_c02u_duplicate_source_tool_symbols_fail_closed() -> None:
    bad = SOURCE.replace("return [list_tables, describe_table]",
                         "return [list_tables, list_tables]")
    with pytest.raises(ValueError):
        inspect_pydantic_level_returns("agent/tools.py", bad)


def test_c02u_source_selection_to_sdk_wrapper_is_source_only() -> None:
    result = inspect_pydantic_tool_plumbing(OUTER, INNER)
    assert result["selected_tool_registration_source_chain"] is True
    assert result["runtime_tool_registration_verified"] is False
    assert result["effective_agent_can_call"] is None


def test_c02u_breaking_wrapper_registration_fails_closed() -> None:
    bad = INNER.replace("self._agent.tool(tool)", "self._agent.other(tool)")
    with pytest.raises(ValueError):
        inspect_pydantic_tool_plumbing(OUTER, bad)
    bad_owner = INNER.replace("self.tools = tools or []", "self.tools = []")
    with pytest.raises(ValueError):
        inspect_pydantic_tool_plumbing(OUTER, bad_owner)
    bad2 = OUTER.replace("tools=tools", "tools=everything")
    with pytest.raises(ValueError):
        inspect_pydantic_tool_plumbing(bad2, INNER)


def test_c02u_path_syntax_and_missing_function_fail_closed() -> None:
    for path in ("/unsafe.py", "../bad.py", "bad.js", "bad\\tools.py"):
        with pytest.raises(ValueError):
            inspect_pydantic_level_returns(path, SOURCE)
    with pytest.raises(ValueError):
        inspect_pydantic_level_returns(
            "agent/tools.py", SOURCE.replace(
                "def get_tools_for_level", "def another_function"
            )
        )
    with pytest.raises(SyntaxError):
        inspect_pydantic_level_returns("agent/tools.py", "def wrong(:")


def test_c02u_plumbing_dynamic_selector_is_not_accepted_as_static() -> None:
    changed = OUTER.replace(
        "get_tools_for_level(self.demo_level)", "custom_selector(self.demo_level)"
    )
    with pytest.raises(ValueError):
        inspect_pydantic_tool_plumbing(changed, INNER)
