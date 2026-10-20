"""rw149 source-conditional Pydantic tools: scoped, never effective authority."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COHORT = ROOT / "research/wave-c-c02f-active145/expected-agent-review-scopes.json"
TREE = ROOT / "research/wave-c-c02j-rw149/pinned-source-tree.json"
LEDGER = ROOT / "research/wave-c-c02j-rw149/conditional-tool-source-candidates.json"
SHA = re.compile(r"[a-f0-9]{40}\Z")


def _docs() -> tuple[dict, dict]:
    return (
        json.loads(TREE.read_text(encoding="utf-8")),
        json.loads(LEDGER.read_text(encoding="utf-8")),
    )


def _source_line(doc: dict, path: str, line: int) -> str:
    results = [
        row["expression"] for row in doc["observations"]
        if row["path"] == path and row["line"] == line
    ]
    assert len(results) == 1, (path, line)
    return results[0]


def test_rw149_cohort_and_source_sha_are_not_scanner_derived() -> None:
    tree, doc = _docs()
    scopes = json.loads(COHORT.read_text(encoding="utf-8"))["expected_scopes"]
    case = next(row for row in scopes if row["case_id"] == "rw-149")
    assert case["framework"] == "pydantic-ai"
    assert doc["cohort_scope_id"] == case["scope_id"]
    assert case["source_role"] == doc["source_role"] == "unknown"
    assert doc["repository"] == case["repository"] == tree["repository"]
    assert doc["pinned_commit_sha"] == case["commit_sha"] == tree["commit_sha"]
    assert tree["truncated"] is False
    assert len(tree["entries"]) == 22
    assert tree["tree_sha"] == doc["pinned_tree_sha"]
    assert tree["tree_sha"] == "672f992626f1d06f45e8effcb0756059171c9a2c"


def test_rw149_source_sites_are_pinned_to_existing_git_blobs() -> None:
    tree, doc = _docs()
    blob_sha = {item["path"]: item["sha"] for item in tree["entries"]
                if item["type"] == "blob"}
    files = {item["path"]: item["blob_sha"] for item in doc["source_files"]}
    assert set(files) == {
        "agent/agent.py", "agent/tools.py", "agent/base_agent.py", "app.py",
    }
    assert len(files) == 4
    assert len(doc["observations"]) == 37
    assert len({item["id"] for item in doc["observations"]}) == 37
    assert all(blob_sha[path] == sha and SHA.fullmatch(sha)
               for path, sha in files.items())
    assert all(
        entry["path"] in files
        and files[entry["path"]] == entry["blob_sha"]
        and isinstance(entry["line"], int) and entry["line"] > 0
        and entry["expression"].strip()
        and entry["source_syntax_only"] is True
        for entry in doc["observations"]
    )


def test_rw149_four_declared_level_tool_sets_are_source_conditional() -> None:
    _, doc = _docs()
    table = {
        entry["demo_level"]: entry["source_selected_tool_symbols"]
        for entry in doc["declared_tool_sets"]
    }
    assert set(table) == {1, 2, 3, 4}
    assert table[1] == []
    assert table[2] == ["list_tables", "describe_table"]
    full = [
        "list_tables", "describe_table", "execute_query",
        "get_current_date", "get_stock_query_template",
    ]
    assert table[3] == full
    assert table[4] == full
    assert _source_line(doc, "agent/tools.py", 422) == "if level == 1:"
    assert _source_line(doc, "agent/tools.py", 423) == "return []"
    assert _source_line(doc, "agent/tools.py", 424) == "elif level == 2:"
    assert _source_line(doc, "agent/tools.py", 425) == (
        "return [list_tables, describe_table]"
    )
    assert _source_line(doc, "agent/tools.py", 427) == "return ["
    assert [
        _source_line(doc, "agent/tools.py", n).rstrip(",")
        for n in range(428, 433)
    ] == full
    assert _source_line(doc, "agent/tools.py", 433) == "]"


def test_rw149_constructor_and_tool_binding_chain_is_explicit() -> None:
    _, doc = _docs()
    assert _source_line(doc, "agent/agent.py", 83) == (
        "tools = get_tools_for_level(self.demo_level)"
    )
    assert _source_line(doc, "agent/agent.py", 96).startswith(
        "self._agent: BaseAgent"
    )
    assert _source_line(doc, "agent/agent.py", 99) == "tools=tools,"
    assert _source_line(doc, "agent/base_agent.py", 110) == (
        "self.tools = tools or []"
    )
    assert _source_line(doc, "agent/base_agent.py", 131).startswith(
        "self._agent: Agent"
    )
    assert _source_line(doc, "agent/base_agent.py", 134) == (
        "for tool in self.tools:"
    )
    assert _source_line(doc, "agent/base_agent.py", 135) == (
        "self._agent.tool(tool)"
    )
    assert _source_line(doc, "app.py", 43) == "agent = SQLQueryAgent()"


def test_rw149_default_is_environment_dependent_not_deployed_truth() -> None:
    _, doc = _docs()
    assert _source_line(doc, "agent/agent.py", 35) == (
        'return int(os.getenv("DEMO_LEVEL", "4"))'
    )
    assert _source_line(doc, "agent/agent.py", 74) == (
        "self.demo_level = demo_level or get_demo_level()"
    )
    assert _source_line(doc, "agent/agent.py", 91) == (
        "if self.demo_level == 1:"
    )
    assert _source_line(doc, "agent/agent.py", 92) == (
        "output_type = StructuredQueryPlan"
    )


def test_rw149_source_level_negative_not_runtime_authorization() -> None:
    _, doc = _docs()
    assert doc["record_type"] == (
        "source_first_conditional_tool_selection_not_runtime_authority"
    )
    for key in (
        "source_checkout_verification_completed",
        "independent_source_review_completed",
        "positive_universe_complete", "negative_universe_complete",
        "actual_deployed_demo_level_verified",
        "agent_tool_runtime_callability_verified",
        "production_cutover_authorized",
    ):
        assert doc[key] is False
    assert doc["certified_precision"] is None
    assert doc["certified_recall"] is None
    assert len(doc["source_review_questions"]) >= 7
    assert all(
        "truth" not in item and "expected_label" not in item
        for item in doc["observations"]
    )
