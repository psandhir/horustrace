"""Source-only positive and hard-negative tests for imported Strands tools."""
from pathlib import Path

from horustrace.strands_repository import _build_modules, _vended_tool


def test_python_repl_alias_is_observed_import_not_observed_effect(tmp_path: Path):
    source = tmp_path / "agent.py"
    source.write_text("from strands_tools import python_repl as local_repl\n", encoding="utf-8")
    info = next(iter(_build_modules(tmp_path, [source]).values()))
    tool = _vended_tool(info, "local_repl")
    assert tool is not None
    assert any(
        fact.fact == "source_import=strands_tools.python_repl"
        and fact.origin == "observed"
        for fact in tool.provenance
    )
    assert all(
        fact.origin == "inferred"
        for fact in tool.provenance
        if fact.fact.startswith("capability=")
    )


def test_duplicate_python_repl_alias_is_not_resolved(tmp_path: Path):
    source = tmp_path / "agent.py"
    source.write_text(
        "from strands_tools import python_repl as local_repl\n"
        "from strands_tools import python_repl as local_repl\n",
        encoding="utf-8",
    )
    info = next(iter(_build_modules(tmp_path, [source]).values()))
    assert _vended_tool(info, "local_repl") is None
