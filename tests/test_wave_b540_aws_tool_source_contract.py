"""Wave B source-contract regression guards for third-party AWS and MCP effects."""
from pathlib import Path

from horustrace.strands_repository import _build_modules, _vended_tool


def _tool(tmp_path: Path, text: str, name: str):
    source = tmp_path / "agent.py"
    source.write_text(text, encoding="utf-8")
    info = next(iter(_build_modules(tmp_path, [source]).values()))
    return _vended_tool(info, name)


def test_aws_tool_alias_is_source_observed_but_effect_inferred(tmp_path: Path):
    tool = _tool(tmp_path, "from strands_tools import use_aws as aws_access\n", "aws_access")
    assert tool is not None
    assert any(
        fact.fact == "source_import=strands_tools.use_aws" and fact.origin == "observed"
        for fact in tool.provenance
    )
    assert all(
        fact.origin == "inferred"
        for fact in tool.provenance
        if fact.fact.startswith("capability=")
    )
    assert not any(
        "BYPASS_TOOL_CONSENT" in fact.fact or "approval" in fact.fact
        for fact in tool.provenance
    )


def test_file_write_import_does_not_verify_runtime_control(tmp_path: Path):
    tool = _tool(tmp_path, "from strands_tools import file_write\n", "file_write")
    assert tool is not None
    assert any(fact.fact == "source_import=strands_tools.file_write" for fact in tool.provenance)
    assert all(
        fact.origin == "inferred"
        for fact in tool.provenance
        if fact.fact.startswith("capability=")
    )
    assert not any("approval" in fact.fact or "allowlist" in fact.fact for fact in tool.provenance)


def test_ambiguous_aws_tool_alias_is_not_resolved(tmp_path: Path):
    assert _tool(
        tmp_path,
        "from strands_tools import use_aws as aws_access\n"
        "from strands_tools import use_aws as aws_access\n",
        "aws_access",
    ) is None
