"""FastAgent rw002 post-hoc source positive/negative contract tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from scripts import verify_wave_b540_rw002_fastagent_negatives as module


def _fake_pinned_source(tmp_path: Path, monkeypatch) -> tuple[dict[str, bytes], Path]:
    file = tmp_path / module.APP_FILE
    file.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "from mcp_agent.core.fastagent import FastAgent",
        "class McpAgent: pass",
    ]

    def put(line: int, value: str) -> None:
        while len(lines) < line - 1:
            lines.append("")
        lines.append(value)

    put(63, "class TagRelayAgent(McpAgent): pass")
    put(71, "fast = FastAgent('fixture')")
    put(75, "@fast.agent(name='Primary')")
    put(76, "async def primary(): pass")
    put(80, "@fast.custom(TagRelayAgent, name='Custom')")
    put(81, "async def custom(): pass")
    source = ("\n".join(lines) + "\n").encode()
    file.write_bytes(source)

    other_path = tmp_path / module.COMPACTION_FILE
    other_path.parent.mkdir(parents=True, exist_ok=True)
    other_lines = [""] * 533 + [
        "def create():", "    pass",
        "    shell = LlmAgent(AgentConfig(name='compactor'))",
    ]
    assert "LlmAgent" in other_lines[535]
    other = ("\n".join(other_lines) + "\n").encode()
    other_path.write_bytes(other)
    sources = {module.APP_FILE: source, module.COMPACTION_FILE: other}
    monkeypatch.setattr(module, "BLOBS", {
        path: module._blob(raw) for path, raw in sources.items()
    })
    monkeypatch.setattr(module, "DECORATED_AGENTS", {
        ("Primary", "agent", 75), ("Custom", "custom", 80)
    })
    return sources, tmp_path


def test_source_pos_and_negative_roles_remain_separate(tmp_path: Path, monkeypatch) -> None:
    sources, root = _fake_pinned_source(tmp_path, monkeypatch)
    result = module.adjudicate(sources, root)
    assert result["source_positive_agent_count"] == 2
    assert result["custom_agent_declarations"] == 1
    assert len(result["source_hard_negative_not_agent"]) == 2
    assert {r["symbol"] for r in result["source_hard_negative_not_agent"]} == {
        "fast", "TagRelayAgent"
    }
    assert result["secondary_source_conditional_agents"][0]["line"] == 536
    assert result["agent_precision"] is None and result["agent_recall"] is None
    assert result["independent_exhaustive_negative_labels"] is False
    assert result["original_frozen_reference_rewritten"] is False
    assert result["wave_b_go"] is False


def test_changes_to_source_bytes_do_not_pass_git_blob_pin(
    tmp_path: Path, monkeypatch,
) -> None:
    sources, root = _fake_pinned_source(tmp_path, monkeypatch)
    sources[module.APP_FILE] += b"# mutation\n"
    with pytest.raises(ValueError, match="Git blob changed"):
        module.adjudicate(sources, root)


def test_missing_second_source_file_is_not_assumed_no_compactor(
    tmp_path: Path, monkeypatch,
) -> None:
    sources, root = _fake_pinned_source(tmp_path, monkeypatch)
    del sources[module.COMPACTION_FILE]
    with pytest.raises(ValueError, match="exact pinned"):
        module.adjudicate(sources, root)


def test_factory_is_not_mislabeled_as_agent(tmp_path: Path, monkeypatch) -> None:
    sources, root = _fake_pinned_source(tmp_path, monkeypatch)
    item = sources[module.APP_FILE].replace(
        b"fast = FastAgent('fixture')", b"fast = SomethingElse('fixture')"
    )
    monkeypatch.setattr(module, "BLOBS", {
        **module.BLOBS, module.APP_FILE: module._blob(item)
    })
    sources[module.APP_FILE] = item
    (root / module.APP_FILE).write_bytes(item)
    with pytest.raises(ValueError, match="factory/custom subclass"):
        module.adjudicate(sources, root)


def test_source_only_custom_agents_are_not_invented_absent(
    tmp_path: Path, monkeypatch,
) -> None:
    sources, root = _fake_pinned_source(tmp_path, monkeypatch)
    modified = sources[module.APP_FILE].replace(
        b"@fast.custom(TagRelayAgent, name='Custom')", b"@fast.chain(name='Custom')"
    )
    monkeypatch.setattr(module, "BLOBS", {
        **module.BLOBS, module.APP_FILE: module._blob(modified)
    })
    sources[module.APP_FILE] = modified
    (root / module.APP_FILE).write_bytes(modified)
    with pytest.raises(ValueError, match="census changed"):
        module.adjudicate(sources, root)


def test_source_negative_class_without_proof_is_unresolved(
    tmp_path: Path, monkeypatch,
) -> None:
    sources, root = _fake_pinned_source(tmp_path, monkeypatch)
    altered = sources[module.APP_FILE].replace(
        b"TagRelayAgent(McpAgent)", b"TagRelayAgent(object)"
    )
    monkeypatch.setattr(module, "BLOBS", {
        **module.BLOBS, module.APP_FILE: module._blob(altered)
    })
    sources[module.APP_FILE] = altered
    (root / module.APP_FILE).write_bytes(altered)
    with pytest.raises(ValueError, match="factory/custom subclass"):
        module.adjudicate(sources, root)


def test_compactor_source_declaration_missing_fails_closed(
    tmp_path: Path, monkeypatch,
) -> None:
    sources, root = _fake_pinned_source(tmp_path, monkeypatch)
    changed = sources[module.COMPACTION_FILE].replace(b"LlmAgent(", b"Helper(")
    monkeypatch.setattr(module, "BLOBS", {
        **module.BLOBS, module.COMPACTION_FILE: module._blob(changed)
    })
    sources[module.COMPACTION_FILE] = changed
    (root / module.COMPACTION_FILE).write_bytes(changed)
    with pytest.raises(ValueError, match="compaction LlmAgent"):
        module.adjudicate(sources, root)


def test_same_decorator_name_duplicate_is_not_independently_truth(
    tmp_path: Path, monkeypatch,
) -> None:
    sources, root = _fake_pinned_source(tmp_path, monkeypatch)
    changed = sources[module.APP_FILE].replace(
        b"name='Custom'", b"name='Primary'"
    )
    monkeypatch.setattr(module, "BLOBS", {
        **module.BLOBS, module.APP_FILE: module._blob(changed)
    })
    sources[module.APP_FILE] = changed
    (root / module.APP_FILE).write_bytes(changed)
    with pytest.raises(ValueError, match="census changed"):
        module.adjudicate(sources, root)
