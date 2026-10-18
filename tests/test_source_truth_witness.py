"""C02b offline pinned Git witness validation and denial regressions."""
from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.source_truth_witness import (
    score_verified_reference,
    verify_reference_witnesses,
)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL
    ).decode().strip()


def _fixture(tmp_path: Path) -> tuple[dict, dict, Path]:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    src = root / "src"
    src.mkdir()
    (src / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('model')\n"
        "app = FastAgent('app')  # factory, not a source agent\n",
        encoding="utf-8",
    )
    _git(root, "add", "--", "src/agent.py")
    _git(
        root, "-c", "user.name=fixture",
        "-c", "user.email=fixture@example.org", "commit", "-qm", "fixture"
    )
    commit = _git(root, "rev-parse", "HEAD")
    blob = _git(root, "rev-parse", f"{commit}:src/agent.py")
    scope = {
        "scope_id": "d01:agent:runtime",
        "case_id": "d01",
        "repository": "example/test-fixture",
        "commit_sha": commit,
        "construct": "agent",
        "source_role": "runtime",
        "positive_complete": True,
        "negative_complete": True,
        "review_method": "independent_blind",
        "review_ref": "synthetic-only-not-human-review",
        "scanner_blind": True,
        "negative_method": "synthetic source-positive and factory-negative fixture",
    }
    def label(name: str, kind: str, line: int) -> dict:
        return {
            "scope_id": scope["scope_id"],
            "claim_id": name,
            "truth": kind,
            "source": {
                "path": "src/agent.py", "blob_sha": blob,
                "line_start": line, "line_end": line,
            },
            "reason": "synthetic fixture only",
        }
    ref = {
        "schema_version": 1,
        "scopes": [scope],
        "labels": [
            label("agent:real", "positive", 2),
            label("factory:not-agent", "negative", 3),
        ],
    }
    return ref, {scope["scope_id"]: str(root)}, root


def test_c02b_pinned_git_blob_and_span_are_checked(tmp_path: Path) -> None:
    ref, roots, root = _fixture(tmp_path)
    result = verify_reference_witnesses(ref, roots)
    assert result["all_source_witnesses_verified"] is True
    assert result["executed_target_source"] is False
    assert result["remote_access_used"] is False
    item = result["scopes"][0]
    assert item["commit_sha"] == _git(root, "rev-parse", "HEAD")
    assert item["source_witnesses_checked"] == 2
    assert item["source_interpretation_verified"] is False
    assert item["repository_owner_identity_verified"] is False
    assert item["reviewer_independence_verified"] is False
    assert all(
        fact["source"]["verified_as"]
        == "source_bytes_and_anchor_only_not_claim_truth"
        for fact in item["verified_witnesses"]
    )


def test_c02b_verified_scoring_remains_nonrelease_research(tmp_path: Path) -> None:
    ref, roots, _ = _fixture(tmp_path)
    scored = score_verified_reference(ref, [{
        "scope_id": "d01:agent:runtime", "claim_id": "agent:real",
    }], roots)
    assert scored["aggregate"]["precision"] == 1.0
    assert scored["aggregate"]["recall"] == 1.0
    assert scored["source_interpretation_independently_adjudicated"] is False
    assert scored["production_cutover_authorized"] is False
    assert scored["independent_reviewer_attestation_externally_verified"] is False


def test_c02b_dirty_worktree_does_not_replace_pinned_object(tmp_path: Path) -> None:
    ref, roots, root = _fixture(tmp_path)
    (root / "src" / "agent.py").write_text("tampered uncommitted contents\n")
    result = verify_reference_witnesses(ref, roots)
    assert result["scopes"][0]["source_witnesses_checked"] == 2


def test_c02b_mismatched_sha_refused(tmp_path: Path) -> None:
    ref, roots, _ = _fixture(tmp_path)
    ref["scopes"][0]["commit_sha"] = "a" * 40
    with pytest.raises(ValueError, match="HEAD differs"):
        score_verified_reference(ref, [], roots)


def test_c02b_wrong_blob_anchor_refused(tmp_path: Path) -> None:
    ref, roots, _ = _fixture(tmp_path)
    ref["labels"][0]["source"]["blob_sha"] = "c" * 40
    with pytest.raises(ValueError, match="blob SHA"):
        score_verified_reference(ref, [], roots)


def test_c02b_missing_source_or_invalid_line_refused(tmp_path: Path) -> None:
    ref, roots, _ = _fixture(tmp_path)
    ref["labels"][0]["source"]["path"] = "src/not-present.py"
    with pytest.raises(ValueError, match="source file absent"):
        verify_reference_witnesses(ref, roots)

    ref, roots, _ = _fixture(tmp_path / "second")
    ref["labels"][1]["source"]["line_end"] = 100
    with pytest.raises(ValueError, match="exceeds actual blob"):
        verify_reference_witnesses(ref, roots)


def test_c02b_absent_or_extra_checkout_mapping_refused(tmp_path: Path) -> None:
    ref, roots, root = _fixture(tmp_path)
    with pytest.raises(ValueError, match="exactly match"):
        verify_reference_witnesses(ref, {})
    with pytest.raises(ValueError, match="exactly match"):
        verify_reference_witnesses(ref, {**roots, "extra": str(root)})
    with pytest.raises(TypeError, match="checkouts"):
        verify_reference_witnesses(ref, [])


def test_c02b_wrong_repository_root_refused(tmp_path: Path) -> None:
    ref, roots, root = _fixture(tmp_path)
    roots["d01:agent:runtime"] = str(root / "src")
    with pytest.raises(ValueError, match="top level"):
        verify_reference_witnesses(ref, roots)


def test_c02b_symlink_blob_is_not_source_file(tmp_path: Path) -> None:
    ref, roots, root = _fixture(tmp_path)
    # A source-tree symlink is a Git blob containing the *link target*, not
    # Python source. Even an in-root link is not an acceptable source witness.
    (root / "src" / "link.py").symlink_to("agent.py")
    _git(root, "add", "--", "src/link.py")
    _git(
        root, "-c", "user.name=fixture",
        "-c", "user.email=fixture@example.org", "commit", "-qm", "symlink"
    )
    commit = _git(root, "rev-parse", "HEAD")
    ref["scopes"][0]["commit_sha"] = commit
    symlink_blob = _git(root, "rev-parse", f"{commit}:src/link.py")
    altered = deepcopy(ref["labels"][0])
    altered["claim_id"] = "agent:symlink"
    altered["source"]["path"] = "src/link.py"
    altered["source"]["blob_sha"] = symlink_blob
    altered["source"]["line_start"] = 1
    altered["source"]["line_end"] = 1
    ref["labels"].append(altered)
    with pytest.raises(ValueError, match="not a regular Git source file"):
        score_verified_reference(ref, [], roots)


def test_c02b_empty_witness_line_fails(tmp_path: Path) -> None:
    ref, roots, root = _fixture(tmp_path)
    # Rewrite the *committed* file to include an empty line, and bind the new
    # revision/blob rather than claiming an old revision points to new bytes.
    (root / "src" / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('model')\n"
        "app = FastAgent('app')\n"
    )
    _git(root, "add", "--", "src/agent.py")
    _git(
        root, "-c", "user.name=fixture",
        "-c", "user.email=fixture@example.org", "commit", "-qm", "blank"
    )
    commit = _git(root, "rev-parse", "HEAD")
    blob = _git(root, "rev-parse", f"{commit}:src/agent.py")
    ref["scopes"][0]["commit_sha"] = commit
    for label in ref["labels"]:
        label["source"]["blob_sha"] = blob
    ref["labels"][0]["source"]["line_start"] = 2
    ref["labels"][0]["source"]["line_end"] = 2
    with pytest.raises(ValueError, match="only blank lines"):
        verify_reference_witnesses(ref, roots)


def test_c02b_output_does_not_expose_checkout_paths(tmp_path: Path) -> None:
    ref, roots, _ = _fixture(tmp_path)
    report = verify_reference_witnesses(ref, roots)
    assert str(tmp_path) not in json.dumps(report)
