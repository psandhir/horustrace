"""Source-backed rw-004 import closure: tree presence != runtime callability."""
from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.source_truth_imports import review_import_closure

ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / "research/wave-c-c02h-rw004/pinned-source-tree.json"
IMPORTS = ROOT / "research/wave-c-c02h-rw004/relative-import-anchors.json"


def _real() -> tuple[dict, dict]:
    return (
        json.loads(TREE.read_text(encoding="utf-8")),
        json.loads(IMPORTS.read_text(encoding="utf-8")),
    )


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL,
    ).decode().strip()


def _fixture(tmp_path: Path) -> tuple[dict, dict, Path]:
    root = tmp_path / "source"
    (root / "app" / "tools").mkdir(parents=True)
    _git(root, "init", "-q")
    source = root / "app" / "agent.py"
    source.write_text(
        "from .tools import get_tool\n"
        "from .missing import unknown_tool\n",
        encoding="utf-8",
    )
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "tools" / "__init__.py").write_text(
        "get_tool = object()\n", encoding="utf-8"
    )
    _git(root, "add", ".")
    _git(root, "-c", "user.name=fixture", "-c",
         "user.email=fixture@example.org", "commit", "-qm", "exact")
    commit = _git(root, "rev-parse", "HEAD")
    tree_sha = _git(root, "rev-parse", "HEAD^{tree}")
    source_blob = _git(root, "rev-parse", "HEAD:app/agent.py")
    directory_tree = _git(root, "rev-parse", "HEAD:app/tools")
    tree = {
        "schema_version": 1, "repository": "example/offline-fixture",
        "commit_sha": commit, "tree_sha": tree_sha,
        "truncated": False,
        "entries": [
            {"path": "app", "type": "tree",
             "sha": _git(root, "rev-parse", "HEAD:app")},
            {"path": "app/__init__.py", "type": "blob",
             "sha": _git(root, "rev-parse", "HEAD:app/__init__.py")},
            {"path": "app/agent.py", "type": "blob", "sha": source_blob},
            {"path": "app/tools", "type": "tree", "sha": directory_tree},
            {"path": "app/tools/__init__.py", "type": "blob",
             "sha": _git(root, "rev-parse", "HEAD:app/tools/__init__.py")},
        ],
    }
    row = {
        "schema_version": 1, "case_id": "synthetic",
        "repository": tree["repository"], "commit_sha": commit,
        "source_files": [{"path": "app/agent.py", "blob_sha": source_blob}],
        "imports": [{
            "id": "available", "source_path": "app/agent.py",
            "source_blob_sha": source_blob, "line": 1,
            "expression": "from .tools import get_tool", "module": ".tools",
        }, {
            "id": "missing", "source_path": "app/agent.py",
            "source_blob_sha": source_blob, "line": 2,
            "expression": "from .missing import unknown_tool",
            "module": ".missing",
        }],
    }
    return tree, row, root


def test_c02h_real_pinned_git_tree_has_exact_source_closure() -> None:
    tree, ledger = _real()
    report = review_import_closure(tree, ledger)
    assert tree["tree_sha"] == "002a3a94c6d6652c185cfbe73911aaccc633a0d0"
    assert tree["commit_sha"] == "0160690bb47cca17e70ceb8486209d7b1cacaf76"
    assert report["tree_entry_count"] == 41
    assert report["source_witness_count"] == 4
    assert report["import_count"] == 14
    assert report["tree_resolution_counts"] == {
        "namespace_directory_only": 1,
        "no_tracked_module": 5,
        "tracked_module": 7,
        "tracked_package": 1,
    }
    rows = {x["id"]: x for x in report["imports"]}
    for id_ in ("rw004-import-02", "rw004-import-07", "rw004-import-08",
                "rw004-import-09", "rw004-import-14"):
        assert rows[id_]["tree_resolution"] == "no_tracked_module"
        assert rows[id_]["resolved_tree_path"] is None
    assert rows["rw004-import-01"]["tree_resolution"] == "namespace_directory_only"
    assert rows["rw004-import-05"]["resolved_tree_path"] == (
        "agentGemini/tools/__init__.py"
    )
    assert rows["rw004-import-10"]["resolved_tree_path"] == (
        "agentGemini/tools/conversion_tools.py"
    )
    assert rows["rw004-import-13"]["resolved_tree_path"] == (
        "agentGemini/services/firestore_service.py"
    )
    assert report["local_git_source_lines_verified"] is False
    assert report["local_full_git_tree_verified"] is False
    assert report["production_cutover_authorized"] is False
    assert report["certified_precision"] is None
    assert report["certified_recall"] is None
    assert all(x["runtime_agent_can_call"] is None for x in report["imports"])
    assert all(x["runtime_import_available"] is None for x in report["imports"])
    assert all(x["source_line_blob_verified_at_runtime"] is False
               for x in report["imports"])


def test_c02h_complete_tree_must_be_declared() -> None:
    tree, ledger = _real()
    tree["truncated"] = True
    with pytest.raises(ValueError, match="truncated"):
        review_import_closure(tree, ledger)


def test_c02h_pinned_tree_and_ledger_must_match() -> None:
    tree, ledger = _real()
    ledger["commit_sha"] = "f" * 40
    with pytest.raises(ValueError, match="different repositories/revisions"):
        review_import_closure(tree, ledger)


def test_c02h_git_tree_blob_drift_fails_closed() -> None:
    tree, ledger = _real()
    ledger["source_files"][0]["blob_sha"] = "a" * 40
    with pytest.raises(ValueError, match="not pinned"):
        review_import_closure(tree, ledger)


def test_c02h_duplicate_or_bad_tree_entry_fails() -> None:
    tree, ledger = _real()
    tree["entries"].append(deepcopy(tree["entries"][0]))
    with pytest.raises(ValueError, match="duplicate Git tree path"):
        review_import_closure(tree, ledger)
    tree, ledger = _real()
    tree["entries"][0]["path"] = "../wrong"
    with pytest.raises(ValueError, match="invalid Git tree entry"):
        review_import_closure(tree, ledger)


def test_c02h_fake_relative_import_statement_is_rejected() -> None:
    tree, ledger = _real()
    ledger["imports"][0]["module"] = "..tools"
    with pytest.raises(ValueError, match="disagree"):
        review_import_closure(tree, ledger)


def test_c02h_imports_escaping_source_package_are_rejected() -> None:
    tree, ledger = _real()
    ledger["imports"][0]["module"] = "..tools"
    ledger["imports"][0]["expression"] = "from ..tools import replacement"
    with pytest.raises(ValueError, match="escapes"):
        review_import_closure(tree, ledger)


def test_c02h_offline_pinned_checkout_rechecks_source_line_and_git_blob(
    tmp_path: Path,
) -> None:
    tree, ledger, root = _fixture(tmp_path)
    report = review_import_closure(tree, ledger, checkout=root)
    assert report["local_git_source_lines_verified"] is True
    assert report["local_full_git_tree_verified"] is True
    assert report["tree_resolution_counts"] == {
        "no_tracked_module": 1, "tracked_package": 1,
    }
    assert all(x["source_line_blob_verified_at_runtime"]
               for x in report["imports"])


def test_c02h_checkout_wrong_head_or_source_line_fails_closed(
    tmp_path: Path,
) -> None:
    tree, ledger, root = _fixture(tmp_path)
    ledger["imports"][0]["expression"] = "from .tools import invented"
    with pytest.raises(ValueError, match="import statement"):
        review_import_closure(tree, ledger, checkout=root)
    tree, ledger, root = _fixture(tmp_path / "other")
    tree["commit_sha"] = "f" * 40
    ledger["commit_sha"] = "f" * 40
    with pytest.raises(ValueError, match="local checkout HEAD differs"):
        review_import_closure(tree, ledger, checkout=root)


def test_c02h_missing_module_never_becomes_runtime_negative(
    tmp_path: Path,
) -> None:
    tree, ledger, root = _fixture(tmp_path)
    report = review_import_closure(tree, ledger, checkout=root)
    missing = next(x for x in report["imports"] if x["id"] == "missing")
    assert missing["tree_resolution"] == "no_tracked_module"
    assert missing["source_line_blob_verified_at_runtime"] is True
    assert missing["negative_source_claim_certified"] is False
    assert missing["runtime_agent_can_call"] is None
    assert missing["runtime_import_available"] is None


def test_c02h_malformed_tree_entry_collection_rejected_as_type_error() -> None:
    tree, ledger = _real()
    tree["entries"] = "not-a-tree-list"
    with pytest.raises(TypeError, match="must be a list"):
        review_import_closure(tree, ledger)


def test_c02h_checkout_snapshot_omission_fails_before_absence_claim(
    tmp_path: Path,
) -> None:
    tree, ledger, root = _fixture(tmp_path)
    tree["entries"] = [
        row for row in tree["entries"]
        if row["path"] != "app/tools/__init__.py"
    ]
    with pytest.raises(ValueError, match="tree entries differ"):
        review_import_closure(tree, ledger, checkout=root)


def test_c02h_checkout_false_tree_sha_rejected(
    tmp_path: Path,
) -> None:
    tree, ledger, root = _fixture(tmp_path)
    tree["tree_sha"] = "f" * 40
    with pytest.raises(ValueError, match="Git tree SHA differs"):
        review_import_closure(tree, ledger, checkout=root)


def test_c02h_checkout_snapshot_wrong_leaf_blob_fails(
    tmp_path: Path,
) -> None:
    tree, ledger, root = _fixture(tmp_path)
    for row in tree["entries"]:
        if row["path"] == "app/tools/__init__.py":
            row["sha"] = "f" * 40
    with pytest.raises(ValueError, match="tree entries differ"):
        review_import_closure(tree, ledger, checkout=root)
