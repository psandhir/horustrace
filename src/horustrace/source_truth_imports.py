"""Wave C C02h: offline pinned-tree relative-import closure diagnostic.

Evidence of source files in a *complete Git tree* is not proof of runtime
import success, tool availability, reachability, or approval controls.
Source anchors are fully verified only when an exact pinned local checkout
is supplied. Source-only results are provisional and never release truth.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_PATH = re.compile(r"[a-zA-Z0-9_.+/@-]+(?:/[a-zA-Z0-9_.+@-]+)*\Z")
_MODULE = re.compile(r"\.+[A-Za-z_][A-Za-z0-9_.]*\Z")


def _read_json(path: str) -> Any:
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, check=True, timeout=15,
    )
    return result.stdout



def _verify_pinned_full_tree(
    root: Path, commit_sha: str, tree_sha: str,
    snapshot_paths: dict[str, dict[str, Any]],
) -> None:
    """Fail closed unless the entire recorded tree equals the pinned checkout.

    A caller-supplied `truncated=false` flag is not by itself evidence that
    a tree snapshot contains every source file. The complete Git object
    tree must be checked before any absence-derived classification.
    """
    head = _git(root, "rev-parse", "HEAD").decode().strip()
    if head != commit_sha:
        raise ValueError("local checkout HEAD differs from the exact source SHA")
    pinned_tree = _git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    if pinned_tree != tree_sha:
        raise ValueError("local checkout Git tree SHA differs from recorded tree")
    observed: dict[str, dict[str, Any]] = {}
    for entry in _git(root, "ls-tree", "-r", "-t", "-z", "HEAD").split(b"\0"):
        if not entry:
            continue
        metadata, separator, raw_path = entry.partition(b"\t")
        parts = metadata.decode("ascii").split()
        if not separator or len(parts) != 3:
            raise ValueError("malformed local Git tree entry")
        _mode, kind, sha = parts
        path = raw_path.decode("utf-8")
        if kind not in {"blob", "tree"} or not _SHA.fullmatch(sha):
            raise ValueError("unsupported local Git tree entry")
        if path in observed:
            raise ValueError("duplicate local Git tree entry")
        observed[path] = {"path": path, "type": kind, "sha": sha}
    if observed != snapshot_paths:
        raise ValueError("local checkout tree entries differ from recorded snapshot")


def _verify_checkout(
    root: Path, commit_sha: str, source_path: str, source_blob_sha: str,
    line_no: int, expression: str,
) -> bool:
    head = _git(root, "rev-parse", "HEAD").decode().strip()
    if head != commit_sha:
        raise ValueError("local checkout HEAD differs from the exact source SHA")
    entry = _git(root, "ls-tree", "HEAD", "--", source_path).decode().strip()
    if not entry or not entry.startswith("100644 blob " + source_blob_sha + "\t"):
        raise ValueError("local pinned Git blob does not match import witness")
    content = _git(root, "cat-file", "blob", source_blob_sha).decode("utf-8")
    lines = content.splitlines()
    if line_no < 1 or line_no > len(lines):
        raise ValueError("witness line is outside pinned blob")
    if lines[line_no - 1].strip() != expression:
        raise ValueError("import statement does not match the pinned source line")
    return True


def _module_paths(source_path: str, dotted_module: str) -> tuple[str, str, str]:
    """Return (module.py, module/__init__.py, namespace directory)."""
    level = len(dotted_module) - len(dotted_module.lstrip("."))
    parts = source_path.split("/")[:-1]
    if level > len(parts) + 1:
        raise ValueError("relative import escapes its source package")
    base = parts[:len(parts) - (level - 1)]
    rest = dotted_module[level:].split(".")
    if any(not chunk.isidentifier() for chunk in rest):
        raise ValueError("invalid Python dotted import")
    components = base + rest
    module = "/".join(components)
    return module + ".py", module + "/__init__.py", module


def review_import_closure(
    tree_snapshot: Any, import_ledger: Any, checkout: str | Path | None = None,
) -> dict[str, Any]:
    if not isinstance(tree_snapshot, dict) or set(tree_snapshot) != {
        "schema_version", "repository", "commit_sha", "tree_sha",
        "truncated", "entries",
    }:
        raise ValueError("pinned Git tree snapshot schema mismatch")
    if not isinstance(import_ledger, dict) or set(import_ledger) != {
        "schema_version", "case_id", "repository", "commit_sha",
        "source_files", "imports",
    }:
        raise ValueError("relative-import review ledger schema mismatch")
    if any(type(doc["schema_version"]) is not int or doc["schema_version"] != 1
           for doc in (tree_snapshot, import_ledger)):
        raise ValueError("unsupported import review schema")
    if (tree_snapshot["repository"] != import_ledger["repository"]
            or tree_snapshot["commit_sha"] != import_ledger["commit_sha"]):
        raise ValueError("tree and source ledger pin different repositories/revisions")
    if (not isinstance(tree_snapshot["commit_sha"], str)
            or not _SHA.fullmatch(tree_snapshot["commit_sha"])
            or not isinstance(tree_snapshot["tree_sha"], str)
            or not _SHA.fullmatch(tree_snapshot["tree_sha"])):
        raise ValueError("un-pinned source commit/tree")
    if tree_snapshot["truncated"] is not False:
        raise ValueError("cannot assert source absence from a truncated Git tree")
    if not isinstance(tree_snapshot["entries"], list):
        raise TypeError("Git tree entries must be a list")
    paths: dict[str, dict[str, Any]] = {}
    for entry in tree_snapshot["entries"]:
        if (not isinstance(entry, dict) or set(entry) != {"path", "type", "sha"}
                or not isinstance(entry["path"], str)
                or not _PATH.fullmatch(entry["path"])
                or ".." in entry["path"].split("/")
                or entry["type"] not in {"blob", "tree"}
                or not isinstance(entry["sha"], str)
                or not _SHA.fullmatch(entry["sha"])):
            raise ValueError("invalid Git tree entry")
        if entry["path"] in paths:
            raise ValueError("duplicate Git tree path")
        paths[entry["path"]] = entry
    source_files = import_ledger["source_files"]
    if not isinstance(source_files, list) or not source_files:
        raise ValueError("source file witnesses required")
    known_sources = {}
    for item in source_files:
        if (not isinstance(item, dict) or set(item) != {"path", "blob_sha"}
                or not isinstance(item["path"], str)
                or not isinstance(item["blob_sha"], str)):
            raise ValueError("invalid source witness")
        if item["path"] in known_sources:
            raise ValueError("duplicate source path")
        if not item["path"].endswith(".py"):
            raise ValueError("source witness is not Python")
        if paths.get(item["path"]) != {
            "path": item["path"], "type": "blob", "sha": item["blob_sha"],
        }:
            raise ValueError("source witness not pinned in recorded Git tree")
        known_sources[item["path"]] = item["blob_sha"]
    import_rows = import_ledger["imports"]
    if not isinstance(import_rows, list) or not import_rows:
        raise ValueError("import ledger has no source imports")
    root = Path(checkout) if checkout is not None else None
    if root is not None:
        _verify_pinned_full_tree(
            root, tree_snapshot["commit_sha"], tree_snapshot["tree_sha"], paths,
        )
    output = []
    ids: set[str] = set()
    counts: Counter[str] = Counter()
    for row in import_rows:
        if not isinstance(row, dict) or set(row) != {
            "id", "source_path", "source_blob_sha", "line",
            "expression", "module",
        }:
            raise ValueError("import witness schema mismatch")
        if (not isinstance(row["id"], str) or not row["id"].strip()
                or row["id"] in ids):
            raise ValueError("missing or duplicate import witness ID")
        ids.add(row["id"])
        src = row["source_path"]
        if src not in known_sources or known_sources[src] != row["source_blob_sha"]:
            raise ValueError("import refers to unpinned source blob")
        if (type(row["line"]) is not int or row["line"] < 1
                or not isinstance(row["module"], str)
                or not _MODULE.fullmatch(row["module"])
                or not isinstance(row["expression"], str)
                or not row["expression"].strip().startswith("from ")):
            raise ValueError("invalid relative-import statement anchor")
        expected_prefix = "from " + row["module"] + " import "
        if not row["expression"].startswith(expected_prefix):
            raise ValueError("import statement and requested module disagree")
        module_py, module_init, namespace = _module_paths(src, row["module"])
        if paths.get(module_py, {}).get("type") == "blob":
            status, matched = "tracked_module", module_py
        elif paths.get(module_init, {}).get("type") == "blob":
            status, matched = "tracked_package", module_init
        elif paths.get(namespace, {}).get("type") == "tree":
            status, matched = "namespace_directory_only", namespace
        else:
            status, matched = "no_tracked_module", None
        witnessed = False
        if root is not None:
            witnessed = _verify_checkout(
                root, tree_snapshot["commit_sha"], src,
                row["source_blob_sha"], row["line"], row["expression"],
            )
        counts[status] += 1
        output.append({
            **row, "tree_resolution": status, "resolved_tree_path": matched,
            "source_line_blob_verified_at_runtime": witnessed,
            "runtime_import_available": None,
            "runtime_agent_can_call": None,
            "negative_source_claim_certified": False,
        })
    return {
        "schema_version": 1,
        "mode": "pinned_source_tree_import_closure_not_runtime_truth",
        "case_id": import_ledger["case_id"],
        "repository": tree_snapshot["repository"],
        "commit_sha": tree_snapshot["commit_sha"],
        "tree_sha": tree_snapshot["tree_sha"],
        "tree_entry_count": len(paths),
        "source_witness_count": len(known_sources),
        "import_count": len(output),
        "tree_resolution_counts": dict(sorted(counts.items())),
        "imports": output,
        "local_git_source_lines_verified": root is not None,
        "local_full_git_tree_verified": root is not None,
        "source_universe_complete": False,
        "independent_review_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Offline pinned source import closure review")
    p.add_argument("--tree", required=True)
    p.add_argument("--imports", required=True)
    p.add_argument("--checkout", help="Optional local checkout at exact pinned HEAD")
    args = p.parse_args()
    print(json.dumps(review_import_closure(
        _read_json(args.tree), _read_json(args.imports), args.checkout,
    ), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
