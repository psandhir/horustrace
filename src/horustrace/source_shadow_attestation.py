"""C02x: exact Git-source attestation for bounded MCP source-only shadows.

Seal the shadow only against a committed Git checkout. The verifier checks
every witness against BOTH the current worktree bytes and the exact HEAD Git
tree. These self-generated digests establish source consistency, NOT external
trust, independently adjudicated reference accuracy or runtime authority.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any

_GIT_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MODES = frozenset({"100644", "100755"})
_CONTRACT = "c02x_exact_git_sha1_blob_and_worktree_sha256"
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_FILES = 2048


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, check=True, timeout=20,
    )
    return result.stdout.decode("utf-8").strip()


def _checkout(root: Path) -> tuple[Path, str]:
    scope = root.resolve(strict=True)
    if not scope.is_dir():
        raise ValueError("attested MCP source scope must be a directory")
    try:
        git_root = Path(_git(scope, "rev-parse", "--show-toplevel")).resolve(
            strict=True
        )
        head = _git(scope, "rev-parse", "--verify", "HEAD")
        object_format = _git(scope, "rev-parse", "--show-object-format")
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise ValueError("attested MCP source requires a Git checkout") from exc
    if git_root != scope or object_format != "sha1" or not _GIT_SHA1.fullmatch(head):
        raise ValueError("attested scope must be a SHA-1 Git repository root at HEAD")
    return scope, head


def _witness_paths(shadow: dict[str, Any]) -> set[str]:
    from horustrace.source_shadow_html import validate_source_shadow

    nodes, _ = validate_source_shadow(shadow)
    paths = {n["location"]["path"] for n in nodes}
    if len(paths) > _MAX_FILES:
        raise ValueError("source attestation exceeds bounded file count")
    return paths


def _read_source(scope: Path, path: str, head: str) -> dict[str, Any]:
    # validate_source_shadow already rejects absolute, dotdot and backslash paths.
    target = (scope / path).resolve(strict=True)
    if not target.is_relative_to(scope) or not target.is_file():
        raise ValueError(f"out-of-scope or nonfile MCP witness: {path}")
    if target.stat().st_size > _MAX_FILE_BYTES:
        raise ValueError(f"oversized MCP source witness: {path}")
    raw = target.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    git_blob = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()
    try:
        row = _git(scope, "ls-tree", head, "--", path)
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise ValueError(f"Git witness lookup failed: {path}") from exc
    expected_lines = row.splitlines()
    if len(expected_lines) != 1 or "\t" not in row:
        raise ValueError(f"source witness is not a unique tracked Git blob: {path}")
    details, recorded_path = row.split("\t", 1)
    parts = details.split()
    if (recorded_path != path or len(parts) != 3
            or parts[0] not in _MODES or parts[1] != "blob"
            or not _GIT_SHA1.fullmatch(parts[2])
            or git_blob != parts[2]):
        raise ValueError(f"uncommitted, symlink or changed MCP source: {path}")
    return {
        "path": path, "sha256": digest,
        "git_blob_sha": git_blob, "git_mode": parts[0],
        "size_bytes": len(raw),
    }



def _claims_sha256(shadow: dict[str, Any]) -> str:
    """Bind node/edge/source claim metadata to the exact attested artifact."""
    frozen = {
        key: shadow.get(key)
        for key in ("schema_version", "mode", "nodes", "edges", "edge_kinds",
                    "unresolved", "target_source_executed",
                    "runtime_tool_catalogue_verified",
                    "effective_authority_verified",
                    "independent_source_truth_verified",
                    "certified_precision", "certified_recall",
                    "production_cutover_authorized")
    }
    return hashlib.sha256(
        json.dumps(frozen, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def seal_mcp_source_shadow(shadow: dict[str, Any], root: Path) -> dict[str, Any]:
    """Produce a new, non-promoted v2 evidence artifact from raw v1 shadow."""
    if shadow.get("schema_version") != 1:
        raise ValueError("only original unsealed v1 shadow may be sealed")
    scope, head = _checkout(root)
    paths = _witness_paths(shadow)
    if not paths:
        raise ValueError("cannot attest empty MCP source witness universe")
    evidence = deepcopy(shadow)
    evidence["schema_version"] = 2
    evidence["source_revision"] = {
        "mode": _CONTRACT,
        "commit_sha": head,
        "claims_sha256": _claims_sha256(evidence),
        "files": [_read_source(scope, path, head) for path in sorted(paths)],
        "runtime_effective_authority_verified": False,
        "independently_adjudicated": False,
    }
    return evidence


def verify_mcp_source_shadow(shadow: dict[str, Any], root: Path) -> None:
    """Fail closed on missing, cherry-picked, forged or stale source witnesses."""
    if shadow.get("schema_version") != 2:
        raise ValueError("legacy/unsealed MCP shadow is not Workbench-eligible")
    revision = shadow.get("source_revision")
    if not isinstance(revision, dict):
        raise TypeError("source revision attestation is missing")
    if (revision.get("mode") != _CONTRACT
            or revision.get("runtime_effective_authority_verified") is not False
            or revision.get("independently_adjudicated") is not False):
        raise ValueError("invalid source attestation mode or promoted review claims")
    scope, current_head = _checkout(root)
    if revision.get("commit_sha") != current_head:
        raise ValueError("MCP source shadow does not match the checked-out commit")
    claimed = revision.get("claims_sha256")
    if (not isinstance(claimed, str) or not _SHA256.fullmatch(claimed)
            or claimed != _claims_sha256(shadow)):
        raise ValueError("MCP source node/edge evidence was changed after sealing")
    paths = _witness_paths(shadow)
    rows = revision.get("files")
    if not isinstance(rows, list):
        raise TypeError("source attestation file manifest must be a list")
    if len(rows) != len(paths) or not paths:
        raise ValueError("source attestation file universe incomplete")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise TypeError("malformed source file attestation")
        if set(row) != {
            "path", "sha256", "git_blob_sha", "git_mode", "size_bytes",
        }:
            raise ValueError("malformed source file attestation")
        path = row["path"]
        if not isinstance(path, str) or path not in paths or path in seen:
            raise ValueError("missing, duplicate or extra Git source witness")
        seen.add(path)
        if (not isinstance(row["sha256"], str)
                or not _SHA256.fullmatch(row["sha256"])
                or not isinstance(row["git_blob_sha"], str)
                or not _GIT_SHA1.fullmatch(row["git_blob_sha"])
                or row["git_mode"] not in _MODES
                or type(row["size_bytes"]) is not int
                or not 0 <= row["size_bytes"] <= _MAX_FILE_BYTES):
            raise ValueError("invalid source digest/size witness")
        if row != _read_source(scope, path, current_head):
            raise ValueError(f"stale or tampered MCP source witness: {path}")
    if seen != paths:
        raise ValueError("source witness list not exhaustive")
