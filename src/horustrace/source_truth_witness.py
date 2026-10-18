"""Wave C C02b: verify pinned source witnesses against local Git objects.

Git plumbing reads immutable commit/tree/blob objects. It never imports or
executes code from a scanned checkout and never fetches remote repositories.
Matching bytes/lines is NOT a judgment that a security claim is true.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from horustrace.source_truth_oracle import score_reference, validate_reference

MAX_BLOB_BYTES = 1_048_576
GIT_TIMEOUT_SECONDS = 15


def _git(checkout: Path, *args: str) -> bytes:
    """Invoke read-only Git plumbing with a bounded command timeout."""
    try:
        completed = subprocess.run(  # noqa: S603
            ["git", "--no-optional-locks", "-C", str(checkout), *args],
            capture_output=True, check=False, timeout=GIT_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("git metadata not accessible") from exc
    if completed.returncode != 0:
        raise ValueError("git object not found or checkout inaccessible")
    return completed.stdout


def _scope_checkout(scope: dict[str, Any], checkouts: dict[str, str]) -> Path:
    """Require a dedicated, exact-commit Git checkout per reference scope."""
    path = checkouts.get(scope["scope_id"])
    if not isinstance(path, str) or not path.strip():
        raise ValueError("no checkout mapped to reference scope")
    root = Path(path).resolve()
    if not root.is_dir():
        raise ValueError("checkout directory does not exist")
    top = _git(root, "rev-parse", "--show-toplevel").decode(
        "utf-8", errors="replace"
    ).strip()
    if Path(top).resolve() != root:
        raise ValueError("checkout must be the repository top level")
    head = _git(root, "rev-parse", "--verify", "HEAD").decode(
        "ascii", errors="replace"
    ).strip().lower()
    if head != scope["commit_sha"].lower():
        raise ValueError("checkout HEAD differs from pinned source commit")
    return root


def _blob_witness(
    root: Path, commit_sha: str, witness: dict[str, Any],
) -> dict[str, Any]:
    """Verify source mode, Git tree membership, blob bytes and line span."""
    path = witness["path"]
    record = _git(root, "ls-tree", "-z", "--full-tree", commit_sha, "--", path)
    rows = [part for part in record.split(b"\0") if part]
    if len(rows) != 1:
        raise ValueError("source file absent or tree entry ambiguous")
    try:
        fields, found_path = rows[0].split(b"\t", 1)
        mode, object_type, blob_sha = fields.decode("ascii").split(" ")
        found_path_text = found_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid git tree record") from exc
    if found_path_text != path:
        raise ValueError("git tree path differs from source witness")
    if object_type != "blob" or mode not in ("100644", "100755"):
        raise ValueError("source witness is not a regular Git source file")
    if blob_sha.lower() != witness["blob_sha"].lower():
        raise ValueError("Git blob SHA does not match declared source anchor")
    size_raw = _git(root, "cat-file", "-s", blob_sha).decode("ascii").strip()
    try:
        size = int(size_raw)
    except ValueError as exc:
        raise ValueError("Git source blob has invalid size") from exc
    if size > MAX_BLOB_BYTES:
        raise ValueError("source witness blob exceeds offline byte limit")
    data = _git(root, "cat-file", "blob", blob_sha)
    if len(data) != size:
        raise ValueError("Git blob size does not match source bytes")
    computed_sha = hashlib.sha1(  # noqa: S324
        b"blob " + str(size).encode("ascii") + b"\0" + data
    ).hexdigest()
    if computed_sha != blob_sha.lower():
        raise ValueError("Git blob bytes differ from pinned object")
    lines = data.splitlines()
    start, end = witness["line_start"], witness["line_end"]
    if start > len(lines) or end > len(lines):
        raise ValueError("source witness line span exceeds actual blob lines")
    if not any(line.strip() for line in lines[start - 1:end]):
        raise ValueError("source witness contains only blank lines")
    return {
        "path": path,
        "blob_sha": blob_sha.lower(),
        "line_start": start,
        "line_end": end,
        "sha256": hashlib.sha256(data).hexdigest(),
        "verified_as": "source_bytes_and_anchor_only_not_claim_truth",
    }


def verify_reference_witnesses(
    reference: Any, checkouts: Any,
) -> dict[str, Any]:
    """Verify every source label, with no silent omissions or network fetches.

    A checkout mapping must contain *exactly* the reference scope IDs. The
    repository owner/name and reviewer independence are NOT verified by this
    local Git-object proof, even when the commit SHA and blob are valid.
    """
    document = validate_reference(reference)
    if not isinstance(checkouts, dict):
        raise TypeError("checkouts must map scope IDs to local Git directories")
    scopes = {item["scope_id"]: item for item in document["scopes"]}
    if set(checkouts) != set(scopes):
        raise ValueError("checkout mapping must exactly match reference scopes")
    by_scope: dict[str, list[dict[str, Any]]] = {
        key: [] for key in scopes
    }
    for label in document["labels"]:
        by_scope[label["scope_id"]].append(label)

    verified: list[dict[str, Any]] = []
    for scope_id in sorted(scopes):
        scope = scopes[scope_id]
        root = _scope_checkout(scope, checkouts)
        witnesses: list[dict[str, Any]] = []
        for label in sorted(by_scope[scope_id], key=lambda x: x["claim_id"]):
            source = _blob_witness(
                root, scope["commit_sha"], label["source"]
            )
            witnesses.append({
                "claim_id": label["claim_id"],
                "truth_status": label["truth"],
                "source": source,
            })
        verified.append({
            "scope_id": scope_id,
            "commit_sha": scope["commit_sha"].lower(),
            "verified_witnesses": witnesses,
            "source_witnesses_checked": len(witnesses),
            "commit_and_blob_anchors_valid": True,
            "source_interpretation_verified": False,
            "repository_owner_identity_verified": False,
            "reviewer_independence_verified": False,
        })
    return {
        "schema_version": 1,
        "mode": "offline_pinned_git_witness_verification",
        "all_source_witnesses_verified": True,
        "remote_access_used": False,
        "executed_target_source": False,
        "scopes": verified,
    }


def score_verified_reference(
    reference: Any, predictions: Any, checkouts: Any,
) -> dict[str, Any]:
    """Prove Git anchors *before* publishing any C02a numeric score.

    Inaccessible, missing, mismatched, symlink or unverifiable source raises
    ValueError; no partial score can be returned or mistaken for release GO.
    """
    proof = verify_reference_witnesses(reference, checkouts)
    score = score_reference(reference, predictions)
    score["source_witness_verification"] = proof
    score["source_interpretation_independently_adjudicated"] = False
    score["production_cutover_authorized"] = False
    return score


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Git source witnesses before scoring a C02 source oracle"
    )
    parser.add_argument("--reference", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--checkouts", required=True,
                        help="JSON mapping of scope IDs to local pinned Git checkouts")
    args = parser.parse_args()
    with open(args.reference, encoding="utf-8") as handle:
        reference = json.load(handle)
    with open(args.predictions, encoding="utf-8") as handle:
        predictions = json.load(handle)
    with open(args.checkouts, encoding="utf-8") as handle:
        checkouts = json.load(handle)
    print(json.dumps(
        score_verified_reference(reference, predictions, checkouts),
        indent=2, sort_keys=True,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
