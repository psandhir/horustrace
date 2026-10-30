"""Wave C C02d: provisional, reproducible, source-only D01 holdout sealing.

This module creates a *private* selected-case manifest and a *public* digest.
It cannot attest independent selection, prevent access to scanner results or
prove a real holdout was unseen. Never commit the private manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
from typing import Any

_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/#@+-]*\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_ROLES = frozenset({
    "runtime", "cli", "application-support", "test", "example",
    "tutorial", "notebook", "template-generated", "provider_only", "unknown",
})


def _obj(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} must contain exactly {sorted(fields)}")
    return value


def _nonempty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be nonempty text")
    return value


def _digest(data: Any) -> str:
    return hashlib.sha256(json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def _case(record: Any) -> dict[str, str]:
    row = _obj(record, {
        "case_id", "repository", "commit_sha", "framework", "source_role",
    }, "candidate")
    case_id = _nonempty(row["case_id"], "case_id")
    if not _ID.fullmatch(case_id):
        raise ValueError("case_id must be a portable identifier")
    repo = _nonempty(row["repository"], "repository").lower()
    if not _REPO.fullmatch(repo):
        raise ValueError("repository must be owner/name")
    sha = _nonempty(row["commit_sha"], "commit_sha").lower()
    if not _SHA.fullmatch(sha) or sha == "0" * 40:
        raise ValueError("commit_sha must be a nonzero full 40-hex SHA")
    framework = _nonempty(row["framework"], "framework")
    if not _ID.fullmatch(framework):
        raise ValueError("framework must be a portable identifier")
    if not isinstance(row["source_role"], str) or row["source_role"] not in _ROLES:
        raise ValueError("invalid source role")
    return {
        "case_id": case_id,
        "repository": repo,
        "commit_sha": sha,
        "framework": framework,
        "source_role": row["source_role"],
    }


def _inputs(
    candidates: Any, exposures: Any, selection: Any,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    candidates = _obj(candidates, {"schema_version", "cases"}, "candidates")
    exposures = _obj(exposures, {
        "schema_version", "known_exposed_repositories",
        "inventory_declared_complete", "inventory_ref",
    }, "prior exposure inventory")
    selection = _obj(selection, {
        "schema_version", "selected_case_ids", "source_selection_ref",
        "selection_protocol",
    }, "selection")
    if any(doc["schema_version"] != 1 or
           type(doc["schema_version"]) is not int
           for doc in (candidates, exposures, selection)):
        raise ValueError("unsupported holdout input schema")
    if not all(isinstance(doc[field], list) for doc, field in (
        (candidates, "cases"), (exposures, "known_exposed_repositories"),
        (selection, "selected_case_ids"),
    )):
        raise TypeError("holdout case/exposure/selection collections must be lists")
    if type(exposures["inventory_declared_complete"]) is not bool:
        raise TypeError("inventory_declared_complete must be a boolean")
    if not exposures["inventory_declared_complete"]:
        raise ValueError("incomplete exposure inventory cannot seal holdout")
    _nonempty(exposures["inventory_ref"], "inventory_ref")
    _nonempty(selection["source_selection_ref"], "source_selection_ref")
    _nonempty(selection["selection_protocol"], "selection_protocol")
    items = [_case(row) for row in candidates["cases"]]
    by_id = {row["case_id"]: row for row in items}
    if len(items) != len(by_id):
        raise ValueError("duplicate candidate case_id")
    if len(items) != len({(x["repository"], x["commit_sha"]) for x in items}):
        raise ValueError("duplicate candidate repository+SHA")
    raw_exposed = exposures["known_exposed_repositories"]
    if any(not isinstance(repo, str) or not _REPO.fullmatch(repo)
           for repo in raw_exposed):
        raise ValueError("exposure inventory needs owner/name repository slugs")
    exposed = {repo.lower() for repo in raw_exposed}
    if len(exposed) != len(raw_exposed):
        raise ValueError("duplicate exposed repository")
    ids = selection["selected_case_ids"]
    if not ids:
        raise ValueError("cannot seal an empty holdout")
    if any(not isinstance(case, str) or not _ID.fullmatch(case) for case in ids):
        raise ValueError("selection contains invalid case_id")
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate selected case_id")
    if any(case_id not in by_id for case_id in ids):
        raise ValueError("selected case absent from independent candidate pool")
    chosen = sorted((by_id[case_id] for case_id in ids), key=lambda x: x["case_id"])
    if any(row["repository"] in exposed for row in chosen):
        raise ValueError("holdout reuses a repository declared previously exposed")
    if len({row["repository"] for row in chosen}) != len(chosen):
        raise ValueError("holdout includes multiple commits from one repository")
    return chosen, {
        "candidate_pool_sha256": _digest(candidates),
        "exposure_inventory_sha256": _digest(exposures),
        "selection_input_sha256": _digest(selection),
        "source_selection_ref": selection["source_selection_ref"],
        "exposure_inventory_ref": exposures["inventory_ref"],
        "selection_protocol": selection["selection_protocol"],
        "declared_exposure_inventory_complete": True,
    }


def _assemble_seal(
    selected: list[dict[str, str]], provenance: dict[str, Any],
    private_nonce: str,
) -> dict[str, Any]:
    """Build commitments using a private 256-bit nonce (not a digital signature)."""
    if (not isinstance(private_nonce, str) or len(private_nonce) != 64
            or re.fullmatch(r"[0-9a-f]{64}", private_nonce) is None):
        raise ValueError("private holdout nonce must be 256-bit lowercase hex")
    private_body = {
        "schema_version": 1,
        "mode": "source_only_provisional_d01_holdout",
        "selected_cases": selected,
        "provenance": provenance,
        "private_nonce": private_nonce,
        "scanner_predictions_used": False,
        "external_access_log_verified": False,
        "reviewer_independence_verified": False,
        "source_universe_completeness_verified": False,
        "release_certified": False,
    }
    private = {**private_body, "manifest_sha256": _digest(private_body)}
    # Public output contains only the nonce-bound digest and coarse case count.
    # Do not leak unsalted hashes of tiny exposure/candidate pools or a free-text
    # selection_ref; these allow inference and offline guessing of hidden cases.
    public_body = {
        "schema_version": 1,
        "mode": "d01_public_commitment_not_certification",
        "commitment_algorithm": "sha256_of_private_nonce_bound_manifest_v1",
        "manifest_sha256": private["manifest_sha256"],
        "case_count": len(selected),
        "external_access_log_verified": False,
        "reviewer_independence_verified": False,
        "holdout_unseen_externally_verified": False,
        "release_certified": False,
    }
    return {
        "private_manifest": private,
        "public_commitment": {
            **public_body, "commitment_sha256": _digest(public_body),
        },
    }


def seal_holdout(
    candidates: Any, exposures: Any, selection: Any,
) -> dict[str, Any]:
    """Issue a private nonce-bound seal and a non-identifying public commitment.

    The public digest is not an authenticated signature or external access log.
    Confidential inputs and the nonce must never be committed to public Git.
    """
    selected, provenance = _inputs(candidates, exposures, selection)
    return _assemble_seal(selected, provenance, secrets.token_hex(32))


def verify_holdout_seal(
    candidates: Any, exposures: Any, selection: Any,
    private_manifest: Any, public_commitment: Any,
) -> dict[str, Any]:
    """Replay source inputs and the original secret nonce; reject any changes."""
    if not isinstance(private_manifest, dict):
        raise TypeError("private holdout manifest must be an object")
    selected, provenance = _inputs(candidates, exposures, selection)
    expected = _assemble_seal(
        selected, provenance, private_manifest.get("private_nonce"),
    )
    if private_manifest != expected["private_manifest"]:
        raise ValueError("private holdout manifest differs from source inputs")
    if public_commitment != expected["public_commitment"]:
        raise ValueError("public commitment differs from the private manifest")
    return {
        "schema_version": 1,
        "mode": "offline_d01_holdout_seal_replay_not_release_certification",
        "replay_matches_sealed_inputs": True,
        "manifest_sha256": expected["private_manifest"]["manifest_sha256"],
        "external_access_log_verified": False,
        "holdout_unseen_externally_verified": False,
        "release_certified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seal or replay a D01 source-only holdout offline"
    )
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--exposures", required=True)
    parser.add_argument("--selection", required=True)
    parser.add_argument("--private-manifest")
    parser.add_argument("--public-commitment")
    parser.add_argument("--private-output")
    parser.add_argument("--public-output")
    args = parser.parse_args()
    def read_file(path: str) -> Any:
        with open(path, encoding="utf-8") as stream:
            return json.load(stream)

    cases = read_file(args.candidates)
    exposures = read_file(args.exposures)
    selection = read_file(args.selection)
    if bool(args.private_manifest) != bool(args.public_commitment):
        parser.error("verification needs both private manifest and public commitment")
    if args.private_manifest:
        if args.private_output or args.public_output:
            parser.error("verification does not write a new seal")
        result = verify_holdout_seal(
            cases, exposures, selection,
            read_file(args.private_manifest), read_file(args.public_commitment),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if not args.private_output or not args.public_output:
        parser.error("sealing requires separate --private-output and --public-output")
    if os.path.abspath(args.private_output) == os.path.abspath(args.public_output):
        parser.error("private/public output paths must be distinct")
    result = seal_holdout(cases, exposures, selection)
    # Exclusive local creation, never overwriting an existing confidential seal.
    # An inaccessible output fails closed instead of printing a private payload.
    descriptor = os.open(
        args.private_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(result["private_manifest"], handle, indent=2, sort_keys=True)
        handle.write("\n")
    with open(args.public_output, "x", encoding="utf-8") as handle:
        json.dump(result["public_commitment"], handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({
        "mode": "public_only_seal_created",
        "public_commitment": result["public_commitment"],
        "private_manifest_redacted": True,
        "release_certified": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
