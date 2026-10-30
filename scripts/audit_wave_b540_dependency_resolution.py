"""Frozen Amazon third-party resolution audit: source proof is not runtime proof.

Never install/run the target repo or its dependencies. Recompute exact pinned
Git blob witnesses, identify unversioned tool supply chain and dynamic MCP
enumeration, and keep the twelve historical effects/control claims unresolved.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts.verify_wave_b540_unresolved_claims import (
    REPO_SHA,
    UNRESOLVED,
    acceptance_check,
)

REPOSITORY = "aws-samples/sample-multi-agent-region-expansion-planner"
# Immutable Git blobs of the exact historical sample, not floating branch names.
EXPECTED_BLOBS = {
    "requirements.txt": "0eab7c9a2cdca55e7b2b82382e5b37e46afacb38",
    "src/utils/config.py": "f8ef81efe8af9a932f14808f9de91c5c80f9e93d",
    "src/agents/cfn_explorer.py": "b52551548200e06c797c670a06a5fca8ef3fdebf",
    "src/agents/pricing_explorer.py": "2c7c942b22ba50e857b4b75a1c38c7a8ef8f2cc2",
    "src/agents/planning_report_generator.py": "0029d4cdad6062a97f7d563bb7472b105d05d18f",
    "src/agents/multi_region_expansion_planner.py": "f1d201e7f312a01f09f687fc2bb0acde05af9646",
    "src/agents/waypoint_explorer.py": "91dbbb65331563c779c07661168e8a8f49988458",
}
EXPECTED_MCP = {
    "src/agents/cfn_explorer.py": ("uvx", ("awslabs.cfn-mcp-server@latest",)),
    "src/agents/pricing_explorer.py": ("uvx", ("awslabs.aws-pricing-mcp-server@latest",)),
    "src/agents/planning_report_generator.py":
        ("npx", ("mcp-remote", "https://knowledge-mcp.global.api.aws")),
    "src/agents/multi_region_expansion_planner.py":
        ("npx", ("mcp-remote", "https://knowledge-mcp.global.api.aws")),
    "src/agents/waypoint_explorer.py":
        ("npx", ("mcp-remote", "https://knowledge-mcp.global.api.aws")),
}
LOCK_BASENAMES = {
    "uv.lock", "poetry.lock", "pdm.lock", "pipfile.lock",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "requirements.lock", "requirements-frozen.txt", "conda-lock.yml",
}
# Not an exhaustive universal lockfile detector: this specifically rejects
# newly introduced common lock patterns in the immutable 29-entry source tree.

def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + bytes([0]) + data
    ).hexdigest()


def source_tree_records(tree: dict[str, Any], expected: dict[str, str]) -> dict[str, str]:
    if tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
        raise ValueError("missing/full source tree not verified")
    entries = tree["tree"]
    if len(entries) != 29:
        raise ValueError("pinned source tree entry count changed")
    records: dict[str, str] = {}
    for row in entries:
        if not isinstance(row, dict):
            raise ValueError("invalid source tree entry")
        path = row.get("path")
        if not isinstance(path, str) or path in records or path.startswith("/"):
            raise ValueError("duplicate or unsafe source path")
        if row.get("type") not in {"blob", "tree"}:
            raise ValueError("unexpected source tree object kind")
        records[path] = row.get("sha", "")
        basename = path.rsplit("/", 1)[-1].lower()
        if basename in LOCK_BASENAMES or basename.endswith(".lock"):
            raise ValueError("pinned source lockfile inventory has changed")
    for path, sha in expected.items():
        if records.get(path) != sha:
            raise ValueError(f"source tree lacks exact pinned Git blob: {path}")
    return records


def static_mcp_witness(source: str, path: str) -> dict[str, Any]:
    parsed = ast.parse(source, filename=path)
    clients: list[ast.Call] = []
    params: list[ast.Call] = []
    enumerations: list[ast.Call] = []
    for item in ast.walk(parsed):
        if not isinstance(item, ast.Call):
            continue
        name = getattr(item.func, "id", None)
        if name == "MCPClient":
            clients.append(item)
        if name == "StdioServerParameters":
            params.append(item)
        if isinstance(item.func, ast.Attribute) and item.func.attr == "list_tools_sync":
            enumerations.append(item)
    if len(params) != 1 or len(clients) != 1 or len(enumerations) != 1:
        raise ValueError(f"dynamic MCP source construct changed: {path}")
    keywords = {k.arg: k.value for k in params[0].keywords}
    try:
        command = ast.literal_eval(keywords["command"])
        arguments = ast.literal_eval(keywords["args"])
    except (KeyError, ValueError, TypeError, SyntaxError) as exc:
        raise ValueError(f"runtime-driven MCP command cannot be source attested: {path}") from exc
    if not isinstance(command, str) or not isinstance(arguments, list):
        raise ValueError(f"nonliteral MCP stdio arguments: {path}")
    actual = (command, tuple(arguments))
    if actual != EXPECTED_MCP[path]:
        raise ValueError(f"MCP transport/cmd/source changed: {path}")
    return {
        "source_path": path,
        "server_configuration_line": params[0].lineno,
        "runtime_catalogue_call_line": enumerations[0].lineno,
        "command": command,
        "arguments": arguments,
        "transport": "stdio_spawned_volatile" if command == "uvx" else "npx_remote_proxy",
        "tool_catalogue": "runtime_enumerated_unresolved",
        "server_package_immutable": False,
        "runtime_invocation_verified": False,
    }


def source_requests_consent_bypass(source: str) -> bool:
    parsed = ast.parse(source)
    for item in ast.walk(parsed):
        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
            continue
        targets = item.targets if isinstance(item, ast.Assign) else [item.target]
        for target in targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Attribute)
                and target.value.attr == "environ"
                and isinstance(target.slice, ast.Constant)
                and target.slice.value == "BYPASS_TOOL_CONSENT"
                and isinstance(item.value, ast.Constant)
                and str(item.value.value).lower() == "true"
            ):
                return True
    return False


def resolution_audit(
    tree: dict[str, Any],
    sources: dict[str, bytes],
    ledgers: list[dict[str, Any]],
    *,
    expected_blobs: dict[str, str] | None = None,
) -> dict[str, Any]:
    expected = EXPECTED_BLOBS if expected_blobs is None else expected_blobs
    records = source_tree_records(tree, expected)
    if set(sources) != set(expected):
        raise ValueError("missing or unexpected frozen source file")
    for path, body in sources.items():
        digest = git_blob_sha(body)
        if digest != expected[path] or records[path] != digest:
            raise ValueError(f"unverified source content Git blob: {path}")
    requirements = sources["requirements.txt"].decode("utf-8").splitlines()
    if [s.strip() for s in requirements if s.strip()] != [
        "strands-agents-tools", "mcp[cli]", "boto3", "botocore"
    ]:
        raise ValueError("source dependency declaration has changed")
    mcp = [
        {**static_mcp_witness(sources[path].decode("utf-8"), path),
         "source_blob_sha": expected[path]}
        for path in EXPECTED_MCP
    ]
    if not source_requests_consent_bypass(
        sources["src/utils/config.py"].decode("utf-8")
    ):
        raise ValueError("source control request disappeared")
    old = acceptance_check(ledgers)
    if (old["total_historical_claims"] != 73
        or len(old["unresolved"]) != 12
        or set(UNRESOLVED) != {
            r["historical_claim_key"].rsplit(":", 1)[-1] for r in old["unresolved"]
        }):
        raise ValueError("historical review ledger does not match source witness")
    return {
        "schema_version": 1,
        "scope": "exact_pinned_application_source_only",
        "repository": REPOSITORY,
        "source_sha": REPO_SHA,
        "exact_source_blob_count": len(sources),
        "full_tree_entry_count": len(records),
        "lockfile_or_installed_resolution_present": False,
        "strands_agents_tools_declaration": "unversioned",
        "installed_strands_agents_tools_version": None,
        "installed_strands_agents_tools_digest": None,
        "mcp": mcp,
        "mcp_stdio_launchers": len(mcp),
        "floating_uvx_servers": sum(row["command"] == "uvx" for row in mcp),
        "runtime_npx_remote_clients": sum(row["command"] == "npx" for row in mcp),
        "consent_bypass_env_requested": True,
        "consent_bypass_enforced": None,
        "historical_unresolved_claims": old["unresolved"],
        "historical_unresolved_claim_count": 12,
        "missing_evidence": [
            "attested_install_environment_and_package_artifact_digests_at_scan_target_execution",
            "resolved_uvx_and_npx_package_versions_and_content_hashes",
            "same_environment_live_MCP_tool_list_per_endpoint_and_identity",
            "actual_credential_scopes_effective_controls_and_tool_execution_traces",
            "independently_reviewed_positive_and_negative_claim_ground_truth",
        ],
        "runtime_tool_effects_verified": False,
        "independent_ground_truth": False,
        "precision": None,
        "recall": None,
        "wave_b_go": False,
        "wave_c_go": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--high", type=Path, required=True)
    parser.add_argument("--medium", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = resolution_audit(
        json.loads(args.tree.read_text(encoding="utf-8")),
        {p: (args.source_root / p).read_bytes() for p in EXPECTED_BLOBS},
        [json.loads(args.high.read_text(encoding="utf-8")),
         json.loads(args.medium.read_text(encoding="utf-8"))],
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "source_blobs_verified": evidence["exact_source_blob_count"],
        "mcp_launchers": evidence["mcp_stdio_launchers"],
        "historical_unknowns": evidence["historical_unresolved_claim_count"],
        "wave_b_go": False,
    }))


if __name__ == "__main__":
    main()
