"""C02s independent AST source oracle vs unchanged MCP scanner/shadow.

The only target operations are Git object reads and static source scanning.
The source repository is NEVER imported or executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from horustrace.mcp_source_implementation_shadow import (
    project_bound_source_mcp_implementations,
)
from horustrace.scanner import scan
from horustrace.source_truth_ast_mcp import inspect_mcp_scope

CASE_ID = "rw-080"
REPOSITORY = "Amlan66/SSEEnabledMCPAgent"
SOURCE_SHA = "11531239e71b123f25b3c6103ee36a9d614d0032"
SOURCE_FILES = (
    "mcp_server_1.py",
    "mcp_server_2.py",
    "mcp_server_3.py",
    "mcp_telegram_server.py",
)
LOCAL_STDIO = frozenset(SOURCE_FILES[:3])
PINNED_BLOBS = {
    "mcp_server_1.py": "23618439e4a8858da83d3dbdc0918784fd553406",
    "mcp_server_2.py": "f7177c6bbddb2dc875c4cd6202c01bd774e93b07",
    "mcp_server_3.py": "9e282724e8ceb83bef65ac0177538b3dc9d2ecab",
    "mcp_telegram_server.py": "4408926e80d60b06a77b07a4690e0b06c11c0824",
}


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, check=True, timeout=40,
    ).stdout


def read_pinned_source(checkout: Path) -> dict[str, str]:
    if _git(checkout, "rev-parse", "HEAD").decode().strip() != SOURCE_SHA:
        raise ValueError("pinned checkout HEAD mismatch")
    files: dict[str, str] = {}
    for path in SOURCE_FILES:
        expected = PINNED_BLOBS[path]
        entry = _git(checkout, "ls-tree", "HEAD", "--", path).decode().strip()
        if entry != f"100644 blob {expected}\t{path}":
            raise ValueError(f"pinned Git tree entry mismatch: {path}")
        data = _git(checkout, "cat-file", "blob", expected)
        git_sha = hashlib.sha1(
            b"blob " + str(len(data)).encode("ascii") + b"\0" + data
        ).hexdigest()
        if git_sha != expected:
            raise ValueError(f"pinned Git blob digest mismatch: {path}")
        files[path] = data.decode("utf-8")
    return files


def compare_scope(oracle: dict, shadow: dict) -> dict:
    """Compare exact static source-declaration sites, not runtime semantics."""
    source = {
        (x["path"], x["line"], x["name"])
        for x in oracle["tools"] if x["path"] in LOCAL_STDIO
    }
    projected = {
        (x["location"]["path"], x["location"]["line"], x["name"])
        for x in shadow["nodes"] if x["kind"] == "mcp_source_tool"
    }
    original_servers = {
        (x["path"], x["line"], x["name"])
        for x in oracle["implementations"] if x["path"] in LOCAL_STDIO
    }
    projected_servers = {
        (x["location"]["path"], x["location"]["line"], x["name"])
        for x in shadow["nodes"] if x["kind"] == "mcp_source_implementation"
    }
    return {
        "local_tool_sites_source_only": len(source),
        "local_tool_sites_shadow": len(projected),
        "missing_source_tool_sites_in_shadow": sorted(source - projected),
        "unexpected_shadow_tool_sites": sorted(projected - source),
        "local_implementation_sites_source_only": len(original_servers),
        "local_implementation_sites_shadow": len(projected_servers),
        "missing_source_implementations_in_shadow": sorted(
            original_servers - projected_servers
        ),
        "unexpected_shadow_implementations": sorted(
            projected_servers - original_servers
        ),
        "source_only": True,
        "certified_false_negatives": None,
        "certified_false_positives": None,
        "effective_agent_can_call": None,
    }


def run_study(checkout: Path, output: Path) -> dict:
    if not checkout.is_dir():
        raise ValueError("pinned source checkout missing")
    original_files = read_pinned_source(checkout)
    oracle = inspect_mcp_scope(original_files)
    if oracle["unresolved"]:
        raise ValueError("pinned source unexpectedly contains unsupported syntax")
    # A bounded syntactic census: four unique constructors, 28 decorator
    # functions, resource and prompt hard negatives. No claims about runtime.
    if len(oracle["implementations"]) != 4 or len(oracle["tools"]) != 28:
        raise ValueError("pinned source AST witness count drift")
    if len(oracle["excluded_non_tools"]) != 3:
        raise ValueError("pinned MCP resource/prompt near-miss count drift")
    if sorted(row["kind"] for row in oracle["excluded_non_tools"]) != [
        "prompt", "prompt", "resource",
    ]:
        raise ValueError("non-tool negative source category drift")
    if (len({x["id"] for x in oracle["implementations"]}) != 4
            or len({x["id"] for x in oracle["tools"]}) != 28):
        raise ValueError("source identities collapsed or duplicated")
    before_graph, findings = scan(checkout)
    before_adg = before_graph.adg.as_dict() if before_graph.adg else None
    if before_adg is None:
        raise ValueError("current scanner produced no ADG")
    frozen = json.dumps(before_adg, sort_keys=True)
    shadow = project_bound_source_mcp_implementations(before_graph, checkout)
    if json.dumps(before_graph.adg.as_dict(), sort_keys=True) != frozen:
        raise ValueError("shadow projection mutated production ADG")
    comparison = compare_scope(oracle, shadow)
    if any(value for key, value in comparison.items()
           if key.startswith(("missing_", "unexpected_"))):
        raise ValueError("AST/source-shadow disagreement; investigate before merge")
    if comparison["local_tool_sites_source_only"] != 25:
        raise ValueError("expected local source tool scope changed")
    if (shadow["edge_kinds"].get("EXPOSES_TOOL") != 25
            or shadow["edge_kinds"].get(
                "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION"
            ) != 3):
        raise ValueError("MCP shadow source topology regression")
    result = {
        "schema_version": 1,
        "mode": "wave_c_c02s_bounded_source_ast_not_accuracy_certification",
        "case_id": CASE_ID,
        "repository": REPOSITORY,
        "pinned_commit": SOURCE_SHA,
        "pinned_blobs": PINNED_BLOBS,
        "oracle": oracle,
        "comparison": comparison,
        "scanner_adg_nodes": len(before_adg["nodes"]),
        "scanner_adg_edges": len(before_adg["edges"]),
        "scanner_findings": len(findings),
        "scanner_adg_unchanged": True,
        "source_scope_complete_only_for_declared_ast_constructs": True,
        "deployed_runtime_verified": False,
        "independent_human_review_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "ast-source-oracle.json").write_text(
        json.dumps(oracle, sort_keys=True, indent=2) + "\n", encoding="utf-8",
    )
    (output / "result.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8",
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_study(args.checkout.resolve(), args.output.resolve())
    print(json.dumps({
        "case_id": result["case_id"],
        "implementations": len(result["oracle"]["implementations"]),
        "declared_tools": len(result["oracle"]["tools"]),
        "excluded_non_tools": len(result["oracle"]["excluded_non_tools"]),
        "shadow_local_tool_site_agreement": not any(
            result["comparison"][key] for key in (
                "missing_source_tool_sites_in_shadow",
                "unexpected_shadow_tool_sites",
            )
        ),
        "production_cutover_authorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
