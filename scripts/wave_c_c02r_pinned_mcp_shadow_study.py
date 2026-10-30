"""C02r rw080: exact-commit static scanner source-MCP shadow study.

No target code execution or SDK imports. Does not modify real Graph/ADG.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from horustrace.mcp_c03_crosswalk import build_mcp_source_crosswalk
from horustrace.mcp_c03_candidate import (
    build_mcp_adg_candidate,
    verify_mcp_candidate_rollback,
)
from horustrace.mcp_source_implementation_shadow import (
    project_bound_source_mcp_implementations,
)
from horustrace.scanner import scan
from horustrace.source_truth_ast_mcp import inspect_mcp_scope
from scripts.wave_c_c02s_independent_ast_mcp_study import read_pinned_source
from horustrace.source_shadow_attestation import (
    seal_mcp_source_shadow,
    verify_mcp_source_shadow,
)

CASE = "rw-080"
REPO = "Amlan66/SSEEnabledMCPAgent"
SHA = "11531239e71b123f25b3c6103ee36a9d614d0032"
DECLARATIONS = {
    "mcp_server_1.py": (33, "mcp = FastMCP(\"Calculator\")"),
    "mcp_server_2.py": (28, "mcp = FastMCP(\"Calculator\")"),
    "mcp_server_3.py": (209, "mcp = FastMCP(\"ddg-search\")"),
    "mcp_telegram_server.py": (27, "mcp = FastMCP(\"telegram-integration\")"),
}


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True, capture_output=True, timeout=30,
    ).stdout


def review_pinned_source(checkout: Path) -> list[dict]:
    if _git(checkout, "rev-parse", "HEAD").decode().strip() != SHA:
        raise ValueError("exact source revision mismatch")
    witnessed = []
    for path, (line, expression) in sorted(DECLARATIONS.items()):
        entry = _git(checkout, "ls-tree", "HEAD", "--", path).decode().strip()
        metadata = entry.split("\t", 1)
        if len(metadata) != 2 or metadata[1] != path:
            raise ValueError("missing pinned MCP source file")
        details = metadata[0].split()
        if len(details) != 3 or details[1] != "blob":
            raise ValueError("source witness is not a tracked Git blob")
        sha = details[2]
        raw = _git(checkout, "cat-file", "blob", sha)
        digest = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        ).hexdigest()
        if digest != sha:
            raise ValueError("Git source blob digest mismatch")
        lines = raw.decode("utf-8").splitlines()
        if len(lines) < line or lines[line - 1].strip() != expression:
            raise ValueError(f"source constructor changed: {path}:{line}")
        witnessed.append({"path": path, "line": line, "blob_sha": sha})
    return witnessed


def run_study(checkout: Path, output: Path) -> dict:
    if not checkout.is_dir():
        raise ValueError("source checkout must be a directory")
    witnesses = review_pinned_source(checkout)
    graph, findings = scan(checkout)
    pre_adg = graph.adg.as_dict() if graph.adg is not None else None
    if pre_adg is None:
        raise ValueError("current scan did not produce an ADG")
    original_nodes = len(pre_adg["nodes"])
    original_edges = len(pre_adg["edges"])
    raw_shadow = project_bound_source_mcp_implementations(graph, checkout)
    shadow = seal_mcp_source_shadow(raw_shadow, checkout)
    verify_mcp_source_shadow(shadow, checkout)
    if (shadow["source_revision"]["commit_sha"] != SHA
            or shadow["source_revision"]["mode"]
            != "c02x_exact_git_sha1_blob_and_worktree_sha256"):
        raise ValueError("pinned source attestation contract unexpectedly changed")
    if (original_nodes != len(pre_adg["nodes"])
            or original_edges != len(pre_adg["edges"])):
        raise ValueError("shadow unexpectedly mutated production ADG")
    exposed = shadow["edge_kinds"].get("EXPOSES_TOOL", 0)
    implementations = [
        n for n in shadow["nodes"]
        if n["kind"] == "mcp_source_implementation"
    ]
    # Frozen source source-level row census, not deployed runtime truth.
    if len(implementations) != 3 or exposed != 25:
        raise ValueError(
            f"source shadow parity mismatch: {len(implementations)} implementations, "
            f"{exposed} source tool declarations"
        )
    names = {node["location"]["path"]: node["name"] for node in implementations}
    if names != {
        "mcp_server_1.py": "Calculator",
        "mcp_server_2.py": "Calculator",
        "mcp_server_3.py": "ddg-search",
    }:
        raise ValueError("distinct source implementation identities collapsed")
    if any(edge["kind"] in {"AGENT_CAN_CALL", "INVOKES"}
           for edge in shadow["edges"]):
        raise ValueError("source exposure promoted to runtime callability")
    # Reversible C03a candidate is a quarantined ADG-shaped snapshot,
    # not a source of production findings/paths or a runtime authority graph.
    candidate = build_mcp_adg_candidate(graph.adg, shadow, checkout)
    verify_mcp_candidate_rollback(graph.adg, candidate)
    crosswalk = build_mcp_source_crosswalk(graph.adg, candidate)
    if (len(crosswalk["node_correspondences"]) != len(shadow["nodes"])
            or len(crosswalk["edge_correspondences"]) != len(shadow["edges"])
            or crosswalk["production_cutover_authorized"] is not False
            or crosswalk["runtime_authority_verified"] is not False):
        raise ValueError("C03b source crosswalk missing witnesses or promoting authority")
    difference = candidate["differential"]
    if (len(difference["added_source_node_ids"]) != len(shadow["nodes"])
            or len(difference["added_source_edge_ids"]) != len(shadow["edges"])
            or difference["added_source_edge_kinds"] != {
                "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION": 3,
                "EXPOSES_TOOL": 25,
            }
            or difference["effective_agent_can_call_edges_added"] != 0
            or candidate["production_cutover_authorized"] is not False
            or graph.adg.as_dict() != pre_adg):
        raise ValueError("C03a source-only candidate parity or rollback failed")
    # Independent AST source-declaration corpus: not the scanner's labels.
    # Exact Git blob witnesses are verified separately by C02s.
    oracle = inspect_mcp_scope(read_pinned_source(checkout))
    if (oracle["unresolved"] or len(oracle["implementations"]) != 4
            or len(oracle["tools"]) != 28):
        raise ValueError("independent MCP source AST scope changed")
    local = {"mcp_server_1.py", "mcp_server_2.py", "mcp_server_3.py"}
    expected_servers = {
        (row["path"], row["line"], row["name"])
        for row in oracle["implementations"] if row["path"] in local
    }
    expected_tools = {
        (row["path"], row["line"], row["name"])
        for row in oracle["tools"] if row["path"] in local
    }
    candidate_nodes = [
        node for node in candidate["candidate_adg"]["nodes"]
        if node["id"].startswith("c03-candidate:")
    ]
    actual_servers = {
        (node["location"]["path"], node["location"]["line"], node["name"])
        for node in candidate_nodes if node["kind"] == "mcp_source_implementation"
    }
    actual_tools = {
        (node["location"]["path"], node["location"]["line"], node["name"])
        for node in candidate_nodes if node["kind"] == "mcp_source_tool"
    }
    if (len(expected_servers) != 3 or len(expected_tools) != 25
            or actual_servers != expected_servers
            or actual_tools != expected_tools):
        raise ValueError("independent AST and C03 candidate source sites disagree")
    data = {
        "schema_version": 1,
        "mode": "wave_c_c02r_source_implementation_shadow_not_release_truth",
        "case_id": CASE,
        "repository": REPO,
        "pinned_source_sha": SHA,
        "witnesses": witnesses,
        "scanner_adg_unchanged": True,
        "scanner_adg_nodes": original_nodes,
        "scanner_adg_edges": original_edges,
        "scanner_findings": len(findings),
        "source_shadow": shadow,
        "source_revision": shadow["source_revision"],
        "c03_candidate_baseline_adg_digest": candidate["baseline_adg_digest"],
        "c03b_source_crosswalk_sha256": crosswalk["crosswalk_sha256"],
        "c03b_node_status_counts": crosswalk["node_status_counts"],
        "c03b_edge_status_counts": crosswalk["edge_status_counts"],
        "c03_candidate_snapshot_sha256": candidate["candidate_snapshot_sha256"],
        "c03_candidate_nodes_added": len(difference["added_source_node_ids"]),
        "c03_candidate_edges_added": len(difference["added_source_edge_ids"]),
        "c03_candidate_no_canonical_mutation": True,
        "c03_candidate_ast_source_sites_corroborated": True,
        "c03_candidate_ast_source_tool_sites": len(expected_tools),
        "c03_candidate_production_cutover_authorized": False,
        "effective_authority_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "result.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    (output / "c03-mcp-source-crosswalk.json").write_text(
        json.dumps(crosswalk, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "c03-mcp-candidate.json").write_text(
        json.dumps(candidate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "source-shadow.json").write_text(
        json.dumps(shadow, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_study(args.checkout.resolve(), args.output.resolve())
    print(json.dumps({
        "case_id": result["case_id"],
        "source": result["pinned_source_sha"],
        "shadow_implementation_count": len([
            x for x in result["source_shadow"]["nodes"]
            if x["kind"] == "mcp_source_implementation"
        ]),
        "shadow_exposes_tool": result["source_shadow"]["edge_kinds"]["EXPOSES_TOOL"],
        "production_cutover_authorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
