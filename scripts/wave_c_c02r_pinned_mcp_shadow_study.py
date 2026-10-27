"""C02r rw080: exact-commit static scanner source-MCP shadow study.

No target code execution or SDK imports. Does not modify real Graph/ADG.
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
        "effective_authority_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "result.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8",
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
