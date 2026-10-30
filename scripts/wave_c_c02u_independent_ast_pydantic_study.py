"""C02u pinned Pydantic conditional tool selection AST source study.

No target dependency installation, imports, environment execution or runtime
authority assumptions. Checks exact original Git object bytes and static AST.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from horustrace.pydantic_c03_candidate import (
    build_pydantic_conditional_source_candidate,
    verify_pydantic_conditional_candidate_rollback,
)
from horustrace.scanner import scan
from horustrace.source_truth_ast_pydantic import (
    inspect_pydantic_level_returns,
    inspect_pydantic_tool_plumbing,
)

REPOSITORY = "LeonieFreisinger/pydanticai-base-agent"
CASE_ID = "rw-149"
SOURCE_SHA = "0cf88a4caf2b5da29ff7af8364d4db14ac9e50b4"
BLOBS = {
    "agent/tools.py": "4dc2632448c29ec347cd95d60e0555bdbd4d8cf4",
    "agent/agent.py": "a91f05c4bc4ba7476e2d73692d1211fee72dec53",
    "agent/base_agent.py": "17f586aad5f64ad228ec774dc368e8b068dc55f3",
    "app.py": "dfafe6f01a0dbbb1a58ee18d6d3462eb43f6d4a2",
}


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True, capture_output=True, timeout=40,
    ).stdout


def read_pinned(checkout: Path) -> dict[str, str]:
    if _git(checkout, "rev-parse", "HEAD").decode().strip() != SOURCE_SHA:
        raise ValueError("Pydantic source checkout commit changed")
    files: dict[str, str] = {}
    for path, sha in sorted(BLOBS.items()):
        info = _git(checkout, "ls-tree", "HEAD", "--", path).decode().strip()
        if info != f"100644 blob {sha}\t{path}":
            raise ValueError(f"pinned Git source file identity mismatch: {path}")
        blob = _git(checkout, "cat-file", "blob", sha)
        actual_sha = hashlib.sha1(
            b"blob " + str(len(blob)).encode("ascii") + b"\0" + blob
        ).hexdigest()
        if sha != actual_sha:
            raise ValueError(f"pinned Git source blob corrupted: {path}")
        files[path] = blob.decode("utf-8")
    return files


def run_study(checkout: Path, output: Path) -> dict:
    if not checkout.is_dir():
        raise ValueError("pinned source checkout missing")
    files = read_pinned(checkout)
    oracle = inspect_pydantic_level_returns(
        "agent/tools.py", files["agent/tools.py"]
    )
    plumbing = inspect_pydantic_tool_plumbing(
        files["agent/agent.py"], files["agent/base_agent.py"]
    )
    if (oracle["level_1"] != []
            or oracle["level_2"] != ["list_tables", "describe_table"]
            or oracle["else_branch_other_values"] != [
                "list_tables", "describe_table", "execute_query",
                "get_current_date", "get_stock_query_template",
            ]):
        raise ValueError("Pydantic conditional tool symbols changed")
    graph, findings = scan(checkout)
    adg = graph.adg.as_dict() if graph.adg is not None else None
    if adg is None:
        raise ValueError("scanner did not produce ADG")
    # Quarantined, schema-incompatible C03 source ADG candidate; do not feed
    # it into production scanner, authority, findings or attack paths.
    original = graph.adg.as_dict()
    candidate = build_pydantic_conditional_source_candidate(graph.adg, checkout)
    verify_pydantic_conditional_candidate_rollback(graph.adg, candidate)
    if (graph.adg.as_dict() != original
            or candidate["differential"]["source_nodes_added"] != 8
            or candidate["differential"]["source_edges_added"] != 7
            or candidate["runtime_level_known"] is not False
            or candidate["production_cutover_authorized"] is not False):
        raise ValueError("pinned Pydantic conditional source candidate parity failed")
    result = {
        "schema_version": 1,
        "mode": "c02u_independent_bounded_ast_source_only_not_release_truth",
        "case_id": CASE_ID,
        "repository": REPOSITORY,
        "pinned_source_sha": SOURCE_SHA,
        "pinned_blobs": BLOBS,
        "oracle": oracle,
        "source_tool_registration_plumbing": plumbing,
        "scanner_adg_nodes": len(adg["nodes"]),
        "scanner_adg_edges": len(adg["edges"]),
        "scanner_findings": len(findings),
        "c03_pydantic_candidate_nodes_added": 8,
        "c03_pydantic_candidate_edges_added": 7,
        "c03_pydantic_source_only": True,
        "source_scope_mechanically_complete_only_for_literal_return_ast": True,
        "deployed_demo_level": None,
        "installed_sdk_semantics_verified": False,
        "runtime_callability_verified": False,
        "independent_human_review_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "pydantic-conditional-ast-oracle.json").write_text(
        json.dumps(oracle, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    (output / "c03-pydantic-source-candidate.json").write_text(
        json.dumps(candidate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8",
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
        "level_1_source_tools": len(result["oracle"]["level_1"]),
        "level_2_source_tools": len(result["oracle"]["level_2"]),
        "all_other_integer_levels_source_tools":
            len(result["oracle"]["else_branch_other_values"]),
        "runtime_callability_verified": False,
        "production_cutover_authorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
