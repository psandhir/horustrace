"""C02t rw005 pinned Google ADK source AST oracle and scanner study.

Pinned Git object reads and static scanner only. No target import, runtime
execution, LLM API or certified independent accuracy claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from horustrace.scanner import scan
from horustrace.source_truth_ast_adk import inspect_adk_scope

REPOSITORY = "Ojas-Patil26/VeriQ"
CASE_ID = "rw-005"
SOURCE_SHA = "067cb330ab943279b4b8ea13c91c9042bdd9f421"
BLOBS = {
    "agent.py": "89ce05579a18e8e09822d4157cace7121a5d7c99",
    "api.py": "bfed9d84fd977eb20a4e7f8453aebff675ac9faf",
}


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True, capture_output=True, timeout=40,
    ).stdout


def read_pinned(checkout: Path) -> dict[str, str]:
    if _git(checkout, "rev-parse", "HEAD").decode().strip() != SOURCE_SHA:
        raise ValueError("pinned source HEAD changed")
    rows: dict[str, str] = {}
    for path, sha in sorted(BLOBS.items()):
        info = _git(checkout, "ls-tree", "HEAD", "--", path).decode().strip()
        if info != f"100644 blob {sha}\t{path}":
            raise ValueError(f"wrong Git blob or non-file source: {path}")
        data = _git(checkout, "cat-file", "blob", sha)
        object_hash = hashlib.sha1(
            b"blob " + str(len(data)).encode("ascii") + b"\0" + data
        ).hexdigest()
        if object_hash != sha:
            raise ValueError(f"Git blob content digest mismatch: {path}")
        rows[path] = data.decode("utf-8")
    return rows


def run_study(checkout: Path, output: Path) -> dict:
    if not checkout.is_dir():
        raise ValueError("checkout path does not exist")
    oracle = inspect_adk_scope(read_pinned(checkout))
    if oracle["unresolved"]:
        raise ValueError("real pinned ADK source has unresolved AST witnesses")
    if (len(oracle["agents"]) != 5
            or len(oracle["direct_tool_entries"]) != 8
            or len(oracle["sub_agent_entries"]) != 4):
        raise ValueError("pinned ADK source AST expected declaration counts changed")
    by_symbol = {x["symbol"]: x for x in oracle["agents"]}
    if len(by_symbol) != 5:
        raise ValueError("distinct agent constructor source identities collapsed")
    if {x["source_agent"] for x in oracle["sub_agent_entries"]} != {
        "root_agent",
    }:
        raise ValueError("unexpected ADK source delegation ownership")
    if {x["source_agent"] for x in oracle["direct_tool_entries"]} != {
        "ingestion_agent", "anomaly_agent", "root_cause_agent",
    }:
        raise ValueError("conditional/direct ADK tool ownership changed")
    if any(x["source_agent"] in {"root_agent", "report_agent"}
           for x in oracle["direct_tool_entries"]):
        raise ValueError("report/root falsely inherited child direct tools")
    if any(x["path"] == "api.py" for x in oracle["agents"]):
        raise ValueError("API alias or Runner incorrectly interpreted as agent")
    if any(x["target_symbol"] not in by_symbol
           for x in oracle["sub_agent_entries"]):
        raise ValueError("missing statically referenced child agent constructor")
    graph, findings = scan(checkout)
    adg = graph.adg.as_dict() if graph.adg is not None else None
    if adg is None:
        raise ValueError("scanner did not return a production ADG")
    result = {
        "schema_version": 1,
        "case_id": CASE_ID,
        "repository": REPOSITORY,
        "pinned_commit": SOURCE_SHA,
        "pinned_blobs": BLOBS,
        "mode": "bounded_adk_source_ast_oracle_not_release_accuracy",
        "oracle": oracle,
        "scanner_adg_nodes": len(adg["nodes"]),
        "scanner_adg_edges": len(adg["edges"]),
        "scanner_findings": len(findings),
        "source_constructs_mechanically_verified": [
            "module_level_LlmAgent_literal_constructor",
            "explicit_list_sub_agents",
            "explicit_list_direct_tool_bindings",
            "API_alias_not_constructor",
            "report_agent_empty_direct_tools",
        ],
        "deployed_runtime_verified": False,
        "independent_human_review_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "adk-source-ast-oracle.json").write_text(
        json.dumps(oracle, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    (output / "scanner-adg.json").write_text(
        json.dumps(adg, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    (output / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = run_study(args.checkout.resolve(), args.output.resolve())
    print(json.dumps({
        "case_id": CASE_ID,
        "source_agent_sites": len(result["oracle"]["agents"]),
        "source_direct_tool_entries":
            len(result["oracle"]["direct_tool_entries"]),
        "source_delegations": len(result["oracle"]["sub_agent_entries"]),
        "release_precision": None,
        "production_cutover_authorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
