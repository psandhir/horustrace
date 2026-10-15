"""Check WAB-01 source-native semantic proof against pinned source-reviewed anchors.

This is a diagnostic source witness, not an independent precision/recall score.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from horustrace.source_native_mcp import inspect_local_pydantic_mcp


def verify(source: Path, ledger_path: Path) -> dict[str, object]:
    with ledger_path.open(encoding="utf-8") as stream:
        ledger = json.load(stream)
    actual = inspect_local_pydantic_mcp(source).as_dict()

    # Validate pinned source file blobs with Git's source hash convention.
    import hashlib

    for name, pin in (
        ("agent.py", ledger["input_proof"]["agent_source"]),
        ("mcp_server.py", ledger["input_proof"]["provider"]),
    ):
        payload = (source / name).read_bytes()
        git_blob = b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload
        digest = hashlib.sha1(git_blob).hexdigest()
        if digest != pin["blob_sha"]:
            raise ValueError(f"pinned source blob mismatch: {name}")

    entities = {entity["entity_id"]: entity for entity in actual["entities"]}
    exposure_edges = [
        edge for edge in actual["bindings"] if edge["kind"] == "exposes_tool"
    ]
    expected = {item["tool_name"] for item in ledger["exposure_tools"]}
    found = {entities[edge["target_id"]]["name"] for edge in exposure_edges}
    if found != expected or len(exposure_edges) != len(expected):
        raise ValueError(
            "source registration set differs from pinned per-tool reference: "
            f"missing={sorted(expected - found)}, unexpected={sorted(found - expected)}"
        )
    edge_types = [edge["kind"] for edge in actual["bindings"]]
    if edge_types.count("agent_binds_client") != 1:
        raise ValueError("expected one source-linked agent to client edge")
    if edge_types.count("client_connects_to_server") != 1:
        raise ValueError("expected one source-linked client to local FastMCP server edge")
    if "agent_can_call" in edge_types:
        raise ValueError("source-only pilot must not infer effective AGENT_CAN_CALL")
    if any(edge["resolution"] != "proven" for edge in actual["bindings"]):
        raise ValueError("source-native edge changed from explicitly supported")
    return {
        "case_id": ledger["case_id"],
        "source_exposed_tools": len(found),
        "source_linked_agent_client": 1,
        "source_linked_client_server": 1,
        "agent_callable_adjudicated": False,
        "runtime_verified": False,
        "independent_ground_truth": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument(
        "--ledger", type=Path,
        default=Path("research/accuracy-wave-b-pilot-20261014/pharmiq-source-tool-proof.json"),
    )
    args = parser.parse_args()
    print(json.dumps(verify(args.source, args.ledger), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
