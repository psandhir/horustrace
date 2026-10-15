"""WAB-03: independently pin source blobs and verify conditional ToolSet links.

This validates fidelity to declared source, not running/authenticated exposure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from horustrace.source_native_toolsets import inspect_local_toolset_catalogues

PINS = {
    "src/cb_mcp/core/app.py": "1e6ec5dfe0ca5e808c776cad3f1905bb90d9aa99",
    "src/cb_mcp/core/spec.py": "5da06ea6f8ed11234939d428b7b4650492aab974",
    "src/cb_mcp/servers/operational/spec.py": "86f965fe1e699dc5b7d5ebc2a844e7bfa6c24fdf",
    "src/cb_mcp/servers/operational_insights/spec.py": "3664f744fdc33da31e6219e0721ef12321bad6bf",
    "src/cb_mcp/tools/operational/__init__.py": "5a9fef1e213016b624a0d975d0bc9842d7c29cd8",
    "src/cb_mcp/tools/operational_insights/__init__.py": "f5bffeb88668179b7031bb0dfaba918b879eb827",
}
EXPECTED = {
    "operational": {"read_only": 28, "write": 12},
    "operational_insights": {"read_only": 11, "write": 2},
}


def verify(root: Path) -> dict[str, object]:
    for path, blob_sha in PINS.items():
        payload = (root / path).read_bytes()
        actual = hashlib.sha1(
            b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload
        ).hexdigest()
        if actual != blob_sha:
            raise ValueError(f"pinned source blob differs: {path}")

    graph = inspect_local_toolset_catalogues(root).as_dict()
    nodes = {n["entity_id"]: n for n in graph["entities"]}
    totals: dict[str, Counter[str]] = {}
    for edge in graph["bindings"]:
        assert edge["kind"] == "exposes_tool"
        assert edge["resolution"] == "partial"
        assert edge["metadata"]["exposure_state"] == "conditional_candidate"
        assert edge["metadata"]["disabled_tools"] == "unresolved"
        assert edge["metadata"]["auth_scope"] == "unresolved"
        assert edge["metadata"]["agent_callability"] == "not_adjudicated"
        assert nodes[edge["source_id"]]["kind"] == "mcp_server"
        assert nodes[edge["target_id"]]["kind"] == "tool"
        name = nodes[edge["source_id"]]["name"]
        totals.setdefault(name, Counter())[edge["metadata"]["registration_bucket"]] += 1

    measured = {name: dict(counts) for name, counts in totals.items()}
    if measured != EXPECTED:
        raise ValueError(f"source declaration counts changed: {measured}")
    assert len(graph["bindings"]) == 53
    assert not any(n["kind"] == "agent" for n in graph["entities"])
    return {
        "case": "gen-mcp-003",
        "pinned_source": "couchbase/mcp-server-couchbase@df5d9ceb013f57143171f65ec3ba033ace06aa9a",
        "provider_spec_counts": measured,
        "source_toolset_candidates": 53,
        "catalogue_exposure_verified": False,
        "effective_agent_authority_verified": False,
        "production_graph_changed": False,
        "independent_precision_recall": None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.source), indent=2, sort_keys=True))
