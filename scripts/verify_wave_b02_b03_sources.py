"""Verify WAB-02/03 against pinned original source blobs (not scanner truth)."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from horustrace.source_native_dynamic_mcp import inspect_dynamic_mcp_registration

SOURCES = {
    "couchbase": (
        "src/cb_mcp/core/app.py",
        "1e6ec5dfe0ca5e808c776cad3f1905bb90d9aa99",
    ),
    "microsoft": (
        "dotnet-agent-no-teams/Agent365/WorkIqToolProvider.cs",
        "0d60ab1b3966478c0ceea370cd6c604b31af1f8f",
    ),
}


def _check_blob(root: Path, key: str) -> Path:
    path, expected = SOURCES[key]
    source = root / path
    content = source.read_bytes()
    digest = hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()
    if digest != expected:
        raise ValueError(f"pinned {key} blob mismatch")
    return source


def validate(couchbase: Path, microsoft: Path) -> dict[str, object]:
    provider = inspect_dynamic_mcp_registration(
        _check_blob(couchbase, "couchbase")
    ).as_dict()
    client = inspect_dynamic_mcp_registration(
        _check_blob(microsoft, "microsoft")
    ).as_dict()
    provider_edges = provider["bindings"]
    client_edges = client["bindings"]
    assert len(provider_edges) == 1
    assert provider_edges[0]["kind"] == "contains"
    assert provider_edges[0]["resolution"] == "partial"
    assert len(client_edges) == 1
    assert client_edges[0]["kind"] == "dispatches_to"
    assert client_edges[0]["resolution"] == "unresolved"
    assert len([n for n in client["entities"] if n["kind"] == "unknown"]) == 1
    assert all(
        e["kind"] not in ("exposes_tool", "agent_can_call")
        for e in provider_edges + client_edges
    )
    return {
        "reference_status": "pinned_source_evidence_not_independent_truth",
        "case_ids": ["gen-mcp-003", "ff60-microsoft-04"],
        "provider_factory_registration_edges": len(provider_edges),
        "remote_unresolved_enumeration_edges": len(client_edges),
        "source_proven_tool_names": 0,
        "agent_callability_verified": False,
        "production_graph_changed": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--couchbase", type=Path, required=True)
    parser.add_argument("--microsoft", type=Path, required=True)
    options = parser.parse_args()
    print(json.dumps(validate(options.couchbase, options.microsoft), indent=2))
