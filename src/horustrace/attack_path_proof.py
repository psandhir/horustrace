"""Conservative, framework-neutral description of attack-path evidence strength.

This classification does not change path generation, severity, or confidence.
In particular, source-backed patterns are not promoted to full data-flow proofs.
"""
from __future__ import annotations

from typing import Any

PATH_PROOF_SCHEMA_VERSION = 1

_STATIC_FLOW_BASES = frozenset({"static_dataflow", "source_proven_tool_dataflow"})
_AUTHORITY_BASES = frozenset({
    "source_bound_delegated_authority",
    "source_bound_ingress_authority",
})


def proof_for_path_basis(basis: str) -> dict[str, Any]:
    if basis in _STATIC_FLOW_BASES:
        category = "static_dataflow"
        source_to_sink = True
        authority = False
    elif basis in _AUTHORITY_BASES:
        category = "authority_reachability"
        source_to_sink = False
        authority = True
    elif basis == "capability_cooccurrence":
        category = "capability_combination"
        source_to_sink = False
        authority = False
    else:
        category = "source_backed_pattern" if basis.startswith("source_proven_") else "other_potential"
        source_to_sink = False
        authority = False
    return {
        "schema_version": PATH_PROOF_SCHEMA_VERSION,
        "category": category,
        "basis": basis,
        "static_source_to_sink_established": source_to_sink,
        "authority_reachability_established": authority,
        "runtime_exploitability": "not_verified",
    }
