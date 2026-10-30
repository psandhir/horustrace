"""Wave C C03c: opt-in, presentation-only MCP C03 crosswalk overlay.

Recompute crosswalk from the current canonical ADG and exact Git-attested
source evidence. Never trust a claimed precomputed JSON mapping for UI.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from horustrace.adg import AgentDependencyGraph
from horustrace.mcp_c03_candidate import build_mcp_adg_candidate
from horustrace.mcp_c03_crosswalk import build_mcp_source_crosswalk

_ALLOWED = frozenset({
    "candidate_only", "corroborated_source_site", "ambiguous_source_site",
})
_LABELS = {
    "candidate_only": "No exact canonical source-site match",
    "corroborated_source_site": "Matching canonical source site",
    "ambiguous_source_site": "Ambiguous canonical source-site matches",
}


def attach_mcp_c03_crosswalk_preview(
    overlay: dict[str, Any],
    baseline: AgentDependencyGraph,
    attested_shadow: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    """Decorate a copy of the already opted-in source evidence UI model.

    The source site match is NOT canonical semantic identity and no runtime
    authority is inferred. Default report callers need never invoke this.
    """
    if (not isinstance(overlay, dict)
            or overlay.get("mode") != "opt_in_mcp_source_evidence_not_authority"
            or overlay.get("source_only") is not True
            or overlay.get("runtime_authority_verified") is not False
            or overlay.get("source_integrity_checked") is not True):
        raise ValueError("C03 preview requires verified source-only Workbench overlay")
    if not isinstance(baseline, AgentDependencyGraph):
        raise TypeError("C03 preview requires the current canonical ADG")
    original = deepcopy(overlay)
    before = baseline.canonical_digest()
    candidate = build_mcp_adg_candidate(baseline, attested_shadow, root)
    crosswalk = build_mcp_source_crosswalk(baseline, candidate)
    if overlay.get("source_commit_sha") != crosswalk["source_commit_sha"]:
        raise ValueError("C03 preview source revision does not match Workbench overlay")
    matches = {
        row["candidate_id"].removeprefix("c03-candidate:"): row
        for row in crosswalk["node_correspondences"]
    }
    node_ids = {row.get("id") for row in overlay.get("nodes", [])}
    if node_ids != set(matches) or len(overlay["nodes"]) != len(matches):
        raise ValueError("C03 crosswalk candidate sites differ from Workbench evidence")
    decorated = deepcopy(overlay)
    for node in decorated["nodes"]:
        entry = matches[node["id"]]
        if (entry["candidate_kind"] != node["kind"]
                or entry["name"] != node["name"]
                or entry["source_site"]["path"] != node["path"]
                or entry["source_site"]["line"] != node["line"]
                or entry["status"] not in _ALLOWED
                or entry["semantic_identity_verified"] is not False
                or entry["runtime_identity_verified"] is not False
                or entry["effective_authority_verified"] is not False):
            raise ValueError("C03 Workbench source-site witness mismatch")
        node["c03_source_site_match"] = {
            "status": entry["status"],
            "label": _LABELS[entry["status"]],
            "canonical_match_count": len(entry["canonical_source_site_matches"]),
            "canonical_source_kinds": sorted({
                item["kind"] for item in entry["canonical_source_site_matches"]
            }),
            "semantic_identity_verified": False,
            "runtime_authority_verified": False,
        }
    decorated["c03_preview"] = {
        "mode": "c03c_source_site_only_no_authority",
        "source_commit_sha": crosswalk["source_commit_sha"],
        "baseline_adg_digest": crosswalk["baseline_adg_digest"],
        "crosswalk_sha256": crosswalk["crosswalk_sha256"],
        "node_status_counts": crosswalk["node_status_counts"],
        "edge_status_counts": crosswalk["edge_status_counts"],
        "source_site_only": True,
        "independently_adjudicated": False,
        "runtime_authority_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
    if original != overlay or baseline.canonical_digest() != before:
        raise RuntimeError("C03 Workbench preview mutated source evidence or canonical ADG")
    return decorated
