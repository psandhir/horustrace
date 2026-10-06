"""Authority-resolution confidence metrics and CI gate helpers."""
from __future__ import annotations

from typing import Any

from horustrace.effective_authority import effective_authority_relationships
from horustrace.models import Graph

AUTHORITY_RESOLUTION_SCHEMA_VERSION = 1


def authority_resolution_summary(graph: Graph) -> dict[str, Any]:
    relationships = effective_authority_relationships(graph)
    counts = {
        "fully_resolved": 0,
        "partially_resolved": 0,
        "unknown": 0,
    }
    core_counts = {
        "fully_resolved": 0,
        "partially_resolved": 0,
        "unknown": 0,
    }
    unresolved_dimensions: dict[str, int] = {}
    core_unresolved_dimensions: dict[str, int] = {}
    for relationship in relationships:
        counts[relationship.resolution] += 1
        core_counts[relationship.core_resolution] += 1
        for dimension in relationship.unresolved:
            unresolved_dimensions[dimension] = unresolved_dimensions.get(dimension, 0) + 1
        for dimension in relationship.core_unresolved:
            core_unresolved_dimensions[dimension] = (
                core_unresolved_dimensions.get(dimension, 0) + 1
            )

    unresolved = counts["partially_resolved"] + counts["unknown"]
    core_unresolved = (
        core_counts["partially_resolved"] + core_counts["unknown"]
    )
    total = len(relationships)
    return {
        "schema_version": AUTHORITY_RESOLUTION_SCHEMA_VERSION,
        "relationships": total,
        "fully_resolved_relationships": counts["fully_resolved"],
        "partially_resolved_relationships": counts["partially_resolved"],
        "unknown_relationships": counts["unknown"],
        "unresolved_relationships": unresolved,
        "fully_resolved_ratio": (
            round(counts["fully_resolved"] / total, 6) if total else 1.0
        ),
        "detail_fully_resolved_ratio": (
            round(counts["fully_resolved"] / total, 6) if total else 1.0
        ),
        "core_fully_resolved_relationships": core_counts["fully_resolved"],
        "core_partially_resolved_relationships": core_counts[
            "partially_resolved"
        ],
        "core_unknown_relationships": core_counts["unknown"],
        "core_unresolved_relationships": core_unresolved,
        "core_fully_resolved_ratio": (
            round(core_counts["fully_resolved"] / total, 6)
            if total
            else 1.0
        ),
        "unresolved_dimensions": dict(sorted(unresolved_dimensions.items())),
        "core_unresolved_dimensions": dict(
            sorted(core_unresolved_dimensions.items())
        ),
        "runtime_effectiveness": "not_verified",
    }


def compare_authority_resolution(base_graph: Graph, head_graph: Graph) -> dict[str, Any]:
    base = authority_resolution_summary(base_graph)
    head = authority_resolution_summary(head_graph)
    delta = head["unresolved_relationships"] - base["unresolved_relationships"]
    core_delta = (
        head["core_unresolved_relationships"]
        - base["core_unresolved_relationships"]
    )
    return {
        "schema_version": AUTHORITY_RESOLUTION_SCHEMA_VERSION,
        "base": base,
        "head": head,
        "unresolved_relationship_delta": delta,
        "regressed": delta > 0,
        "core_unresolved_relationship_delta": core_delta,
        "core_regressed": core_delta > 0,
        "runtime_effectiveness": "not_verified",
    }


def exceeds_unresolved_budget(graph: Graph, maximum: int) -> bool:
    if maximum < 0:
        raise ValueError("maximum unresolved authority relationships must be >= 0")
    return authority_resolution_summary(graph)["unresolved_relationships"] > maximum
