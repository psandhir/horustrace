"""Wave C01b: conservative crosswalk of existing source-native semantic discoveries.

The input source-native producers were introduced in Wave B. This report
compares their exact source sites with the legacy-derived shadow sidecar but
never merges objects, adds Graph edges, or grants executable tool authority.
A source-only edge is NOT a missing production false negative by itself.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

from horustrace.semantic_discovery import (
    SemanticDiscovery,
    SemanticEntity,
    SemanticResolution,
)
from horustrace.source_context import classify_source_context

# Names intentionally match the existing opt-in sidecar keys; no producer is
# invoked inside the reconciliation algorithm.
SOURCE_PRODUCERS = (
    "source_native",
    "source_native_dynamic",
    "source_native_strands",
    "source_native_toolsets",
)
_MATCH_TYPES = frozenset(("agent", "tool", "mcp_server", "mcp_client", "skill"))


def _site(entity: SemanticEntity) -> tuple[str, str, str, int] | None:
    if entity.location is None:
        return None
    return (
        entity.kind.value,
        entity.name,
        entity.location.path.as_posix(),
        entity.location.line,
    )


def _context(entity: SemanticEntity) -> str:
    # Call on the portable relative source path, not an absolute checkout path.
    return classify_source_context(
        entity.location.path if entity.location is not None else None
    )


def reconcile_native_source_proofs(
    legacy: SemanticDiscovery,
    sources: Mapping[str, SemanticDiscovery],
) -> dict[str, Any]:
    """Crosswalk source-native facts to legacy shadow *sites*, not authority.

    Matching exact kind/name/path/line is deliberately conservative. Mismatched
    versions, alias naming and deferred factories remain source-only. A source
    producer and an inherited legacy graph cannot certify one another.
    """
    legacy.validate()
    if set(sources) != set(SOURCE_PRODUCERS):
        raise ValueError("C01b requires the exact four canonical source producers")
    sites: dict[tuple[str, str, str, int], set[str]] = defaultdict(set)
    for entity in legacy.entities:
        site = _site(entity)
        if site is not None and entity.kind.value in _MATCH_TYPES:
            sites[site].add(entity.entity_id)

    records: list[dict[str, Any]] = []
    producer_counts: dict[str, dict[str, int]] = {}
    unknown: list[dict[str, str]] = []
    for producer in SOURCE_PRODUCERS:
        discovery = sources[producer]
        discovery.validate()
        entities = discovery.entity_map()
        counts: Counter[str] = Counter()
        for binding in sorted(discovery.bindings, key=lambda x: x.binding_id):
            src = entities[binding.source_id]
            dst = entities[binding.target_id]
            src_site, dst_site = _site(src), _site(dst)
            source_matches = sorted(sites.get(src_site, set())) if src_site else []
            target_matches = sorted(sites.get(dst_site, set())) if dst_site else []
            if len(source_matches) > 1 or len(target_matches) > 1:
                match = "ambiguous_legacy_instance_site"
            elif source_matches and target_matches:
                match = "both_legacy_sites"
            elif source_matches or target_matches:
                match = "one_legacy_site"
            else:
                match = "source_only_not_false_negative"
            counts[match] += 1
            counts["edges"] += 1
            if binding.resolution == SemanticResolution.UNRESOLVED:
                counts["unresolved_edges"] += 1
            if binding.resolution == SemanticResolution.PARTIAL:
                counts["conditional_edges"] += 1
            # Whitelisted fields only; never echo arbitrary metadata, scripts,
            # URL endpoints, source bodies, tool arguments or secrets.
            records.append({
                "producer": producer,
                "source_binding_id": binding.binding_id,
                "kind": binding.kind.value,
                "source_entity_id": binding.source_id,
                "target_entity_id": binding.target_id,
                "source_kind": src.kind.value,
                "target_kind": dst.kind.value,
                "source_site": (
                    {"path": src_site[2], "line": src_site[3]}
                    if src_site is not None else None
                ),
                "target_site": (
                    {"path": dst_site[2], "line": dst_site[3]}
                    if dst_site is not None else None
                ),
                "source_context": _context(src),
                "target_context": _context(dst),
                "resolution": binding.resolution.value,
                "source_witness": (
                    {"path": binding.location.path.as_posix(),
                     "line": binding.location.line}
                    if binding.location is not None else None
                ),
                "legacy_source_site_ids": source_matches,
                "legacy_target_site_ids": target_matches,
                "reconciliation": match,
                "authority_verified": False,
                "runtime_executed": False,
            })
        for observation in discovery.observations:
            if observation.resolution == SemanticResolution.UNRESOLVED:
                entity = entities[observation.entity_id]
                unknown.append({
                    "producer": producer,
                    "entity_id": observation.entity_id,
                    "observation_id": observation.observation_id,
                    "entity_kind": entity.kind.value,
                    "source_context": _context(entity),
                    "status": "unresolved_not_absent",
                })
        counts["entities"] = len(discovery.entities)
        counts["observations"] = len(discovery.observations)
        counts["unresolved_observations"] = sum(
            item.resolution == SemanticResolution.UNRESOLVED
            for item in discovery.observations
        )
        producer_counts[producer] = dict(sorted(counts.items()))
    return {
        "schema_version": 1,
        "mode": "passive_source_native_legacy_site_crosswalk",
        "production_projection_authorized": False,
        "source_precision": None,
        "source_recall": None,
        "not_assessed": "independent_positive_and_negative_source_truth",
        "no_implicit_exposure_to_callability": True,
        "no_source_proof_of_runtime_effectiveness": True,
        "legacy_site_matching": "exact_kind_name_relative_file_line",
        "producers": producer_counts,
        "source_edge_crosswalk": sorted(
            records, key=lambda row: (
                row["producer"], row["source_binding_id"]
            )
        ),
        "unresolved_observation_queue": sorted(
            unknown, key=lambda row: (
                row["producer"], row["observation_id"]
            )
        ),
    }
