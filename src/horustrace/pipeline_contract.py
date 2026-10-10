"""Deterministic analysis-stage checkpoints and graph-integrity diagnostics.

Checkpoints are observational: they must not mutate inferred authority, paths or
findings. A consumer (CI/studies) may enforce assert_valid separately.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from horustrace.models import Graph
from horustrace.semantic_contract import validate_graph_semantics

PIPELINE_CONTRACT_VERSION = 1
PIPELINE_STAGES = (
    "discovered",
    "normalized",
    "flows_resolved",
    "attack_paths",
    "adg",
    "findings",
)


def validate_adg_integrity(graph: Graph) -> list[str]:
    """Check graph identities and edge endpoints without inferring new authority."""
    if graph.adg is None:
        return ["ADG was not constructed"]
    errors: list[str] = []
    node_ids: set[str] = set()
    edge_ids: set[str] = set()
    for node in graph.adg.nodes:
        node_id = getattr(node, "node_id", None)
        if not isinstance(node_id, str) or not node_id:
            errors.append("ADG node has an empty or invalid ID")
        elif node_id in node_ids:
            errors.append(f"duplicate ADG node ID: {node_id}")
        else:
            node_ids.add(node_id)

    for edge in graph.adg.edges:
        edge_id = getattr(edge, "edge_id", None)
        if not isinstance(edge_id, str) or not edge_id:
            errors.append("ADG edge has an empty or invalid ID")
        elif edge_id in edge_ids:
            errors.append(f"duplicate ADG edge ID: {edge_id}")
        else:
            edge_ids.add(edge_id)

        for endpoint in ("source", "target"):
            referenced = getattr(edge, endpoint, None)
            if referenced not in node_ids:
                errors.append(
                    f"ADG edge {edge_id or '<missing>'} has missing {endpoint}: "
                    f"{referenced!r}"
                )
    return sorted(set(errors))


@dataclass
class PipelineCheckpoints:
    """Ordered, versioned diagnostics for a single repository scan."""

    _completed: list[dict[str, Any]] = field(default_factory=list, init=False)

    def record(
        self,
        stage: str,
        graph: Graph,
        *,
        finding_count: int | None = None,
    ) -> None:
        index = len(self._completed)
        if index >= len(PIPELINE_STAGES) or stage != PIPELINE_STAGES[index]:
            expected = PIPELINE_STAGES[index] if index < len(PIPELINE_STAGES) else "<end>"
            raise ValueError(f"out-of-order pipeline checkpoint: {stage!r}; expected {expected!r}")
        issues: list[str] = []
        if stage in {"normalized", "flows_resolved", "attack_paths", "adg", "findings"}:
            issues.extend(validate_graph_semantics(graph))
        if stage in {"adg", "findings"}:
            issues.extend(validate_adg_integrity(graph))
        if stage == "findings" and finding_count is None:
            raise ValueError("final finding checkpoint requires a finding count")

        record: dict[str, Any] = {
            "stage": stage,
            "agents": len(graph.agents),
            "tools": len(graph.all_tools()),
            "skills": len(graph.all_skills()),
            "mcp_servers": len(graph.all_mcp_servers()),
            "flows": len(graph.flow_paths),
            "attack_paths": len(graph.attack_paths),
            "issues": sorted(set(issues)),
        }
        if finding_count is not None:
            record["findings"] = finding_count
        self._completed.append(record)
        graph.coverage.resolution["analysis_pipeline"] = self.as_dict()

    def as_dict(self) -> dict[str, Any]:
        issues = sum(len(item["issues"]) for item in self._completed)
        return {
            "schema_version": PIPELINE_CONTRACT_VERSION,
            "complete": len(self._completed) == len(PIPELINE_STAGES),
            "valid": issues == 0,
            "issue_count": issues,
            "stages": list(self._completed),
        }

    def assert_valid(self) -> None:
        report = self.as_dict()
        if not report["complete"] or not report["valid"]:
            failures = [
                f"{entry['stage']}: {issue}"
                for entry in self._completed
                for issue in entry["issues"]
            ]
            if not report["complete"]:
                failures.append("pipeline did not reach final findings checkpoint")
            raise ValueError("; ".join(failures))
