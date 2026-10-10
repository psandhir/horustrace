"""Evidence-backed taxonomy for unresolved MCP bindings.

This module classifies *binding* uncertainty. Authority uncertainty on an already-bound
MCP relationship (for example an unknown tool catalogue) remains in mcp_effective.py and
is deliberately not converted into an unresolved binding reason.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from horustrace.models import Graph, MCPServer, SourceLocation
from horustrace.source_context import SOURCE_CONTEXTS, classify_source_context

MCP_UNRESOLVED_REFERENCE_SCHEMA_VERSION = 1

_RESOLUTION_CLASS = {
    "server_not_declared": "resolvable_static",
    "declaration_not_agent_bound": "resolvable_static",
    "cross_file_reference_unlinked": "resolvable_static",
    "name_mismatch": "resolvable_static",
    "scope_reference_unmatched": "resolvable_static",
    "dynamic_server_selection": "evidence_limited",
    "dynamic_tool_filter": "evidence_limited",
    "catalogue_unknown": "evidence_limited",
    "external_configuration": "evidence_limited",
    "framework_semantics_unknown": "evidence_limited",
    "ambiguous_multiple_candidates": "evidence_limited",
    "unsupported_reference_shape": "evidence_limited",
}

_RECOMMENDATIONS = {
    "server_not_declared": (
        "Add or check in the referenced MCP server declaration, or make the "
        "framework binding explicit."
    ),
    "declaration_not_agent_bound": (
        "Reference this declaration from an agent if it is intended to be reachable; "
        "otherwise treat it as unused configuration."
    ),
    "cross_file_reference_unlinked": (
        "Use an explicit import/configuration link that uniquely identifies the "
        "repository-local MCP declaration."
    ),
    "name_mismatch": (
        "Align the explicit MCP reference and declaration names."
    ),
    "scope_reference_unmatched": (
        "Align the referenced MCP tool scope with a statically known server catalogue."
    ),
    "dynamic_server_selection": (
        "Replace runtime-computed MCP server selection with a static declaration or "
        "provide repository-local configuration that HorusTrace can resolve."
    ),
    "dynamic_tool_filter": (
        "Use a static MCP tool allowlist when possible."
    ),
    "catalogue_unknown": (
        "Declare the MCP tool catalogue or an explicit positive allowlist."
    ),
    "external_configuration": (
        "Provide the repository-local configuration that establishes this binding."
    ),
    "framework_semantics_unknown": (
        "Add a supported framework binding pattern or adapter evidence for this reference."
    ),
    "ambiguous_multiple_candidates": (
        "Disambiguate the reference so exactly one static MCP declaration can satisfy it."
    ),
    "unsupported_reference_shape": (
        "Use a statically named MCP reference or a supported repository-local binding shape."
    ),
}


def _location(location: SourceLocation | None) -> dict[str, Any] | None:
    if location is None:
        return None
    return {
        "path": str(location.path),
        "line": location.line,
        "column": location.column,
    }


def _candidate(server: MCPServer) -> dict[str, Any]:
    return {
        "server": server.name,
        "transport": server.transport,
        "destination": server.url or server.command,
        "location": _location(server.location),
    }


def _stable_reference_id(
    *,
    reference_kind: str,
    agent: str | None,
    framework: str,
    server: str,
    transport: str,
    reason: str,
    source: str,
) -> str:
    # Deliberately exclude destination values and source locations. URLs can contain
    # credentials/query material, and checkout paths/line movement must not affect ID.
    payload = json.dumps(
        {
            "reference_kind": reference_kind,
            "agent": agent,
            "framework": framework,
            "server": server,
            "transport": transport,
            "reason": reason,
            "source": source,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"mcp-unresolved-v1:{digest}"


@dataclass(frozen=True, slots=True)
class UnresolvedMCPReference:
    reference_id: str
    reference_kind: str
    agent: str | None
    framework: str
    server: str
    transport: str
    destination: str | None
    reason: str
    resolution_class: str
    source: str
    source_context: str
    location: dict[str, Any] | None
    candidate_declarations: tuple[dict[str, Any], ...]
    evidence_gaps: tuple[str, ...]
    recommendation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "reference_kind": self.reference_kind,
            "agent": self.agent,
            "framework": self.framework,
            "server": self.server,
            "transport": self.transport,
            "destination": self.destination,
            "reason": self.reason,
            "resolution_class": self.resolution_class,
            "source": self.source,
            "source_context": self.source_context,
            "location": self.location,
            "candidate_declarations": list(self.candidate_declarations),
            "evidence_gaps": list(self.evidence_gaps),
            "recommendation": self.recommendation,
            "runtime_effectiveness": "not_verified",
        }


def _reason_for_reference(
    server: MCPServer,
    same_name_candidates: list[MCPServer],
) -> str:
    hint = str(server.metadata.get("context_binding") or "")
    if hint == "dynamic_server_selection":
        return "dynamic_server_selection"
    if hint in {
        "ambiguous_fast_agent_reference",
        "ambiguous_imported_reference",
    }:
        return "ambiguous_multiple_candidates"
    if hint == "missing_fast_agent_declaration":
        return "server_not_declared"
    if hint == "unsupported_import_reference":
        return "unsupported_reference_shape"
    if hint == "unresolved_imported_reference":
        if len(same_name_candidates) > 1:
            return "ambiguous_multiple_candidates"
        if len(same_name_candidates) == 1:
            return "cross_file_reference_unlinked"
        return "server_not_declared"
    if hint == "external_configuration":
        return "external_configuration"
    return "framework_semantics_unknown"


def _evidence_gaps(server: MCPServer, reason: str) -> tuple[str, ...]:
    gaps: set[str] = set()
    if reason == "server_not_declared":
        gaps.add("server_declaration")
    elif reason == "ambiguous_multiple_candidates":
        gaps.add("unique_server_binding")
    elif reason == "cross_file_reference_unlinked":
        gaps.add("repository_linkage")
    elif reason == "dynamic_server_selection":
        gaps.add("static_server_name")
    elif reason == "unsupported_reference_shape":
        gaps.add("supported_reference_shape")
    elif reason == "external_configuration":
        gaps.add("repository_local_configuration")
    elif reason == "framework_semantics_unknown":
        gaps.add("supported_framework_binding_semantics")

    if server.metadata.get("dynamic_mcp_endpoint"):
        gaps.add("static_endpoint")
    if server.metadata.get("dynamic_command"):
        gaps.add("static_command")
    return tuple(sorted(gaps))


def _portable_unique_reference_ids(
    references: list[UnresolvedMCPReference],
) -> list[UnresolvedMCPReference]:
    """Disambiguate identical declaration aliases without absolute-workspace IDs.

    Public IDs stay unchanged for single occurrences; repeated test fixtures
    and repeated server declarations receive source-relative qualifiers.
    """
    counts = Counter(item.reference_id for item in references)
    if all(n == 1 for n in counts.values()):
        return references
    paths = [
        Path(item.location["path"]).resolve()
        for item in references
        if item.location is not None and item.location.get("path")
    ]
    base = (
        Path(os.path.commonpath([str(path.parent) for path in paths]))
        if paths else None
    )
    used: Counter[str] = Counter()
    output: list[UnresolvedMCPReference] = []
    for item in references:
        if counts[item.reference_id] == 1:
            output.append(item)
            continue
        path_text = "<unknown>"
        if item.location and item.location.get("path"):
            path = Path(item.location["path"]).resolve()
            path_text = path.relative_to(base).as_posix() if base else path.name
        qualifier = {
            "source": path_text,
            "line": (item.location or {}).get("line"),
            "column": (item.location or {}).get("column"),
            "reference_kind": item.reference_kind,
            "server": item.server,
        }
        digest = hashlib.sha256(
            json.dumps(qualifier, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:16]
        candidate = f"{item.reference_id}:{digest}"
        used[candidate] += 1
        if used[candidate] > 1:
            candidate = f"{candidate}:{used[candidate]}"
        output.append(replace(item, reference_id=candidate))
    return output


def unresolved_mcp_references(
    graph: Graph, *, root: Path | None = None,
) -> list[UnresolvedMCPReference]:
    """Return deterministic reason records for every unresolved MCP observation."""
    concrete = list(graph.unbound_mcp_servers)
    observations = [
        *graph.unbound_mcp_servers,
        *graph.unresolved_mcp_references,
    ]
    result: list[UnresolvedMCPReference] = []

    for server in observations:
        reference_only = bool(server.metadata.get("reference_only"))
        same_name = [
            candidate
            for candidate in concrete
            if candidate is not server and candidate.name == server.name
        ]

        if reference_only:
            reason = _reason_for_reference(server, same_name)
            reference_kind = "agent_reference"
            agent_value = server.metadata.get("reference_agent")
            agent = str(agent_value) if agent_value else None
            candidates = server.metadata.get("candidate_declarations")
            if isinstance(candidates, list) and candidates:
                candidate_docs = tuple(
                    dict(item) for item in candidates if isinstance(item, dict)
                )
            else:
                candidate_docs = tuple(_candidate(item) for item in same_name)
        else:
            reason = (
                "ambiguous_multiple_candidates"
                if server.metadata.get("context_binding")
                == "ambiguous_fast_agent_reference"
                else "declaration_not_agent_bound"
            )
            reference_kind = "server_declaration"
            agent = None
            candidate_docs = ()

        framework = str(server.metadata.get("framework") or "unknown")
        source = str(server.metadata.get("source") or "unknown")
        resolution_class = _RESOLUTION_CLASS[reason]
        result.append(
            UnresolvedMCPReference(
                reference_id=_stable_reference_id(
                    reference_kind=reference_kind,
                    agent=agent,
                    framework=framework,
                    server=server.name,
                    transport=server.transport,
                    reason=reason,
                    source=source,
                ),
                reference_kind=reference_kind,
                agent=agent,
                framework=framework,
                server=server.name,
                transport=server.transport,
                destination=server.url or server.command,
                reason=reason,
                resolution_class=resolution_class,
                source=source,
                source_context=(
                    str(server.metadata["source_context"])
                    if server.metadata.get("source_context") in SOURCE_CONTEXTS
                    else classify_source_context(
                        server.location.path if server.location is not None else None,
                        root=root,
                    )
                ),
                location=_location(server.location),
                candidate_declarations=tuple(
                    sorted(
                        candidate_docs,
                        key=lambda item: (
                            str(item.get("server") or ""),
                            str(item.get("transport") or ""),
                            str(item.get("destination") or ""),
                            json.dumps(
                                item.get("location") or {},
                                sort_keys=True,
                            ),
                        ),
                    )
                ),
                evidence_gaps=_evidence_gaps(server, reason),
                recommendation=_RECOMMENDATIONS[reason],
            )
        )

    ordered = sorted(
        result,
        key=lambda item: (
            item.reason,
            item.framework,
            item.agent or "",
            item.server,
            item.transport,
            item.reference_id,
            (item.location or {}).get("path") or "",
            (item.location or {}).get("line") or 0,
        ),
    )
    return _portable_unique_reference_ids(ordered)


def unresolved_mcp_summary(
    graph: Graph, *, root: Path | None = None,
) -> dict[str, Any]:
    references = unresolved_mcp_references(graph, root=root)
    reasons = sorted({item.reason for item in references})
    classes = sorted({item.resolution_class for item in references})
    declarations = [
        item for item in references if item.reference_kind == "server_declaration"
    ]
    agent_references = [
        item for item in references if item.reference_kind == "agent_reference"
    ]
    declaration_reasons = sorted({item.reason for item in declarations})
    agent_reasons = sorted({item.reason for item in agent_references})
    return {
        "schema_version": MCP_UNRESOLVED_REFERENCE_SCHEMA_VERSION,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "unresolved_references": len(references),
            "server_declarations": len(declarations),
            "agent_references": len(agent_references),
            "by_source_context": dict(sorted(Counter(
                item.source_context for item in references
            ).items())),
            "by_reason": {
                reason: sum(item.reason == reason for item in references)
                for reason in reasons
            },
            "declaration_by_reason": {
                reason: sum(item.reason == reason for item in declarations)
                for reason in declaration_reasons
            },
            "agent_reference_by_reason": {
                reason: sum(item.reason == reason for item in agent_references)
                for reason in agent_reasons
            },
            "by_resolution_class": {
                resolution_class: sum(
                    item.resolution_class == resolution_class
                    for item in references
                )
                for resolution_class in classes
            },
        },
        "references": [item.as_dict() for item in references],
    }
