"""Change-aware comparison of HorusTrace findings and authority graphs."""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from horustrace.authority_contract import authority_contract_report
from horustrace.authority_delta import compare_effective_authority
from horustrace.authority_policy_delta import compare_authority_contracts
from horustrace.authority_resolution import compare_authority_resolution
from horustrace.config import load_config
from horustrace.git_snapshot import GitSnapshot, materialize_git_ref
from horustrace.models import Finding, Graph, Severity
from horustrace.scanner import scan
from horustrace.security_review import build_security_review
from horustrace.source_context import (
    classify_source_context,
    is_non_runtime_source_context,
)
from horustrace.suppressions import fingerprint

_MAX_CONSOLE_ITEMS = 40


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _finding_record(finding: Finding, root: Path) -> dict[str, Any]:
    value = finding.fingerprint or fingerprint(finding, root)
    location = None
    if finding.location is not None:
        location = {
            "path": _relative_path(finding.location.path, root),
            "line": finding.location.line,
            "column": finding.location.column,
        }
    return {
        "fingerprint": value,
        "rule_id": finding.rule_id,
        "severity": finding.severity.label(),
        "title": finding.title,
        "agent": finding.agent,
        "assessment": finding.assessment,
        "confidence": finding.confidence.value if finding.confidence else None,
        "source_context": finding.source_context,
        "location": location,
        "evidence": sorted(finding.evidence),
    }


def _finding_index(findings: list[Finding], root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for finding in findings:
        record = _finding_record(finding, root)
        result[record["fingerprint"]] = record
    return result


def _finding_semantics(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: record.get(key)
        for key in (
            "rule_id",
            "severity",
            "agent",
            "assessment",
            "confidence",
            "source_context",
            "evidence",
        )
    }


def _record_source_context(record: dict[str, Any]) -> str:
    location = record.get("location") or {}
    path = location.get("path")
    if not isinstance(path, str) or not path:
        return "unknown"
    return classify_source_context(Path(path))


def _authority_node_record(node: dict[str, Any]) -> dict[str, Any]:
    return {
        **node,
        "source_context": _record_source_context(node),
    }


def _context_counts(items: list[dict[str, Any]], *, nested_after: bool = False) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        record = item.get("after", {}) if nested_after else item
        context = str(record.get("source_context") or "unknown")
        counter[context] += 1
    return dict(sorted(counter.items()))


def _contract_missing_record(
    item: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    record = dict(item)
    location = record.get("location")
    if isinstance(location, dict) and isinstance(location.get("path"), str):
        location = dict(location)
        location["path"] = _relative_path(Path(location["path"]), root)
        record["location"] = location
    record["source_context"] = _record_source_context(record)
    return record


def _semantic_node(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": node.get("kind"),
        "name": node.get("name"),
        "framework": node.get("framework"),
        "attributes": node.get("attributes") or {},
    }


def _changed_node_record(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    before_attributes = before.get("attributes") or {}
    after_attributes = after.get("attributes") or {}
    before_capabilities = set(before_attributes.get("capabilities") or [])
    after_capabilities = set(after_attributes.get("capabilities") or [])
    changed_attribute_keys = sorted(
        key
        for key in set(before_attributes) | set(after_attributes)
        if before_attributes.get(key) != after_attributes.get(key)
    )
    return {
        "id": after["id"],
        "kind": after.get("kind"),
        "name": after.get("name"),
        "framework": after.get("framework"),
        "source_context": _record_source_context(after),
        "changed_attributes": changed_attribute_keys,
        "added_capabilities": sorted(after_capabilities - before_capabilities),
        "removed_capabilities": sorted(before_capabilities - after_capabilities),
        "before": _semantic_node(before),
        "after": _semantic_node(after),
    }


def _edge_record(
    edge: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    source = nodes.get(edge.get("source"), {})
    target = nodes.get(edge.get("target"), {})
    context = _record_source_context(edge)
    if context == "unknown":
        source_context = _record_source_context(source)
        target_context = _record_source_context(target)
        if source_context == target_context:
            context = source_context
    return {
        **edge,
        "source_name": source.get("name"),
        "source_kind": source.get("kind"),
        "target_name": target.get("name"),
        "target_kind": target.get("kind"),
        "source_context": context,
    }


def compare_scans(
    base_graph: Graph,
    base_findings: list[Finding],
    base_root: Path,
    head_graph: Graph,
    head_findings: list[Finding],
    head_root: Path,
    *,
    base_ref: str,
    head_ref: str,
    base_commit: str | None = None,
    head_commit: str | None = None,
    base_skipped_entries: int = 0,
    head_skipped_entries: int = 0,
) -> dict[str, Any]:
    """Return a deterministic security delta between two completed scans."""
    base_finding_index = _finding_index(base_findings, base_root)
    head_finding_index = _finding_index(head_findings, head_root)

    base_fingerprints = set(base_finding_index)
    head_fingerprints = set(head_finding_index)
    introduced_ids = sorted(head_fingerprints - base_fingerprints)
    resolved_ids = sorted(base_fingerprints - head_fingerprints)
    common_ids = sorted(base_fingerprints & head_fingerprints)

    introduced = [head_finding_index[item] for item in introduced_ids]
    resolved = [base_finding_index[item] for item in resolved_ids]
    changed_findings = [
        {
            "fingerprint": item,
            "before": base_finding_index[item],
            "after": head_finding_index[item],
        }
        for item in common_ids
        if _finding_semantics(base_finding_index[item])
        != _finding_semantics(head_finding_index[item])
    ]
    worsened_findings = [
        item
        for item in changed_findings
        if Severity.parse(item["after"]["severity"])
        > Severity.parse(item["before"]["severity"])
    ]

    base_adg = base_graph.adg.as_dict() if base_graph.adg else {"nodes": [], "edges": []}
    head_adg = head_graph.adg.as_dict() if head_graph.adg else {"nodes": [], "edges": []}
    base_nodes = {item["id"]: item for item in base_adg.get("nodes", [])}
    head_nodes = {item["id"]: item for item in head_adg.get("nodes", [])}
    base_edges = {item["id"]: item for item in base_adg.get("edges", [])}
    head_edges = {item["id"]: item for item in head_adg.get("edges", [])}

    added_node_ids = sorted(set(head_nodes) - set(base_nodes))
    removed_node_ids = sorted(set(base_nodes) - set(head_nodes))
    common_node_ids = sorted(set(base_nodes) & set(head_nodes))
    changed_nodes = [
        _changed_node_record(base_nodes[item], head_nodes[item])
        for item in common_node_ids
        if _semantic_node(base_nodes[item]) != _semantic_node(head_nodes[item])
    ]

    added_edge_ids = sorted(set(head_edges) - set(base_edges))
    removed_edge_ids = sorted(set(base_edges) - set(head_edges))
    all_nodes = {**base_nodes, **head_nodes}

    added_nodes = [_authority_node_record(head_nodes[item]) for item in added_node_ids]
    removed_nodes = [_authority_node_record(base_nodes[item]) for item in removed_node_ids]
    added_edges = [_edge_record(head_edges[item], all_nodes) for item in added_edge_ids]
    removed_edges = [_edge_record(base_edges[item], all_nodes) for item in removed_edge_ids]

    base_contract_report = authority_contract_report(base_graph)
    head_contract_report = authority_contract_report(head_graph)
    base_missing = {
        item["agent"]: _contract_missing_record(item, base_root)
        for item in base_contract_report["missing_contracts"]
    }
    head_missing = {
        item["agent"]: _contract_missing_record(item, head_root)
        for item in head_contract_report["missing_contracts"]
    }
    introduced_missing_contracts = [
        head_missing[name] for name in sorted(head_missing.keys() - base_missing.keys())
    ]
    resolved_missing_contracts = [
        base_missing[name] for name in sorted(base_missing.keys() - head_missing.keys())
    ]
    base_agent_names = {agent.name for agent in base_graph.agents}
    head_agent_names = {agent.name for agent in head_graph.agents}
    newly_introduced_agent_names = head_agent_names - base_agent_names
    new_agents_without_contract = [
        item
        for item in introduced_missing_contracts
        if item["agent"] in newly_introduced_agent_names
    ]

    authority_delta = compare_effective_authority(
        base_graph,
        base_root,
        head_graph,
        head_root,
    )
    authority_policy_delta = compare_authority_contracts(
        base_graph,
        base_root,
        head_graph,
        head_root,
        authority_delta,
    )
    security_review = build_security_review(authority_delta, authority_policy_delta)
    authority_resolution = compare_authority_resolution(base_graph, head_graph)

    introduced_by_severity = Counter(item["severity"] for item in introduced)
    high_or_critical = sum(
        Severity.parse(item["severity"]) >= Severity.HIGH for item in introduced
    )

    return {
        "schema_version": 2,
        "base": {
            "ref": base_ref,
            "commit": base_commit,
            "coverage_incomplete": base_graph.coverage.incomplete,
            "analysis_incomplete": (
                base_graph.coverage.incomplete or base_skipped_entries > 0
            ),
            "adg_digest": base_graph.adg.canonical_digest() if base_graph.adg else None,
            "skipped_non_regular_git_entries": base_skipped_entries,
        },
        "head": {
            "ref": head_ref,
            "commit": head_commit,
            "coverage_incomplete": head_graph.coverage.incomplete,
            "analysis_incomplete": (
                head_graph.coverage.incomplete or head_skipped_entries > 0
            ),
            "adg_digest": head_graph.adg.canonical_digest() if head_graph.adg else None,
            "skipped_non_regular_git_entries": head_skipped_entries,
        },
        "summary": {
            "introduced_findings": len(introduced),
            "introduced_high_or_critical": high_or_critical,
            "introduced_findings_by_severity": dict(sorted(introduced_by_severity.items())),
            "resolved_findings": len(resolved),
            "changed_findings": len(changed_findings),
            "worsened_findings": len(worsened_findings),
            "unchanged_findings": len(common_ids) - len(changed_findings),
            "added_authority_nodes": len(added_node_ids),
            "removed_authority_nodes": len(removed_node_ids),
            "changed_authority_nodes": len(changed_nodes),
            "added_authority_edges": len(added_edge_ids),
            "removed_authority_edges": len(removed_edge_ids),
            "added_authority_relationships": authority_delta["summary"]["added_relationships"],
            "removed_authority_relationships": authority_delta["summary"]["removed_relationships"],
            "changed_authority_relationships": authority_delta["summary"]["changed_relationships"],
            "expanded_authority_relationships": authority_delta["summary"]["expanded_relationships"],
            "trust_boundary_crossings": authority_delta["summary"]["trust_boundary_crossings"],
            "expanded_or_weakened_boundary_crossings": authority_delta["summary"][
                "expanded_or_weakened_boundary_crossings"
            ],
            "expanded_boundary_crossings_by_family": authority_delta["summary"][
                "expanded_boundary_crossings_by_family"
            ],
            "weakened_boundary_crossings_by_family": authority_delta["summary"][
                "weakened_boundary_crossings_by_family"
            ],
            "base_policy_violations": authority_policy_delta["summary"][
                "base_violations"
            ],
            "head_policy_violations": authority_policy_delta["summary"][
                "head_violations"
            ],
            "introduced_policy_violations": authority_policy_delta["summary"][
                "introduced_violations"
            ],
            "resolved_policy_violations": authority_policy_delta["summary"][
                "resolved_violations"
            ],
            "introduced_policy_unresolved": authority_policy_delta["summary"][
                "introduced_unresolved"
            ],
            "authority_contract_changes": authority_policy_delta["summary"][
                "contract_changes"
            ],
            "authority_contract_weakenings": authority_policy_delta["summary"][
                "contract_weakenings"
            ],
            "authority_contract_strengthenings": authority_policy_delta["summary"][
                "contract_strengthenings"
            ],
            "base_agents_without_contract": base_contract_report["summary"][
                "agents_without_contract"
            ],
            "head_agents_without_contract": head_contract_report["summary"][
                "agents_without_contract"
            ],
            "introduced_missing_contracts": len(introduced_missing_contracts),
            "resolved_missing_contracts": len(resolved_missing_contracts),
            "new_agents_without_contract": len(new_agents_without_contract),
            "base_unresolved_authority_relationships": authority_resolution["base"][
                "unresolved_relationships"
            ],
            "head_unresolved_authority_relationships": authority_resolution["head"][
                "unresolved_relationships"
            ],
            "authority_resolution_regressed": authority_resolution["regressed"],
        },
        "findings": {
            "introduced": introduced,
            "resolved": resolved,
            "changed": changed_findings,
            "worsened": worsened_findings,
        },
        "authority": {
            "added_nodes": added_nodes,
            "removed_nodes": removed_nodes,
            "changed_nodes": changed_nodes,
            "added_edges": added_edges,
            "removed_edges": removed_edges,
        },
        "effective_authority_delta": authority_delta,
        "authority_policy_delta": authority_policy_delta,
        "authority_contract_coverage": {
            "base": {
                "total_agents": base_contract_report["summary"]["total_agents"],
                "agents_with_contract": base_contract_report["summary"]["agents_with_contract"],
                "agents_without_contract": base_contract_report["summary"]["agents_without_contract"],
                "contract_coverage_percent": base_contract_report["summary"][
                    "contract_coverage_percent"
                ],
            },
            "head": {
                "total_agents": head_contract_report["summary"]["total_agents"],
                "agents_with_contract": head_contract_report["summary"]["agents_with_contract"],
                "agents_without_contract": head_contract_report["summary"]["agents_without_contract"],
                "contract_coverage_percent": head_contract_report["summary"][
                    "contract_coverage_percent"
                ],
            },
            "introduced_missing_contracts": introduced_missing_contracts,
            "resolved_missing_contracts": resolved_missing_contracts,
            "new_agents_without_contract": new_agents_without_contract,
        },
        "security_review": security_review,
        "authority_resolution": authority_resolution,
        "context_summary": {
            "introduced_findings": _context_counts(introduced),
            "worsened_findings": _context_counts(
                worsened_findings,
                nested_after=True,
            ),
            "added_authority_nodes": _context_counts(added_nodes),
            "removed_authority_nodes": _context_counts(removed_nodes),
            "changed_authority_nodes": _context_counts(changed_nodes),
            "added_authority_edges": _context_counts(added_edges),
            "removed_authority_edges": _context_counts(removed_edges),
            "expanded_authority_relationships": _context_counts(
                authority_delta["expansions"]
            ),
        },
    }


def build_git_diff(repo: Path, base_ref: str, head_ref: str) -> dict[str, Any]:
    """Materialize and scan two Git revisions, then compare their security models."""
    with ExitStack() as stack:
        base_snapshot: GitSnapshot = stack.enter_context(
            materialize_git_ref(repo, base_ref)
        )
        head_snapshot: GitSnapshot = stack.enter_context(
            materialize_git_ref(repo, head_ref)
        )

        base_config = load_config(base_snapshot.root, None)
        head_config = load_config(head_snapshot.root, None)
        base_graph, base_findings = scan(
            base_snapshot.root,
            use_default_suppressions=False,
            config=base_config,
        )
        head_graph, head_findings = scan(
            head_snapshot.root,
            use_default_suppressions=False,
            config=head_config,
        )
        return compare_scans(
            base_graph,
            base_findings,
            base_snapshot.root,
            head_graph,
            head_findings,
            head_snapshot.root,
            base_ref=base_ref,
            head_ref=head_ref,
            base_commit=base_snapshot.commit,
            head_commit=head_snapshot.commit,
            base_skipped_entries=base_snapshot.skipped_non_regular_entries,
            head_skipped_entries=head_snapshot.skipped_non_regular_entries,
        )


def _format_location(record: dict[str, Any]) -> str:
    location = record.get("location")
    if not location:
        return ""
    return f" {location['path']}:{location['line']}"


def _relationship_label(item: dict[str, Any]) -> str:
    target = item.get("target") or {}
    return (
        f"{item.get('agent') or '<unknown>'} -> "
        f"{target.get('kind') or 'target'}:{target.get('name') or '<unknown>'}"
    )


def _expansion_added_capabilities(item: dict[str, Any]) -> list[str]:
    capabilities = item.get("capabilities")
    if isinstance(capabilities, dict):
        return list(capabilities.get("added") or [])
    if isinstance(capabilities, list):
        return list(capabilities)
    return []


def _location_label(location: dict[str, Any] | None) -> str:
    if not location:
        return "<unknown>"
    path = location.get("path") or "<unknown>"
    line = location.get("line")
    column = location.get("column")
    suffix = f":{line}" if line else ""
    if line and column:
        suffix += f":{column}"
    return f"{path}{suffix}"


def render_console(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "HorusTrace Change Analysis",
        "=" * 32,
        f"Base: {report['base']['ref']} ({(report['base']['commit'] or 'unknown')[:12]})",
        f"Head: {report['head']['ref']} ({(report['head']['commit'] or 'unknown')[:12]})",
        "",
        "Summary",
        (
            f"  Introduced findings: {summary['introduced_findings']} "
            f"({summary['introduced_high_or_critical']} high/critical)"
        ),
        f"  Resolved findings:   {summary['resolved_findings']}",
        (
            f"  Changed findings:    {summary['changed_findings']} "
            f"({summary['worsened_findings']} worsened)"
        ),
        (
            f"  Authority nodes:     +{summary['added_authority_nodes']} "
            f"-{summary['removed_authority_nodes']} "
            f"~{summary['changed_authority_nodes']}"
        ),
        (
            f"  Authority edges:     +{summary['added_authority_edges']} "
            f"-{summary['removed_authority_edges']}"
        ),
        (
            f"  Effective authority: +{summary['added_authority_relationships']} "
            f"-{summary['removed_authority_relationships']} "
            f"~{summary['changed_authority_relationships']} "
            f"({summary['expanded_authority_relationships']} expanded)"
        ),
        (
            f"  Trust boundaries:    {summary['trust_boundary_crossings']} crossings "
            f"({summary['expanded_or_weakened_boundary_crossings']} expanded/weakened)"
        ),
        (
            f"  Authority policy:    base={summary['base_policy_violations']} "
            f"head={summary['head_policy_violations']} "
            f"+{summary['introduced_policy_violations']} "
            f"-{summary['resolved_policy_violations']} "
            f"({summary['authority_contract_weakenings']} policy weakenings; "
            f"{summary['introduced_policy_unresolved']} new unresolved)"
        ),
        (
            f"  Contract coverage:   base={report['authority_contract_coverage']['base']['contract_coverage_percent']}% "
            f"head={report['authority_contract_coverage']['head']['contract_coverage_percent']}% "
            f"({summary['head_agents_without_contract']} head agents missing; "
            f"{summary['new_agents_without_contract']} newly introduced)"
        ),
        (
            "  Analysis: "
            f"base={'incomplete' if report['base']['analysis_incomplete'] else 'complete'}, "
            f"head={'incomplete' if report['head']['analysis_incomplete'] else 'complete'}"
        ),
    ]

    policy_weakenings = report["authority_policy_delta"]["contract_weakenings"]
    if policy_weakenings:
        lines.extend(["", "Authority Contract weakenings"])
        for item in policy_weakenings[:_MAX_CONSOLE_ITEMS]:
            policy_location = _location_label(item.get("contract_location"))
            before = ",".join(item.get("before") or []) or "<none>"
            after = ",".join(item.get("after") or []) or "<none>"
            lines.append(
                f"  ! agent={item['agent']} clause={item['clause']} "
                f"change={item['change']} before={before} after={after} "
                f"policy={policy_location}"
            )
        if len(policy_weakenings) > _MAX_CONSOLE_ITEMS:
            lines.append(
                f"  ... {len(policy_weakenings) - _MAX_CONSOLE_ITEMS} more policy weakenings"
            )

    new_agents_missing_contract = report["authority_contract_coverage"][
        "new_agents_without_contract"
    ]
    introduced_missing_contracts = report["authority_contract_coverage"][
        "introduced_missing_contracts"
    ]
    if introduced_missing_contracts:
        lines.extend(["", "Introduced missing Authority Contracts"])
        new_names = {item["agent"] for item in new_agents_missing_contract}
        for item in introduced_missing_contracts[:_MAX_CONSOLE_ITEMS]:
            marker = "new agent" if item["agent"] in new_names else "contract removed"
            lines.append(
                f"  ! agent={item['agent']} status={item['status']} "
                f"reason={item['reason']} ({marker}){_format_location(item)}"
            )
        if len(introduced_missing_contracts) > _MAX_CONSOLE_ITEMS:
            lines.append(
                f"  ... {len(introduced_missing_contracts) - _MAX_CONSOLE_ITEMS} "
                "more missing contracts"
            )

    introduced_policy = report["authority_policy_delta"]["introduced_violations"]
    if introduced_policy:
        lines.extend(["", "Introduced Authority Contract violations"])
        for item in introduced_policy[:_MAX_CONSOLE_ITEMS]:
            observed = ",".join(item.get("observed") or []) or "<none>"
            policy_location = _location_label(item.get("contract_location"))
            authority_location = _location_label(item.get("relationship_location"))
            lines.append(
                f"  ! {_relationship_label(item)} clause={item['clause']} "
                f"reason={item['reason']} observed={observed} "
                f"policy={policy_location} authority={authority_location}"
            )
        if len(introduced_policy) > _MAX_CONSOLE_ITEMS:
            lines.append(
                f"  ... {len(introduced_policy) - _MAX_CONSOLE_ITEMS} more policy violations"
            )

    introduced_unresolved = report["authority_policy_delta"]["introduced_unresolved"]
    if introduced_unresolved:
        lines.extend(["", "Introduced unresolved Authority Contract assessments"])
        for item in introduced_unresolved[:_MAX_CONSOLE_ITEMS]:
            policy_location = _location_label(item.get("contract_location"))
            authority_location = _location_label(item.get("relationship_location"))
            lines.append(
                f"  ? {_relationship_label(item)} clause={item['clause']} "
                f"reason={item['reason']} policy={policy_location} "
                f"authority={authority_location}"
            )
        if len(introduced_unresolved) > _MAX_CONSOLE_ITEMS:
            lines.append(
                f"  ... {len(introduced_unresolved) - _MAX_CONSOLE_ITEMS} more unresolved assessments"
            )

    introduced = report["findings"]["introduced"]
    if introduced:
        lines.extend(["", "Introduced findings"])
        for item in introduced[:_MAX_CONSOLE_ITEMS]:
            agent = f" agent={item['agent']}" if item.get("agent") else ""
            lines.append(
                f"  + [{item['severity']}] {item['rule_id']}{agent}"
                f"{_format_location(item)} — {item['title']}"
            )
        if len(introduced) > _MAX_CONSOLE_ITEMS:
            lines.append(
                f"  ... {len(introduced) - _MAX_CONSOLE_ITEMS} more introduced findings"
            )

    added_nodes = report["authority"]["added_nodes"]
    changed_nodes = report["authority"]["changed_nodes"]
    if added_nodes or changed_nodes:
        lines.extend(["", "Authority changes"])
        for item in added_nodes[:_MAX_CONSOLE_ITEMS]:
            capabilities = item.get("attributes", {}).get("capabilities") or []
            suffix = f" capabilities={','.join(capabilities)}" if capabilities else ""
            lines.append(f"  + {item['kind']} {item['name']}{suffix}")
        remaining = max(0, _MAX_CONSOLE_ITEMS - min(len(added_nodes), _MAX_CONSOLE_ITEMS))
        for item in changed_nodes[:remaining]:
            detail = ""
            if item["added_capabilities"]:
                detail = f" +capabilities={','.join(item['added_capabilities'])}"
            lines.append(f"  ~ {item['kind']} {item['name']}{detail}")
        total = len(added_nodes) + len(changed_nodes)
        if total > _MAX_CONSOLE_ITEMS:
            lines.append(f"  ... {total - _MAX_CONSOLE_ITEMS} more authority changes")

    boundary_changes = [
        item
        for item in report["effective_authority_delta"]["changed"]
        if item.get("trust_boundary_crossings")
    ]
    if boundary_changes:
        lines.extend(["", "Trust boundary crossings"])
        emitted = 0
        for item in boundary_changes:
            for crossing in item.get("trust_boundary_crossings", []):
                if emitted >= _MAX_CONSOLE_ITEMS:
                    break
                lines.append(
                    f"  ~ {_relationship_label(item)} "
                    f"{crossing['family']}:{crossing['before']}->{crossing['after']} "
                    f"[{crossing['direction']}]"
                )
                emitted += 1
            if emitted >= _MAX_CONSOLE_ITEMS:
                break
        total_crossings = sum(
            len(item.get("trust_boundary_crossings", []))
            for item in boundary_changes
        )
        if total_crossings > _MAX_CONSOLE_ITEMS:
            lines.append(
                f"  ... {total_crossings - _MAX_CONSOLE_ITEMS} more boundary crossings"
            )

    expansions = report["effective_authority_delta"]["expansions"]
    if expansions:
        lines.extend(["", "Effective authority expansions"])
        for item in expansions[:_MAX_CONSOLE_ITEMS]:
            reasons = ",".join(item.get("expansion_reasons") or [])
            capabilities = _expansion_added_capabilities(item)
            cap_suffix = (
                f" +capabilities={','.join(capabilities)}"
                if capabilities
                else ""
            )
            lines.append(
                f"  ! {_relationship_label(item)} reasons={reasons}{cap_suffix}"
            )
        if len(expansions) > _MAX_CONSOLE_ITEMS:
            lines.append(
                f"  ... {len(expansions) - _MAX_CONSOLE_ITEMS} more authority expansions"
            )

    return "\n".join(lines)


def _markdown_location(record: dict[str, Any]) -> str:
    location = record.get("location")
    if not location:
        return ""
    path = location.get("path")
    line = location.get("line")
    if not path:
        return ""
    suffix = f":{line}" if line else ""
    return f" `{path}{suffix}`"


def _split_context(
    items: list[dict[str, Any]],
    *,
    nested_after: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    application: list[dict[str, Any]] = []
    non_runtime: list[dict[str, Any]] = []
    for item in items:
        record = item.get("after", {}) if nested_after else item
        context = str(record.get("source_context") or "unknown")
        target = non_runtime if is_non_runtime_source_context(context) else application
        target.append(item)
    return application, non_runtime


def _render_markdown_findings(
    lines: list[str],
    title: str,
    introduced: list[dict[str, Any]],
    worsened: list[dict[str, Any]],
) -> None:
    if not introduced and not worsened:
        return
    lines.extend(["", f"### {title}", ""])
    for item in introduced[:_MAX_CONSOLE_ITEMS]:
        context = item.get("source_context") or "unknown"
        agent = f"; agent `{item['agent']}`" if item.get("agent") else ""
        lines.append(
            f"- **{item['severity'].upper()} {item['rule_id']}** — "
            f"{item['title']}{_markdown_location(item)} "
            f"(context `{context}`{agent})"
        )
    for item in worsened[:_MAX_CONSOLE_ITEMS]:
        before = item["before"]
        after = item["after"]
        context = after.get("source_context") or "unknown"
        lines.append(
            f"- **{before['severity'].upper()} → {after['severity'].upper()} "
            f"{after['rule_id']}** — {after['title']}{_markdown_location(after)} "
            f"(context `{context}`)"
        )
    total = len(introduced) + len(worsened)
    if total > _MAX_CONSOLE_ITEMS:
        lines.append(f"- … {total - _MAX_CONSOLE_ITEMS} more finding changes")


def _render_markdown_authority(
    lines: list[str],
    title: str,
    added_nodes: list[dict[str, Any]],
    changed_nodes: list[dict[str, Any]],
    added_edges: list[dict[str, Any]],
) -> None:
    if not added_nodes and not changed_nodes and not added_edges:
        return
    lines.extend(["", f"### {title}", ""])
    emitted = 0
    for item in added_nodes:
        if emitted >= _MAX_CONSOLE_ITEMS:
            break
        context = item.get("source_context") or "unknown"
        capabilities = item.get("attributes", {}).get("capabilities") or []
        suffix = f"; capabilities `{', '.join(capabilities)}`" if capabilities else ""
        lines.append(
            f"- **Added {item['kind']}** `{item['name']}` "
            f"(context `{context}`{suffix})"
        )
        emitted += 1
    for item in changed_nodes:
        if emitted >= _MAX_CONSOLE_ITEMS:
            break
        context = item.get("source_context") or "unknown"
        changes = ", ".join(item.get("changed_attributes") or []) or "attributes"
        capabilities = item.get("added_capabilities") or []
        suffix = f"; added capabilities `{', '.join(capabilities)}`" if capabilities else ""
        lines.append(
            f"- **Changed {item['kind']}** `{item['name']}` — {changes} "
            f"(context `{context}`{suffix})"
        )
        emitted += 1
    for item in added_edges:
        if emitted >= _MAX_CONSOLE_ITEMS:
            break
        context = item.get("source_context") or "unknown"
        lines.append(
            f"- **Added {item['kind']}** "
            f"`{item.get('source_name') or item['source']}` → "
            f"`{item.get('target_name') or item['target']}` "
            f"(context `{context}`)"
        )
        emitted += 1
    total = len(added_nodes) + len(changed_nodes) + len(added_edges)
    if total > _MAX_CONSOLE_ITEMS:
        lines.append(f"- … {total - _MAX_CONSOLE_ITEMS} more authority changes")


def _render_markdown_policy_delta(
    lines: list[str],
    report: dict[str, Any],
) -> None:
    policy = report["authority_policy_delta"]
    introduced = policy["introduced_violations"]
    resolved = policy["resolved_violations"]
    unresolved = policy["introduced_unresolved"]
    weakenings = policy["contract_weakenings"]

    if weakenings:
        lines.extend(["", "### Authority Contract weakenings", ""])
        for item in weakenings[:_MAX_CONSOLE_ITEMS]:
            before = ", ".join(item.get("before") or []) or "<none>"
            after = ", ".join(item.get("after") or []) or "<none>"
            policy_location = _location_label(item.get("contract_location"))
            lines.append(
                f"- **Policy weakened** agent `{item['agent']}` — "
                f"clause `{item['clause']}` at `{policy_location}`; "
                f"change `{item['change']}`; "
                f"before `{before}`; after `{after}`"
            )

    if introduced:
        lines.extend(["", "### Introduced Authority Contract violations", ""])
        for item in introduced[:_MAX_CONSOLE_ITEMS]:
            expected = ", ".join(item.get("expected") or []) or "<none>"
            observed = ", ".join(item.get("observed") or []) or "<none>"
            context = item.get("source_context") or "unknown"
            policy_location = _location_label(item.get("contract_location"))
            authority_location = _location_label(item.get("relationship_location"))
            lines.append(
                f"- **Policy violation** `{_relationship_label(item)}` — "
                f"clause `{item['clause']}` at `{policy_location}`; "
                f"reason `{item['reason']}`; expected `{expected}`; "
                f"observed `{observed}`; authority source "
                f"`{authority_location}` (context `{context}`)"
            )
    if resolved:
        lines.extend(["", "### Resolved Authority Contract violations", ""])
        for item in resolved[:_MAX_CONSOLE_ITEMS]:
            context = item.get("source_context") or "unknown"
            policy_location = _location_label(item.get("contract_location"))
            lines.append(
                f"- **Resolved policy violation** `{_relationship_label(item)}` — "
                f"clause `{item['clause']}` at `{policy_location}`; "
                f"reason `{item['reason']}` (context `{context}`)"
            )
    if unresolved:
        lines.extend(["", "### Introduced unresolved Authority Contract assessments", ""])
        lines.append(
            "These are not policy violations and do not fail the policy gate."
        )
        for item in unresolved[:_MAX_CONSOLE_ITEMS]:
            context = item.get("source_context") or "unknown"
            policy_location = _location_label(item.get("contract_location"))
            authority_location = _location_label(item.get("relationship_location"))
            lines.append(
                f"- **Unresolved** `{_relationship_label(item)}` — "
                f"clause `{item['clause']}` at `{policy_location}`; "
                f"reason `{item['reason']}`; authority source "
                f"`{authority_location}` (context `{context}`)"
            )


def _render_markdown_boundary_crossings(
    lines: list[str],
    title: str,
    changes: list[dict[str, Any]],
) -> None:
    crossings = [
        (item, crossing)
        for item in changes
        for crossing in item.get("trust_boundary_crossings", [])
    ]
    if not crossings:
        return
    lines.extend(["", f"### {title}", ""])
    for item, crossing in crossings[:_MAX_CONSOLE_ITEMS]:
        context = item.get("source_context") or "unknown"
        lines.append(
            f"- **{crossing['direction'].replace('_', ' ').title()} "
            f"{crossing['family']} boundary** "
            f"`{_relationship_label(item)}` — "
            f"`{crossing['before']}` → `{crossing['after']}` "
            f"(context `{context}`)"
        )
    if len(crossings) > _MAX_CONSOLE_ITEMS:
        lines.append(
            f"- … {len(crossings) - _MAX_CONSOLE_ITEMS} more trust-boundary crossings"
        )


def _render_markdown_authority_expansions(
    lines: list[str],
    title: str,
    expansions: list[dict[str, Any]],
) -> None:
    if not expansions:
        return
    lines.extend(["", f"### {title}", ""])
    for item in expansions[:_MAX_CONSOLE_ITEMS]:
        context = item.get("source_context") or "unknown"
        reasons = ", ".join(item.get("expansion_reasons") or []) or "authority changed"
        capabilities = _expansion_added_capabilities(item)
        capability_suffix = (
            f"; added capabilities `{', '.join(capabilities)}`"
            if capabilities
            else ""
        )
        lines.append(
            f"- **Authority expanded** `{_relationship_label(item)}` — "
            f"{reasons} (context `{context}`{capability_suffix})"
        )
    if len(expansions) > _MAX_CONSOLE_ITEMS:
        lines.append(
            f"- … {len(expansions) - _MAX_CONSOLE_ITEMS} more authority expansions"
        )


def render_markdown(report: dict[str, Any]) -> str:
    """Render a concise GitHub-friendly security delta."""
    summary = report["summary"]
    lines = [
        "# HorusTrace Security Delta",
        "",
        (
            f"Base: `{report['base']['ref']}` "
            f"(`{(report['base']['commit'] or 'unknown')[:12]}`)"
        ),
        (
            f"Head: `{report['head']['ref']}` "
            f"(`{(report['head']['commit'] or 'unknown')[:12]}`)"
        ),
        "",
    ]
    if report["base"]["analysis_incomplete"] or report["head"]["analysis_incomplete"]:
        lines.extend(
            [
                (
                    "> **Analysis incomplete.** The absence of a reported change is not "
                    "proof that no security-relevant change exists."
                ),
                "",
            ]
        )

    lines.extend(
        [
            "| Security delta | Count |",
            "|---|---:|",
            f"| Introduced findings | {summary['introduced_findings']} |",
            f"| Introduced high/critical | {summary['introduced_high_or_critical']} |",
            f"| Worsened findings | {summary['worsened_findings']} |",
            f"| Resolved findings | {summary['resolved_findings']} |",
            f"| Added authority nodes | {summary['added_authority_nodes']} |",
            f"| Changed authority nodes | {summary['changed_authority_nodes']} |",
            f"| Added authority edges | {summary['added_authority_edges']} |",
            (
                f"| Expanded effective-authority relationships | "
                f"{summary['expanded_authority_relationships']} |"
            ),
            f"| Trust-boundary crossings | {summary['trust_boundary_crossings']} |",
            (
                f"| Expanded/weakened trust boundaries | "
                f"{summary['expanded_or_weakened_boundary_crossings']} |"
            ),
            f"| Base Authority Contract violations | {summary['base_policy_violations']} |",
            f"| Head Authority Contract violations | {summary['head_policy_violations']} |",
            f"| Introduced Authority Contract violations | {summary['introduced_policy_violations']} |",
            f"| Resolved Authority Contract violations | {summary['resolved_policy_violations']} |",
            f"| Authority Contract changes | {summary['authority_contract_changes']} |",
            f"| Authority Contract weakenings | {summary['authority_contract_weakenings']} |",
            f"| Authority Contract strengthenings | {summary['authority_contract_strengthenings']} |",
            f"| Introduced unresolved contract assessments | {summary['introduced_policy_unresolved']} |",
        ]
    )

    review = report.get("security_review", {"items": []})
    if review.get("items"):
        lines.extend(["", "## Security impact review"])
        for item in review["items"]:
            if item["kind"] == "policy_weakening":
                weakening = item["policy_weakening"]
                lines.append(
                    f"- **{item.get('agent') or '<unknown>'}**: Authority Contract "
                    f"weakened — clause `{weakening.get('clause')}`, "
                    f"change `{weakening.get('change')}`."
                )
                continue
            target = item.get("target") or {}
            lines.append(
                f"- **{item.get('agent') or '<unknown>'} → "
                f"{target.get('kind') or 'target'}:{target.get('name') or '<unknown>'}**"
            )
            reasons = item.get("expansion_reasons") or []
            if reasons:
                formatted_reasons = ", ".join(f"`{reason}`" for reason in reasons)
                lines.append(f"  - Authority expansion: {formatted_reasons}")
            for crossing in item.get("trust_boundary_crossings") or []:
                lines.append(
                    f"  - Trust boundary: **{crossing.get('direction')} "
                    f"{crossing.get('family')}** — `{crossing.get('before')}` → "
                    f"`{crossing.get('after')}`"
                )
            for violation in item.get("policy_violations") or []:
                lines.append(
                    f"  - Authority Contract: **VIOLATION** — clause "
                    f"`{violation.get('clause')}`, reason `{violation.get('reason')}`"
                )
            lines.append("  - Runtime effectiveness: `not_verified`")

    _render_markdown_policy_delta(lines, report)

    runtime_introduced, nonruntime_introduced = _split_context(
        report["findings"]["introduced"]
    )
    runtime_worsened, nonruntime_worsened = _split_context(
        report["findings"]["worsened"],
        nested_after=True,
    )
    runtime_added_nodes, nonruntime_added_nodes = _split_context(
        report["authority"]["added_nodes"]
    )
    runtime_changed_nodes, nonruntime_changed_nodes = _split_context(
        report["authority"]["changed_nodes"]
    )
    runtime_added_edges, nonruntime_added_edges = _split_context(
        report["authority"]["added_edges"]
    )
    runtime_expansions, nonruntime_expansions = _split_context(
        report["effective_authority_delta"]["expansions"]
    )
    boundary_changes = [
        item
        for item in report["effective_authority_delta"]["changed"]
        if item.get("trust_boundary_crossings")
    ]
    runtime_boundary_changes, nonruntime_boundary_changes = _split_context(
        boundary_changes
    )

    _render_markdown_boundary_crossings(
        lines,
        "Application/runtime trust-boundary crossings",
        runtime_boundary_changes,
    )
    _render_markdown_authority_expansions(
        lines,
        "Application/runtime effective authority expansions",
        runtime_expansions,
    )
    _render_markdown_findings(
        lines,
        "Application/runtime finding changes",
        runtime_introduced,
        runtime_worsened,
    )
    _render_markdown_authority(
        lines,
        "Application/runtime authority changes",
        runtime_added_nodes,
        runtime_changed_nodes,
        runtime_added_edges,
    )
    _render_markdown_boundary_crossings(
        lines,
        "Non-runtime trust-boundary crossings",
        nonruntime_boundary_changes,
    )
    _render_markdown_authority_expansions(
        lines,
        "Non-runtime effective authority expansions",
        nonruntime_expansions,
    )
    _render_markdown_findings(
        lines,
        "Non-runtime finding changes",
        nonruntime_introduced,
        nonruntime_worsened,
    )
    _render_markdown_authority(
        lines,
        "Non-runtime authority changes",
        nonruntime_added_nodes,
        nonruntime_changed_nodes,
        nonruntime_added_edges,
    )

    if (
        not report["findings"]["introduced"]
        and not report["findings"]["worsened"]
        and not report["authority"]["added_nodes"]
        and not report["authority"]["changed_nodes"]
        and not report["authority"]["added_edges"]
        and not report["effective_authority_delta"]["expansions"]
        and not boundary_changes
        and not report["authority_policy_delta"]["introduced_violations"]
        and not report["authority_policy_delta"]["contract_weakenings"]
        and not report["authority_policy_delta"]["introduced_unresolved"]
    ):
        lines.extend(["", "No introduced or worsened security delta was detected."])

    return "\n".join(lines) + "\n"

