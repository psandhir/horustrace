"""Self-contained visual security report for HorusTrace scans.

The report is deliberately presentation-only. Security conclusions are produced by
the existing scanner, Effective Authority, Authority Contract, ASG, and OWASP
models; this module projects those results into a portable offline HTML document.
"""
from __future__ import annotations

import json
from collections import Counter
from html import escape
from pathlib import Path
from typing import Any

from horustrace.assurance import build_assurance_report
from horustrace.authority_contract import authority_contract_report
from horustrace.effective_authority import effective_authority_report
from horustrace.models import Finding, Graph
from horustrace.owasp import build_owasp_agentic_summary
from horustrace.provenance import context as provenance_context
from horustrace.security_graph import build_agent_security_graph

VISUAL_REPORT_SCHEMA_VERSION = 1
VISUAL_REPORT_MODEL = "horustrace.visual_report"


def _relative_path(value: str, root: Path) -> str:
    path = Path(value)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def _relativize(value: Any, root: Path) -> Any:
    if isinstance(value, list):
        return [_relativize(item, root) for item in value]
    if isinstance(value, tuple):
        return [_relativize(item, root) for item in value]
    if not isinstance(value, dict):
        return value
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key == "path" and isinstance(item, str):
            result[key] = _relative_path(item, root)
        else:
            result[key] = _relativize(item, root)
    return result


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(item.severity.label() for item in findings)
    return {
        level: counts[level]
        for level in ("critical", "high", "medium", "low", "info")
    }


def _agent_location(agent: Any, root: Path) -> dict[str, Any] | None:
    if agent.location is None:
        return None
    return {
        "path": _relative_path(str(agent.location.path), root),
        "line": agent.location.line,
        "column": agent.location.column,
    }



def _component_location(location: Any, root: Path) -> dict[str, Any] | None:
    if location is None:
        return None
    return {
        "path": _relative_path(str(location.path), root),
        "line": location.line,
        "column": location.column,
    }


def _component_resources(resources: list[Any]) -> list[dict[str, Any]]:
    return [
        {"kind": r.kind, "selector": r.selector, "access": sorted(r.access)}
        for r in resources
    ]


def _component_inventories(graph: Graph, root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Inventory *instances*, not distinct names, preserving bound/unbound state.

    Agent attribution is only asserted for explicitly bound objects. We do not
    infer that every finding on an agent applies to all its connected tools.
    """
    tools: list[dict[str, Any]] = []
    servers: list[dict[str, Any]] = []

    def add_tool(item: Any, agent: str | None) -> None:
        tools.append({
            "name": item.name,
            "kind": item.kind,
            "binding_state": "bound" if agent else "unbound",
            "bound_agents": [agent] if agent else [],
            "location": _component_location(item.location, root),
            "capabilities": sorted(item.capabilities),
            "approval": item.approval,
            "guardrails": item.guardrails,
            "identity": item.identity,
            "resources": _component_resources(item.resources),
            "destinations": [d.target for d in item.destinations],
        })

    def add_server(item: Any, agent: str | None, unresolved: bool = False) -> None:
        servers.append({
            "name": item.name,
            "transport": item.transport,
            "binding_state": (
                "unresolved_reference" if unresolved else ("bound" if agent else "unbound")
            ),
            "bound_agents": [agent] if agent else [],
            "location": _component_location(item.location, root),
            # Avoid embedding URL query strings or execution arguments in the HTML.
            "endpoint": item.url.split("?", 1)[0].split("#", 1)[0] if item.url else None,
            "command": item.command,
            "authenticated": item.authenticated,
            "approval": item.approval,
            "guardrails": item.guardrails,
            "allowed_tools": sorted(item.allowed_tools),
            "denied_tools": sorted(item.denied_tools),
            "identity": item.identity,
            "resources": _component_resources(item.resources),
        })

    for agent in graph.agents:
        for tool in agent.tools:
            add_tool(tool, agent.name)
        for server in agent.mcp_servers:
            add_server(server, agent.name)
    for tool in graph.unbound_tools:
        add_tool(tool, None)
    for server in graph.unbound_mcp_servers:
        add_server(server, None)
    for server in graph.unresolved_mcp_references:
        add_server(server, None, unresolved=True)

    def finish(items: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
        items.sort(key=lambda item: (
            item["name"],
            (item.get("location") or {}).get("path", ""),
            (item.get("location") or {}).get("line", 0),
            item["bound_agents"],
            item["binding_state"],
        ))
        for index, item in enumerate(items):
            item["id"] = f"{prefix}-{index}"
        return items

    return finish(tools, "tool"), finish(servers, "mcp")


def _write_capable(relationship: dict[str, Any]) -> bool:
    markers = ("write", "create", "update", "delete", "admin", "execute", "shell", "mutation")
    values: list[str] = [str(item) for item in relationship.get("capabilities", [])]
    for resource in relationship.get("resources", []):
        values.extend(str(item) for item in resource.get("access", []))
    mutation = relationship.get("semantics", {}).get("mutation")
    if mutation:
        values.append(str(mutation))
    return any(marker in value.lower() for value in values for marker in markers)


def _attack_path_view(
    path: dict[str, Any],
    *,
    agent_name: str,
    flows_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Project an attack path into an explicitly typed presentation chain.

    This function does not infer new security facts. It only labels the evidence
    already carried by AttackPath / FlowPath so the browser can render supported
    data-flow and capability-cooccurrence paths differently.
    """
    metadata = path.get("metadata") or {}
    basis = str(metadata.get("basis") or "capability_cooccurrence")
    nodes = [str(item) for item in path.get("nodes") or []]
    steps: list[dict[str, Any]] = []

    flow_id = metadata.get("flow_id")
    flow = flows_by_id.get(str(flow_id)) if flow_id else None
    if basis == "static_dataflow" and flow:
        flow_steps = list(flow.get("steps") or [])
        if flow_steps:
            first = flow_steps[0]
            steps.append(
                {
                    "kind": "source",
                    "label": str(first.get("label") or "source"),
                    "role": str(first.get("kind") or metadata.get("source_kind") or "source"),
                }
            )
            steps.append({"kind": "agent", "label": agent_name, "role": "Agent"})
            for item in flow_steps[1:]:
                step_kind = str(item.get("kind") or "flow_step")
                semantic_kind = (
                    "destination"
                    if step_kind in {"external_send", "network_destination"}
                    else "function"
                )
                steps.append(
                    {
                        "kind": semantic_kind,
                        "label": str(item.get("label") or step_kind),
                        "role": step_kind,
                    }
                )
    elif path.get("path_id") == "PATH005" and len(nodes) >= 4:
        steps = [
            {"kind": "input", "label": nodes[0], "role": "Untrusted input"},
            {"kind": "agent", "label": nodes[1], "role": "Agent"},
            {"kind": "secret", "label": nodes[2], "role": "Reads secrets"},
            {"kind": "tool", "label": nodes[3], "role": "Outbound tool"},
            {
                "kind": "destination",
                "label": "Unrestricted external destination",
                "role": "Destination constraint",
            },
        ]
    elif path.get("path_id") == "PATH003" and len(nodes) >= 4:
        steps = [
            {"kind": "source", "label": nodes[0], "role": "Sensitive data"},
            {"kind": "agent", "label": nodes[1], "role": "Agent"},
            {"kind": "tool", "label": nodes[2], "role": "External write / HTTP tool"},
            {"kind": "destination", "label": nodes[3], "role": "External destination"},
        ]
    else:
        for index, label in enumerate(nodes):
            steps.append(
                {
                    "kind": "agent" if label == agent_name else "step",
                    "label": label,
                    "role": "Agent" if label == agent_name else f"Path step {index + 1}",
                }
            )

    return {
        **path,
        "basis": basis,
        "evidence_strength": (
            "supported_static_dataflow"
            if basis == "static_dataflow"
            else "potential_capability_cooccurrence"
        ),
        "edge_style": "solid" if basis == "static_dataflow" else "dashed",
        "steps": steps,
    }



def _finding_provenance_digest(finding: Finding, root: Path) -> dict[str, Any]:
    """Summarise attributed source facts without conflating different locations.

    A fact at the finding's own location is immediately relevant. For a
    cross-file rule (e.g., denied policy plus observed tool capability), we
    also show separately located facts when their subject/value appears in
    the finding's explanation. Raw facts remain available for audit.
    """
    location = finding.location
    search_text = " ".join(
        [finding.title, finding.message, *finding.evidence]
    ).lower()
    grouped: dict[tuple[str, str, int, int], list[Any]] = {}
    for fact in finding.provenance:
        source = fact.location
        if source is None or fact.fact == "agent_configuration_detected":
            continue
        same_source = (
            location is not None
            and source.path == location.path
            and source.line == location.line
        )
        subject_relevant = (
            len(fact.subject) > 2 and fact.subject.lower() in search_text
        )
        value_relevant = (
            "=" in fact.fact
            and len(fact.fact.split("=", 1)[1]) > 2
            and fact.fact.split("=", 1)[1].lower() in search_text
        )
        if not (same_source or subject_relevant or value_relevant):
            continue
        key = (fact.subject, str(source.path), source.line, source.column)
        grouped.setdefault(key, []).append(fact)

    items: list[dict[str, Any]] = []
    capability_labels = {
        "network.external": "external network access",
        "process.execute": "process execution",
        "data.read": "data read access",
        "data.write": "data write access",
        "external.write": "external writes",
        "computer.control": "computer control",
    }
    for (subject, path, line, column), source_facts in grouped.items():
        raw_facts = [fact.fact for fact in source_facts]
        origin = " + ".join(dict.fromkeys(fact.origin for fact in source_facts))
        capabilities: list[str] = []
        controls: list[str] = []
        attributes: list[str] = []
        for raw in dict.fromkeys(raw_facts):
            if "=" not in raw:
                attributes.append(raw.replace("_", " "))
                continue
            key, value = raw.split("=", 1)
            if key == "capability":
                capabilities.append(value)
            elif key == "approval_configuration":
                controls.append({
                    "True": "approval configured",
                    "False": "approval not detected",
                    "None": "approval configuration unresolved",
                }.get(value, f"approval configuration: {value}"))
            elif key == "guardrail_hook_detected":
                controls.append({
                    "True": "guardrail hook detected",
                    "False": "guardrail hook not detected",
                }.get(value, f"guardrail hook: {value}"))
            elif key == "authentication_configuration":
                controls.append({
                    "True": "authentication configured",
                    "False": "authentication configuration not detected",
                }.get(value, f"authentication configuration: {value}"))
            else:
                attributes.append(f"{key.replace('_', ' ')}: {value}")

        parts = []
        if capabilities:
            parts.append(
                "Capabilities: " + ", ".join(
                    capability_labels.get(value, value) for value in capabilities[:4]
                )
                + (f" (+{len(capabilities) - 4} more)" if len(capabilities) > 4 else "")
            )
        if controls:
            parts.append("Controls: " + ", ".join(controls))
        if attributes:
            parts.append(
                "Other observations: " + "; ".join(attributes[:2])
                + (f" (+{len(attributes) - 2} more)" if len(attributes) > 2 else "")
            )
        if not parts:
            continue
        relevance = (
            (4 if len(subject) > 2 and subject.lower() in search_text else 0)
            + min(4, sum(2 for fact in raw_facts if fact.lower() in search_text))
            + (2 if controls else 0)
            + (1 if capabilities else 0)
        )
        items.append({
            "subject": subject,
            "origin": origin,
            "location": {
                "path": _relative_path(path, root),
                "line": line,
                "column": column,
            },
            "summary": "; ".join(parts),
            "_relevance": relevance,
        })

    items.sort(key=lambda item: item["_relevance"], reverse=True)
    for item in items:
        del item["_relevance"]
    return {"items": items[:2], "additional_contexts": max(0, len(items) - 2)}


def build_visual_report(
    graph: Graph,
    findings: list[Finding],
    root: Path,
) -> dict[str, Any]:
    """Build the versioned data contract consumed by the offline HTML renderer."""
    root = root.resolve()
    authority = _relativize(effective_authority_report(graph), root)
    contract = _relativize(authority_contract_report(graph), root)
    security_graph = build_agent_security_graph(graph, root).as_dict()
    findings_docs = [
        {
            **_relativize(item.as_dict(), root),
            "provenance_digest": _finding_provenance_digest(item, root),
        }
        for item in findings
    ]
    attack_paths = security_graph.get("attack_paths", [])
    flows_by_id = {
        str(item.get("flow_id")): item
        for item in security_graph.get("flows", [])
        if item.get("flow_id")
    }

    contract_relationships = {
        item["authority_relationship_id"]: item
        for item in contract.get("relationships", [])
    }
    contract_violations_by_agent: dict[str, list[dict[str, Any]]] = {}
    contract_unresolved_by_agent: dict[str, list[dict[str, Any]]] = {}
    for item in contract.get("violations", []):
        contract_violations_by_agent.setdefault(item["agent"], []).append(item)
    for item in contract.get("unresolved", []):
        contract_unresolved_by_agent.setdefault(item["agent"], []).append(item)

    agents: list[dict[str, Any]] = []
    all_resources: set[str] = set()
    all_destinations: set[str] = set()
    write_relationships = 0

    for agent in sorted(graph.agents, key=lambda item: item.name):
        relationships = [
            item
            for item in authority.get("relationships", [])
            if item.get("agent") == agent.name
        ]
        agent_findings = [
            item for item in findings_docs if item.get("agent") == agent.name
        ]
        agent_policy_findings = [
            item
            for item in agent_findings
            if item.get("assessment") == "policy_violation"
        ]
        agent_attack_paths = [
            item for item in attack_paths if item.get("agent") == agent.name
        ]
        agent_path_views = [
            _attack_path_view(
                item,
                agent_name=agent.name,
                flows_by_id=flows_by_id,
            )
            for item in agent_attack_paths
        ]
        resources = sorted(
            {
                str(resource.get("selector"))
                for relationship in relationships
                for resource in relationship.get("resources", [])
                if resource.get("selector")
            }
        )
        destinations = sorted(
            {
                str(destination.get("target"))
                for relationship in relationships
                for destination in relationship.get("destinations", [])
                if destination.get("target")
            }
        )
        identities = sorted(
            {
                str(relationship["identity"]["name"])
                for relationship in relationships
                if relationship.get("identity")
                and relationship["identity"].get("name")
            }
        )
        all_resources.update(resources)
        all_destinations.update(destinations)
        agent_write_relationships = sum(_write_capable(item) for item in relationships)
        write_relationships += agent_write_relationships

        relationship_contracts = [
            contract_relationships[item["relationship_id"]]
            for item in relationships
            if item["relationship_id"] in contract_relationships
        ]
        contract_status = (
            "declared" if agent.policy.authority is not None else "not_declared"
        )
        if relationship_contracts:
            statuses = {item["status"] for item in relationship_contracts}
            if "violation" in statuses:
                contract_status = "violation"
            elif "unresolved" in statuses:
                contract_status = "unresolved"
            else:
                contract_status = "compliant"

        contract_doc = (
            _relativize(agent.policy.authority.as_dict(), root)
            if agent.policy.authority is not None
            else None
        )
        agents.append(
            {
                "name": agent.name,
                "provenance_inventory": [
                    _relativize(fact.as_dict(), root)
                    for fact in provenance_context(agent)
                ],
                "framework": str(agent.metadata.get("framework") or "generic"),
                "location": _agent_location(agent, root),
                "summary": {
                    "tools": len(agent.tools),
                    "skills": len(agent.skills),
                    "mcp_servers": len(agent.mcp_servers),
                    "identities": len(identities),
                    "resources": len(resources),
                    "destinations": len(destinations),
                    "authority_relationships": len(relationships),
                    "write_capable_relationships": agent_write_relationships,
                    "findings": len(agent_findings),
                    "policy_violations": len(agent_policy_findings),
                    "attack_paths": len(agent_attack_paths),
                    "contract_status": contract_status,
                    "contract_violations": len(
                        contract_violations_by_agent.get(agent.name, [])
                    ),
                    "contract_unresolved": len(
                        contract_unresolved_by_agent.get(agent.name, [])
                    ),
                },
                "severity": _severity_counts(
                    [item for item in findings if item.agent == agent.name]
                ),
                "skills": [
                    {
                        "name": skill.name,
                        "description": skill.description,
                        "allowed_tools": sorted(skill.allowed_tools),
                        "scripts": list(skill.scripts),
                        "location": (
                            {
                                "path": _relative_path(str(skill.location.path), root),
                                "line": skill.location.line,
                                "column": skill.location.column,
                            }
                            if skill.location
                            else None
                        ),
                        "binding_origin": skill.metadata.get("binding_origin"),
                    }
                    for skill in sorted(agent.skills, key=lambda item: item.name)
                ],
                "resources": resources,
                "destinations": destinations,
                "identities": identities,
                "effective_authority": relationships,
                "findings": agent_findings,
                "attack_paths": agent_attack_paths,
                "path_views": agent_path_views,
                "contract": {
                    "declared": contract_doc,
                    "relationships": relationship_contracts,
                    "violations": contract_violations_by_agent.get(agent.name, []),
                    "unresolved": contract_unresolved_by_agent.get(agent.name, []),
                },
            }
        )

    skill_inventory: dict[tuple[str, str], dict[str, Any]] = {}
    for agent in graph.agents:
        for skill in agent.skills:
            location = (
                _relative_path(str(skill.location.path), root)
                if skill.location
                else ""
            )
            key = (skill.name, location)
            item = skill_inventory.setdefault(
                key,
                {
                    "name": skill.name,
                    "description": skill.description,
                    "location": (
                        {
                            "path": location,
                            "line": skill.location.line,
                            "column": skill.location.column,
                        }
                        if skill.location
                        else None
                    ),
                    "allowed_tools": sorted(skill.allowed_tools),
                    "scripts": list(skill.scripts),
                    "capabilities": sorted(skill.capabilities),
                    "source": skill.source,
                    "resources": _component_resources(skill.resources),
                    "destinations": [d.target for d in skill.destinations],
                    "bound_agents": [],
                    "binding_state": "bound",
                },
            )
            if agent.name not in item["bound_agents"]:
                item["bound_agents"].append(agent.name)
    for skill in graph.unbound_skills:
        location = (
            _relative_path(str(skill.location.path), root)
            if skill.location
            else ""
        )
        key = (skill.name, location)
        skill_inventory.setdefault(
            key,
            {
                "name": skill.name,
                "description": skill.description,
                "location": (
                    {
                        "path": location,
                        "line": skill.location.line,
                        "column": skill.location.column,
                    }
                    if skill.location
                    else None
                ),
                "allowed_tools": sorted(skill.allowed_tools),
                "scripts": list(skill.scripts),
                "capabilities": sorted(skill.capabilities),
                "source": skill.source,
                "resources": _component_resources(skill.resources),
                "destinations": [d.target for d in skill.destinations],
                "bound_agents": [],
                "binding_state": "unbound",
            },
        )
    skills = sorted(
        skill_inventory.values(),
        key=lambda item: (item["name"], (item.get("location") or {}).get("path", "")),
    )
    for index, skill in enumerate(skills):
        skill["id"] = f"skill-{index}"
    tools, mcp_servers = _component_inventories(graph, root)

    owasp = build_owasp_agentic_summary(
        findings,
        disabled_rules=graph.configuration_audit.get("disabled_rules", []),
    )
    assurance = build_assurance_report(findings, contract, owasp)
    return {
        "schema_version": VISUAL_REPORT_SCHEMA_VERSION,
        "model": VISUAL_REPORT_MODEL,
        "root": ".",
        "summary": {
            "agents": len(graph.agents),
            "tools": len(graph.all_tools()),
            "skills": len(graph.all_skills()),
            "bound_skills": sum(len(agent.skills) for agent in graph.agents),
            "unbound_skills": len(graph.unbound_skills),
            "mcp_servers": len(graph.all_mcp_servers()),
            "unbound_tools": len(graph.unbound_tools),
            "unbound_mcp_servers": len(graph.unbound_mcp_servers),
            "unresolved_mcp_references": len(graph.unresolved_mcp_references),
            "identities": len(graph.all_identities()),
            "resources": len(all_resources),
            "destinations": len(all_destinations),
            "authority_relationships": authority["summary"]["relationships"],
            "authority_not_fully_resolved": (
                authority["summary"]["partially_resolved_relationships"]
                + authority["summary"]["unknown_relationships"]
            ),
            "write_capable_relationships": write_relationships,
            "attack_paths": len(graph.attack_paths),
            "findings": len(findings),
            "severity": _severity_counts(findings),
            "policy_violations": assurance["organization_policy"]["violations"],
            "owasp_categories_with_findings": assurance["owasp_agentic"][
                "categories_with_findings"
            ],
            "owasp_categories_not_assessed": assurance["owasp_agentic"][
                "categories_not_assessed"
            ],
            "agents_with_contract": contract["summary"]["agents_with_contract"],
            "contract_violations": contract["summary"]["violations"],
            "contract_unresolved": contract["summary"]["unresolved"],
            "analysis_incomplete": graph.coverage.incomplete,
        },
        "agents": agents,
        "skills": skills,
        "tools": tools,
        "mcp_servers": mcp_servers,
        "findings": findings_docs,
        "assurance": assurance,
        "authority_contract": contract,
        "owasp_agentic": owasp,
        "security_graph": security_graph,
        "coverage": _relativize(graph.coverage.as_dict(), root),
        "suppressed_findings": [
            _relativize(item.as_dict(), root) for item in graph.suppressed_findings
        ],
        "suppression_diagnostics": _relativize(graph.suppression_diagnostics, root),
    }


def _json_for_html(data: dict[str, Any]) -> str:
    # Prevent scan-controlled strings from terminating the inert JSON script element.
    return (
        json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_visual_report_html(
    graph: Graph,
    findings: list[Finding],
    root: Path,
) -> str:
    """Render a single-file, offline interactive HorusTrace report."""
    report = build_visual_report(graph, findings, root)
    payload = _json_for_html(report)
    title = escape(f"HorusTrace Security Report — {root.name or '.'}")
    return f"""<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
<title>{title}</title>
<style>
:root{{--bg:#080d18;--sidebar:#0b1220;--surface:#101827;--surface2:#151f31;--surface3:#0c1422;
--text:#f3f6fb;--muted:#93a1b5;--muted2:#6f7e92;--line:#263247;--line-strong:#3a4b67;
--accent:#86aefb;--accent-soft:#172846;--critical:#ff707a;--high:#ff9e66;--medium:#f6cd62;
--low:#73bdf4;--ok:#63d6a0;--warn:#f1c75b;--unknown:#a8b3c7;--shadow:0 14px 38px #00000038;
--radius:12px;--radius-lg:16px}}

/* Light is the default. Dark remains available without network, dependencies or rebuild. */
html[data-theme="light"]{{--bg:#f8fafc;--sidebar:#ffffff;--surface:#ffffff;--surface2:#f0f4f8;
--surface3:#edf2f7;--text:#1b2b46;--muted:#54647a;--muted2:#68778e;
--line:#dce4ec;--line-strong:#bfcddb;--accent:#285f99;--accent-soft:#ecf3fb;
--critical:#b12645;--high:#244068;--medium:#244068;--low:#245b58;
--ok:#196a50;--warn:#244068;--unknown:#53647c;--shadow:0 12px 32px #2035500d;
color-scheme:light}}
html[data-theme="dark"]{{color-scheme:dark}}
.theme-switch{{padding:11px 8px 15px;display:flex;flex-direction:column;gap:6px}}
.theme-switch-label{{color:var(--muted2);font-size:10px;text-transform:uppercase;letter-spacing:.11em;font-weight:800}}
.theme-choices{{display:flex;padding:3px;gap:4px;background:var(--surface3);border:1px solid var(--line);border-radius:10px}}
.theme-choices button{{flex:1;border:1px solid transparent;border-radius:7px;padding:6px 9px;
background:transparent;color:var(--muted);font-size:12px;font-weight:750;cursor:pointer}}
.theme-choices button[aria-pressed="true"]{{background:var(--surface);border-color:var(--line-strong);
box-shadow:0 2px 6px #121d3220;color:var(--text)}}
.theme-choices button:hover{{color:var(--text)}}
html[data-theme="light"] .brand-row,html[data-theme="light"] .sidebar-meta{{border-color:var(--line)}}
html[data-theme="light"] .brand-mark{{color:#fff}}
html[data-theme="light"] .nav button::before{{background:#8295b0}}
html[data-theme="light"] .nav button.active{{border-color:#c7dbf2}}
html[data-theme="light"] .nav button.active::before{{box-shadow:0 0 0 4px #205caa16}}
html[data-theme="light"] .assessment-banner{{background:linear-gradient(135deg,#fff,#f1f6fc);border-color:var(--line-strong)}}
html[data-theme="light"] .assessment-banner.critical{{background:linear-gradient(135deg,#fff2f3,#fff)}}
html[data-theme="light"] .assessment-banner.high{{background:linear-gradient(135deg,#fff7f7,#fff)}}
html[data-theme="light"] .assessment-banner.warn{{background:linear-gradient(135deg,#f2f6fc,#fff)}}
html[data-theme="light"] .card{{box-shadow:0 5px 18px #20355008}}
html[data-theme="light"] .card.drill:hover{{border-color:var(--line-strong)}}
html[data-theme="light"] th{{background:#eef3f9}}
html[data-theme="light"] tr.clickable:hover,html[data-theme="light"] .drill-row:hover{{background:#eaf2fc}}
html[data-theme="light"] .badge{{background:#edf3fa}}
html[data-theme="light"] .badge.critical{{border-color:#e5aab4}}
html[data-theme="light"] .badge.high{{border-color:#e6c4d0}}
html[data-theme="light"] .badge.medium{{border-color:#dfd1db}}
html[data-theme="light"] .badge.violation{{background:#fff1f3;border-color:#e9b3bc}}
html[data-theme="light"] .badge.compliant{{background:#eaf7ef;border-color:#a1d5b8}}
html[data-theme="light"] .badge.unresolved{{background:#f1f5fa;border-color:#d5dfe8}}
html[data-theme="light"] .badge.declared{{border-color:#b4c9eb}}
html[data-theme="light"] .filter-chip.active{{border-color:#acc5e5}}
html[data-theme="light"] .filter-banner{{background:#edf4fc;border-color:var(--line-strong)}}
html[data-theme="light"] .finding p{{color:var(--text)}}
html[data-theme="light"] code,html[data-theme="light"] .badge{{background-color:var(--surface3)}}
html[data-theme="light"] details{{border-color:var(--line)}}
html[data-theme="light"] details summary{{color:var(--text)}}
html[data-theme="light"] pre,html[data-theme="light"] .map-toolbar input{{background:var(--surface3)}}
html[data-theme="light"] .graph{{background:#f8fafd}}
html[data-theme="light"] svg text{{fill:var(--text)}}
html[data-theme="light"] .edge{{stroke:#647b9b}}
html[data-theme="light"] .node rect{{fill:#edf3fb;stroke:#7895b8}}
html[data-theme="light"] .node.agent rect{{fill:#e1edff;stroke:#306fba}}
html[data-theme="light"] .node.identity rect{{fill:#f0e8fa;stroke:#8063ae}}
html[data-theme="light"] .node.resource rect{{fill:#e3f5eb;stroke:#388562}}
html[data-theme="light"] .node.destination rect{{fill:#fff0f2;stroke:#bb768c}}
html[data-theme="light"] .path-step{{background:var(--surface3)}}
html[data-theme="light"] .empty{{background:#f3f7fb}}
html[data-theme="light"] .coverage-track{{background:#e5edf6}}
html[data-theme="light"] .footer{{border-color:var(--line)}}
@media(max-width:760px){{.theme-switch{{padding:10px 0 3px}} .theme-choices{{max-width:250px}}}}
*{{box-sizing:border-box}} html{{scroll-behavior:smooth}} body{{margin:0;font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,
BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}}
button,input{{font:inherit}} button{{color:inherit}} button:focus-visible,input:focus-visible,[tabindex]:focus-visible{{outline:2px solid var(--accent);outline-offset:2px}}
.shell{{display:grid;grid-template-columns:264px minmax(0,1fr);min-height:100vh}}
aside{{border-right:1px solid var(--line);padding:18px 14px;position:sticky;top:0;height:100vh;background:var(--sidebar);display:flex;flex-direction:column;z-index:20}}
.brand-row{{display:flex;align-items:center;gap:10px;padding:5px 8px 19px;border-bottom:1px solid #ffffff0a;margin-bottom:16px}}
.brand-mark{{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:linear-gradient(145deg,#233c66,#17243d);border:1px solid #48658f;font-size:12px;font-weight:900;letter-spacing:.05em;box-shadow:inset 0 1px #ffffff12}}
.brand{{font-size:17px;font-weight:800;letter-spacing:.1px;line-height:1.15}} .brand small{{display:block;font-size:10px;color:var(--muted);font-weight:650;margin-top:4px;text-transform:uppercase;letter-spacing:.08em}}
.nav-label{{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted2);font-weight:800;padding:4px 10px 7px}} .nav{{display:flex;flex-direction:column;gap:3px}}
.nav button{{position:relative;width:100%;text-align:left;background:transparent;color:var(--muted);border:1px solid transparent;border-radius:9px;padding:9px 11px 9px 31px;cursor:pointer;font-weight:620}}
.nav button::before{{content:"";position:absolute;left:12px;top:50%;width:6px;height:6px;border-radius:50%;background:#53627a;transform:translateY(-50%)}}
.nav button.active{{background:var(--accent-soft);border-color:#314b71;color:var(--text)}} .nav button.active::before{{background:var(--accent);box-shadow:0 0 0 4px #86aefb18}} .nav button:hover{{background:var(--surface2);color:var(--text)}}
.sidebar-meta{{margin-top:auto;border-top:1px solid #ffffff0a;padding:14px 8px 3px}} .sidebar-meta strong{{display:block;font-size:11px;margin-bottom:4px}} .sidebar-meta span{{display:block;color:var(--muted);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
main{{padding:32px 38px 42px;max-width:1560px;width:100%;min-width:0}} h1{{font-size:28px;letter-spacing:-.025em;margin:0 0 5px;line-height:1.2}} h2{{font-size:18px;letter-spacing:-.01em;margin:26px 0 11px}} h3{{font-size:14px;margin:0 0 9px}} p{{margin:8px 0 12px}}
.muted{{color:var(--muted)}} .muted2{{color:var(--muted2)}} .view{{display:none}} .view.active{{display:block}}
.page-head{{display:flex;justify-content:space-between;gap:22px;align-items:flex-start;margin-bottom:22px}} .eyebrow{{font-size:10px;text-transform:uppercase;letter-spacing:.13em;color:var(--muted2);font-weight:850;margin-bottom:6px}} .page-actions{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end}}
.hero{{display:flex;justify-content:space-between;gap:20px;align-items:start;margin-bottom:22px}}
.assessment-banner{{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:22px;align-items:center;padding:20px 22px;border:1px solid var(--line-strong);border-radius:var(--radius-lg);background:linear-gradient(135deg,#111c2f,#0e1727 62%,#111827);box-shadow:var(--shadow);margin-bottom:18px;cursor:pointer}}
.assessment-banner.critical{{border-color:#7d3a45;background:linear-gradient(135deg,#2a171e,#111827 62%)}} .assessment-banner.high{{border-color:#70452f;background:linear-gradient(135deg,#251b18,#111827 62%)}} .assessment-banner.warn{{border-color:#66552e;background:linear-gradient(135deg,#231f16,#111827 62%)}}
.assessment-title{{font-size:19px;font-weight:820;letter-spacing:-.01em;margin-bottom:4px}} .assessment-copy{{max-width:760px;color:var(--muted)}} .assessment-side{{display:flex;align-items:center;gap:16px}} .assessment-count{{font-size:34px;font-weight:850;letter-spacing:-.04em;text-align:right}} .assessment-count small{{display:block;font-size:10px;color:var(--muted);font-weight:700;letter-spacing:.06em;text-transform:uppercase}}
.pill{{display:inline-flex;align-items:center;gap:5px;padding:4px 8px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:11px;white-space:nowrap}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:11px}} .card{{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:14px 15px;box-shadow:0 5px 18px #00000018;min-width:0}}
.card.drill{{cursor:pointer;transition:transform .12s ease,border-color .12s ease,background .12s ease}} .card.drill:hover{{transform:translateY(-1px);border-color:#52688f;background:var(--surface2)}} .metric{{font-size:26px;font-weight:850;letter-spacing:-.035em;font-variant-numeric:tabular-nums}} .metric-label{{color:var(--muted);font-size:11px;font-weight:650;margin-top:2px}} .metric-detail{{color:var(--muted2);font-size:10px;margin-top:7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.critical{{color:var(--critical)}} .high{{color:var(--high)}} .medium{{color:var(--medium)}} .low{{color:var(--low)}} .ok{{color:var(--ok)}} .warn{{color:var(--warn)}}
.grid2{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px}} .panel{{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:15px;margin-bottom:14px;min-width:0}} .panel.flush{{padding:0;overflow:hidden}}
.section-head{{display:flex;align-items:end;justify-content:space-between;gap:12px;margin:26px 0 10px}} .section-head h2{{margin:0}} .section-head p{{margin:2px 0 0;font-size:12px;color:var(--muted)}}
.table-wrap{{overflow:auto}} table{{width:100%;border-collapse:collapse;min-width:690px}} th,td{{padding:10px 11px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}} th{{font-size:10px;text-transform:uppercase;letter-spacing:.075em;color:var(--muted2);font-weight:800;background:#0e1625;position:sticky;top:0}} tbody tr:last-child td{{border-bottom:0}} tr.clickable{{cursor:pointer}} tr.clickable:hover{{background:#ffffff08}}
.row-title{{font-weight:720}} .row-sub{{color:var(--muted);font-size:11px;margin-top:2px}} .row-chevron{{color:var(--muted2);font-size:18px;text-align:right}}
.badge{{display:inline-flex;align-items:center;gap:5px;padding:3px 7px;border-radius:999px;font-size:10px;font-weight:800;background:#ffffff0b;border:1px solid var(--line);white-space:nowrap}} .badge.violation{{color:var(--critical);border-color:#ff6b7560;background:#ff6b7510}} .badge.compliant{{color:var(--ok);border-color:#63d69f60;background:#63d69f0c}} .badge.unresolved{{color:var(--warn);border-color:#f1c75b60;background:#f1c75b0b}} .badge.not_declared{{color:var(--muted)}} .badge.declared{{color:var(--accent);border-color:#8ab4ff60}} .badge.critical{{color:var(--critical);border-color:#ff707a55}} .badge.high{{color:var(--high);border-color:#ff9e6655}} .badge.medium{{color:var(--medium);border-color:#f6cd6255}}
.search{{width:100%;max-width:520px;background:var(--surface3);color:var(--text);border:1px solid var(--line);border-radius:9px;padding:9px 11px;margin:0}} .toolbar{{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:12px 0}} .toolbar-left,.toolbar-right{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}} .filter-chips{{display:flex;gap:6px;flex-wrap:wrap}} .filter-chip{{border:1px solid var(--line);background:var(--surface);color:var(--muted);border-radius:999px;padding:6px 10px;font-size:11px;font-weight:720;cursor:pointer}} .filter-chip:hover{{border-color:var(--line-strong);color:var(--text)}} .filter-chip.active{{background:var(--accent-soft);border-color:#3b5a84;color:var(--text)}}
.agent-head{{display:flex;gap:14px;justify-content:space-between;align-items:start;padding:18px 0 3px}} .breadcrumb{{border:0;background:transparent;color:var(--muted);padding:0;cursor:pointer;font-size:12px;margin-bottom:9px}} .breadcrumb:hover{{color:var(--text)}}
.tabs{{display:flex;gap:3px;border-bottom:1px solid var(--line);margin:15px 0 15px;overflow:auto;position:sticky;top:0;background:var(--bg);z-index:9;padding-top:5px}} .tabs button{{border:0;background:transparent;color:var(--muted);padding:9px 10px;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;font-size:12px;font-weight:700}} .tabs button.active{{color:var(--text);border-bottom-color:var(--accent)}} .tab-count{{margin-left:4px;color:var(--muted2);font-size:10px}}
.agent-tab{{display:none}} .agent-tab.active{{display:block}} .kv{{display:grid;grid-template-columns:170px minmax(0,1fr);gap:7px 14px}} .kv div:nth-child(odd){{color:var(--muted)}} .kv div:nth-child(even){{min-width:0;overflow-wrap:anywhere}}
.drill-list{{display:flex;flex-direction:column;gap:2px}} .drill-row{{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:16px;cursor:pointer;border-radius:7px;padding:7px 8px;margin:0 -8px;color:inherit}} .drill-row:hover{{background:#ffffff08}} .drill-value{{display:flex;align-items:center;gap:8px;font-variant-numeric:tabular-nums;font-weight:700}} .drill-value::after{{content:"›";color:var(--muted);font-size:16px;line-height:1;opacity:.7}}
.filter-banner{{display:flex;justify-content:space-between;align-items:center;gap:12px;background:#101a31;border:1px solid #344566;border-radius:9px;padding:9px 11px;margin:12px 0}}
.source-context{{margin:12px 0;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--surface3)}} .source-context-title{{font-size:11px;font-weight:800;margin-bottom:6px}} .source-note{{font-size:12px;padding:5px 0;overflow-wrap:anywhere}} .source-note+.source-note{{border-top:1px solid var(--line)}} .source-note-heading{{margin-bottom:2px}} .source-context .small{{font-size:11px}}
.finding{{border-left:3px solid var(--line);padding:14px 15px;margin:10px 0;background:var(--surface);border-radius:9px;border-top:1px solid var(--line);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}} .finding[data-sev="critical"]{{border-left-color:var(--critical)}} .finding[data-sev="high"]{{border-left-color:var(--high)}} .finding[data-sev="medium"]{{border-left-color:var(--medium)}} .finding[data-sev="low"]{{border-left-color:var(--low)}} .finding-head{{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}} .finding-title{{display:flex;gap:7px;align-items:center;flex-wrap:wrap}} .finding-name{{font-size:14px;font-weight:760;margin-top:7px}} .finding-meta{{display:flex;gap:7px;flex-wrap:wrap;margin:8px 0 0;color:var(--muted);font-size:11px}} .finding p{{color:#d8dfeb}}
code,pre{{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}} code{{background:#ffffff0b;padding:2px 5px;border-radius:5px}} details{{margin-top:8px;border-top:1px solid #ffffff0a;padding-top:7px}} details summary{{cursor:pointer;color:#c9d4e5;font-weight:650;font-size:12px}} pre{{white-space:pre-wrap;word-break:break-word;background:#09101e;border:1px solid var(--line);padding:12px;border-radius:8px;max-height:340px;overflow:auto}}
.map-toolbar{{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin:8px 0 10px}} .map-toolbar input{{min-width:250px;flex:1;background:#09101e;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:7px 9px}} .map-btn{{border:1px solid var(--line);background:var(--surface);color:var(--text);border-radius:8px;padding:7px 9px;cursor:pointer;font-size:12px}} .map-btn:hover{{border-color:#52688f;background:var(--surface2)}} .map-hint{{font-size:11px;color:var(--muted);margin:-2px 0 10px}}
.graph-wrap{{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:12px;position:relative}} .graph-wrap.expanded{{position:fixed;inset:14px;z-index:9999;background:var(--bg);padding:14px;border:1px solid var(--line);border-radius:14px;grid-template-columns:minmax(0,1fr) 340px;box-shadow:0 24px 80px #000b}} .graph-wrap.expanded .graph{{height:calc(100vh - 105px)}} body.graph-modal-open{{overflow:hidden}} .graph-canvas{{position:relative;min-width:0}} .graph{{width:100%;height:520px;background:#09101e;border:1px solid var(--line);border-radius:10px;touch-action:none;cursor:grab}} .graph.panning{{cursor:grabbing}} .inspector{{min-height:120px;overflow:auto}} .legend{{display:flex;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:11px;margin:7px 0 10px}}
.dot{{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:4px}} .empty{{padding:28px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:10px;background:#0b1321}} .back{{border:1px solid var(--line);background:var(--surface);color:var(--text);padding:7px 10px;border-radius:8px;cursor:pointer}} .small{{font-size:11px}} .nowrap{{white-space:nowrap}} .sevbar{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}
svg text{{fill:var(--text);font-family:ui-sans-serif,system-ui;font-size:12px}} .edge{{stroke:#65728c;stroke-width:1.4;opacity:.72}} .node rect{{fill:#16213a;stroke:#42516f;stroke-width:1}} .node.agent rect{{fill:#1b3157;stroke:#78a8ff}} .node.identity rect{{fill:#2b2545;stroke:#a895ff}} .node.resource rect{{fill:#21362f;stroke:#63d69f}} .node.destination rect{{fill:#3a2d22;stroke:#f1b36a}} .node.unresolved rect{{stroke-dasharray:5 4}} .node{{cursor:pointer;transition:opacity .12s}} .node:hover rect{{stroke-width:2}} .node.dim{{opacity:.16}} .node.match rect,.node.selected rect{{stroke-width:3}} .edge.dim{{opacity:.08}} .edge.selected{{stroke-width:2.5;opacity:1}} .label2{{fill:var(--muted);font-size:10px}}
.path-card{{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:16px;margin:12px 0}} .path-head{{display:flex;justify-content:space-between;gap:12px;align-items:start;flex-wrap:wrap}} .path-chain{{display:flex;flex-direction:column;align-items:flex-start;margin-top:15px;padding-left:8px}} .path-step{{min-width:260px;max-width:680px;background:#0d1628;border:1px solid var(--line);border-radius:9px;padding:9px 11px}} .path-step.agent{{border-color:#78a8ff}} .path-step.secret{{border-color:#c98cff}} .path-step.destination{{border-color:#f1b36a}} .path-step.input,.path-step.source{{border-color:#8ab4ff}} .path-role{{font-size:9px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:2px;font-weight:800}} .path-arrow{{height:22px;margin-left:28px;border-left:2px solid #6d7e9f}} .path-arrow.dashed{{border-left-style:dashed}} .path-meta{{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}}
.severity-chart{{display:grid;gap:8px;padding:14px 15px;border:1px solid var(--line);border-radius:var(--radius);background:var(--surface)}}
.severity-chart-row{{padding:7px 8px;border:1px solid transparent;border-radius:8px;cursor:pointer}}
.severity-chart-row:hover,.severity-chart-row:focus-visible{{background:var(--surface2);border-color:var(--line-strong)}}
.severity-chart-head{{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:5px;font-size:12px}}
.severity-chart-label{{font-weight:720}} .severity-chart-count{{font-weight:800;font-variant-numeric:tabular-nums}}
.severity-chart-track{{display:block;height:9px;border:1px solid var(--line);background:var(--surface3);border-radius:999px;overflow:hidden}}
.severity-chart-fill{{display:block;height:100%;border-radius:999px;background:var(--muted2)}}
.severity-chart-fill.critical{{background:var(--critical)}} .severity-chart-fill.high{{background:var(--high)}}
.severity-chart-fill.medium{{background:var(--medium)}} .severity-chart-fill.low{{background:var(--low)}}
.severity-chart-fill.info{{background:var(--unknown)}}
.severity-chart-caption{{margin:2px 8px 0;font-size:10px;color:var(--muted)}}
.authority-chart{{margin-bottom:12px}}
.authority-chart-row{{display:block;width:100%;background:transparent;text-align:left;color:var(--text);font:inherit;appearance:none}}
.authority-chart-row .severity-chart-fill.fully_resolved{{background:var(--accent)}}
.authority-chart-row .severity-chart-fill.partially_resolved{{background:var(--warn)}}
.authority-chart-row .severity-chart-fill.unknown{{background:var(--unknown)}}
.owasp-chart{{margin-bottom:15px}}
.owasp-chart-row .severity-chart-fill.finding{{background:var(--critical)}}
.owasp-chart-row .severity-chart-fill.no_runtime_findings{{background:var(--medium)}}
.owasp-chart-row .severity-chart-fill.no_mapped_findings{{background:var(--accent)}}
.owasp-chart-row .severity-chart-fill.not_assessed{{background:var(--unknown)}}
.coverage-track{{height:8px;background:#09101e;border-radius:999px;overflow:hidden;border:1px solid var(--line);margin-top:9px}} .coverage-fill{{height:100%;background:var(--ok);border-radius:inherit}} .footer{{color:var(--muted2);font-size:10px;margin:30px 0 3px;padding-top:14px;border-top:1px solid #ffffff0a}}
/* Soft presentation-style status bars, light theme only. Semantic text remains contrast-safe. */
html[data-theme="light"]{{--bar-risk:#EFB5C2;--bar-warning:#F6D4C8;--bar-good:#B9DECD;--bar-unknown:#CED9E4}}
html[data-theme="light"] .severity-chart-track{{background:#EFF2F6}}
html[data-theme="light"] .severity-chart-fill{{box-shadow:inset 0 0 0 1px #31415912}}
html[data-theme="light"] .severity-chart-fill.critical{{background:var(--bar-risk)}}
html[data-theme="light"] .severity-chart-fill.high,
html[data-theme="light"] .severity-chart-fill.medium{{background:var(--bar-warning)}}
html[data-theme="light"] .severity-chart-fill.low{{background:var(--bar-good)}}
html[data-theme="light"] .severity-chart-fill.info{{background:var(--bar-unknown)}}
html[data-theme="light"] .authority-chart-row .severity-chart-fill.fully_resolved{{background:var(--bar-good)}}
html[data-theme="light"] .authority-chart-row .severity-chart-fill.partially_resolved{{background:var(--bar-warning)}}
html[data-theme="light"] .authority-chart-row .severity-chart-fill.unknown{{background:var(--bar-unknown)}}
html[data-theme="light"] .owasp-chart-row .severity-chart-fill.finding{{background:var(--bar-risk)}}
html[data-theme="light"] .owasp-chart-row .severity-chart-fill.no_runtime_findings{{background:var(--bar-warning)}}
html[data-theme="light"] .owasp-chart-row .severity-chart-fill.no_mapped_findings{{background:var(--bar-good)}}
html[data-theme="light"] .owasp-chart-row .severity-chart-fill.not_assessed{{background:var(--bar-unknown)}}
html[data-theme="light"] .coverage-fill{{background:var(--bar-good)}}
html[data-theme="light"] .coverage-fill.incomplete{{background:var(--bar-warning)}}

/* Light-mode chart rows: semantic dots persist at zero; bars show actual counts. */
html[data-theme="light"] .severity-chart-row{{padding:10px 12px;border-radius:10px}}
html[data-theme="light"] .severity-chart-head{{font-size:13px;margin-bottom:9px}}
html[data-theme="light"] .severity-chart-track{{height:14px;background:#f0f2f1;border:1px solid #e0e5e2}}
html[data-theme="light"] .severity-chart-fill{{box-shadow:none}}
html[data-theme="light"] .severity-chart-row[data-tone="critical"][data-present="true"],
html[data-theme="light"] .severity-chart-row[data-tone="finding"][data-present="true"]{{background:#fff6f6}}
html[data-theme="light"] .severity-chart-row[data-tone="high"][data-present="true"],
html[data-theme="light"] .severity-chart-row[data-tone="medium"][data-present="true"],
html[data-theme="light"] .severity-chart-row[data-tone="partially_resolved"][data-present="true"],
html[data-theme="light"] .severity-chart-row[data-tone="no_runtime_findings"][data-present="true"]{{background:#fff9f7}}
html[data-theme="light"] .severity-chart-row[data-tone="low"][data-present="true"],
html[data-theme="light"] .severity-chart-row[data-tone="fully_resolved"][data-present="true"],
html[data-theme="light"] .severity-chart-row[data-tone="no_mapped_findings"][data-present="true"]{{background:#f4faf6}}
html[data-theme="light"] .severity-chart-row[data-present="false"]{{opacity:.78}}
html[data-theme="light"] .severity-chart-label::before{{content:"";display:inline-block;width:11px;height:11px;
border-radius:4px;margin-right:9px;vertical-align:-1px;background:var(--bar-unknown);
border:1px solid #31415912}}
html[data-theme="light"] .severity-chart-row[data-tone="critical"] .severity-chart-label::before,
html[data-theme="light"] .severity-chart-row[data-tone="finding"] .severity-chart-label::before{{background:var(--bar-risk)}}
html[data-theme="light"] .severity-chart-row[data-tone="high"] .severity-chart-label::before,
html[data-theme="light"] .severity-chart-row[data-tone="medium"] .severity-chart-label::before,
html[data-theme="light"] .severity-chart-row[data-tone="partially_resolved"] .severity-chart-label::before,
html[data-theme="light"] .severity-chart-row[data-tone="no_runtime_findings"] .severity-chart-label::before{{background:var(--bar-warning)}}
html[data-theme="light"] .severity-chart-row[data-tone="low"] .severity-chart-label::before,
html[data-theme="light"] .severity-chart-row[data-tone="fully_resolved"] .severity-chart-label::before,
html[data-theme="light"] .severity-chart-row[data-tone="no_mapped_findings"] .severity-chart-label::before{{background:var(--bar-good)}}
html[data-theme="light"] .badge.critical,html[data-theme="light"] .badge.violation{{background:#fdebf0;border-color:#efb5c2}}
html[data-theme="light"] .badge.high,html[data-theme="light"] .badge.medium{{background:#fff4f1;border-color:#f6d4c8}}
html[data-theme="light"] .badge.unresolved{{background:#f1f5fa;border-color:#d5dfe8}}
html[data-theme="light"] .badge.compliant{{background:#eaf7f0;border-color:#b9decd}}


/* Security workbench: neutral surface, intentional accent and source-safe inline icons. */
.ui-icon{{width:17px;height:17px;flex:none;vertical-align:-3px;stroke:currentColor}}
.nav button{{display:flex;align-items:center;gap:11px;padding:10px 11px}}
.nav button::before{{display:none}}
.nav button .ui-icon{{opacity:.78}}
.nav button.active .ui-icon{{opacity:1}}
.metric-top{{display:flex;align-items:start;justify-content:space-between;gap:8px;min-height:29px}}
.metric-top .metric-label{{font-size:12px;line-height:1.35;margin-top:2px}}
.metric-icon{{height:33px;width:33px;flex:none;display:grid;place-items:center;border-radius:9px;
background:var(--surface3);color:var(--muted)}}
.metric{{margin-top:5px}}
.metric-detail{{white-space:normal;overflow-wrap:anywhere;line-height:1.4}}
.page-title-row,.section-title-row{{display:flex;align-items:center;gap:10px}}
.page-title-row .ui-icon{{width:22px;height:22px;color:var(--accent)}}
.section-title-row .ui-icon{{color:var(--muted2)}}
.report-context{{font-size:10px;text-transform:uppercase;font-weight:800;letter-spacing:.1em;
color:var(--muted);display:flex;align-items:center;gap:8px;margin-bottom:10px}}
.report-context::before{{content:"";display:inline-block;width:7px;height:7px;
border-radius:50%;background:var(--accent)}}
html[data-theme="light"]{{--bg:#f7f9fc;--sidebar:#ffffff;--surface:#ffffff;--surface2:#f1f5f9;
--surface3:#f0f4f8;--line:#dce5ee;--line-strong:#bfcfdf;--accent:#21639b;--accent-soft:#eaf3fc}}
html[data-theme="light"] aside{{box-shadow:2px 0 12px #182d4308}}
html[data-theme="light"] .nav button{{font-size:13px;font-weight:650}}
html[data-theme="light"] .nav button.active{{background:#e8f2f9;border-color:#d3e4ef;
color:#184d73;box-shadow:inset 3px 0 #377da8}}
html[data-theme="light"] .nav button:hover:not(.active){{background:#f3f7fa}}
html[data-theme="light"] .metric-icon{{background:#eef4f8;color:#376a89}}
html[data-theme="light"] .card{{border-color:#dce5ed;box-shadow:0 3px 12px #203b5b08}}
html[data-theme="light"] .card.drill:hover{{border-color:#9fbfd4;box-shadow:0 5px 18px #1e527011}}
html[data-theme="light"] .card:focus-visible{{outline:2px solid var(--accent);outline-offset:2px}}
html[data-theme="light"] .assessment-banner{{background:#fff;border-left:4px solid #89abc0;
border-color:#dce5ec;box-shadow:0 4px 16px #182d4308}}
html[data-theme="light"] .assessment-banner.critical{{background:linear-gradient(110deg,#fff8fa,#fff 60%);
border-left:4px solid #b12645}}
html[data-theme="light"] .assessment-banner.high{{background:linear-gradient(110deg,#fff8fa,#fff 60%);
border-left:4px solid #bd5670}}
html[data-theme="light"] .assessment-banner.warn{{background:linear-gradient(110deg,#f5faff,#fff 60%);
border-left:4px solid #377da8}}
html[data-theme="light"] .assessment-banner:focus-visible{{outline:2px solid var(--accent);outline-offset:2px}}
html[data-theme="light"] .section-title-row .ui-icon{{color:#31718e}}
html[data-theme="light"] .page-title-row .ui-icon{{color:#21639b}}
@media(max-width:760px){{.nav button .ui-icon{{width:16px;height:16px}}}}
@media(prefers-reduced-motion:reduce){{*{{scroll-behavior:auto!important;transition:none!important}}}}
@media(max-width:1000px){{.shell{{grid-template-columns:220px minmax(0,1fr)}} main{{padding:26px 24px}} .graph-wrap{{grid-template-columns:1fr}} .inspector{{max-height:280px}}}}
@media(max-width:760px){{.shell{{grid-template-columns:1fr}} aside{{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line);padding:12px}} .brand-row{{padding-bottom:11px;margin-bottom:9px}} .nav-label,.sidebar-meta{{display:none}} .nav{{display:flex;flex-direction:row;overflow:auto;gap:4px}} .nav button{{width:auto;white-space:nowrap;padding:8px 10px}} .nav button::before{{display:none}} main{{padding:20px 14px 30px}} .grid2,.assessment-banner{{grid-template-columns:1fr}} .assessment-side{{justify-content:flex-start}} .assessment-count{{text-align:left}} .page-head{{flex-direction:column}} .page-actions{{justify-content:flex-start}} .sevbar{{grid-template-columns:repeat(2,1fr)}} .kv{{grid-template-columns:1fr}} .graph{{height:440px}} .graph-wrap.expanded{{inset:4px;padding:8px;grid-template-columns:1fr}} .graph-wrap.expanded .inspector{{display:none}} .tabs{{position:static}}}}

/* Source-backed agent supply chain (not an inferred runtime execution diagram). */
.supply-toolbar{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:14px 0}}
.supply-select{{background:var(--surface);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:8px;max-width:100%;min-width:160px}}
.supply-viewport{{overflow:auto;border:1px solid var(--line);border-radius:12px;background:var(--surface2);max-height:685px;min-height:365px}}
.supply-diagram{{display:block;min-width:1090px;background:var(--surface);}}
.supply-diagram text{{fill:var(--text);font-size:12px}}
.supply-diagram .supply-col-title{{font-size:11px;fill:var(--muted);font-weight:800;letter-spacing:.07em}}
.supply-node rect{{fill:var(--surface3);stroke:var(--line-strong);stroke-width:1.4}}
.supply-node[data-kind="agent"] rect,.supply-node[data-kind="workflow_node"] rect{{fill:#e6f0fb;stroke:#7da9d2}}
.supply-node[data-kind="mcp_server"] rect,.supply-node[data-kind="tool"] rect,.supply-node[data-kind="delegation"] rect{{fill:#e9f0ff;stroke:#9ab4d3}}
.supply-node[data-kind="skill"] rect,.supply-node[data-kind="model"] rect{{fill:#f0eaff;stroke:#b5a1d4}}
.supply-node[data-kind="identity"] rect,.supply-node[data-kind="approval_control"] rect,.supply-node[data-kind="policy_control"] rect{{fill:#e7f5ed;stroke:#84bc9c}}
.supply-node[data-kind="network_destination"] rect,.supply-node[data-kind="data_resource"] rect{{fill:#fff0e4;stroke:#d5aa87}}
.supply-node text{{fill:#23354a}}
.supply-node .supply-kind{{font-size:10px;fill:#526783}}
.supply-node{{cursor:pointer}}
.supply-node:hover rect,.supply-node.selected rect{{stroke-width:2.8}}
.supply-edge{{fill:none;stroke:#7893ae;stroke-width:1.5;opacity:.62;cursor:pointer}}
.supply-edge.authority{{stroke:#668f80;stroke-dasharray:5 4}}
.supply-edge.data{{stroke:#ce9574}}
.supply-edge:hover,.supply-edge.selected{{stroke-width:3;opacity:1}}
.supply-inspector{{min-height:165px}}
.supply-relationship{{padding:8px 0;border-bottom:1px solid var(--line);font-size:12px}}
.supply-relationship:last-child{{border-bottom:0}}
.supply-note{{font-size:11px;color:var(--muted);margin:9px 0}}
html[data-theme="dark"] .supply-node[data-kind="agent"] rect,html[data-theme="dark"] .supply-node[data-kind="workflow_node"] rect{{fill:#182c46}}
html[data-theme="dark"] .supply-node[data-kind="mcp_server"] rect,html[data-theme="dark"] .supply-node[data-kind="tool"] rect,html[data-theme="dark"] .supply-node[data-kind="delegation"] rect{{fill:#222f4b}}
html[data-theme="dark"] .supply-node[data-kind="skill"] rect,html[data-theme="dark"] .supply-node[data-kind="model"] rect{{fill:#302946}}
html[data-theme="dark"] .supply-node[data-kind="identity"] rect,html[data-theme="dark"] .supply-node[data-kind="approval_control"] rect,html[data-theme="dark"] .supply-node[data-kind="policy_control"] rect{{fill:#1f382e}}
html[data-theme="dark"] .supply-node[data-kind="network_destination"] rect,html[data-theme="dark"] .supply-node[data-kind="data_resource"] rect{{fill:#403123}}
html[data-theme="dark"] .supply-node text{{fill:#e2e9f2}}
html[data-theme="dark"] .supply-node .supply-kind{{fill:#a6b8d0}}
</style>
</head>
<body>
<div class="shell">
<aside>
  <div class="brand-row"><div class="brand-mark" aria-hidden="true">HT</div><div class="brand">HorusTrace<small>Agent Security Workbench</small></div></div>
  <div class="nav-label">Assessment</div>
  <nav class="nav" aria-label="Report sections">
    <button class="active" data-view="dashboard" data-icon="overview">Dashboard</button>
    <button data-view="agents" data-icon="agents">Agents</button>
    <button data-view="components" data-icon="resources">Components</button>
    <button data-view="supply" data-icon="attack">Supply chain</button>
    <button data-view="findings" data-icon="findings">Findings</button>
    <button data-view="policy" data-icon="policy">Organisation policy</button>
    <button data-view="owasp" data-icon="owasp">OWASP Top 10</button>
    <button data-view="attack" data-icon="attack">Attack paths</button>
    <button data-view="contracts" data-icon="contracts">Agent contracts</button>
    <button data-view="evidence" data-icon="evidence">Scan evidence</button>
  </nav>
  <div class="theme-switch" role="group" aria-label="Report color theme">
    <span class="theme-switch-label">Appearance</span>
    <div class="theme-choices">
      <button type="button" data-theme-choice="light" aria-pressed="true">Light</button>
      <button type="button" data-theme-choice="dark" aria-pressed="false">Dark</button>
    </div>
  </div>
  <div class="sidebar-meta"><strong>Offline security evidence</strong><span title="{escape(root.name or '.')}">Scope: {escape(root.name or '.')}</span><span>Schema v{VISUAL_REPORT_SCHEMA_VERSION}</span></div>
</aside>
<main>
  <section id="dashboard" class="view active"></section><section id="agents" class="view"></section><section id="agent-detail" class="view"></section><section id="components" class="view"></section><section id="supply" class="view"></section>
  <section id="findings" class="view"></section><section id="policy" class="view"></section><section id="owasp" class="view"></section><section id="attack" class="view"></section><section id="contracts" class="view"></section><section id="evidence" class="view"></section>
  <div class="footer">Static evidence only · Runtime effectiveness is not verified · No report data leaves this file.</div>
</main>
</div>
<script id="horus-data" type="application/json">{payload}</script>
<script>
"use strict";
const DATA=JSON.parse(document.getElementById("horus-data").textContent);
const THEME_STORAGE_KEY="horustrace-report-theme";
function setTheme(choice){{
 const next=choice==="dark"?"dark":"light";
 document.documentElement.setAttribute("data-theme",next);
 document.querySelectorAll("[data-theme-choice]").forEach(btn=>btn.setAttribute("aria-pressed",String(btn.dataset.themeChoice===next)));
 try{{window.localStorage.setItem(THEME_STORAGE_KEY,next);}}catch(_error){{/* file:// or restricted browser storage */}}
}}
let initialTheme="light";
try{{initialTheme=window.localStorage.getItem(THEME_STORAGE_KEY)||"light";}}catch(_error){{/* offline file storage can be disabled */}}
setTheme(initialTheme);
document.querySelectorAll("[data-theme-choice]").forEach(btn=>btn.addEventListener("click",()=>setTheme(btn.dataset.themeChoice)));

const esc=(v)=>String(v??"").replace(/[&<>"']/g,c=>({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[c]));
const loc=(v)=>v&&v.path?esc(v.path)+":"+esc(v.line||1):"n/a";
const badge=(s)=>'<span class="badge '+esc(s)+'">'+esc(String(s).replaceAll("_"," "))+'</span>';
const number=(v)=>Number(v||0).toLocaleString();
const severityRank=(s)=>({{critical:5,high:4,medium:3,low:2,info:1}}[String(s||"").toLowerCase()]||0);

/* Small audited static SVG dictionary; no CDN, icon font, or scan-controlled SVG. */
const ICONS=Object.freeze({{
 overview:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
 agents:'<circle cx="12" cy="7" r="3"/><path d="M5 21v-2a7 7 0 0 1 14 0v2"/>',
 findings:'<path d="M12 3 2 20h20L12 3Z"/><path d="M12 9v5m0 4h.01"/>',
 policy:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/>',
 owasp:'<path d="M4 5h4m4 0h8M4 12h4m4 0h8M4 19h4m4 0h8"/>',
 attack:'<circle cx="5" cy="5" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="12" cy="19" r="2"/><path d="M7 6 11 17m6-11-4 11M7 5h10"/>',
 contracts:'<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8m-8 5 2 2 5-5"/>',
 evidence:'<path d="M7 3h7l5 5v12H5V5a2 2 0 0 1 2-2Zm7 0v5h5M8 13h8M8 17h5"/>',
 tools:'<path d="M15 7a4 4 0 0 0-5 5L4 18l2 2 6-6a4 4 0 0 0 5-5l-3 2-2-2 3-2Z"/>',
 skills:'<path d="M12 6a8 8 0 0 0-9-1v15a8 8 0 0 1 9 1 8 8 0 0 1 9-1V5a8 8 0 0 0-9 1Zm0 0v15"/>',
 mcp:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6h.01M7 17h.01M12 10v4"/>',
 identities:'<circle cx="8" cy="9" r="4"/><path d="M12 9h10m-4 0v4m-3-4v3"/>',
 resources:'<path d="m12 2 9 5-9 5-9-5 9-5Zm-9 10 9 5 9-5M3 17l9 5 9-5"/>',
 chart:'<path d="M4 20V9m6 11V4m6 16v-7m5 7H2"/>',
 coverage:'<path d="M8 3H5a2 2 0 0 0-2 2v3m13-5h3a2 2 0 0 1 2 2v3M3 16v3a2 2 0 0 0 2 2h3m13-5v3a2 2 0 0 1-2 2h-3"/><path d="m9 12 2 2 4-4"/>'
}});
function uiIcon(name){{
 const graphic=Object.prototype.hasOwnProperty.call(ICONS,name)?ICONS[name]:"";
 return graphic?'<svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'+graphic+'</svg>':"";
}}
const ICON_FOR_METRIC=Object.freeze({{
 "Active findings":"findings","Policy violations":"policy","Contract violations":"contracts",
 "OWASP categories with findings":"owasp","Agents":"agents","Attack paths":"attack",
 "Tools":"tools","Skills":"skills","MCP servers":"mcp","Identities":"identities",
 "Resources":"resources","Critical":"findings","High":"findings","Medium":"findings",
 "Low":"findings","Files considered":"coverage","Files scanned":"coverage"
}});
const ICON_FOR_SECTION=Object.freeze({{
 "Priority review queue":"findings","Finding severity":"chart","Effective agency":"attack",
 "OWASP assessment states":"owasp","Environment inventory":"resources",
 "Agent contracts":"contracts","Coverage status":"coverage","Skill inventory":"skills",
 "Components":"resources","Affected agents":"agents","Supply chain":"attack"
}});
document.querySelectorAll(".nav button[data-icon]").forEach(btn=>btn.insertAdjacentHTML("afterbegin",uiIcon(btn.dataset.icon)));
function showView(id){{
 const navId=id==="agent-detail"?"agents":id;
 document.querySelectorAll(".view").forEach(el=>el.classList.toggle("active",el.id===id));
 document.querySelectorAll(".nav button").forEach(el=>{{const active=el.dataset.view===navId;el.classList.toggle("active",active);if(active)el.setAttribute("aria-current","page");else el.removeAttribute("aria-current");}});
 window.scrollTo(0,0);
}}
document.querySelectorAll(".nav button").forEach(btn=>btn.addEventListener("click",()=>showView(btn.dataset.view)));
function metric(label,value,cls="",drill="",detail=""){{
 const attrs=drill?' drill" role="button" tabindex="0" data-drill="'+esc(drill):'"';
 return '<div class="card'+attrs+'"><div class="metric-top"><div class="metric-label">'+esc(label)+'</div><span class="metric-icon">'+uiIcon(ICON_FOR_METRIC[label]||"chart")+'</span></div><div class="metric '+cls+'">'+number(value)+'</div>'+(detail?'<div class="metric-detail">'+esc(detail)+'</div>':"")+'</div>';
}}
function pageHead(eyebrow,title,copy,actions=""){{return '<div class="page-head"><div><div class="eyebrow">'+esc(eyebrow)+'</div><div class="page-title-row">'+uiIcon(ICON_FOR_SECTION[title]||"overview")+'<h1>'+esc(title)+'</h1></div><div class="muted">'+esc(copy)+'</div></div>'+(actions?'<div class="page-actions">'+actions+'</div>':"")+'</div>';}}
function sectionHead(title,copy="",action=""){{return '<div class="section-head"><div><div class="section-title-row">'+uiIcon(ICON_FOR_SECTION[title])+'<h2>'+esc(title)+'</h2></div>'+(copy?'<p>'+esc(copy)+'</p>':"")+'</div>'+action+'</div>';}}
function scanCoverageStatus(incomplete){{
 const label=incomplete?"Coverage incomplete":"No reported coverage gaps";
 return '<span class="badge '+(incomplete?"unresolved":"")+'" aria-label="Scan completeness: '+label+'">'+label+'</span>';
}}
function assessmentState(s){{
 if((s.severity?.critical||0)>0)return {{tone:"critical",label:"Critical review required",count:s.severity.critical,unit:"critical findings",copy:"Critical static findings were detected. Review the affected agents and evidence before deployment or approval."}};
 if((s.severity?.high||0)>0)return {{tone:"high",label:"High-priority review",count:s.severity.high,unit:"high findings",copy:"High-severity static findings were detected. Prioritise the affected agents and attack paths."}};
 if((s.contract_violations||0)>0)return {{tone:"critical",label:"Contract review required",count:s.contract_violations,unit:"contract violations",copy:"Effective authority exceeds at least one declared Authority Contract constraint."}};
 if(s.analysis_incomplete)return {{tone:"warn",label:"Coverage review required",count:s.authority_not_fully_resolved||0,unit:"unresolved relationships",copy:"The scan completed with evidence gaps. Treat conclusions as incomplete until the unresolved authority is reviewed."}};
 return {{tone:"ok",label:"No critical/high findings detected",count:s.findings||0,unit:"total findings",copy:"Within the scanned static evidence, no critical or high-severity finding was detected. Review medium/low findings and coverage before relying on this assessment."}};
}}
function agentAttention(a){{
 if((a.severity?.critical||0)>0)return '<span class="badge critical">critical</span>';
 if((a.severity?.high||0)>0)return '<span class="badge high">high</span>';
 if((a.summary.contract_violations||0)>0)return '<span class="badge violation">contract violation</span>';
 if((a.summary.attack_paths||0)>0)return '<span class="badge unresolved">attack path</span>';
 if((a.summary.contract_unresolved||0)>0)return '<span class="badge unresolved">unresolved</span>';
 return '<span class="badge">no priority signal</span>';
}}
function agentPriority(a){{return (a.severity?.critical||0)*10000+(a.severity?.high||0)*1000+(a.summary.contract_violations||0)*500+(a.summary.attack_paths||0)*100+(a.severity?.medium||0)*20+(a.summary.contract_unresolved||0)*10+(a.summary.write_capable_relationships||0);}}
function severityCards(s,interactive=false){{
 return '<div class="sevbar">'+metric("Critical",s.critical,"critical",interactive?"findings:critical":"")+
 metric("High",s.high,"high",interactive?"findings:high":"")+metric("Medium",s.medium,"medium",interactive?"findings:medium":"")+
 metric("Low",s.low,"low",interactive?"findings:low":"")+'</div>';
}}
function severityChart(s){{
 const levels=[["critical","Critical"],["high","High"],["medium","Medium"],["low","Low"],["info","Info"]];
 const max=Math.max(1,...levels.map(([key])=>Number(s?.[key]||0)));
 const rows=levels.map(([key,label])=>{{
  const count=Math.max(0,Number(s?.[key]||0));
  const width=count?Math.max(3,Math.round(100*count/max)):0;
  return '<div class="severity-chart-row" data-tone="'+key+'" data-present="'+(count>0)+'" role="button" tabindex="0" data-drill="findings:'+key+'" aria-label="'+esc(label)+': '+number(count)+' active findings. Open filtered findings.">'+
   '<span class="severity-chart-head"><span class="severity-chart-label">'+esc(label)+'</span><span class="severity-chart-count">'+number(count)+'</span></span>'+
   '<span class="severity-chart-track" aria-hidden="true"><span class="severity-chart-fill '+key+'" style="width:'+width+'%"></span></span></div>';
 }}).join("");
 return '<div class="severity-chart" role="group" aria-label="Findings by scanner severity">'+rows+
  '<p class="severity-chart-caption">Coloured markers identify severity even when a count is zero. Filled bars represent detected findings; exploitability is not verified.</p></div>';
}}
function authorityResolutionChart(agents){{
 const relationships=agents.flatMap(a=>a.effective_authority||[]);
 const levels=[["fully_resolved","Fully resolved"],["partially_resolved","Partially resolved"],["unknown","Unknown"]];
 if(!relationships.length)return '<div class="panel"><p class="muted">No effective-authority relationships were reconstructed. This is not evidence that agent authority is safe or absent.</p></div>';
 const max=Math.max(1,...levels.map(([key])=>relationships.filter(r=>r.resolution===key).length));
 const rows=levels.map(([key,label])=>{{
  const count=relationships.filter(r=>r.resolution===key).length;
  const width=count?Math.max(3,Math.round(count/max*100)):0;
  return '<button type="button" class="severity-chart-row authority-chart-row" data-tone="'+key+'" data-present="'+(count>0)+'" data-drill="agents:'+key+'" aria-label="'+esc(label)+': '+number(count)+' authority relationships. View affected agents.">'+
   '<span class="severity-chart-head"><span class="severity-chart-label">'+esc(label)+'</span><span class="severity-chart-count">'+number(count)+'</span></span>'+
   '<span class="severity-chart-track" aria-hidden="true"><span class="severity-chart-fill '+key+'" style="width:'+width+'%"></span></span></button>';
 }}).join("");
 return '<div class="severity-chart authority-chart" role="group" aria-label="Effective authority resolution">'+rows+
   '<p class="severity-chart-caption">'+number(relationships.length)+' relationships. Selecting a bar shows agents with matching relationships. Resolution does not imply least privilege, policy compliance or runtime validation.</p></div>';
}}
function findingCard(f){{
 const evidence=(f.evidence||[]).map(x=>"<li>"+esc(x)+"</li>").join("");
 const prov=(f.provenance||[]).map(x=>"<li>"+esc(x.subject)+": "+esc(x.origin)+": "+esc(x.fact)+(x.location?" — "+loc(x.location):"")+"</li>").join("");
 const notes=(f.provenance_digest?.items||[]).map(x=>'<div class="source-note"><div class="source-note-heading"><strong>'+esc(x.subject)+'</strong><span class="muted"> · '+esc(x.origin)+' · '+loc(x.location)+'</span></div><div>'+esc(x.summary)+'</div></div>').join("");
 const additional=f.provenance_digest?.additional_contexts||0;
 const context=notes?'<div class="source-context"><div class="source-context-title">Source context <span class="muted">· static evidence, not verified enforcement</span></div>'+notes+(additional?'<div class="muted small">+'+number(additional)+' more source context(s) at this location in full provenance</div>':"")+'</div>':"";
 const agent=f.agent?'<span class="pill">agent: '+esc(f.agent)+'</span>':"";
 const policy=f.assessment==="policy_violation"?'<span class="pill">policy violation</span>':"";
 const owasp=(f.standards?.owasp_agentic||[]).map(x=>'<span class="pill">OWASP '+esc(x)+'</span>').join("");
 return '<article class="finding" data-sev="'+esc(f.severity)+'"><div class="finding-head"><div><div class="finding-title"><strong>'+esc(f.rule_id)+'</strong><span class="badge '+esc(f.severity)+'">'+esc(String(f.severity).toUpperCase())+'</span>'+agent+'</div><div class="finding-name">'+esc(f.title)+'</div></div><span class="muted small">'+loc(f.location)+'</span></div>'+
 '<div class="finding-meta"><span>'+esc(f.assessment||"static")+' assessment</span>'+policy+owasp+'</div><p>'+esc(f.message)+'</p>'+context+
 (evidence?'<details><summary>Finding evidence ('+number(f.evidence.length)+')</summary><ul>'+evidence+'</ul></details>':"")+
 (prov?'<details><summary>Full provenance ('+number(f.provenance.length)+' raw facts)</summary><ul>'+prov+'</ul></details>':"")+
 (f.recommendation?'<details><summary>Remediation</summary><p>'+esc(f.recommendation)+'</p></details>':"")+'</article>';
}}

function owaspAssessmentChart(categories){{
 const statuses=[["finding","Runtime findings"],["no_runtime_findings","Mapped findings (none runtime-classified)"],["no_mapped_findings","No mapped findings"],["not_assessed","Not assessed"]];
 if(!categories.length)return '<div class="empty">No OWASP assessment categories were supplied with this report.</div>';
 const max=Math.max(1,...statuses.map(([key])=>categories.filter(c=>owaspStatusLabel(c).replaceAll(" ","_")===key).length));
 const rows=statuses.map(([key,label])=>{{
  const count=categories.filter(c=>owaspStatusLabel(c).replaceAll(" ","_")===key).length;
  const width=count?Math.max(3,Math.round(100*count/max)):0;
  return '<button type="button" class="severity-chart-row authority-chart-row owasp-chart-row" data-tone="'+key+'" data-present="'+(count>0)+'" data-drill="owasp:status.'+key+'" aria-label="'+esc(label)+': '+number(count)+' of '+number(categories.length)+' OWASP categories. View matching categories.">'+
   '<span class="severity-chart-head"><span class="severity-chart-label">'+esc(label)+'</span><span class="severity-chart-count">'+number(count)+' / '+number(categories.length)+'</span></span>'+
   '<span class="severity-chart-track" aria-hidden="true"><span class="severity-chart-fill '+key+'" style="width:'+width+'%"></span></span></button>';
 }}).join("");
 return '<div class="severity-chart owasp-chart" role="group" aria-label="OWASP Agentic Top 10 assessment states">'+rows+
 '<p class="severity-chart-caption">Detector coverage is not proof of security. Not assessed means no enabled mapped detector; no mapped findings does not imply safe.</p></div>';
}}
function renderDashboard(){{
 const s=DATA.summary,state=assessmentState(s),root=document.getElementById("dashboard");
 const attention=DATA.agents.filter(a=>a.summary.findings||a.summary.contract_violations||a.summary.contract_unresolved||a.summary.attack_paths).sort((a,b)=>agentPriority(b)-agentPriority(a)).slice(0,10);
 const drillRow=(label,value,drill,cls="")=>'<div class="drill-row" role="button" tabindex="0" data-drill="'+esc(drill)+'"><span>'+esc(label)+'</span><span class="drill-value '+esc(cls)+'">'+number(value)+'</span></div>';
 const drillList=(rows)=>'<div class="drill-list">'+rows.join("")+'</div>';
 const primaryDrill=(s.severity?.critical||0)?"findings:critical":((s.severity?.high||0)?"findings:high":(s.contract_violations?"contracts:violation":"findings:all"));
 root.innerHTML='<div class="report-context">Repository security · Source-backed assessment</div>'+pageHead("Repository overview","Security assessment","Prioritised static evidence for effective authority, findings, attack paths and declared agent contracts.",scanCoverageStatus(s.analysis_incomplete))+
 '<div class="assessment-banner '+esc(state.tone)+'" data-drill="'+primaryDrill+'" role="button" tabindex="0"><div><div class="eyebrow">Assessment signal</div><div class="assessment-title '+esc(state.tone)+'">'+esc(state.label)+'</div><div class="assessment-copy">'+esc(state.copy)+'</div></div><div class="assessment-side"><div class="assessment-count">'+number(state.count)+'<small>'+esc(state.unit)+'</small></div></div></div>'+
 '<div class="cards">'+metric("Active findings",s.findings,(s.severity?.critical||s.severity?.high)?"high":"","Critical "+number(s.severity?.critical||0)+" · High "+number(s.severity?.high||0))+metric("Policy violations",s.policy_violations,s.policy_violations?"critical":"","policy:all","Configured HorusTrace policy rules")+metric("Contract violations",s.contract_violations,s.contract_violations?"critical":"","contracts:violation",number(s.contract_unresolved)+" unresolved checks")+metric("OWASP categories with findings",s.owasp_categories_with_findings,s.owasp_categories_with_findings?"warn":"","owasp:all",number(s.owasp_categories_not_assessed)+" not assessed")+metric("Agents",s.agents,"","agents:all",number(s.write_capable_relationships)+" write-capable relationships")+metric("Attack paths",s.attack_paths,"","attack:all","Static evidence; exploitability not verified")+'</div>'+
 sectionHead("Priority review queue","Agents ordered by static review priority.")+agentTable(attention)+
 '<div class="grid2"><div>'+sectionHead("Finding severity","Active findings by scanner severity.") +severityChart(s.severity)+'</div><div>'+sectionHead("Effective agency","Reconstructed authority and destination scope.")+authorityResolutionChart(DATA.agents)+'<div class="panel">'+drillList([drillRow("Authority relationships",s.authority_relationships,"agents:authority"),drillRow("Not fully resolved",s.authority_not_fully_resolved,"agents:unresolved","warn"),drillRow("Write-capable relationships",s.write_capable_relationships,"agents:write"),drillRow("Unique destinations",s.destinations,"agents:destinations")])+'</div></div></div>'+
 sectionHead("OWASP assessment states","Mapped detector coverage and finding categories; not an assurance score.")+owaspAssessmentChart(DATA.owasp_agentic.categories||[])+
 '<div class="grid2"><div>'+sectionHead("Environment inventory","Security-relevant components found in the scan.")+'<div class="cards">'+metric("Tools",s.tools,"","components:tools")+metric("Skills",s.skills,"","components:skills",number(s.bound_skills)+" bound · "+number(s.unbound_skills)+" unbound")+metric("MCP servers",s.mcp_servers,"","components:mcp")+metric("Identities",s.identities,"","agents:identities")+metric("Resources",s.resources,"","agents:resources")+'</div></div><div>'+sectionHead("Agent contracts","Declared authority compared with effective authority.")+'<div class="panel">'+drillList(['<div class="drill-row" style="cursor:default"><span>Overall status</span><span>'+badge(DATA.assurance.authority_contract.status)+'</span></div>',drillRow("Agents with contract",s.agents_with_contract,"contracts:declared"),drillRow("Violations",s.contract_violations,"contracts:violation","critical"),drillRow("Unresolved checks",s.contract_unresolved,"contracts:unresolved","warn")])+'</div></div></div>';
 bindDashboardDrill(root);bindAgentRows(root);
}}

function drillLabel(kind,value){{
 const labels={{
  "agents:all":"All agents","agents:tools":"Agents with tools","agents:skills":"Agents with bound skills","agents:mcp":"Agents with MCP servers",
  "agents:identities":"Agents with resolved identities","agents:resources":"Agents reaching resources",
  "agents:authority":"Agents with effective authority","agents:unresolved":"Agents with unresolved authority",
  "agents:write":"Agents with write-capable authority","agents:destinations":"Agents with external destinations",
   "agents:fully_resolved":"Agents with fully resolved relationships","agents:partially_resolved":"Agents with partially resolved relationships","agents:unknown":"Agents with unknown relationships",
  "findings:all":"All findings","findings:critical":"Critical findings","findings:high":"High findings",
  "findings:medium":"Medium findings","findings:low":"Low findings","policy:all":"Organisation policy violations",
  "owasp:all":"OWASP Agentic Top 10","contracts:declared":"Agents with declared contracts",
  "contracts:violation":"Agents with contract violations","contracts:unresolved":"Agents with unresolved contract checks",
  "attack:all":"Attack paths","agents:attention":"Agents needing attention","agents:attack":"Agents with attack paths","agents:contract":"Agents with contract issues"
 }};
 return labels[kind+":"+value]||"Dashboard filter";
}}
function routeDrill(action){{
 const [kind,value="all"]=String(action).split(":",2);
 if(kind==="agents"){{renderAgents(value);showView("agents");}}
 else if(kind==="components"){{renderComponents(value);showView("components");}}
 else if(kind==="supply"){{renderSupplyChain();showView("supply");}}
 else if(kind==="findings"){{renderFindings(value);showView("findings");}}
 else if(kind==="policy"){{renderPolicy();showView("policy");}}
 else if(kind==="owasp"){{renderOwasp(value);showView("owasp");}}
 else if(kind==="contracts"){{renderContracts(value);showView("contracts");}}
 else if(kind==="attack"){{renderAttack();showView("attack");}}
}}
function bindDashboardDrill(root=document){{
 root.querySelectorAll("[data-drill]").forEach(el=>{{
   const activate=()=>routeDrill(el.dataset.drill);
   el.addEventListener("click",activate);
   if(el.tagName!=="BUTTON")el.addEventListener("keydown",event=>{{if(event.key==="Enter"||event.key===" "){{event.preventDefault();activate();}}}});
 }});
}}
function agentTable(items){{
 if(!items.length)return '<div class="empty">No agents matched this view.</div>';
 const rows=items.map(a=>'<tr class="clickable" role="button" tabindex="0" data-agent="'+encodeURIComponent(a.name)+'"><td><div class="row-title">'+esc(a.name)+'</div><div class="row-sub">'+esc(a.framework)+' · '+loc(a.location)+'</div></td><td>'+agentAttention(a)+'</td><td>'+badge(a.summary.contract_status)+'</td><td>'+number(a.summary.findings)+'</td><td>'+number(a.summary.attack_paths)+'</td><td>'+number(a.summary.authority_relationships)+'</td><td>'+number(a.summary.write_capable_relationships)+'</td><td class="row-chevron">›</td></tr>').join("");
 return '<div class="panel flush table-wrap"><table><thead><tr><th>Agent</th><th>Attention</th><th>Contract</th><th>Findings</th><th>Attack paths</th><th>Authority</th><th>Write-capable</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div>';
}}

function bindAgentRows(root=document){{
 root.querySelectorAll("[data-agent]").forEach(row=>{{const activate=()=>openAgent(decodeURIComponent(row.dataset.agent));row.addEventListener("click",activate);row.addEventListener("keydown",event=>{{if(event.key==="Enter"||event.key===" "){{event.preventDefault();activate();}}}});}});
}}

function agentMatchesFilter(a,mode){{
 if(mode==="attention")return a.summary.findings>0||a.summary.attack_paths>0||a.summary.contract_violations>0||a.summary.contract_unresolved>0;
 if(mode==="attack")return a.summary.attack_paths>0;
 if(mode==="contract")return a.summary.contract_violations>0||a.summary.contract_unresolved>0;
 if(mode==="tools")return a.summary.tools>0;if(mode==="skills")return a.summary.skills>0;if(mode==="mcp")return a.summary.mcp_servers>0;if(mode==="identities")return a.summary.identities>0;if(mode==="resources")return a.summary.resources>0;if(mode==="authority")return a.summary.authority_relationships>0;
 if(["fully_resolved","partially_resolved","unknown"].includes(mode))return (a.effective_authority||[]).some(r=>r.resolution===mode);
 if(mode==="unresolved")return (a.effective_authority||[]).some(r=>r.resolution!=="fully_resolved");if(mode==="write")return a.summary.write_capable_relationships>0;if(mode==="destinations")return a.summary.destinations>0;return true;
}}

function renderAgents(mode="all"){{
 const root=document.getElementById("agents"),scoped=DATA.agents.filter(a=>agentMatchesFilter(a,mode)).sort((a,b)=>agentPriority(b)-agentPriority(a)||a.name.localeCompare(b.name));
 const filters=[["all","All"],["attention","Needs attention"],["attack","Attack paths"],["write","Write-capable"],["contract","Contract issues"],["fully_resolved","Fully resolved"],["partially_resolved","Partially resolved"],["unknown","Unknown"]];
 const chips=filters.map(([value,label])=>'<button class="filter-chip '+(mode===value?"active":"")+'" data-agent-filter="'+value+'">'+esc(label)+'</button>').join("");
 const banner=mode==="all"?"":'<div class="filter-banner"><span>'+esc(drillLabel("agents",mode))+' · '+number(scoped.length)+' agents</span><button class="back" id="clear-agent-filter">Clear filter</button></div>';
 root.innerHTML=pageHead("Inventory","Agents","Review effective agency, attack paths, findings and Authority Contract posture for each discovered agent.")+banner+'<div class="toolbar"><div class="toolbar-left"><div class="filter-chips">'+chips+'</div></div><div class="toolbar-right"><input id="agent-search" class="search" aria-label="Search agents" placeholder="Search agents, frameworks, identities or resources"></div></div><div class="muted small" id="agent-count">'+number(scoped.length)+' agents</div><div id="agent-table">'+agentTable(scoped)+'</div>';
 bindAgentRows(root);root.querySelectorAll("[data-agent-filter]").forEach(btn=>btn.addEventListener("click",()=>renderAgents(btn.dataset.agentFilter)));if(mode!=="all")root.querySelector("#clear-agent-filter").addEventListener("click",()=>renderAgents("all"));
 root.querySelector("#agent-search").addEventListener("input",e=>{{const q=e.target.value.trim().toLowerCase();const items=scoped.filter(a=>JSON.stringify([a.name,a.framework,a.location,a.skills,a.resources,a.identities,a.destinations,a.findings]).toLowerCase().includes(q));root.querySelector("#agent-count").textContent=number(items.length)+" agents";root.querySelector("#agent-table").innerHTML=agentTable(items);bindAgentRows(root);}});
}}

function inventoryEntries(kind){{
 return kind==="tools"?(DATA.tools||[]):kind==="skills"?(DATA.skills||[]):(DATA.mcp_servers||[]);
}}
function inventoryControl(value){{
 return value===true?"Configured/detected (not verified)":value===false?"Not detected":"Unresolved";
}}
function inventorySummary(item,kind){{
 if(kind==="mcp")return item.endpoint||item.command||"Endpoint unresolved";
 if(kind==="tools")return (item.capabilities||[]).join(", ")||"Capabilities unresolved";
 return (item.allowed_tools||[]).join(", ")||"No allowed tools declared";
}}
function inventoryTable(items,kind){{
 if(!items.length)return '<div class="empty">No matching components in this scan.</div>';
 const rows=items.map(item=>'<tr class="clickable" role="button" tabindex="0" data-inventory-row="'+esc(item.id)+'">'+
 '<td><div class="row-title">'+esc(item.name)+'</div><div class="row-sub">'+esc(kind==="mcp"?(item.transport||"unknown transport"):kind==="tools"?(item.kind||"tool"):(item.source||"skill"))+' · '+loc(item.location)+'</div></td>'+
 '<td>'+badge(item.binding_state)+'</td><td>'+esc((item.bound_agents||[]).join(", ")||"—")+'</td>'+
 '<td>'+esc(inventorySummary(item,kind))+'</td><td class="row-chevron">›</td></tr>').join("");
 return '<div class="panel flush table-wrap"><table aria-label="'+esc(kind)+' inventory"><thead><tr><th>Component</th><th>Binding</th><th>Agent(s)</th><th>Capabilities / endpoint</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div>';
}}
function inventoryDetail(item,kind){{
 const format=(values)=>values&&values.length?values.join(", "):"—";
 const resource=(item.resources||[]).map(r=>r.kind+": "+r.selector+" ("+format(r.access)+")").join("; ")||"—";
 const meta=[["Binding",item.binding_state],["Source",item.location?(item.location.path+":"+(item.location.line||1)):"n/a"]];
 if(kind==="mcp")meta.push(["Transport",item.transport||"unresolved"],["Endpoint (query omitted)",item.endpoint||"—"],["Command (arguments omitted)",item.command||"—"],["Authentication",inventoryControl(item.authenticated)],["Approval",inventoryControl(item.approval)],["Guardrail hook",inventoryControl(item.guardrails)],["Allowed tools",format(item.allowed_tools)],["Denied tools",format(item.denied_tools)],["Identity",item.identity||"unresolved"]);
 else if(kind==="tools")meta.push(["Tool kind",item.kind||"—"],["Capabilities",format(item.capabilities)],["Destinations",format(item.destinations)],["Approval",inventoryControl(item.approval)],["Guardrail hook",inventoryControl(item.guardrails)],["Identity",item.identity||"unresolved"]);
 else meta.push(["Description",item.description||"—"],["Skill source",item.source||"unknown"],["Capabilities",format(item.capabilities)],["Allowed tools",format(item.allowed_tools)],["Scripts",format(item.scripts)],["Destinations",format(item.destinations)]);
 meta.push(["Resources",resource]);
 const details=meta.map(([label,value])=>'<div>'+esc(label)+'</div><div>'+esc(value)+'</div>').join("");
 const agents=(item.bound_agents||[]).map(name=>'<button class="filter-chip" type="button" data-inventory-agent="'+encodeURIComponent(name)+'">'+uiIcon("agents")+esc(name)+' ↗</button>').join("");
 return '<div id="inventory-detail">'+sectionHead(item.name,"Source-backed instance: "+kind,'<button type="button" id="inventory-clear" class="back">Close detail</button>')+
 '<div class="panel"><div class="kv">'+details+'</div></div>'+
 sectionHead("Connected agents","A binding does not mean that every agent finding applies to this component.")+
 (agents?'<div class="filter-chips">'+agents+'</div>':'<div class="empty">No source-proven agent binding.</div>')+'</div>';
}}
function renderComponents(kind="mcp",selectedId=null){{
 if(!["mcp","tools","skills"].includes(kind))kind="mcp";
 const root=document.getElementById("components"),items=inventoryEntries(kind),selected=items.find(item=>item.id===selectedId);
 const tabs=[["mcp","MCP servers"],["tools","Tools"],["skills","Skills"]].map(([key,label])=>
 '<button type="button" class="filter-chip '+(kind===key?"active":"")+'" data-inventory-kind="'+key+'">'+uiIcon(key==="mcp"?"mcp":key)+esc(label)+' ('+number(inventoryEntries(key).length)+')</button>').join("");
 root.innerHTML=pageHead("Repository inventory","Components","Search discovered component instances, bindings and source evidence. This is a static inventory, not live deployment discovery.")+
 '<div class="cards">'+metric("MCP servers",(DATA.mcp_servers||[]).filter(x=>x.binding_state!=="unresolved_reference").length)+metric("Tools",(DATA.tools||[]).length)+metric("Skills",(DATA.skills||[]).length)+metric("Unresolved references",(DATA.mcp_servers||[]).filter(x=>x.binding_state==="unresolved_reference").length)+'</div>'+
 '<div class="toolbar"><div class="filter-chips">'+tabs+'</div><div class="toolbar-right"><input id="inventory-search" class="search" aria-label="Search inventory" placeholder="Search component, capability, agent or file"></div></div>'+
 (selected?inventoryDetail(selected,kind):"")+
 '<div class="toolbar"><div class="filter-chips">'+[["all","All"],["bound","Bound"],["unbound","Unbound"],["unresolved_reference","Unresolved"]].map(([key,label])=>'<button type="button" class="filter-chip '+(key==="all"?"active":"")+'" data-inventory-filter="'+key+'">'+label+'</button>').join("")+'</div><span class="muted small" id="inventory-count"></span></div><div id="inventory-table"></div>';
 let filter="all";const input=root.querySelector("#inventory-search");
 const update=()=>{{
  const q=input.value.toLowerCase().trim();
  const scoped=items.filter(item=>(filter==="all"||item.binding_state===filter)&&(!q||JSON.stringify(item).toLowerCase().includes(q)));
  root.querySelector("#inventory-count").textContent=number(scoped.length)+" detected instances";
  root.querySelector("#inventory-table").innerHTML=inventoryTable(scoped,kind);
  root.querySelectorAll("[data-inventory-row]").forEach(row=>{{
   const activate=()=>{{renderComponents(kind,row.dataset.inventoryRow);const detail=root.querySelector("#inventory-detail");if(detail)detail.scrollIntoView({{block:"start"}});}};
   row.addEventListener("click",activate);
   row.addEventListener("keydown",event=>{{if(event.key==="Enter"||event.key===" "){{event.preventDefault();activate();}}}});
  }});
 }};
 root.querySelectorAll("[data-inventory-kind]").forEach(btn=>btn.addEventListener("click",()=>renderComponents(btn.dataset.inventoryKind)));
 root.querySelectorAll("[data-inventory-filter]").forEach(btn=>btn.addEventListener("click",()=>{{filter=btn.dataset.inventoryFilter;root.querySelectorAll("[data-inventory-filter]").forEach(x=>x.classList.toggle("active",x===btn));update();}}));
 input.addEventListener("input",update);
 const clear=root.querySelector("#inventory-clear");if(clear)clear.addEventListener("click",()=>renderComponents(kind));
 root.querySelectorAll("[data-inventory-agent]").forEach(btn=>btn.addEventListener("click",()=>openAgent(decodeURIComponent(btn.dataset.inventoryAgent),"overview",null,{{kind,id:selected.id}})));
 update();
}}

function contractItem(item){{
 return '<div class="finding" data-sev="'+(item.status==="violation"?"high":"medium")+'"><div class="finding-title">'+badge(item.status)+
 '<strong>'+esc(item.clause)+'</strong><span>'+esc(item.reason)+'</span></div><div class="kv small"><div>Dimension</div><div>'+esc(item.dimension)+'</div>'+
 '<div>Expected</div><div>'+esc((item.expected||[]).join(", ")||"—")+'</div><div>Observed</div><div>'+esc((item.observed||[]).join(", ")||"—")+'</div>'+
 '<div>Contract evidence</div><div>'+loc(item.contract_location)+'</div><div>Authority evidence</div><div>'+loc(item.relationship_location)+'</div></div></div>';
}}
function renderAgentOverview(a){{
 const state=agentAttention(a);
 return '<div class="cards">'+metric("Tools",a.summary.tools)+metric("Skills",a.summary.skills)+metric("MCP servers",a.summary.mcp_servers)+metric("Authority paths",a.summary.authority_relationships)+metric("Resources",a.summary.resources)+metric("Write-capable",a.summary.write_capable_relationships)+metric("Findings",a.summary.findings)+'</div>'+
 '<div class="grid2"><div>'+sectionHead("Effective scope","Resolved skill, identity, resource and destination scope.")+'<div class="panel"><div class="kv"><div>Review signal</div><div>'+state+'</div><div>Skills</div><div>'+esc((a.skills||[]).map(s=>s.name).join(", ")||"none")+'</div><div>Identities</div><div>'+esc(a.identities.join(", ")||"unresolved / none")+'</div><div>Resources</div><div>'+esc(a.resources.join(", ")||"unresolved / none")+'</div><div>Destinations</div><div>'+esc(a.destinations.join(", ")||"unresolved / none")+'</div></div></div></div>'+
 '<div>'+sectionHead("Contract posture","Declared contract versus reconstructed authority.")+'<div class="panel"><div class="kv"><div>Status</div><div>'+badge(a.summary.contract_status)+'</div><div>Violations</div><div>'+number(a.summary.contract_violations)+'</div><div>Unresolved</div><div>'+number(a.summary.contract_unresolved)+'</div><div>Attack paths</div><div>'+number(a.summary.attack_paths)+'</div></div></div></div></div>'+
 sectionHead("Finding severity","Scanner findings attributed to this agent.")+severityCards(a.severity);
}}

function renderGraph(a){{
 const rels=a.effective_authority||[];
 if(!rels.length)return '<div class="empty">No effective-authority relationships were reconstructed for this agent.</div>';
 return '<div class="map-toolbar"><input id="map-search" aria-label="Search agency map" placeholder="Find tool, MCP, identity, resource or destination">'+
 '<button class="map-btn" id="map-toggle-groups">Expand all</button><button class="map-btn" id="map-zoom-out" aria-label="Zoom out">−</button><button class="map-btn" id="map-zoom-in" aria-label="Zoom in">+</button><button class="map-btn" id="map-fit">Fit</button><button class="map-btn" id="map-fullscreen" aria-pressed="false">Expand map</button></div>'+
 '<div class="map-hint">Select a node to inspect evidence. Drag the canvas to pan; use the mouse wheel or controls to zoom.</div>'+
 '<div class="legend"><span><i class="dot" style="background:#78a8ff"></i>Agent</span><span><i class="dot" style="background:#6f84aa"></i>Tool / MCP</span><span><i class="dot" style="background:#a895ff"></i>Identity</span><span><i class="dot" style="background:#63d69f"></i>Resource</span><span><i class="dot" style="background:#f1b36a"></i>Destination</span></div>'+
 '<div class="graph-wrap" id="agency-map-shell"><div class="graph-canvas"><svg class="graph" id="agency-svg" viewBox="0 0 1080 520" preserveAspectRatio="xMidYMid meet" aria-label="Effective agency map"><g id="agency-stage"></g></svg></div><div class="panel inspector" id="graph-inspector"><div class="eyebrow">Evidence</div><h3>Path inspector</h3><p class="muted">Select a graph node to inspect the authority evidence behind it.</p></div></div>';
}}

function svgNode(x,y,w,label,sub,kind,key,unresolved=false){{
 const cls="node "+kind+(unresolved?" unresolved":"");
 return '<g class="'+cls+'" data-node="'+esc(key)+'" data-label="'+esc((label+" "+sub).toLowerCase())+'" transform="translate('+x+','+y+')"><rect width="'+w+'" height="54" rx="8"></rect>'+
 '<text x="12" y="22">'+esc(label.length>28?label.slice(0,26)+"…":label)+'</text><text class="label2" x="12" y="40">'+esc(sub)+'</text></g>';
}}
const AGENCY_GRAPH_STATE=new Map();
function agencyState(a){{
 if(!AGENCY_GRAPH_STATE.has(a.name))AGENCY_GRAPH_STATE.set(a.name,{{collapsed:(a.effective_authority||[]).length>6,scale:1,tx:0,ty:0,selected:null}});
 return AGENCY_GRAPH_STATE.get(a.name);
}}
function applyGraphTransform(a){{
 const stage=document.getElementById("agency-stage"); if(!stage)return;
 const state=agencyState(a);
 stage.setAttribute("transform","translate("+state.tx+" "+state.ty+") scale("+state.scale+")");
}}
function graphEdge(x1,y1,x2,y2,from,to){{
 return '<line class="edge" data-from="'+esc(from)+'" data-to="'+esc(to)+'" x1="'+x1+'" y1="'+y1+'" x2="'+x2+'" y2="'+y2+'"></line>';
}}
function inspectGraphNode(a,key,item){{
 const panel=document.getElementById("graph-inspector"); if(!panel)return;
 panel.innerHTML='<h3>'+esc(item.name||item.target?.name||item.selector||item.target||item.label||a.name)+'</h3>'+
 '<div style="display:flex;gap:7px;margin-bottom:8px"><button class="map-btn" id="focus-node">Focus</button><button class="map-btn" id="clear-focus">Clear focus</button></div>'+
 '<pre>'+esc(JSON.stringify(item,null,2))+'</pre>';
 panel.querySelector("#focus-node").addEventListener("click",()=>focusGraphNode(key));
 panel.querySelector("#clear-focus").addEventListener("click",()=>focusGraphNode(null));
}}
function focusGraphNode(key){{
 const svg=document.getElementById("agency-svg"); if(!svg)return;
 const neighbours=new Set(key?[key]:[]);
 if(key){{
   svg.querySelectorAll(".edge").forEach(edge=>{{
     if(edge.dataset.from===key||edge.dataset.to===key){{neighbours.add(edge.dataset.from);neighbours.add(edge.dataset.to);edge.classList.add("selected");edge.classList.remove("dim");}}
     else{{edge.classList.remove("selected");edge.classList.add("dim");}}
   }});
 }}else svg.querySelectorAll(".edge").forEach(edge=>edge.classList.remove("selected","dim"));
 svg.querySelectorAll(".node").forEach(node=>{{
   const selected=key&&node.dataset.node===key;
   node.classList.toggle("selected",Boolean(selected));
   node.classList.toggle("dim",Boolean(key&&!neighbours.has(node.dataset.node)));
 }});
}}
function filterGraph(query){{
 const svg=document.getElementById("agency-svg"); if(!svg)return;
 const q=String(query||"").trim().toLowerCase();
 svg.querySelectorAll(".node").forEach(node=>{{
   const match=!q||String(node.dataset.label||"").includes(q);
   node.classList.toggle("match",Boolean(q&&match));
   node.classList.toggle("dim",Boolean(q&&!match));
 }});
 svg.querySelectorAll(".edge").forEach(edge=>edge.classList.toggle("dim",Boolean(q)));
}}
function bindGraphControls(a){{
 const state=agencyState(a),svg=document.getElementById("agency-svg"),shell=document.getElementById("agency-map-shell");
 if(!svg||!shell||shell.dataset.bound==="1")return; shell.dataset.bound="1";
 const groupBtn=document.getElementById("map-toggle-groups"),fullBtn=document.getElementById("map-fullscreen");
 const updateGroupLabel=()=>groupBtn.textContent=state.collapsed?"Expand all":"Collapse groups"; updateGroupLabel();
 groupBtn.addEventListener("click",()=>{{state.collapsed=!state.collapsed;state.selected=null;drawGraph(a);updateGroupLabel();}});
 document.getElementById("map-zoom-in").addEventListener("click",()=>{{state.scale=Math.min(3,state.scale*1.2);applyGraphTransform(a);}});
 document.getElementById("map-zoom-out").addEventListener("click",()=>{{state.scale=Math.max(.35,state.scale/1.2);applyGraphTransform(a);}});
 document.getElementById("map-fit").addEventListener("click",()=>{{state.scale=1;state.tx=0;state.ty=0;applyGraphTransform(a);focusGraphNode(null);}});
 const setExpanded=(expanded)=>{{shell.classList.toggle("expanded",expanded);document.body.classList.toggle("graph-modal-open",expanded);fullBtn.textContent=expanded?"Exit full screen":"Expand map";fullBtn.setAttribute("aria-pressed",String(expanded));}};
 fullBtn.addEventListener("click",()=>setExpanded(!shell.classList.contains("expanded")));
 document.getElementById("map-search").addEventListener("input",event=>filterGraph(event.target.value));
 svg.addEventListener("wheel",event=>{{event.preventDefault();state.scale=Math.max(.35,Math.min(3,state.scale*(event.deltaY<0?1.1:.9)));applyGraphTransform(a);}},{{passive:false}});
 let dragging=false,lastX=0,lastY=0;
 svg.addEventListener("pointerdown",event=>{{if(event.target.closest(".node"))return;dragging=true;lastX=event.clientX;lastY=event.clientY;svg.classList.add("panning");svg.setPointerCapture(event.pointerId);}});
 svg.addEventListener("pointermove",event=>{{if(!dragging)return;state.tx+=(event.clientX-lastX)/state.scale;state.ty+=(event.clientY-lastY)/state.scale;lastX=event.clientX;lastY=event.clientY;applyGraphTransform(a);}});
 const stop=()=>{{dragging=false;svg.classList.remove("panning");}};svg.addEventListener("pointerup",stop);svg.addEventListener("pointercancel",stop);
 document.addEventListener("keydown",event=>{{if(event.key==="Escape"&&shell.classList.contains("expanded"))setExpanded(false);}});
}}

function drawGraph(a){{
 const svg=document.getElementById("agency-svg"), stage=document.getElementById("agency-stage"); if(!svg||!stage)return;
 const state=agencyState(a), rels=a.effective_authority||[], nodes=[],edges=[],info={{}};
 if(state.collapsed&&rels.length>6){{
   const groups={{tools:rels.filter(r=>r.target.kind!=="mcp_server"),mcp:rels.filter(r=>r.target.kind==="mcp_server")}};
   const visible=Object.entries(groups).filter(([,items])=>items.length);
   const height=Math.max(520,140+visible.length*100),center=height/2-27;svg.setAttribute("viewBox","0 0 1080 "+height);
   nodes.push(svgNode(60,center,190,a.name,a.framework,"agent","agent"));info.agent={{type:"Agent",name:a.name,location:a.location,framework:a.framework}};
   visible.forEach(([kind,items],i)=>{{const y=center+(i-(visible.length-1)/2)*95,k="group-"+kind,label=kind==="mcp"?"MCP servers":"Tools";
     edges.push(graphEdge(250,center+27,390,y+27,"agent",k));nodes.push(svgNode(390,y,230,label+" ("+items.length+")","click to expand","target",k,false));
     info[k]={{name:label,count:items.length,targets:items.map(r=>r.target.name)}};}});
 }}else{{
   const height=Math.max(520,80+rels.length*68),row=Math.max(62,(height-80)/Math.max(1,rels.length)),center=height/2-27;svg.setAttribute("viewBox","0 0 1080 "+height);
   nodes.push(svgNode(30,center,185,a.name,a.framework,"agent","agent"));info.agent={{type:"Agent",name:a.name,location:a.location,framework:a.framework}};
   rels.forEach((r,i)=>{{const y=24+i*row,targetKey="target-"+i;
     edges.push(graphEdge(215,center+27,300,y+27,"agent",targetKey));nodes.push(svgNode(300,y,205,r.target.name,r.target.kind,"target",targetKey,r.resolution!=="fully_resolved"));info[targetKey]=r;
     let prevX=505,prevY=y+27,prevKey=targetKey;
     if(r.identity){{const k="identity-"+i;edges.push(graphEdge(prevX,prevY,570,prevY,prevKey,k));nodes.push(svgNode(570,y,190,r.identity.name,r.identity.provider||"identity","identity",k,r.dimensions.identity!=="resolved"));info[k]=r.identity;prevX=760;prevKey=k;}}
     const outputs=[];(r.resources||[]).slice(0,3).forEach(x=>outputs.push(["resource",x.selector,x.kind,x]));(r.destinations||[]).slice(0,2).forEach(x=>outputs.push(["destination",x.target,x.direction,x]));
     outputs.forEach((o,j)=>{{const oy=y+(j-(outputs.length-1)/2)*58,k=o[0]+"-"+i+"-"+j;edges.push(graphEdge(prevX,prevY,825,oy+27,prevKey,k));nodes.push(svgNode(825,oy,220,o[1],o[2],o[0],k,false));info[k]=o[3];}});
   }});
 }}
 stage.innerHTML=edges.join("")+nodes.join("");applyGraphTransform(a);
 stage.querySelectorAll("[data-node]").forEach(n=>n.addEventListener("click",()=>{{const key=n.dataset.node;if(key&&key.startsWith("group-")){{state.collapsed=false;drawGraph(a);const btn=document.getElementById("map-toggle-groups");if(btn)btn.textContent="Collapse groups";return;}}inspectGraphNode(a,key,info[key]);focusGraphNode(key);}}));
}}
function pathStep(step){{
 return '<div class="path-step '+esc(step.kind||"step")+'"><div class="path-role">'+esc(step.role||step.kind||"step")+'</div><strong>'+esc(step.label||"")+'</strong></div>';
}}
function renderPathCard(path){{
 const dashed=path.edge_style==="dashed", steps=path.steps||[];
 const chain=steps.map((step,i)=>pathStep(step)+(i<steps.length-1?'<div class="path-arrow '+(dashed?"dashed":"")+'"></div>':"")).join("");
 const basis=path.evidence_strength==="supported_static_dataflow"?"Supported static data flow":"Potential capability path";
 return '<div class="path-card"><div class="path-head"><div><div class="finding-title"><strong>'+esc(path.path_id)+'</strong><span class="'+esc(path.severity)+'">'+esc(String(path.severity).toUpperCase())+'</span></div>'+
 '<h3 style="margin-top:7px">'+esc(path.title)+'</h3></div><span class="badge '+(dashed?"unresolved":"compliant")+'">'+esc(basis)+'</span></div>'+
 '<p class="muted">'+esc(path.rationale||"")+'</p><div class="path-chain">'+chain+'</div>'+
 '<div class="path-meta"><span class="pill">basis: '+esc(path.basis||"unknown")+'</span><span class="pill">runtime exploitability: '+esc(path.metadata?.exploitability||"not verified")+'</span></div></div>';
}}
function renderAgentPaths(a){{
 const paths=a.path_views||[];
 if(!paths.length)return '<div class="empty">No attack path was reconstructed for this agent. Effective authority may still exist; a path is shown only when HorusTrace has the required source/capability evidence.</div>';
 return '<p class="muted">Solid connectors represent supported static data flow. Dashed connectors represent capability co-occurrence: the components are present on the same agent, but executable data flow is not proven.</p>'+paths.map(renderPathCard).join("");
}}
function renderAgentFindings(a,owaspRisk=null){{
 const items=owaspRisk?a.findings.filter(f=>(f.standards?.owasp_agentic||[]).includes(owaspRisk)):a.findings;
 const filter=owaspRisk?'<div class="filter-banner"><span>OWASP '+esc(owaspRisk)+' · '+number(items.length)+' mapped findings for this agent</span><button class="back" id="clear-agent-owasp">Show all agent findings</button></div>':"";
 return filter+(items.length?items.map(findingCard).join(""):'<div class="empty">No findings matched this agent and OWASP category.</div>');
}}
function renderAgentContract(a){{
 const c=a.contract;
 if(!c.declared)return '<div class="empty">No Authority Contract is declared for this agent.</div>';
 const items=[...(c.violations||[]),...(c.unresolved||[])];
 return '<div class="grid2"><div class="panel"><h3>Declared contract</h3><pre>'+esc(JSON.stringify(c.declared,null,2))+'</pre></div>'+
 '<div><div class="cards">'+metric("Violations",c.violations.length,"critical")+metric("Unresolved",c.unresolved.length,"warn")+'</div>'+
 (items.length?items.map(contractItem).join(""):'<div class="panel"><span class="badge compliant">compliant</span> No constrained effective-authority relationship violated the contract.</div>')+'</div></div>';
}}
function renderAgentEvidence(a){{
 const rels=a.effective_authority||[];
 const inventory=a.provenance_inventory||[];
 const raw=inventory.length?'<div class="panel"><h3>Full agent evidence inventory</h3><p class="muted">Agent-wide observations for audit; these are not individually asserted to support every finding.</p><details><summary>All '+number(inventory.length)+' source facts</summary><pre>'+esc(JSON.stringify(inventory,null,2))+'</pre></details></div>':"";
 if(!rels.length)return raw+'<div class="empty">No relationship evidence available.</div>';
 return raw+rels.map(r=>'<div class="panel"><h3>'+esc(r.target.kind)+": "+esc(r.target.name)+'</h3><div class="kv"><div>Relationship</div><div><code>'+esc(r.relationship_id)+'</code></div>'+
 '<div>Resolution</div><div>'+badge(r.resolution)+'</div><div>Source</div><div>'+loc(r.location)+'</div><div>Unresolved dimensions</div><div>'+esc((r.unresolved||[]).join(", ")||"none")+'</div></div>'+
 '<details><summary>Full evidence</summary><pre>'+esc(JSON.stringify({{evidence:r.evidence,dimensions:r.dimensions,approval:r.approval,semantics:r.semantics}},null,2))+'</pre></details></div>').join("");
}}
function openAgent(name,initialTab="overview",owaspRisk=null,inventoryFocus=null,supplyFocus=null){{
 const a=DATA.agents.find(x=>x.name===name); if(!a)return; const root=document.getElementById("agent-detail");
 root.innerHTML='<button class="breadcrumb" id="back-agents">← Back to agents</button><div class="agent-head"><div><div class="eyebrow">Agent security profile</div><h1>'+esc(a.name)+'</h1><div class="muted">'+esc(a.framework)+' · '+loc(a.location)+'</div></div><div class="page-actions">'+agentAttention(a)+badge(a.summary.contract_status)+'</div></div>'+
 '<div class="tabs" role="tablist"><button class="active" data-tab="overview">Overview</button><button data-tab="map">Agency map <span class="tab-count">'+number(a.summary.authority_relationships)+'</span></button><button data-tab="paths">Attack paths <span class="tab-count">'+number(a.summary.attack_paths)+'</span></button><button data-tab="findings">Findings <span class="tab-count">'+number(a.summary.findings)+'</span></button><button data-tab="contract">Contract <span class="tab-count">'+number(a.summary.contract_violations+a.summary.contract_unresolved)+'</span></button><button data-tab="evidence">Evidence</button></div>'+
 '<div id="tab-overview" class="agent-tab active">'+renderAgentOverview(a)+'</div><div id="tab-map" class="agent-tab">'+renderGraph(a)+'</div><div id="tab-paths" class="agent-tab">'+renderAgentPaths(a)+'</div><div id="tab-findings" class="agent-tab">'+renderAgentFindings(a,owaspRisk)+'</div><div id="tab-contract" class="agent-tab">'+renderAgentContract(a)+'</div><div id="tab-evidence" class="agent-tab">'+renderAgentEvidence(a)+'</div>';
 root.querySelector("#back-agents").textContent=owaspRisk?"← Back to OWASP "+owaspRisk:(inventoryFocus?"← Back to components":(supplyFocus?"← Back to supply chain":"← Back to agents"));
 root.querySelector("#back-agents").addEventListener("click",()=>{{if(owaspRisk){{renderOwasp(owaspRisk);showView("owasp");}}else if(inventoryFocus){{renderComponents(inventoryFocus.kind,inventoryFocus.id);showView("components");}}else if(supplyFocus){{renderSupplyChain(supplyFocus.focus,supplyFocus.layer,supplyFocus.selected);showView("supply");}}else showView("agents");}});
 const clearOwasp=root.querySelector("#clear-agent-owasp");
 if(clearOwasp)clearOwasp.addEventListener("click",()=>{{root.querySelector("#tab-findings").innerHTML=renderAgentFindings(a);}});
 root.querySelectorAll("[data-tab]").forEach(btn=>btn.addEventListener("click",()=>{{
   if(btn.dataset.tab!=="map"){{const shell=root.querySelector("#agency-map-shell");if(shell)shell.classList.remove("expanded");document.body.classList.remove("graph-modal-open");const full=root.querySelector("#map-fullscreen");if(full){{full.textContent="Expand map";full.setAttribute("aria-pressed","false");}}}}
   root.querySelectorAll("[data-tab]").forEach(x=>x.classList.toggle("active",x===btn));root.querySelectorAll(".agent-tab").forEach(x=>x.classList.toggle("active",x.id==="tab-"+btn.dataset.tab));if(btn.dataset.tab==="map"){{drawGraph(a);bindGraphControls(a);}}
 }}));
 if(initialTab==="findings")root.querySelector('[data-tab="findings"]').click();
 showView("agent-detail");
}}

function renderFindings(severity="all"){{
 const root=document.getElementById("findings"),filters=["all","critical","high","medium","low","info"];
 const chips=filters.map(value=>'<button class="filter-chip '+(severity===value?"active":"")+'" data-finding-filter="'+value+'">'+esc(value==="all"?"All":value[0].toUpperCase()+value.slice(1))+'</button>').join("");
 root.innerHTML=pageHead("Risk review","Findings","Search and triage active scanner findings. Severity is scanner-assigned static evidence, not runtime exploitability.")+
 '<div class="toolbar"><div class="toolbar-left"><div class="filter-chips">'+chips+'</div></div><div class="toolbar-right"><input id="finding-search" class="search" aria-label="Search findings" placeholder="Search rule, title, agent, message or file"></div></div><div class="muted small" id="finding-count"></div><div id="finding-list"></div>';
 const list=root.querySelector("#finding-list"),count=root.querySelector("#finding-count"),search=root.querySelector("#finding-search");
 const apply=()=>{{const q=search.value.trim().toLowerCase();const items=DATA.findings.filter(item=>(severity==="all"||item.severity===severity)&&(!q||JSON.stringify([item.rule_id,item.title,item.agent,item.message,item.location]).toLowerCase().includes(q))).sort((a,b)=>severityRank(b.severity)-severityRank(a.severity)||String(a.rule_id).localeCompare(String(b.rule_id)));count.textContent=number(items.length)+" active findings";list.innerHTML=items.length?items.map(findingCard).join(""):'<div class="empty">No findings matched this view.</div>';}};
 root.querySelectorAll("[data-finding-filter]").forEach(btn=>btn.addEventListener("click",()=>renderFindings(btn.dataset.findingFilter)));search.addEventListener("input",apply);apply();
}}

function renderPolicy(){{
 const assurance=DATA.assurance.organization_policy;
 const items=DATA.findings.filter(item=>item.assessment==="policy_violation").sort((a,b)=>severityRank(b.severity)-severityRank(a.severity)||String(a.rule_id).localeCompare(String(b.rule_id)));
 document.getElementById("policy").innerHTML=pageHead("Policy assurance","Organisation policy","Configured HorusTrace policy rules that were violated by reconstructed agent authority or security state.",badge(assurance.status))+
 '<div class="cards">'+metric("Violations",assurance.violations,assurance.violations?"critical":"")+metric("Affected agents",(assurance.affected_agents||[]).length)+metric("Triggered rules",(assurance.rule_ids||[]).length)+'</div>'+
 '<div class="panel"><div class="kv"><div>Policy scope</div><div>'+esc(assurance.scope)+'</div><div>Status</div><div>'+badge(assurance.status)+'</div><div>Rules</div><div>'+esc((assurance.rule_ids||[]).join(", ")||"none")+'</div><div>Affected agents</div><div>'+esc((assurance.affected_agents||[]).join(", ")||"none")+'</div></div></div>'+
 sectionHead("Policy violations","These are findings whose rule metadata classifies the assessment as policy_violation; Authority Contract results are reported separately.")+
 (items.length?items.map(findingCard).join(""):'<div class="empty">No configured HorusTrace policy violations were detected.</div>');
}}

function owaspStatusLabel(item){{
 if(item.runtime_status==="finding")return "finding";
 if(item.runtime_status==="no_runtime_findings")return "no runtime findings";
 if(item.runtime_status==="no_mapped_findings")return "no mapped findings";
 return "not assessed";
}}
function owaspAgentRows(mapped){{
 const grouped=new Map();
 mapped.forEach(f=>{{const name=typeof f.agent==="string"?f.agent.trim():"";const key=name||"(unattributed)";if(!grouped.has(key))grouped.set(key,{{name,findings:[]}});grouped.get(key).findings.push(f);}});
 if(!grouped.size)return '<div class="empty">No mapped agent findings in this category.</div>';
 const rows=[...grouped.values()].sort((a,b)=>b.findings.length-a.findings.length||a.name.localeCompare(b.name)).map(group=>{{
  const canOpen=Boolean(group.name&&DATA.agents.some(agent=>agent.name===group.name));
  const runtime=group.findings.filter(f=>f.source_context==="runtime").length;
  const highest=group.findings.map(f=>f.severity).sort((a,b)=>severityRank(b)-severityRank(a))[0]||"—";
  const rules=[...new Set(group.findings.map(f=>f.rule_id))].sort();
  const rowAction=canOpen?' role="button" tabindex="0" data-owasp-agent="'+encodeURIComponent(group.name)+'"':"";
  return '<tr class="'+(canOpen?"clickable":"")+'"'+rowAction+'><td><div class="row-title">'+esc(group.name||"Unattributed findings")+'</div><div class="row-sub">'+(canOpen?"Open agent profile and category findings":"Agent profile unavailable; review evidence below")+'</div></td><td>'+number(runtime)+'</td><td>'+number(group.findings.length)+'</td><td>'+badge(highest)+'</td><td>'+esc(rules.join(", "))+'</td><td class="row-chevron">'+(canOpen?"›":"")+'</td></tr>';
 }}).join("");
 return '<div class="panel flush table-wrap"><table aria-label="Agents with mapped OWASP findings"><thead><tr><th>Agent</th><th>Runtime findings</th><th>Total findings</th><th>Highest</th><th>Mapped rules</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div>';
}}
function renderOwasp(risk="all"){{
 const report=DATA.owasp_agentic,categories=report.categories||[];
 const statusMode=String(risk).startsWith("status.")?String(risk).slice(7):null;
 const shownCategories=statusMode?categories.filter(item=>owaspStatusLabel(item).replaceAll(" ","_")===statusMode):categories;
 const rows=shownCategories.map(item=>{{
  const agents=item.affected_agents||[];
  const preview=agents.length?agents.slice(0,2).join(", ")+(agents.length>2?" +"+number(agents.length-2)+" more":""):(item.finding_count?"Findings without agent attribution":"No attributed agents");
  return '<tr class="clickable" role="button" tabindex="0" aria-label="Inspect '+esc(item.id)+' category and affected agents" data-owasp="'+esc(item.id)+'"><td><div class="row-title">'+esc(item.id)+" "+esc(item.title)+'</div><div class="row-sub">'+esc((item.mapped_rules||[]).join(", ")||"no enabled mapped detector")+'</div></td><td>'+badge(owaspStatusLabel(item).replaceAll(" ","_"))+'</td><td>'+number(item.runtime_finding_count)+'</td><td>'+number(item.finding_count)+'</td><td>'+esc(item.highest_severity||"—")+'</td><td><div class="row-title">'+number(agents.length)+'</div><div class="row-sub">'+esc(preview)+'</div></td><td class="row-chevron">›</td></tr>';
 }}).join("");
 const selected=risk!=="all"&&!statusMode?categories.find(item=>item.id===risk):null;
 const mapped=selected?DATA.findings.filter(f=>(f.standards?.owasp_agentic||[]).includes(selected.id)):[];
 const scope=statusMode?'<div class="filter-banner"><span>Assessment filter: '+esc(statusMode.replaceAll("_"," "))+' · '+number(shownCategories.length)+' categories</span><button class="back" id="owasp-clear">Show all categories</button></div>':"";
 const detail=selected?'<div id="owasp-detail">'+sectionHead(selected.id+" "+selected.title,"Mapped findings and attributed agents (static evidence, not proof of an exploited violation).",'<button class="back" id="owasp-clear">Show all categories</button>')+
   '<div class="cards">'+metric("Total findings",selected.finding_count)+metric("Runtime findings",selected.runtime_finding_count)+metric("Affected agents",(selected.affected_agents||[]).length)+metric("Enabled mapped rules",(selected.mapped_rules||[]).length)+'</div>'+
   sectionHead("Affected agents","Select an agent to review only the findings associated with this OWASP category.")+
   owaspAgentRows(mapped)+
   sectionHead("Mapped finding evidence","Unattributed findings remain visible; agent counts exclude findings without an agent name.")+
   (mapped.length?mapped.map(findingCard).join(""):'<div class="empty">No mapped findings fired for this category.</div>')+'</div>':"";
 const a=DATA.assurance.owasp_agentic;
 const root=document.getElementById("owasp");
 root.innerHTML=pageHead("Standards posture","OWASP Agentic Top 10","Detector-level status for every OWASP Top 10 for Agentic Applications 2026 category. NOT ASSESSED means HorusTrace has no enabled mapped detector.",badge(a.status))+
 '<div class="cards">'+metric("Categories with findings",a.categories_with_findings,a.categories_with_findings?"warn":"")+metric("Runtime finding categories",a.categories_with_runtime_findings)+metric("Mapped detector categories",a.categories_with_mapped_detectors)+metric("Not assessed",a.categories_not_assessed,a.categories_not_assessed?"warn":"")+'</div>'+
 detail+scope+'<div class="panel flush table-wrap"><table><thead><tr><th>OWASP category</th><th>Status</th><th>Runtime findings</th><th>Total findings</th><th>Highest</th><th>Agents</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div>';
 root.querySelectorAll("[data-owasp]").forEach(row=>{{const activate=()=>{{renderOwasp(row.dataset.owasp);const detail=root.querySelector("#owasp-detail");if(detail)detail.scrollIntoView({{block:"start"}});}};row.addEventListener("click",activate);row.addEventListener("keydown",event=>{{if(event.key==="Enter"||event.key===" "){{event.preventDefault();activate();}}}});}});
 root.querySelectorAll("[data-owasp-agent]").forEach(row=>{{const activate=()=>openAgent(decodeURIComponent(row.dataset.owaspAgent),"findings",selected.id);row.addEventListener("click",activate);row.addEventListener("keydown",event=>{{if(event.key==="Enter"||event.key===" "){{event.preventDefault();activate();}}}});}});
 const clear=root.querySelector("#owasp-clear");if(clear)clear.addEventListener("click",()=>renderOwasp("all"));
}}

function renderAttack(){{
 const items=DATA.agents.flatMap(a=>(a.path_views||[])),supported=items.filter(x=>x.evidence_strength==="supported_static_dataflow").length,potential=items.length-supported;
 document.getElementById("attack").innerHTML=pageHead("Risk chains","Attack paths","Evidence-aware chains from source/capability context to sensitive actions or destinations.")+
 '<div class="cards">'+metric("Attack paths",items.length)+metric("Supported data flow",supported,"ok","","Solid connectors")+metric("Potential capability paths",potential,"warn","","Dashed connectors; flow not proven")+'</div>'+
 sectionHead("Reconstructed paths","Runtime exploitability is not verified.")+(items.length?items.sort((a,b)=>severityRank(b.severity)-severityRank(a.severity)).map(renderPathCard).join(""):'<div class="empty">No attack paths detected.</div>');
}}

function renderContracts(mode="all"){{
 let items=DATA.agents;if(mode==="declared")items=items.filter(a=>a.contract.declared);else if(mode==="violation")items=items.filter(a=>a.summary.contract_violations>0);else if(mode==="unresolved")items=items.filter(a=>a.summary.contract_unresolved>0);
 items=[...items].sort((a,b)=>(b.summary.contract_violations-a.summary.contract_violations)||(b.summary.contract_unresolved-a.summary.contract_unresolved)||a.name.localeCompare(b.name));
 const filters=[["all","All"],["declared","Declared"],["violation","Violations"],["unresolved","Unresolved"]],chips=filters.map(([value,label])=>'<button class="filter-chip '+(mode===value?"active":"")+'" data-contract-filter="'+value+'">'+esc(label)+'</button>').join("");
 const rows=items.map(a=>'<tr class="clickable" role="button" tabindex="0" data-agent="'+encodeURIComponent(a.name)+'"><td><div class="row-title">'+esc(a.name)+'</div><div class="row-sub">'+esc(a.framework)+'</div></td><td>'+badge(a.summary.contract_status)+'</td><td>'+number(a.summary.contract_violations)+'</td><td>'+number(a.summary.contract_unresolved)+'</td><td>'+number(a.contract.relationships.length)+'</td><td class="row-chevron">›</td></tr>').join("");
 const root=document.getElementById("contracts");root.innerHTML=pageHead("Policy assurance","Agent contracts","Declared Authority Contract constraints compared with reconstructed effective authority.",badge(DATA.assurance.authority_contract.status))+
 '<div class="cards">'+metric("Agents with contract",DATA.summary.agents_with_contract)+metric("Violations",DATA.summary.contract_violations,DATA.summary.contract_violations?"critical":"")+metric("Unresolved checks",DATA.summary.contract_unresolved,DATA.summary.contract_unresolved?"warn":"")+'</div>'+
 '<div class="toolbar"><div class="filter-chips">'+chips+'</div><div class="muted small">'+number(items.length)+' agents in view</div></div>'+
 (rows?'<div class="panel flush table-wrap"><table><thead><tr><th>Agent</th><th>Status</th><th>Violations</th><th>Unresolved</th><th>Relationships evaluated</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div>':'<div class="empty">No agents matched this contract filter.</div>');
 bindAgentRows(root);root.querySelectorAll("[data-contract-filter]").forEach(btn=>btn.addEventListener("click",()=>renderContracts(btn.dataset.contractFilter)));
}}

function renderEvidence(){{
 const c=DATA.coverage,diags=c.diagnostics||[],considered=Number(c.files_considered||0),scanned=Number(c.files_scanned||0),pct=considered?Math.max(0,Math.min(100,Math.round(scanned/considered*100))):null;
 const skills=DATA.skills||[];
 const skillRows=skills.map(s=>'<tr><td><div class="row-title">'+esc(s.name)+'</div><div class="row-sub">'+loc(s.location)+'</div></td><td>'+badge(s.binding_state)+'</td><td>'+esc((s.bound_agents||[]).join(", ")||"—")+'</td><td>'+esc((s.allowed_tools||[]).join(", ")||"—")+'</td><td>'+number((s.scripts||[]).length)+'</td></tr>').join("");
 document.getElementById("evidence").innerHTML=pageHead("Trust & provenance","Scan evidence","Coverage, diagnostics and report provenance used to qualify the assessment.",scanCoverageStatus(c.incomplete))+
 '<div class="cards">'+metric("Files considered",c.files_considered)+metric("Files scanned",c.files_scanned)+metric("Files skipped",c.files_skipped)+metric("Files failed",c.files_failed,c.files_failed?"high":"")+'</div>'+
 sectionHead("Coverage status","Use coverage gaps to qualify confidence in scanner conclusions.")+'<div class="panel"><div class="kv"><div>Status</div><div>'+scanCoverageStatus(c.incomplete)+'</div><div>Scan completion</div><div>'+(pct===null?'Not available (no files considered)':number(pct)+'%<div class="coverage-track"><div class="coverage-fill '+(c.incomplete?'incomplete':'')+'" style="width:'+pct+'%"></div></div>')+'</div><div>ASG digest</div><div><code>'+esc(DATA.security_graph.digest)+'</code></div><div>Suppressed findings</div><div>'+number(DATA.suppressed_findings.length)+'</div><div>Report model</div><div><code>'+esc(DATA.model)+' / schema '+esc(DATA.schema_version)+'</code></div></div></div>'+
 sectionHead("Skill inventory","Portable agent skills discovered in the repository. Unbound means discovered but not source-proven as available to an agent.")+(skillRows?'<div class="panel flush table-wrap"><table><thead><tr><th>Skill</th><th>Binding</th><th>Agents</th><th>Allowed tools</th><th>Scripts</th></tr></thead><tbody>'+skillRows+'</tbody></table></div>':'<div class="empty">No Agent Skills were discovered.</div>')+
 sectionHead("Diagnostics","Coverage or parsing conditions that may affect completeness.")+(diags.length?diags.map(d=>'<div class="finding" data-sev="medium"><div class="finding-title"><strong>'+esc(d.diagnostic_id||d.code)+'</strong><span class="badge medium">diagnostic</span></div><p>'+esc(d.message)+'</p><div class="muted small">'+loc(d.location)+'</div></div>').join(""):'<div class="empty">No detected coverage diagnostics.</div>');
}}

renderDashboard();renderAgents();renderComponents();renderSupplyChain();renderFindings();renderPolicy();renderOwasp();renderAttack();renderContracts();renderEvidence();
</script>
</body>
</html>
"""


def write_visual_report(
    graph: Graph,
    findings: list[Finding],
    root: Path,
    output: Path,
) -> None:
    output.write_text(
        render_visual_report_html(graph, findings, root) + "\n",
        encoding="utf-8",
    )
