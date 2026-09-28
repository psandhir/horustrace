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

from horustrace.authority_contract import authority_contract_report
from horustrace.effective_authority import effective_authority_report
from horustrace.models import Finding, Graph
from horustrace.owasp import build_owasp_agentic_summary
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
    findings_docs = [_relativize(item.as_dict(), root) for item in findings]
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
                "framework": str(agent.metadata.get("framework") or "generic"),
                "location": _agent_location(agent, root),
                "summary": {
                    "tools": len(agent.tools),
                    "mcp_servers": len(agent.mcp_servers),
                    "identities": len(identities),
                    "resources": len(resources),
                    "destinations": len(destinations),
                    "authority_relationships": len(relationships),
                    "write_capable_relationships": agent_write_relationships,
                    "findings": len(agent_findings),
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

    owasp = build_owasp_agentic_summary(
        findings,
        disabled_rules=graph.configuration_audit.get("disabled_rules", []),
    )
    return {
        "schema_version": VISUAL_REPORT_SCHEMA_VERSION,
        "model": VISUAL_REPORT_MODEL,
        "root": ".",
        "summary": {
            "agents": len(graph.agents),
            "tools": len(graph.all_tools()),
            "mcp_servers": len(graph.all_mcp_servers()),
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
            "agents_with_contract": contract["summary"]["agents_with_contract"],
            "contract_violations": contract["summary"]["violations"],
            "contract_unresolved": contract["summary"]["unresolved"],
            "analysis_incomplete": graph.coverage.incomplete,
        },
        "agents": agents,
        "findings": findings_docs,
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
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
<title>{title}</title>
<style>
:root{{--bg:#0b1020;--panel:#11182b;--panel2:#161f35;--text:#eef3ff;--muted:#9aa9c2;
--line:#29344f;--accent:#8ab4ff;--critical:#ff6b75;--high:#ff9a62;--medium:#ffd166;
--low:#74c0fc;--ok:#63d69f;--warn:#f1c75b;--unknown:#a8b3c7;--shadow:0 12px 30px #0004}}
*{{box-sizing:border-box}} body{{margin:0;font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,
Segoe UI,sans-serif;background:var(--bg);color:var(--text)}} button,input{{font:inherit}}
.shell{{display:grid;grid-template-columns:240px 1fr;min-height:100vh}}
aside{{border-right:1px solid var(--line);padding:22px 16px;position:sticky;top:0;height:100vh;background:#0d1324}}
.brand{{font-size:20px;font-weight:800;letter-spacing:.2px;margin:0 8px 24px}}
.brand small{{display:block;font-size:11px;color:var(--muted);font-weight:600;margin-top:3px}}
.nav button{{width:100%;text-align:left;background:transparent;color:var(--muted);border:0;border-radius:9px;
padding:10px 12px;margin:2px 0;cursor:pointer}} .nav button.active,.nav button:hover{{background:var(--panel2);color:var(--text)}}
main{{padding:28px;max-width:1500px;width:100%}} h1{{font-size:28px;margin:0 0 6px}} h2{{font-size:20px;margin:28px 0 12px}}
h3{{font-size:15px;margin:0 0 10px}} .muted{{color:var(--muted)}} .view{{display:none}} .view.active{{display:block}}
.hero{{display:flex;justify-content:space-between;gap:20px;align-items:start;margin-bottom:22px}} .pill{{display:inline-block;
padding:4px 8px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:12px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}} .card{{background:var(--panel);
border:1px solid var(--line);border-radius:12px;padding:15px;box-shadow:var(--shadow)}} .card.drill{{cursor:pointer;transition:transform .12s ease,border-color .12s ease,background .12s ease}}
.card.drill:hover{{transform:translateY(-1px);border-color:#52688f;background:#151f36}} .card.drill:focus{{outline:2px solid var(--accent);outline-offset:2px}}
.metric{{font-size:28px;font-weight:800}}
.metric-label{{color:var(--muted);font-size:12px;margin-top:3px}} .critical{{color:var(--critical)}} .high{{color:var(--high)}}
.medium{{color:var(--medium)}} .low{{color:var(--low)}} .ok{{color:var(--ok)}} .warn{{color:var(--warn)}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:14px}} .panel{{background:var(--panel);border:1px solid var(--line);
border-radius:12px;padding:16px;margin-bottom:14px}} table{{width:100%;border-collapse:collapse}} th,td{{padding:10px 8px;
border-bottom:1px solid var(--line);text-align:left;vertical-align:top}} th{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}}
tr.clickable{{cursor:pointer}} tr.clickable:hover{{background:#ffffff08}} .badge{{display:inline-block;padding:3px 7px;border-radius:999px;
font-size:11px;font-weight:700;background:#ffffff0b;border:1px solid var(--line)}} .badge.violation{{color:var(--critical);border-color:#ff6b7560}}
.badge.compliant{{color:var(--ok);border-color:#63d69f60}} .badge.unresolved{{color:var(--warn);border-color:#f1c75b60}}
.badge.not_declared{{color:var(--muted)}} .badge.declared{{color:var(--accent);border-color:#8ab4ff60}} .search{{width:100%;max-width:420px;background:var(--panel);color:var(--text);border:1px solid var(--line);
border-radius:9px;padding:9px 11px;margin:0 0 12px}} .agent-head{{display:flex;gap:14px;justify-content:space-between;align-items:start}}
.tabs{{display:flex;gap:6px;border-bottom:1px solid var(--line);margin:18px 0 14px;overflow:auto}} .tabs button{{border:0;background:transparent;
color:var(--muted);padding:9px 10px;cursor:pointer;border-bottom:2px solid transparent}} .tabs button.active{{color:var(--text);border-bottom-color:var(--accent)}}
.agent-tab{{display:none}} .agent-tab.active{{display:block}} .kv{{display:grid;grid-template-columns:170px 1fr;gap:7px 14px}}
.drill-list{{display:flex;flex-direction:column;gap:2px}}
.drill-row{{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:16px;cursor:pointer;border-radius:7px;padding:7px 8px;margin:0 -8px;color:inherit}}
.drill-row:hover{{background:#ffffff08}} .drill-row:focus{{outline:2px solid var(--accent);outline-offset:1px}}
.drill-value{{display:flex;align-items:center;gap:8px;font-variant-numeric:tabular-nums;font-weight:600}}
.drill-value::after{{content:"›";color:var(--muted);font-size:16px;line-height:1;opacity:.7}}
.filter-banner{{display:flex;justify-content:space-between;align-items:center;gap:12px;background:#101a31;border:1px solid #344566;border-radius:9px;padding:9px 11px;margin:12px 0}}
.kv div:nth-child(odd){{color:var(--muted)}} .finding{{border-left:3px solid var(--line);padding:12px 14px;margin:10px 0;background:#0d1426;border-radius:8px}}
.finding[data-sev="critical"]{{border-left-color:var(--critical)}} .finding[data-sev="high"]{{border-left-color:var(--high)}}
.finding[data-sev="medium"]{{border-left-color:var(--medium)}} .finding[data-sev="low"]{{border-left-color:var(--low)}}
.finding-title{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}} code,pre{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
code{{background:#ffffff0b;padding:2px 5px;border-radius:5px}} details{{margin-top:8px}} pre{{white-space:pre-wrap;word-break:break-word;
background:#09101e;border:1px solid var(--line);padding:12px;border-radius:8px;max-height:340px;overflow:auto}}
.map-toolbar{{display:flex;gap:7px;align-items:center;flex-wrap:wrap;margin:8px 0 10px}}
.map-toolbar input{{min-width:220px;flex:1;background:#09101e;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:7px 9px}}
.map-btn{{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:8px;padding:7px 9px;cursor:pointer}}
.map-btn:hover{{border-color:#52688f;background:var(--panel2)}}
.graph-wrap{{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:12px;position:relative}}
.graph-wrap.expanded{{position:fixed;inset:14px;z-index:9999;background:var(--bg);padding:14px;border:1px solid var(--line);border-radius:14px;grid-template-columns:minmax(0,1fr) 340px;box-shadow:0 24px 80px #000b}}
.graph-wrap.expanded .graph{{height:calc(100vh - 105px)}} body.graph-modal-open{{overflow:hidden}}
.graph-canvas{{position:relative;min-width:0}} .graph{{width:100%;height:520px;background:#09101e;border:1px solid var(--line);border-radius:10px;touch-action:none;cursor:grab}}
.graph.panning{{cursor:grabbing}} .inspector{{min-height:120px;overflow:auto}} .legend{{display:flex;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:12px;margin:7px 0 12px}}
.dot{{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:4px}} .empty{{padding:24px;text-align:center;color:var(--muted);
border:1px dashed var(--line);border-radius:10px}} .back{{border:1px solid var(--line);background:var(--panel);color:var(--text);padding:7px 10px;
border-radius:8px;cursor:pointer}} .small{{font-size:12px}} .nowrap{{white-space:nowrap}} .sevbar{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}
svg text{{fill:var(--text);font-family:ui-sans-serif,system-ui;font-size:12px}} .edge{{stroke:#65728c;stroke-width:1.4;opacity:.72}}
.node rect{{fill:#16213a;stroke:#42516f;stroke-width:1}} .node.agent rect{{fill:#1b3157;stroke:#78a8ff}} .node.identity rect{{fill:#2b2545;stroke:#a895ff}}
.node.resource rect{{fill:#21362f;stroke:#63d69f}} .node.destination rect{{fill:#3a2d22;stroke:#f1b36a}} .node.unresolved rect{{stroke-dasharray:5 4}}
.node{{cursor:pointer;transition:opacity .12s}} .node:hover rect{{stroke-width:2}} .node.dim{{opacity:.16}} .node.match rect,.node.selected rect{{stroke-width:3}}
.edge.dim{{opacity:.08}} .edge.selected{{stroke-width:2.5;opacity:1}} .label2{{fill:var(--muted);font-size:10px}}
.path-card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin:12px 0}}
.path-head{{display:flex;justify-content:space-between;gap:12px;align-items:start;flex-wrap:wrap}}
.path-chain{{display:flex;flex-direction:column;align-items:flex-start;margin-top:15px;padding-left:8px}}
.path-step{{min-width:260px;max-width:620px;background:#0d1628;border:1px solid var(--line);border-radius:9px;padding:9px 11px}}
.path-step.agent{{border-color:#78a8ff}} .path-step.secret{{border-color:#c98cff}} .path-step.destination{{border-color:#f1b36a}} .path-step.input,.path-step.source{{border-color:#8ab4ff}}
.path-role{{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:2px}}
.path-arrow{{height:22px;margin-left:28px;border-left:2px solid #6d7e9f}} .path-arrow.dashed{{border-left-style:dashed}}
.path-meta{{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}} .footer{{color:var(--muted);font-size:11px;margin:28px 0 4px}}
@media(max-width:900px){{.shell{{grid-template-columns:1fr}} aside{{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line)}}
.nav{{display:flex;overflow:auto}} .nav button{{width:auto;white-space:nowrap}} main{{padding:18px}} .grid2,.graph-wrap{{grid-template-columns:1fr}}
.graph{{height:440px}} .graph-wrap.expanded{{inset:4px;padding:8px;grid-template-columns:1fr}} .graph-wrap.expanded .inspector{{display:none}} .kv{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="shell">
<aside>
  <div class="brand">HorusTrace<small>Effective Agency Report</small></div>
  <div class="nav">
    <button class="active" data-view="dashboard">Dashboard</button>
    <button data-view="agents">Agents</button>
    <button data-view="findings">Findings</button>
    <button data-view="attack">Attack paths</button>
    <button data-view="contracts">Agent contracts</button>
    <button data-view="evidence">Scan evidence</button>
  </div>
</aside>
<main>
  <section id="dashboard" class="view active"></section>
  <section id="agents" class="view"></section>
  <section id="agent-detail" class="view"></section>
  <section id="findings" class="view"></section>
  <section id="attack" class="view"></section>
  <section id="contracts" class="view"></section>
  <section id="evidence" class="view"></section>
  <div class="footer">Static evidence only. Runtime effectiveness is not verified.</div>
</main>
</div>
<script id="horus-data" type="application/json">{payload}</script>
<script>
"use strict";
const DATA=JSON.parse(document.getElementById("horus-data").textContent);
const esc=(v)=>String(v??"").replace(/[&<>"']/g,c=>({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[c]));
const loc=(v)=>v&&v.path?esc(v.path)+":"+esc(v.line||1):"n/a";
const badge=(s)=>'<span class="badge '+esc(s)+'">'+esc(String(s).replaceAll("_"," "))+'</span>';
const number=(v)=>Number(v||0).toLocaleString();
function showView(id){{
  document.querySelectorAll(".view").forEach(el=>el.classList.toggle("active",el.id===id));
  document.querySelectorAll(".nav button").forEach(el=>el.classList.toggle("active",el.dataset.view===id));
  window.scrollTo(0,0);
}}
document.querySelectorAll(".nav button").forEach(btn=>btn.addEventListener("click",()=>showView(btn.dataset.view)));
function metric(label,value,cls="",drill=""){{
 const attrs=drill?' drill" role="button" tabindex="0" data-drill="'+esc(drill):'"';
 return '<div class="card'+attrs+'"><div class="metric '+cls+'">'+number(value)+'</div><div class="metric-label">'+esc(label)+'</div></div>';
}}
function severityCards(s,interactive=false){{
 return '<div class="sevbar">'+metric("Critical",s.critical,"critical",interactive?"findings:critical":"")+
 metric("High",s.high,"high",interactive?"findings:high":"")+metric("Medium",s.medium,"medium",interactive?"findings:medium":"")+
 metric("Low",s.low,"low",interactive?"findings:low":"")+'</div>';
}}
function findingCard(f){{
 const evidence=(f.evidence||[]).map(x=>"<li>"+esc(x)+"</li>").join("");
 const prov=(f.provenance||[]).map(x=>"<li>"+esc(x.origin)+": "+esc(x.fact)+(x.location?" — "+loc(x.location):"")+"</li>").join("");
 return '<div class="finding" data-sev="'+esc(f.severity)+'"><div class="finding-title"><strong>'+esc(f.rule_id)+'</strong>'+
 '<span class="'+esc(f.severity)+'">'+esc(f.severity.toUpperCase())+'</span><span>'+esc(f.title)+'</span></div>'+
 '<div class="muted small">'+loc(f.location)+' · '+esc(f.assessment||"static")+'</div><p>'+esc(f.message)+'</p>'+
 (evidence?'<details><summary>Evidence</summary><ul>'+evidence+'</ul></details>':"")+
 (prov?'<details><summary>Provenance</summary><ul>'+prov+'</ul></details>':"")+
 (f.recommendation?'<details><summary>Remediation</summary><p>'+esc(f.recommendation)+'</p></details>':"")+'</div>';
}}
function renderDashboard(){{
 const s=DATA.summary;
 const drillRow=(label,value,drill,cls="")=>'<div class="drill-row" role="button" tabindex="0" data-drill="'+esc(drill)+'"><span>'+esc(label)+'</span><span class="drill-value '+esc(cls)+'">'+number(value)+'</span></div>';
 const drillList=(rows)=>'<div class="drill-list">'+rows.join("")+'</div>';
 const root=document.getElementById("dashboard");
 root.innerHTML='<div class="hero"><div><h1>Security assessment</h1><div class="muted">Effective authority, policy findings and agent-contract posture</div></div>'+
 (s.analysis_incomplete?'<span class="badge unresolved">analysis incomplete</span>':'<span class="badge compliant">no detected coverage gaps</span>')+'</div>'+
 '<div class="cards">'+metric("Agents",s.agents,"","agents:all")+metric("Tools",s.tools,"","agents:tools")+metric("MCP servers",s.mcp_servers,"","agents:mcp")+
 metric("Identities",s.identities,"","agents:identities")+metric("Reachable resources",s.resources,"","agents:resources")+metric("Attack paths",s.attack_paths,"","attack:all")+
 metric("Findings",s.findings,"","findings:all")+metric("Contract violations",s.contract_violations,"critical","contracts:violation")+'</div>'+
 '<h2>Finding severity</h2>'+severityCards(s.severity,true)+
 '<div class="grid2"><div><h2>Effective agency</h2><div class="panel">'+drillList([
 drillRow("Authority relationships",s.authority_relationships,"agents:authority"),
 drillRow("Not fully resolved",s.authority_not_fully_resolved,"agents:unresolved","warn"),
 drillRow("Write-capable paths",s.write_capable_relationships,"agents:write"),
 drillRow("Unique destinations",s.destinations,"agents:destinations")
 ])+'</div></div>'+
 '<div><h2>Agent contracts</h2><div class="panel">'+drillList([
 '<div class="drill-row" style="cursor:default"><span>Status</span><span>'+badge(s.contract_violations?"violation":(s.contract_unresolved?"unresolved":"compliant"))+'</span></div>',
 drillRow("Agents with contract",s.agents_with_contract,"contracts:declared"),
 drillRow("Violations",s.contract_violations,"contracts:violation","critical"),
 drillRow("Unresolved checks",s.contract_unresolved,"contracts:unresolved","warn")
 ])+'</div></div></div>'+
 '<h2>Agents needing attention</h2>'+agentTable(DATA.agents.filter(a=>a.summary.findings||a.summary.contract_violations||a.summary.contract_unresolved).slice(0,12));
 bindDashboardDrill(root);
 bindAgentRows(root);
}}
function drillLabel(kind,value){{
 const labels={{
  "agents:all":"All agents","agents:tools":"Agents with tools","agents:mcp":"Agents with MCP servers",
  "agents:identities":"Agents with resolved identities","agents:resources":"Agents reaching resources",
  "agents:authority":"Agents with effective authority","agents:unresolved":"Agents with unresolved authority",
  "agents:write":"Agents with write-capable authority","agents:destinations":"Agents with external destinations",
  "findings:all":"All findings","findings:critical":"Critical findings","findings:high":"High findings",
  "findings:medium":"Medium findings","findings:low":"Low findings","contracts:declared":"Agents with declared contracts",
  "contracts:violation":"Agents with contract violations","contracts:unresolved":"Agents with unresolved contract checks",
  "attack:all":"Attack paths"
 }};
 return labels[kind+":"+value]||"Dashboard filter";
}}
function routeDrill(action){{
 const [kind,value="all"]=String(action).split(":",2);
 if(kind==="agents"){{renderAgents(value);showView("agents");}}
 else if(kind==="findings"){{renderFindings(value);showView("findings");}}
 else if(kind==="contracts"){{renderContracts(value);showView("contracts");}}
 else if(kind==="attack"){{renderAttack();showView("attack");}}
}}
function bindDashboardDrill(root=document){{
 root.querySelectorAll("[data-drill]").forEach(el=>{{
   const activate=()=>routeDrill(el.dataset.drill);
   el.addEventListener("click",activate);
   el.addEventListener("keydown",event=>{{if(event.key==="Enter"||event.key===" "){{event.preventDefault();activate();}}}});
 }});
}}
function agentTable(items){{
 if(!items.length)return '<div class="empty">No agents matched.</div>';
 const rows=items.map(a=>'<tr class="clickable" data-agent="'+encodeURIComponent(a.name)+'"><td><strong>'+esc(a.name)+'</strong><div class="muted small">'+esc(a.framework)+'</div></td>'+
 '<td>'+badge(a.summary.contract_status)+'</td><td>'+number(a.summary.findings)+'</td><td>'+number(a.summary.authority_relationships)+'</td><td>'+number(a.summary.resources)+'</td>'+
 '<td>'+number(a.summary.write_capable_relationships)+'</td><td class="nowrap">'+loc(a.location)+'</td></tr>').join("");
 return '<div class="panel"><table><thead><tr><th>Agent</th><th>Contract</th><th>Findings</th><th>Authority</th><th>Resources</th><th>Write paths</th><th>Location</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
}}
function bindAgentRows(root=document){{
 root.querySelectorAll("[data-agent]").forEach(row=>row.addEventListener("click",()=>openAgent(decodeURIComponent(row.dataset.agent))));
}}
function agentMatchesFilter(a,mode){{
 if(mode==="tools")return a.summary.tools>0;
 if(mode==="mcp")return a.summary.mcp_servers>0;
 if(mode==="identities")return a.summary.identities>0;
 if(mode==="resources")return a.summary.resources>0;
 if(mode==="authority")return a.summary.authority_relationships>0;
 if(mode==="unresolved")return (a.effective_authority||[]).some(r=>r.resolution!=="fully_resolved");
 if(mode==="write")return a.summary.write_capable_relationships>0;
 if(mode==="destinations")return a.summary.destinations>0;
 return true;
}}
function renderAgents(mode="all"){{
 const root=document.getElementById("agents");
 const scoped=DATA.agents.filter(a=>agentMatchesFilter(a,mode));
 const banner=mode==="all"?"":'<div class="filter-banner"><span>'+esc(drillLabel("agents",mode))+' · '+number(scoped.length)+' agents</span><button class="back" id="clear-agent-filter">Clear filter</button></div>';
 root.innerHTML='<h1>Agents</h1><p class="muted">Select an agent to inspect declared and effective agency.</p>'+banner+
 '<input id="agent-search" class="search" placeholder="Filter agents, frameworks or locations"><div id="agent-table">'+agentTable(scoped)+'</div>';
 bindAgentRows(root);
 if(mode!=="all")root.querySelector("#clear-agent-filter").addEventListener("click",()=>renderAgents("all"));
 root.querySelector("#agent-search").addEventListener("input",e=>{{
   const q=e.target.value.toLowerCase();
   const items=scoped.filter(a=>JSON.stringify([a.name,a.framework,a.location,a.resources,a.identities]).toLowerCase().includes(q));
   root.querySelector("#agent-table").innerHTML=agentTable(items); bindAgentRows(root);
 }});
}}
function contractItem(item){{
 return '<div class="finding" data-sev="'+(item.status==="violation"?"high":"medium")+'"><div class="finding-title">'+badge(item.status)+
 '<strong>'+esc(item.clause)+'</strong><span>'+esc(item.reason)+'</span></div><div class="kv small"><div>Dimension</div><div>'+esc(item.dimension)+'</div>'+
 '<div>Expected</div><div>'+esc((item.expected||[]).join(", ")||"—")+'</div><div>Observed</div><div>'+esc((item.observed||[]).join(", ")||"—")+'</div>'+
 '<div>Contract evidence</div><div>'+loc(item.contract_location)+'</div><div>Authority evidence</div><div>'+loc(item.relationship_location)+'</div></div></div>';
}}
function renderAgentOverview(a){{
 return '<div class="cards">'+metric("Tools",a.summary.tools)+metric("MCP servers",a.summary.mcp_servers)+metric("Authority paths",a.summary.authority_relationships)+
 metric("Resources",a.summary.resources)+metric("Write-capable",a.summary.write_capable_relationships)+metric("Findings",a.summary.findings)+'</div>'+
 '<div class="grid2"><div><h2>Effective scope</h2><div class="panel"><div class="kv"><div>Identities</div><div>'+esc(a.identities.join(", ")||"unresolved / none")+'</div>'+
 '<div>Resources</div><div>'+esc(a.resources.join(", ")||"unresolved / none")+'</div><div>Destinations</div><div>'+esc(a.destinations.join(", ")||"unresolved / none")+'</div></div></div></div>'+
 '<div><h2>Contract posture</h2><div class="panel"><div class="kv"><div>Status</div><div>'+badge(a.summary.contract_status)+'</div><div>Violations</div><div>'+number(a.summary.contract_violations)+'</div>'+
 '<div>Unresolved</div><div>'+number(a.summary.contract_unresolved)+'</div></div></div></div></div>'+
 '<h2>Finding severity</h2>'+severityCards(a.severity);
}}
function renderGraph(a){{
 const rels=a.effective_authority||[];
 if(!rels.length)return '<div class="empty">No effective-authority relationships were reconstructed for this agent.</div>';
 return '<div class="map-toolbar"><input id="map-search" placeholder="Find tool, MCP, identity, resource or destination">'+
 '<button class="map-btn" id="map-toggle-groups">Expand all</button><button class="map-btn" id="map-zoom-out">−</button>'+
 '<button class="map-btn" id="map-zoom-in">+</button><button class="map-btn" id="map-fit">Fit</button>'+
 '<button class="map-btn" id="map-fullscreen">Expand map</button></div>'+
 '<div class="legend"><span><i class="dot" style="background:#78a8ff"></i>Agent</span><span><i class="dot" style="background:#6f84aa"></i>Tool / MCP</span>'+
 '<span><i class="dot" style="background:#a895ff"></i>Identity</span><span><i class="dot" style="background:#63d69f"></i>Resource</span><span><i class="dot" style="background:#f1b36a"></i>Destination</span></div>'+
 '<div class="graph-wrap" id="agency-map-shell"><div class="graph-canvas"><svg class="graph" id="agency-svg" viewBox="0 0 1080 520" preserveAspectRatio="xMidYMid meet">'+
 '<g id="agency-stage"></g></svg></div><div class="panel inspector" id="graph-inspector"><h3>Path inspector</h3><p class="muted">Select a graph node to inspect its evidence.</p></div></div>';
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
 const state=agencyState(a), svg=document.getElementById("agency-svg"), shell=document.getElementById("agency-map-shell");
 if(!svg||!shell||shell.dataset.bound==="1")return;
 shell.dataset.bound="1";
 const groupBtn=document.getElementById("map-toggle-groups");
 const updateGroupLabel=()=>groupBtn.textContent=state.collapsed?"Expand all":"Collapse groups";
 updateGroupLabel();
 groupBtn.addEventListener("click",()=>{{state.collapsed=!state.collapsed;state.selected=null;drawGraph(a);updateGroupLabel();}});
 document.getElementById("map-zoom-in").addEventListener("click",()=>{{state.scale=Math.min(3,state.scale*1.2);applyGraphTransform(a);}});
 document.getElementById("map-zoom-out").addEventListener("click",()=>{{state.scale=Math.max(.35,state.scale/1.2);applyGraphTransform(a);}});
 document.getElementById("map-fit").addEventListener("click",()=>{{state.scale=1;state.tx=0;state.ty=0;applyGraphTransform(a);focusGraphNode(null);}});
 document.getElementById("map-fullscreen").addEventListener("click",event=>{{
   const expanded=shell.classList.toggle("expanded"); document.body.classList.toggle("graph-modal-open",expanded);
   event.currentTarget.textContent=expanded?"Exit full screen":"Expand map";
 }});
 document.getElementById("map-search").addEventListener("input",event=>filterGraph(event.target.value));
 svg.addEventListener("wheel",event=>{{event.preventDefault();state.scale=Math.max(.35,Math.min(3,state.scale*(event.deltaY<0?1.1:.9)));applyGraphTransform(a);}},{{passive:false}});
 let dragging=false,lastX=0,lastY=0;
 svg.addEventListener("pointerdown",event=>{{if(event.target.closest(".node"))return;dragging=true;lastX=event.clientX;lastY=event.clientY;svg.classList.add("panning");svg.setPointerCapture(event.pointerId);}});
 svg.addEventListener("pointermove",event=>{{if(!dragging)return;state.tx+=(event.clientX-lastX)/state.scale;state.ty+=(event.clientY-lastY)/state.scale;lastX=event.clientX;lastY=event.clientY;applyGraphTransform(a);}});
 const stop=()=>{{dragging=false;svg.classList.remove("panning");}};
 svg.addEventListener("pointerup",stop);svg.addEventListener("pointercancel",stop);
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
function renderAgentFindings(a){{return a.findings.length?a.findings.map(findingCard).join(""):'<div class="empty">No active findings mapped to this agent.</div>'}}
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
 if(!rels.length)return '<div class="empty">No relationship evidence available.</div>';
 return rels.map(r=>'<div class="panel"><h3>'+esc(r.target.kind)+": "+esc(r.target.name)+'</h3><div class="kv"><div>Relationship</div><div><code>'+esc(r.relationship_id)+'</code></div>'+
 '<div>Resolution</div><div>'+badge(r.resolution)+'</div><div>Source</div><div>'+loc(r.location)+'</div><div>Unresolved dimensions</div><div>'+esc((r.unresolved||[]).join(", ")||"none")+'</div></div>'+
 '<details><summary>Full evidence</summary><pre>'+esc(JSON.stringify({{evidence:r.evidence,dimensions:r.dimensions,approval:r.approval,semantics:r.semantics}},null,2))+'</pre></details></div>').join("");
}}
function openAgent(name){{
 const a=DATA.agents.find(x=>x.name===name); if(!a)return;
 const root=document.getElementById("agent-detail");
 root.innerHTML='<button class="back" id="back-agents">← Agents</button><div class="agent-head"><div><h1>'+esc(a.name)+'</h1><div class="muted">'+esc(a.framework)+' · '+loc(a.location)+'</div></div>'+badge(a.summary.contract_status)+'</div>'+
 '<div class="tabs"><button class="active" data-tab="overview">Overview</button><button data-tab="map">Agency map</button><button data-tab="paths">Attack paths</button><button data-tab="findings">Findings</button><button data-tab="contract">Contract</button><button data-tab="evidence">Evidence</button></div>'+
 '<div id="tab-overview" class="agent-tab active">'+renderAgentOverview(a)+'</div><div id="tab-map" class="agent-tab">'+renderGraph(a)+'</div>'+
 '<div id="tab-paths" class="agent-tab">'+renderAgentPaths(a)+'</div><div id="tab-findings" class="agent-tab">'+renderAgentFindings(a)+'</div><div id="tab-contract" class="agent-tab">'+renderAgentContract(a)+'</div>'+
 '<div id="tab-evidence" class="agent-tab">'+renderAgentEvidence(a)+'</div>';
 root.querySelector("#back-agents").addEventListener("click",()=>showView("agents"));
 root.querySelectorAll("[data-tab]").forEach(btn=>btn.addEventListener("click",()=>{{
   if(btn.dataset.tab!=="map"){{
     const shell=root.querySelector("#agency-map-shell");
     if(shell) shell.classList.remove("expanded");
     document.body.classList.remove("graph-modal-open");
     const full=root.querySelector("#map-fullscreen");
     if(full) full.textContent="Expand map";
   }}
   root.querySelectorAll("[data-tab]").forEach(x=>x.classList.toggle("active",x===btn));
   root.querySelectorAll(".agent-tab").forEach(x=>x.classList.toggle("active",x.id==="tab-"+btn.dataset.tab));
   if(btn.dataset.tab==="map"){{drawGraph(a);bindGraphControls(a);}}
 }}));
 showView("agent-detail");
}}
function renderFindings(severity="all"){{
 const root=document.getElementById("findings");
 const items=severity==="all"?DATA.findings:DATA.findings.filter(item=>item.severity===severity);
 const banner=severity==="all"?"":'<div class="filter-banner"><span>'+esc(drillLabel("findings",severity))+' · '+number(items.length)+' findings</span><button class="back" id="clear-finding-filter">Clear filter</button></div>';
 root.innerHTML='<h1>Findings</h1><p class="muted">'+number(items.length)+' active findings in this view.</p>'+banner+
 (items.length?items.map(findingCard).join(""):'<div class="empty">No findings matched this filter.</div>');
 if(severity!=="all")root.querySelector("#clear-finding-filter").addEventListener("click",()=>renderFindings("all"));
}}
function renderAttack(){{
 const items=DATA.agents.flatMap(a=>(a.path_views||[]));
 document.getElementById("attack").innerHTML='<h1>Attack paths</h1><p class="muted">Evidence-aware risk chains. Runtime exploitability is not verified.</p>'+
 (items.length?items.map(renderPathCard).join(""):'<div class="empty">No attack paths detected.</div>');
}}
function renderContracts(mode="all"){{
 let items=DATA.agents;
 if(mode==="declared")items=items.filter(a=>a.contract.declared);
 else if(mode==="violation")items=items.filter(a=>a.summary.contract_violations>0);
 else if(mode==="unresolved")items=items.filter(a=>a.summary.contract_unresolved>0);
 const rows=items.map(a=>'<tr class="clickable" data-agent="'+encodeURIComponent(a.name)+'"><td><strong>'+esc(a.name)+'</strong></td><td>'+badge(a.summary.contract_status)+'</td>'+
 '<td>'+number(a.summary.contract_violations)+'</td><td>'+number(a.summary.contract_unresolved)+'</td><td>'+number(a.contract.relationships.length)+'</td></tr>').join("");
 const banner=mode==="all"?"":'<div class="filter-banner"><span>'+esc(drillLabel("contracts",mode))+' · '+number(items.length)+' agents</span><button class="back" id="clear-contract-filter">Clear filter</button></div>';
 const root=document.getElementById("contracts"); root.innerHTML='<h1>Agent contracts</h1><p class="muted">Declared Authority Contract versus reconstructed effective authority.</p>'+banner+
 (rows?'<div class="panel"><table><thead><tr><th>Agent</th><th>Status</th><th>Violations</th><th>Unresolved</th><th>Relationships evaluated</th></tr></thead><tbody>'+rows+'</tbody></table></div>':'<div class="empty">No agents matched this contract filter.</div>');
 bindAgentRows(root);
 if(mode!=="all")root.querySelector("#clear-contract-filter").addEventListener("click",()=>renderContracts("all"));
}}
function renderEvidence(){{
 const c=DATA.coverage, diags=c.diagnostics||[];
 document.getElementById("evidence").innerHTML='<h1>Scan evidence</h1><div class="cards">'+metric("Files considered",c.files_considered)+metric("Files scanned",c.files_scanned)+metric("Files skipped",c.files_skipped)+metric("Files failed",c.files_failed)+'</div>'+
 '<h2>Coverage</h2><div class="panel"><div class="kv"><div>Status</div><div>'+badge(c.incomplete?"unresolved":"compliant")+'</div><div>ASG digest</div><div><code>'+esc(DATA.security_graph.digest)+'</code></div>'+
 '<div>Suppressed findings</div><div>'+number(DATA.suppressed_findings.length)+'</div></div></div><h2>Diagnostics</h2>'+
 (diags.length?diags.map(d=>'<div class="finding" data-sev="medium"><strong>'+esc(d.diagnostic_id||d.code)+'</strong> '+esc(d.message)+'<div class="muted small">'+loc(d.location)+'</div></div>').join(""):'<div class="empty">No detected coverage diagnostics.</div>');
}}
renderDashboard();renderAgents();renderFindings();renderAttack();renderContracts();renderEvidence();
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
