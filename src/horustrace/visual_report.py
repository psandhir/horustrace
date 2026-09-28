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
from horustrace.models import Finding, Graph, Severity
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
        contract_status = "not_declared"
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
border:1px solid var(--line);border-radius:12px;padding:15px;box-shadow:var(--shadow)}} .metric{{font-size:28px;font-weight:800}}
.metric-label{{color:var(--muted);font-size:12px;margin-top:3px}} .critical{{color:var(--critical)}} .high{{color:var(--high)}}
.medium{{color:var(--medium)}} .low{{color:var(--low)}} .ok{{color:var(--ok)}} .warn{{color:var(--warn)}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:14px}} .panel{{background:var(--panel);border:1px solid var(--line);
border-radius:12px;padding:16px;margin-bottom:14px}} table{{width:100%;border-collapse:collapse}} th,td{{padding:10px 8px;
border-bottom:1px solid var(--line);text-align:left;vertical-align:top}} th{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}}
tr.clickable{{cursor:pointer}} tr.clickable:hover{{background:#ffffff08}} .badge{{display:inline-block;padding:3px 7px;border-radius:999px;
font-size:11px;font-weight:700;background:#ffffff0b;border:1px solid var(--line)}} .badge.violation{{color:var(--critical);border-color:#ff6b7560}}
.badge.compliant{{color:var(--ok);border-color:#63d69f60}} .badge.unresolved{{color:var(--warn);border-color:#f1c75b60}}
.badge.not_declared{{color:var(--muted)}} .search{{width:100%;max-width:420px;background:var(--panel);color:var(--text);border:1px solid var(--line);
border-radius:9px;padding:9px 11px;margin:0 0 12px}} .agent-head{{display:flex;gap:14px;justify-content:space-between;align-items:start}}
.tabs{{display:flex;gap:6px;border-bottom:1px solid var(--line);margin:18px 0 14px;overflow:auto}} .tabs button{{border:0;background:transparent;
color:var(--muted);padding:9px 10px;cursor:pointer;border-bottom:2px solid transparent}} .tabs button.active{{color:var(--text);border-bottom-color:var(--accent)}}
.agent-tab{{display:none}} .agent-tab.active{{display:block}} .kv{{display:grid;grid-template-columns:170px 1fr;gap:7px 14px}}
.kv div:nth-child(odd){{color:var(--muted)}} .finding{{border-left:3px solid var(--line);padding:12px 14px;margin:10px 0;background:#0d1426;border-radius:8px}}
.finding[data-sev="critical"]{{border-left-color:var(--critical)}} .finding[data-sev="high"]{{border-left-color:var(--high)}}
.finding[data-sev="medium"]{{border-left-color:var(--medium)}} .finding[data-sev="low"]{{border-left-color:var(--low)}}
.finding-title{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}} code,pre{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
code{{background:#ffffff0b;padding:2px 5px;border-radius:5px}} details{{margin-top:8px}} pre{{white-space:pre-wrap;word-break:break-word;
background:#09101e;border:1px solid var(--line);padding:12px;border-radius:8px;max-height:340px;overflow:auto}}
.graph-wrap{{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:12px}} .graph{{width:100%;height:520px;background:#09101e;
border:1px solid var(--line);border-radius:10px}} .inspector{{min-height:120px}} .legend{{display:flex;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:12px;margin:7px 0 12px}}
.dot{{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:4px}} .empty{{padding:24px;text-align:center;color:var(--muted);
border:1px dashed var(--line);border-radius:10px}} .back{{border:1px solid var(--line);background:var(--panel);color:var(--text);padding:7px 10px;
border-radius:8px;cursor:pointer}} .small{{font-size:12px}} .nowrap{{white-space:nowrap}} .sevbar{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}
svg text{{fill:var(--text);font-family:ui-sans-serif,system-ui;font-size:12px}} .edge{{stroke:#65728c;stroke-width:1.4;opacity:.72}}
.node rect{{fill:#16213a;stroke:#42516f;stroke-width:1}} .node.agent rect{{fill:#1b3157;stroke:#78a8ff}} .node.identity rect{{fill:#2b2545;stroke:#a895ff}}
.node.resource rect{{fill:#21362f;stroke:#63d69f}} .node.destination rect{{fill:#3a2d22;stroke:#f1b36a}} .node.unresolved rect{{stroke-dasharray:5 4}}
.node{{cursor:pointer}} .node:hover rect{{stroke-width:2}} .label2{{fill:var(--muted);font-size:10px}} .footer{{color:var(--muted);font-size:11px;margin:28px 0 4px}}
@media(max-width:900px){{.shell{{grid-template-columns:1fr}} aside{{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line)}}
.nav{{display:flex;overflow:auto}} .nav button{{width:auto;white-space:nowrap}} main{{padding:18px}} .grid2,.graph-wrap{{grid-template-columns:1fr}}
.graph{{height:440px}} .kv{{grid-template-columns:1fr}}}}
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
function metric(label,value,cls=""){{return '<div class="card"><div class="metric '+cls+'">'+number(value)+'</div><div class="metric-label">'+esc(label)+'</div></div>'}}
function severityCards(s){{
 return '<div class="sevbar">'+metric("Critical",s.critical,"critical")+metric("High",s.high,"high")+metric("Medium",s.medium,"medium")+metric("Low",s.low,"low")+'</div>';
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
 document.getElementById("dashboard").innerHTML='<div class="hero"><div><h1>Security assessment</h1><div class="muted">Effective authority, policy findings and agent-contract posture</div></div>'+
 (s.analysis_incomplete?'<span class="badge unresolved">analysis incomplete</span>':'<span class="badge compliant">no detected coverage gaps</span>')+'</div>'+
 '<div class="cards">'+metric("Agents",s.agents)+metric("Tools",s.tools)+metric("MCP servers",s.mcp_servers)+metric("Identities",s.identities)+
 metric("Reachable resources",s.resources)+metric("Attack paths",s.attack_paths)+metric("Findings",s.findings)+metric("Contract violations",s.contract_violations,"critical")+'</div>'+
 '<h2>Finding severity</h2>'+severityCards(s.severity)+
 '<div class="grid2"><div><h2>Effective agency</h2><div class="panel"><div class="kv"><div>Authority relationships</div><div>'+number(s.authority_relationships)+'</div>'+
 '<div>Not fully resolved</div><div>'+number(s.authority_not_fully_resolved)+'</div><div>Write-capable paths</div><div>'+number(s.write_capable_relationships)+'</div>'+
 '<div>Unique destinations</div><div>'+number(s.destinations)+'</div></div></div></div>'+
 '<div><h2>Agent contracts</h2><div class="panel"><div class="kv"><div>Agents with contract</div><div>'+number(s.agents_with_contract)+'</div>'+
 '<div>Violations</div><div class="critical">'+number(s.contract_violations)+'</div><div>Unresolved checks</div><div class="warn">'+number(s.contract_unresolved)+'</div></div></div></div></div>'+
 '<h2>Agents needing attention</h2>'+agentTable(DATA.agents.filter(a=>a.summary.findings||a.summary.contract_violations||a.summary.contract_unresolved).slice(0,12));
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
function renderAgents(){{
 const root=document.getElementById("agents");
 root.innerHTML='<h1>Agents</h1><p class="muted">Select an agent to inspect declared and effective agency.</p><input id="agent-search" class="search" placeholder="Filter agents, frameworks or locations">'+
 '<div id="agent-table">'+agentTable(DATA.agents)+'</div>';
 bindAgentRows(root);
 root.querySelector("#agent-search").addEventListener("input",e=>{{
   const q=e.target.value.toLowerCase();
   const items=DATA.agents.filter(a=>JSON.stringify([a.name,a.framework,a.location,a.resources,a.identities]).toLowerCase().includes(q));
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
 return '<div class="legend"><span><i class="dot" style="background:#78a8ff"></i>Agent</span><span><i class="dot" style="background:#6f84aa"></i>Tool / MCP</span>'+
 '<span><i class="dot" style="background:#a895ff"></i>Identity</span><span><i class="dot" style="background:#63d69f"></i>Resource</span><span><i class="dot" style="background:#f1b36a"></i>Destination</span></div>'+
 '<div class="graph-wrap"><svg class="graph" id="agency-svg" viewBox="0 0 1080 520" preserveAspectRatio="xMidYMid meet"></svg><div class="panel inspector" id="graph-inspector"><h3>Path inspector</h3><p class="muted">Select a graph node to inspect its evidence.</p></div></div>';
}}
function svgNode(x,y,w,label,sub,kind,key,unresolved=false){{
 const cls="node "+kind+(unresolved?" unresolved":"");
 return '<g class="'+cls+'" data-node="'+esc(key)+'" transform="translate('+x+','+y+')"><rect width="'+w+'" height="54" rx="8"></rect>'+
 '<text x="12" y="22">'+esc(label.length>26?label.slice(0,24)+"…":label)+'</text><text class="label2" x="12" y="40">'+esc(sub)+'</text></g>';
}}
function drawGraph(a){{
 const svg=document.getElementById("agency-svg"); if(!svg)return;
 const rels=a.effective_authority.slice(0,14), row=Math.max(62,440/Math.max(1,rels.length)), center=235;
 const nodes=[], edges=[], info={{}};
 nodes.push(svgNode(30,center,185,a.name,a.framework,"agent","agent"));
 info.agent={{type:"Agent",name:a.name,location:a.location,framework:a.framework}};
 rels.forEach((r,i)=>{{
   const y=24+i*row, targetKey="target-"+i;
   edges.push('<line class="edge" x1="215" y1="'+(center+27)+'" x2="300" y2="'+(y+27)+'"></line>');
   nodes.push(svgNode(300,y,205,r.target.name,r.target.kind,"target",targetKey,r.resolution!=="fully_resolved"));
   info[targetKey]=r;
   let prevX=505, prevY=y+27;
   if(r.identity){{
     const k="identity-"+i; edges.push('<line class="edge" x1="'+prevX+'" y1="'+prevY+'" x2="570" y2="'+prevY+'"></line>');
     nodes.push(svgNode(570,y,190,r.identity.name,r.identity.provider||"identity","identity",k,r.dimensions.identity!=="resolved")); info[k]=r.identity; prevX=760;
   }}
   const outputs=[];
   (r.resources||[]).slice(0,2).forEach(x=>outputs.push(["resource",x.selector,x.kind,x]));
   (r.destinations||[]).slice(0,1).forEach(x=>outputs.push(["destination",x.target,x.direction,x]));
   outputs.forEach((o,j)=>{{
     const oy=y+(j-(outputs.length-1)/2)*58, k=o[0]+"-"+i+"-"+j;
     edges.push('<line class="edge" x1="'+prevX+'" y1="'+prevY+'" x2="825" y2="'+(oy+27)+'"></line>');
     nodes.push(svgNode(825,oy,220,o[1],o[2],o[0],k,false)); info[k]=o[3];
   }});
 }});
 svg.innerHTML=edges.join("")+nodes.join("");
 svg.querySelectorAll("[data-node]").forEach(n=>n.addEventListener("click",()=>{{
   const item=info[n.dataset.node]; document.getElementById("graph-inspector").innerHTML='<h3>'+esc(item.name||item.target?.name||item.selector||item.target||a.name)+'</h3><pre>'+esc(JSON.stringify(item,null,2))+'</pre>';
 }}));
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
 '<div class="tabs"><button class="active" data-tab="overview">Overview</button><button data-tab="map">Agency map</button><button data-tab="findings">Findings</button><button data-tab="contract">Contract</button><button data-tab="evidence">Evidence</button></div>'+
 '<div id="tab-overview" class="agent-tab active">'+renderAgentOverview(a)+'</div><div id="tab-map" class="agent-tab">'+renderGraph(a)+'</div>'+
 '<div id="tab-findings" class="agent-tab">'+renderAgentFindings(a)+'</div><div id="tab-contract" class="agent-tab">'+renderAgentContract(a)+'</div>'+
 '<div id="tab-evidence" class="agent-tab">'+renderAgentEvidence(a)+'</div>';
 root.querySelector("#back-agents").addEventListener("click",()=>showView("agents"));
 root.querySelectorAll("[data-tab]").forEach(btn=>btn.addEventListener("click",()=>{{
   root.querySelectorAll("[data-tab]").forEach(x=>x.classList.toggle("active",x===btn));
   root.querySelectorAll(".agent-tab").forEach(x=>x.classList.toggle("active",x.id==="tab-"+btn.dataset.tab));
   if(btn.dataset.tab==="map")drawGraph(a);
 }}));
 showView("agent-detail");
}}
function renderFindings(){{
 const root=document.getElementById("findings");
 root.innerHTML='<h1>Findings</h1><p class="muted">'+number(DATA.findings.length)+' active findings from the current rule set.</p>'+
 (DATA.findings.length?DATA.findings.map(findingCard).join(""):'<div class="empty">No active findings.</div>');
}}
function renderAttack(){{
 const items=DATA.security_graph.attack_paths||[];
 const rows=items.map(x=>'<tr><td><strong>'+esc(x.path_id)+'</strong><div class="muted small">'+esc(x.title)+'</div></td><td>'+esc(x.agent)+'</td><td class="'+esc(x.severity)+'">'+esc(x.severity)+'</td><td>'+esc((x.nodes||[]).join(" → "))+'</td></tr>').join("");
 document.getElementById("attack").innerHTML='<h1>Attack paths</h1><p class="muted">Potential static attack paths. Runtime exploitability is not verified.</p>'+
 (rows?'<div class="panel"><table><thead><tr><th>Path</th><th>Agent</th><th>Severity</th><th>Chain</th></tr></thead><tbody>'+rows+'</tbody></table></div>':'<div class="empty">No attack paths detected.</div>');
}}
function renderContracts(){{
 const rows=DATA.agents.map(a=>'<tr class="clickable" data-agent="'+encodeURIComponent(a.name)+'"><td><strong>'+esc(a.name)+'</strong></td><td>'+badge(a.summary.contract_status)+'</td>'+
 '<td>'+number(a.summary.contract_violations)+'</td><td>'+number(a.summary.contract_unresolved)+'</td><td>'+number(a.contract.relationships.length)+'</td></tr>').join("");
 const root=document.getElementById("contracts"); root.innerHTML='<h1>Agent contracts</h1><p class="muted">Declared Authority Contract versus reconstructed effective authority.</p>'+
 '<div class="panel"><table><thead><tr><th>Agent</th><th>Status</th><th>Violations</th><th>Unresolved</th><th>Relationships evaluated</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
 bindAgentRows(root);
}}
function renderEvidence(){{
 const c=DATA.coverage, diags=c.diagnostics||[];
 document.getElementById("evidence").innerHTML='<h1>Scan evidence</h1><div class="cards">'+metric("Files considered",c.files_considered)+metric("Files scanned",c.files_scanned)+metric("Files skipped",c.files_skipped)+metric("Files failed",c.files_failed)+'</div>'+
 '<h2>Coverage</h2><div class="panel"><div class="kv"><div>Status</div><div>'+badge(c.incomplete?"unresolved":"compliant")+'</div><div>ASG digest</div><div><code>'+esc(DATA.security_graph.digest)+'</code></div>'+
 '<div>Suppressed findings</div><div>'+number(DATA.suppressed_findings.length)+'</div></div></div><h2>Diagnostics</h2>'+
 (diags.length?diags.map(d=>'<div class="finding" data-sev="medium"><strong>'+esc(d.diagnostic_id||d.code)+'</strong> '+esc(d.message)+'<div class="muted small">'+loc(d.location)+'</div></div>').join(""):'<div class="empty">No detected coverage diagnostics.</div>');
}}
renderDashboard();renderAgents();renderFindings();renderAttack();renderContracts();renderEvidence();bindAgentRows(document.getElementById("dashboard"));
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
