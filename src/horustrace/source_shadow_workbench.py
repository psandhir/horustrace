"""Isolated, opt-in MCP source-shadow evidence overlay for the Workbench.

No scanner imports or writes, and no canonical ADG, findings, authority, or
attack-path projection. The only accepted inputs are already bounded C02r
source-shadow JSON artifacts for the very same checked-out source scope.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from horustrace.source_shadow_attestation import verify_mcp_source_shadow
from horustrace.source_shadow_html import validate_source_shadow

MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_WITNESS_FILE_BYTES = 2 * 1024 * 1024
MAX_OVERLAY_NODES = 4000
MAX_OVERLAY_EDGES = 8000

SOURCE_OVERLAY_CSS = """
.mcp-evidence-warning{border:1px solid #ebca8b;border-left:4px solid #d89b3d;
background:#fff7e9;border-radius:10px;padding:14px 16px;margin:12px 0 20px}
html[data-theme="dark"] .mcp-evidence-warning{background:#33291b;border-color:#a77b35}
.mcp-evidence-warning strong{display:block;color:var(--text);font-size:13px}
.mcp-evidence-warning p{font-size:12px;line-height:1.6;margin:6px 0;color:var(--muted)}
.mcp-evidence-summary{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0}
.mcp-evidence-summary .card{padding:12px 16px;min-width:125px;flex:1}
.mcp-evidence-summary strong{display:block;font-size:22px}
.mcp-evidence-summary span{font-size:11px;color:var(--muted)}
.mcp-evidence-lanes{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.mcp-evidence-lane{background:var(--surface);border:1px solid var(--line);
border-radius:var(--radius);padding:14px;min-width:0}
.mcp-evidence-lane h2{font-size:14px;margin:0 0 12px}
.mcp-evidence-cards{display:flex;flex-direction:column;gap:8px;max-height:680px;overflow-y:auto}
.mcp-evidence-node{width:100%;text-align:left;border:1px solid var(--line-strong);
background:var(--surface2);color:var(--text);border-radius:10px;
padding:11px;display:flex;flex-direction:column;gap:5px;cursor:pointer}
.mcp-evidence-node[data-kind="mcp_source_implementation"]{border-left:4px solid #74b3c4}
.mcp-evidence-node[data-kind="mcp_source_tool"]{border-left:4px solid #8abf94}
.mcp-evidence-node.selected{outline:2px solid var(--accent);outline-offset:1px}
.mcp-evidence-node.dimmed{opacity:.24}
.mcp-evidence-node:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.mcp-evidence-name{font-weight:700;font-size:13px;overflow-wrap:anywhere}
.mcp-evidence-site,.mcp-evidence-agent{font-size:11px;color:var(--muted);overflow-wrap:anywhere}
.mcp-evidence-status{font-size:11px;color:var(--muted2)}
.mcp-evidence-crosswalk{font-size:11px;color:var(--muted);border-top:1px dashed var(--line);padding-top:6px}
.mcp-evidence-crosswalk-summary{border:1px solid var(--line);border-radius:10px;
background:var(--surface2);padding:12px;margin:12px 0;font-size:12px;color:var(--muted)}
.mcp-evidence-details{margin-top:16px;padding:16px;background:var(--surface);
border:1px solid var(--line);border-radius:var(--radius);min-height:110px}
.mcp-evidence-details h2{font-size:15px;margin:0 0 8px}
.mcp-evidence-details p{font-size:12px;line-height:1.6;color:var(--muted)}
.mcp-evidence-reset{border:1px solid var(--line-strong);background:var(--surface2);
color:var(--text);padding:9px 12px;border-radius:9px;cursor:pointer}
.mcp-evidence-reset:disabled{opacity:.45;cursor:default}
.mcp-evidence-details-head{display:flex;align-items:center;justify-content:space-between;gap:12px}
@media(max-width:880px){.mcp-evidence-lanes{grid-template-columns:1fr}
.mcp-evidence-cards{max-height:320px}}
"""

# All user-controlled display strings flow through the Workbench esc() helper.
# The data itself is embedded in a non-executable, HTML-escaped JSON element.
SOURCE_OVERLAY_JS = r"""
function renderMcpSourceEvidence() {
 const root=document.getElementById("mcp-source-evidence");
 const element=document.getElementById("horus-mcp-source-data");
 if (!root || !element) return;
 const model=JSON.parse(element.textContent);
 const labels={
  mcp_client_configuration:"MCP client configurations",
  mcp_source_implementation:"Source server implementations",
  mcp_source_tool:"Declared source tools"
 };
 const kinds=Object.keys(labels);
 const counts=Object.fromEntries(kinds.map(kind=>[kind,model.nodes.filter(n=>n.kind===kind).length]));
 const exposures=model.edges.filter(e=>e.kind==="EXPOSES_TOOL").length;
 const summary=[
  ["Client configurations",counts.mcp_client_configuration],
  ["Source implementations",counts.mcp_source_implementation],
  ["Declared tool sites",counts.mcp_source_tool],
  ["EXPOSES_TOOL edges",exposures]
 ].map(([label,count])=>'<div class="card"><strong>'+number(count)+'</strong><span>'+esc(label)+'</span></div>').join("");
 const columns=kinds.map(kind=>{
  const cards=model.nodes.filter(n=>n.kind===kind).sort((a,b)=>
    a.path.localeCompare(b.path)||a.line-b.line||a.name.localeCompare(b.name))
   .map(n=>'<button type="button" class="mcp-evidence-node" data-kind="'+esc(n.kind)+'" data-mcp-evidence-node="'+esc(n.id)+'" aria-pressed="false">'+
   '<span class="mcp-evidence-name">'+esc(n.name)+'</span>'+
   '<span class="mcp-evidence-site">'+esc(n.path)+':'+number(n.line)+'</span>'+
   (n.agent?'<span class="mcp-evidence-agent">Source agent context: '+esc(n.agent)+'</span>':'')+
   '<span class="mcp-evidence-status">Source only · Runtime unknown</span>'+
   (n.c03_source_site_match?
    '<span class="mcp-evidence-crosswalk">Canonical source-site correlation: '+
     esc(n.c03_source_site_match.label)+
     ' ('+number(n.c03_source_site_match.canonical_match_count)+
     ' source-site records). Semantic identity and runtime authority unverified.</span>':'')+
   '</button>').join("");
  return '<section class="mcp-evidence-lane"><h2>'+esc(labels[kind])+' · '+number(counts[kind])+'</h2>'+
   '<div class="mcp-evidence-cards">'+(cards||'<p class="muted">No source sites in this category</p>')+'</div></section>';
 }).join("");
 const note=model.unresolved.length?model.unresolved.map(x=>'<li>'+esc(x.reason)+'</li>').join(""):"<li>None reported</li>";
 const crosswalkNote=model.c03_preview?
  '<div class="mcp-evidence-crosswalk-summary"><strong>C03 preview: canonical source-site matches only (NOT semantic identity)</strong>'+
  '<p>Candidate-only: '+number(model.c03_preview.node_status_counts.candidate_only||0)+
  ' · Corroborated source sites: '+number(model.c03_preview.node_status_counts.corroborated_source_site||0)+
  ' · Ambiguous: '+number(model.c03_preview.node_status_counts.ambiguous_source_site||0)+
  '. Runtime authority unknown; precision/recall not assessed. No canonical Graph changes.</p></div>':'';
 root.innerHTML=pageHead("Source evidence · Experimental","MCP source topology",
  "Read-only source declarations. The canonical supply chain, findings and authority assessments are unchanged.")+
  '<div class="mcp-evidence-warning"><strong>Source declarations are not runtime permissions</strong>'+
  '<p>Configuration, MCP implementation and decorated tool provenance only. MCP connection, deployed credentials, effective AGENT_CAN_CALL and attack-path reachability remain unverified. Git HEAD, tracked blob and file SHA-256 were verified at report generation, but claims are not independently adjudicated.</p>'+
  '<p>Checked source revision: <code>'+esc(model.source_commit_sha)+'</code> · source-only evidence, not deployed authority.</p></div>'+
  '<div class="mcp-evidence-summary">'+summary+'</div>'+
  crosswalkNote+
  '<div class="mcp-evidence-lanes">'+columns+'</div>'+
  '<section class="mcp-evidence-details" aria-live="polite">'+
  '<div class="mcp-evidence-details-head"><h2 id="mcp-evidence-title">All source relationships</h2>'+
  '<button class="mcp-evidence-reset" data-mcp-evidence-reset type="button">Show all</button></div>'+
  '<p id="mcp-evidence-description"></p></section>'+
  '<details class="panel"><summary>Unresolved source observations ('+number(model.unresolved.length)+')</summary><ul>'+note+'</ul></details>';
 const byId=new Map(model.nodes.map(n=>[n.id,n]));
 const adj=new Map(model.nodes.map(n=>[n.id,new Set()]));
 for(const edge of model.edges){
  adj.get(edge.source).add(edge.target);
  adj.get(edge.target).add(edge.source);
 }
 const buttons=[...root.querySelectorAll("[data-mcp-evidence-node]")];
 const title=root.querySelector("#mcp-evidence-title");
 const description=root.querySelector("#mcp-evidence-description");
 const reset=root.querySelector("[data-mcp-evidence-reset]");
 let active=null;
 function showSelection(){
  const relevant=new Set();
  if(active!==null){
   const queue=[active];relevant.add(active);
   while(queue.length){
    for(const id of adj.get(queue.shift())||[]){
     if(!relevant.has(id)){relevant.add(id);queue.push(id);}
    }
   }
  }
  for(const btn of buttons){
   const selected=btn.dataset.mcpEvidenceNode===active;
   btn.classList.toggle("selected",selected);
   btn.classList.toggle("dimmed",active!==null&&!relevant.has(btn.dataset.mcpEvidenceNode));
   btn.setAttribute("aria-pressed",String(selected));
  }
  reset.disabled=active===null;
  if(active===null){
   title.textContent="All declared MCP source relationships";
   description.textContent="Select a source configuration, implementation or tool to highlight its connected component. Unrelated elements remain visible but de-emphasized.";
  }else{
   const selected=byId.get(active);
   const edges=model.edges.filter(e=>relevant.has(e.source)&&relevant.has(e.target));
   const sourceAgents=[...new Set(model.nodes.filter(n=>n.agent&&relevant.has(n.id)).map(n=>n.agent))].sort();
   title.textContent=selected.name+" — "+selected.path+":"+selected.line;
   description.textContent=relevant.size+" related source nodes; "+
    edges.filter(e=>e.kind==="CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION").length+" source configuration bindings; "+
    edges.filter(e=>e.kind==="EXPOSES_TOOL").length+" declared tool exposures. Source agent contexts: "+
    (sourceAgents.join(", ")||"none observed")+". Runtime callability and effective authority are unknown.";
  }
 }
 for(const button of buttons){
  button.addEventListener("click",()=>{
   const id=button.dataset.mcpEvidenceNode;
   active=active===id?null:id;showSelection();
  });
 }
 reset.addEventListener("click",()=>{active=null;showSelection();});
 showSelection();
}
renderMcpSourceEvidence();
"""


def load_mcp_source_overlay(evidence: Path, root: Path) -> dict[str, Any]:
    """Load only source-shadow artefacts with local, bounded line witnesses.

    Requires v2 exact Git HEAD/blob and worktree SHA-256 agreement across
    every source file cited by the shadow; this does not independently
    adjudicate the semantic claims or prove any runtime authority.
    """
    if not evidence.is_file() or evidence.stat().st_size > MAX_EVIDENCE_BYTES:
        raise ValueError("source-shadow artifact missing or too large")
    data = json.loads(evidence.read_text(encoding="utf-8"))
    return project_mcp_source_overlay(data, root)


def project_mcp_source_overlay(data: dict[str, Any], root: Path) -> dict[str, Any]:
    """Reject stale source; return minimal display-only canonical-isolated data."""
    nodes, edges = validate_source_shadow(data)
    verify_mcp_source_shadow(data, root)
    if len(nodes) > MAX_OVERLAY_NODES or len(edges) > MAX_OVERLAY_EDGES:
        raise ValueError("MCP source overlay exceeds bounded UI size")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("MCP overlay scope must be a checkout directory")
    cached_lines: dict[str, int] = {}
    projected_nodes: list[dict[str, Any]] = []
    for node in nodes:
        path = node["location"]["path"]
        file = (root / path).resolve(strict=True)
        if not file.is_relative_to(root) or not file.is_file():
            raise ValueError("MCP evidence source witness is outside the scan root")
        if path not in cached_lines:
            if file.stat().st_size > MAX_WITNESS_FILE_BYTES:
                raise ValueError("source witness too large for bounded verification")
            cached_lines[path] = len(file.read_bytes().splitlines())
        if node["location"]["line"] > cached_lines[path]:
            raise ValueError("source witness line does not exist in scan checkout")
        projected_nodes.append({
            "id": node["id"], "kind": node["kind"], "name": node["name"],
            "path": path, "line": node["location"]["line"],
            "agent": node.get("agent") if node["kind"] == "mcp_client_configuration" else None,
        })
    # Only a bounded, inert presentation subset of the input reaches the
    # Workbench. Never use this model to alter scan findings or graph inputs.
    unresolved = data.get("unresolved", [])
    if not isinstance(unresolved, list):
        raise TypeError("invalid source shadow unresolved list")
    return {
        "mode": "opt_in_mcp_source_evidence_not_authority",
        "source_commit_sha": data["source_revision"]["commit_sha"],
        "source_integrity_checked": True,
        "source_only": True,
        "runtime_authority_verified": False,
        "nodes": projected_nodes,
        "edges": [
            {"kind": edge["kind"], "source": edge["source"],
             "target": edge["target"]} for edge in edges
        ],
        "unresolved": [
            {"reason": row["reason"]} for row in unresolved
            if isinstance(row, dict) and isinstance(row.get("reason"), str)
        ][:500],
    }
