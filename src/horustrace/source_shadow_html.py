"""Opt-in, offline HTML explorer for source-only MCP shadow topology.

Does not import scanner or mutate canonical Graph, findings or authority.
Rejects untrusted/non-source evidence and escapes all embedded source labels.
"""
from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

_ALLOWED_NODES = frozenset({
    "mcp_client_configuration", "mcp_source_implementation", "mcp_source_tool",
})
_ALLOWED_EDGES = {
    "CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION": (
        "mcp_client_configuration", "mcp_source_implementation",
    ),
    "EXPOSES_TOOL": ("mcp_source_implementation", "mcp_source_tool"),
}
_LABELS = {
    "mcp_client_configuration": "Client configuration",
    "mcp_source_implementation": "Server implementation",
    "mcp_source_tool": "Source tool declaration",
}
_PALETTE = {
    "mcp_client_configuration": "client",
    "mcp_source_implementation": "server",
    "mcp_source_tool": "tool",
}


def validate_source_shadow(data: Any) -> tuple[list[dict], list[dict]]:
    """Fail closed on authority promotion, invalid nodes/edges, bad provenance."""
    if not isinstance(data, dict) or data.get("schema_version") not in (1, 2):
        raise ValueError("unsupported source-shadow schema")
    if data.get("mode") != "local_stdio_source_implementation_shadow_not_production_adg":
        raise ValueError("not a source-only MCP shadow")
    if (data.get("production_cutover_authorized") is not False
            or data.get("effective_authority_verified") is not False
            or data.get("runtime_tool_catalogue_verified") is not False):
        raise ValueError("not an unverified source-only shadow")
    nodes = data.get("nodes")
    edges = data.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise TypeError("source-shadow nodes/edges must be lists")
    if len(nodes) > 20000 or len(edges) > 40000:
        raise ValueError("bounded offline report size exceeded")
    seen: dict[str, dict] = {}
    for node in nodes:
        if not isinstance(node, dict) or node.get("kind") not in _ALLOWED_NODES:
            raise ValueError("invalid MCP source node")
        key = node.get("id")
        loc = node.get("location")
        if (not isinstance(key, str) or not key.startswith("shadow-mcp:")
                or len(key) > 128 or key in seen or
                not isinstance(node.get("name"), str)
                or not node["name"].strip() or len(node["name"]) > 2048
                or not isinstance(loc, dict)
                or not isinstance(loc.get("path"), str)
                or len(loc["path"]) > 4096
                or loc["path"].startswith(("/", "./"))
                or "\\" in loc["path"]
                or ".." in loc["path"].split("/")
                or type(loc.get("line")) is not int or loc["line"] < 1
                or node.get("source_only") is not True
                or node.get("deployment_verified") is not False
                or node.get("effective_authority") != "unknown"):
            raise ValueError("invalid or promoted MCP source witness")
        if node["kind"] == "mcp_client_configuration":
            agent_context = node.get("agent")
            if (not isinstance(agent_context, str)
                    or not agent_context.strip() or len(agent_context) > 2048):
                raise ValueError("client configuration missing source agent context")
        seen[key] = node
    identifiers: set[str] = set()
    for edge in edges:
        if not isinstance(edge, dict) or edge.get("kind") not in _ALLOWED_EDGES:
            raise ValueError("invalid source-only relation kind")
        key = edge.get("id")
        if not isinstance(key, str) or key in identifiers:
            raise ValueError("duplicate or invalid source edge")
        identifiers.add(key)
        source = seen.get(edge.get("source"))
        target = seen.get(edge.get("target"))
        expected = _ALLOWED_EDGES[edge["kind"]]
        if (source is None or target is None
                or (source["kind"], target["kind"]) != expected
                or edge.get("source_only") is not True
                or edge.get("effective_agent_can_call") is not None):
            raise ValueError("invalid endpoints or promoted source-only authority")
    actual = dict(sorted(Counter(x["kind"] for x in edges).items()))
    if data.get("edge_kinds") != actual:
        raise ValueError("edge count mismatch")
    return nodes, edges


def _safe(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _json_for_script(data: Any) -> str:
    # JSON is embedded within an ordinary inline script: break up HTML and
    # JS line-separator metacharacters even in an adversarial source label.
    return (json.dumps(data, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"))
            .replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026"))


def render_source_shadow_html(data: dict[str, Any]) -> str:
    nodes, edges = validate_source_shadow(data)
    counters = Counter(node["kind"] for node in nodes)
    cards = []
    for kind in ("mcp_client_configuration", "mcp_source_implementation",
                 "mcp_source_tool"):
        group_cards = []
        for node in sorted((n for n in nodes if n["kind"] == kind),
                           key=lambda x: (x["location"]["path"],
                                          x["location"]["line"], x["name"])):
            loc = node["location"]
            location = f'{loc["path"]}:{loc["line"]}'
            group_cards.append(
                '<button type="button" class="node-card '
                + _PALETTE[kind] + '" data-node="' + _safe(node["id"])
                + '" aria-pressed="false">'
                + '<span class="node-name">' + _safe(node["name"]) + '</span>'
                + '<span class="node-site">' + _safe(location) + '</span>'
                + ('<span class="node-agent">Source agent context: '
                   + _safe(node["agent"]) + '</span>'
                   if kind == "mcp_client_configuration" else '')
                + '<span class="node-state">Source declared · Runtime unknown</span>'
                + '</button>'
            )
        cards.append(
            '<section class="lane"><div class="lane-heading"><h2>'
            + _LABELS[kind] + '</h2><span class="count">'
            + str(counters[kind]) + '</span></div><div class="node-stack">'
            + ("".join(group_cards) if group_cards
               else '<p class="empty">No source witnesses in this category</p>')
            + '</div></section>'
        )
    unresolved = data.get("unresolved", [])
    if not isinstance(unresolved, list):
        raise TypeError("invalid unresolved list")
    reasons = Counter(
        x.get("reason", "unspecified")
        for x in unresolved if isinstance(x, dict)
        and isinstance(x.get("reason"), str)
    )
    unresolved_html = "".join(
        '<li><span>' + _safe(reason) + '</span><strong>' + str(count)
        + '</strong></li>' for reason, count in sorted(reasons.items())
    ) or '<li>None reported by this projection</li>'
    connectivity = {
        "nodes": [{"id": n["id"], "name": n["name"],
                   "kind": n["kind"], "path": n["location"]["path"],
                   "line": n["location"]["line"],
                   "agent": n.get("agent") if n["kind"] == "mcp_client_configuration"
                   else None} for n in nodes],
        "edges": [{"source": e["source"], "target": e["target"],
                   "kind": e["kind"]} for e in edges],
    }
    payload = _json_for_script(connectivity)
    # Only fixed application JS is executable. All source text is HTML-escaped
    # in attributes/content and JSON-escaped in the embedded data literal.
    script = r"""
const topology = __PAYLOAD__;
const buttons = [...document.querySelectorAll('[data-node]')];
const lookup = new Map(topology.nodes.map(node => [node.id, node]));
const adjacency = new Map(topology.nodes.map(node => [node.id, new Set()]));
for (const edge of topology.edges) {
  adjacency.get(edge.source).add(edge.target);
  adjacency.get(edge.target).add(edge.source);
}
const detail = document.querySelector('#selection-detail');
const selectionTitle = document.querySelector('#selection-title');
const reset = document.querySelector('#reset-selection');
let active = null;
function updateFocus() {
  let related = new Set();
  if (active !== null) {
    const queue = [active];
    related.add(active);
    while (queue.length) {
      for (const neighbor of adjacency.get(queue.shift()) || []) {
        if (!related.has(neighbor)) { related.add(neighbor); queue.push(neighbor); }
      }
    }
  }
  for (const button of buttons) {
    const selected = button.dataset.node === active;
    button.classList.toggle('selected', selected);
    button.classList.toggle('dimmed', active !== null && !related.has(button.dataset.node));
    button.setAttribute('aria-pressed', selected ? 'true' : 'false');
  }
  reset.disabled = active === null;
  if (active === null) {
    selectionTitle.textContent = 'All declared source relationships';
    detail.textContent = 'Select a configuration, implementation, or tool to focus its connected source component. Unrelated items stay visible, but defocused.';
  } else {
    const node = lookup.get(active);
    selectionTitle.textContent = node.name + ' — ' + node.path + ':' + node.line;
    const relevant = topology.edges.filter(e => related.has(e.source) && related.has(e.target));
    const exposures = relevant.filter(e => e.kind === 'EXPOSES_TOOL').length;
    const resolves = relevant.filter(e => e.kind === 'CONFIG_RESOLVES_TO_SOURCE_IMPLEMENTATION').length;
    const agentContexts = [...new Set(topology.nodes.filter(n => related.has(n.id) && n.kind === 'mcp_client_configuration').map(n => n.agent))].sort();
    detail.textContent = related.size + ' source nodes; ' + resolves + ' source configuration bindings and ' + exposures + ' tool exposure declarations. Source agent contexts: ' + (agentContexts.length ? agentContexts.join(', ') : 'none observed') + '. No runtime callability or effective agent authority is verified.';
  }
}
document.addEventListener('click', event => {
  const button = event.target.closest('[data-node]');
  if (button) {
    active = active === button.dataset.node ? null : button.dataset.node;
    updateFocus();
  }
});
reset.addEventListener('click', () => { active = null; updateFocus(); });
updateFocus();
""".replace("__PAYLOAD__", payload)
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>HorusScan · MCP Source Topology</title>
<style>
:root{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#15253d;background:#f6f8fc}
*{box-sizing:border-box}body{margin:0}main{max-width:1340px;margin:auto;padding:32px 26px 60px}
header{display:flex;justify-content:space-between;gap:24px;flex-wrap:wrap;align-items:start;margin-bottom:24px}
.eyebrow{font-size:12px;font-weight:750;letter-spacing:.13em;text-transform:uppercase;color:#385c92}
h1{font-size:28px;letter-spacing:-.035em;margin:8px 0}p{line-height:1.55;color:#51647b;margin:6px 0}
.pill{background:#eaf1ff;border:1px solid #bed2ef;padding:8px 12px;border-radius:24px;font-size:12px;font-weight:700;color:#2b5388}
.metrics{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:22px}.metric{background:#fff;border:1px solid #e0e7f0;border-radius:14px;padding:14px 18px;min-width:155px;box-shadow:0 1px 2px #192a4810}
.metric strong{font-size:24px;display:block}.metric span{font-size:12px;color:#61738a}
.warning{border-left:4px solid #e4a655;background:#fff8e9;padding:14px 16px;border-radius:9px;margin-bottom:20px}
.warning strong{color:#7a4b10}.warning p{font-size:13px;color:#73582d}
.board{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
.lane{border:1px solid #e0e7f0;background:#fff;border-radius:16px;min-width:0;padding:14px}
.lane-heading{display:flex;justify-content:space-between;align-items:center;gap:6px;margin-bottom:14px}
.lane h2{font-size:15px;margin:0}.count{background:#edf2f9;border-radius:99px;padding:3px 9px;font-size:12px}
.node-stack{display:flex;flex-direction:column;gap:8px;max-height:650px;overflow:auto}
.node-card{text-align:left;cursor:pointer;padding:12px;border-radius:11px;background:#f8faff;border:1px solid #d5e3f2;display:flex;flex-direction:column;gap:5px;color:inherit;transition:opacity .16s,box-shadow .16s}
.node-card:hover,.node-card:focus-visible{outline:2px solid #7da3ed;outline-offset:1px}
.node-card.server{background:#eef8fa;border-color:#bbdfe4}.node-card.tool{background:#f3f7f1;border-color:#c8dfc6}
.node-card.selected{outline:3px solid #486fda;box-shadow:0 2px 10px #1f428625}
.node-card.dimmed{opacity:.23}.node-name{font-size:14px;font-weight:740;overflow-wrap:anywhere}
.node-site{font-size:11px;color:#526b89;overflow-wrap:anywhere}.node-agent{font-size:11px;font-weight:650;color:#3d6486;overflow-wrap:anywhere}.node-state{font-size:11px;color:#7c6b4d}
.inspector{background:#fff;border:1px solid #e0e7f0;border-radius:15px;margin-top:16px;padding:18px}
.inspector h2{font-size:17px;margin:0 0 8px}button#reset-selection{border:1px solid #bfd0e7;border-radius:9px;background:#f5f8fd;color:#315282;padding:9px 14px;font-weight:600;cursor:pointer}
button:disabled{opacity:.45;cursor:default}.inspector-head{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
details{margin-top:16px;background:#fff;border:1px solid #e0e7f0;border-radius:14px;padding:15px}
details summary{cursor:pointer;font-weight:650}details ul{margin-bottom:0;list-style:none;padding:0}details li{display:flex;justify-content:space-between;gap:14px;border-top:1px solid #e8edf4;padding:8px 0;font-size:13px;overflow-wrap:anywhere}
.empty{font-size:13px}@media(max-width:840px){.board{grid-template-columns:1fr}.node-stack{max-height:330px}main{padding:20px 13px}}
</style></head><body><main>
<header><div><div class="eyebrow">HorusScan · Evidence explorer</div><h1>MCP source supply chain</h1>
<p>Source implementation, client configuration and tool declaration provenance.</p></div>
<span class="pill">EXPERIMENTAL · SOURCE ONLY</span></header>
<section class="metrics">
<div class="metric"><strong>__CLIENT_COUNT__</strong><span>Client configurations</span></div>
<div class="metric"><strong>__SERVER_COUNT__</strong><span>Distinct source implementations</span></div>
<div class="metric"><strong>__TOOL_COUNT__</strong><span>Declared source tools</span></div>
<div class="metric"><strong>__EXPOSURE_COUNT__</strong><span>Source EXPOSES_TOOL edges</span></div>
</section>
<aside class="warning"><strong>Declared source relationships, not effective authority</strong>
<p>No runtime catalogue, successful MCP connection, agent invocation permission, credentials or attack-path viability has been verified. This explorer does not change the canonical ADG or security findings.</p></aside>
<div class="board">__CARDS__</div>
<section class="inspector" aria-live="polite"><div class="inspector-head"><h2 id="selection-title"></h2><button id="reset-selection" type="button">Show all</button></div>
<p id="selection-detail"></p></section>
<details><summary>Unresolved source relationships (__UNRESOLVED_COUNT__)</summary><ul>__UNRESOLVED_HTML__</ul></details>
</main><script>__SCRIPT__</script></body></html>
""".replace("__CLIENT_COUNT__", str(counters["mcp_client_configuration"]))\
        .replace("__SERVER_COUNT__", str(counters["mcp_source_implementation"]))\
        .replace("__TOOL_COUNT__", str(counters["mcp_source_tool"]))\
        .replace("__EXPOSURE_COUNT__", str(Counter(x["kind"] for x in edges)["EXPOSES_TOOL"]))\
        .replace("__CARDS__", "".join(cards))\
        .replace("__UNRESOLVED_COUNT__", str(len(unresolved)))\
        .replace("__UNRESOLVED_HTML__", unresolved_html)\
        .replace("__SCRIPT__", script)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render strictly source-only MCP shadow JSON as an offline HTML explorer."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    rendered = render_source_shadow_html(data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "mode": "opt_in_source_only_mcp_html",
        "production_cutover_authorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
