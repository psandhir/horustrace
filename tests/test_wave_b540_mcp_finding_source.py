"""Wave B: positive MCP manifest anchors; unsupported dual-leg risk stays conditional."""
from __future__ import annotations

from pathlib import Path

from horustrace.models import (
    Agent,
    EvidenceFact,
    Finding,
    Graph,
    MCPServer,
    Severity,
    SourceLocation,
    Tool,
)
from horustrace.provenance import attach_findings


def _finding(rule: str, location: SourceLocation, agent: str | None = None,
             url: str = "https://mcp.example.test/api") -> Finding:
    return Finding(
        rule, Severity.MEDIUM, rule, rule, "Review source",
        location=location, agent=agent,
        evidence=(
            ["url=" + url, "allowed_tools=none",
             "tool_scope_resolution=unknown"]
            if rule == "AGT032"
            else ["data.read", "data.write/destructive.write",
                  "authority_relationship=authority-v1:unverified"]
        ),
    )


def test_two_declared_manifest_urls_do_not_cross_attribute(tmp_path: Path) -> None:
    loc = SourceLocation(tmp_path / "ToolingManifest.json", 1)
    a = MCPServer("mcp_Mail", "streamable-http", url="https://mcp.example.test/a",
                  location=loc)
    b = MCPServer("mcp_Calendar", "streamable-http",
                  url="https://mcp.example.test/b", location=loc)
    agent = Agent("manifest-owner", mcp_servers=[a, b])
    findings = [
        _finding("AGT032", loc, url="https://mcp.example.test/a"),
        _finding("AGT032", loc, url="https://mcp.example.test/b"),
    ]
    attach_findings(Graph(agents=[agent]), findings)
    assert [x.provenance[0].subject for x in findings] == [
        "mcp_Mail", "mcp_Calendar"
    ]
    assert [x.provenance[0].fact for x in findings] == [
        "url=https://mcp.example.test/a", "url=https://mcp.example.test/b"
    ]
    assert all(
        len(f.provenance) == 1 and f.provenance[0].origin == "declared"
        and f.provenance[0].location == loc
        and not any("allowlist" in fact.fact or "catalogue" in fact.fact
                    for fact in f.provenance)
        and any("deployed MCP tool catalogue" in lim for lim in f.limitations)
        for f in findings
    )


def test_no_manifest_url_match_must_not_fake_provenance(tmp_path: Path) -> None:
    loc = SourceLocation(tmp_path / "ToolingManifest.json", 1)
    server = MCPServer("one", "http", url="https://mcp.example.test/true",
                       location=loc)
    f = _finding("AGT032", loc, url="https://mcp.example.test/false")
    attach_findings(Graph(unbound_mcp_servers=[server]), [f])
    assert not f.provenance
    assert any("unverified" in x for x in f.limitations)


def test_duplicate_identical_source_sites_are_not_unique(tmp_path: Path) -> None:
    loc = SourceLocation(tmp_path / "ToolingManifest.json", 1)
    url = "https://mcp.example.test/api"
    graph = Graph(unbound_mcp_servers=[
        MCPServer("one", "http", url=url, location=loc),
        MCPServer("two", "http", url=url, location=loc),
    ])
    f = _finding("AGT032", loc)
    attach_findings(graph, [f])
    assert not f.provenance


def test_no_source_location_no_positive_config_fact(tmp_path: Path) -> None:
    loc = SourceLocation(tmp_path / "ToolingManifest.json", 1)
    server = MCPServer("one", "http", url="https://mcp.example.test/api")
    f = _finding("AGT032", loc)
    attach_findings(Graph(unbound_mcp_servers=[server]), [f])
    assert not f.provenance


def test_cap005_unknown_two_legs_remains_findings_but_potential(tmp_path: Path) -> None:
    loc = SourceLocation(tmp_path / "agent.py", 73)
    agent = Agent("agent", location=loc)
    f = _finding("CAP005", loc, agent="agent")
    attach_findings(Graph(agents=[agent]), [f])
    assert f.provenance == []
    assert f.assessment == "heuristic_risk"
    assert f.confidence is not None and f.confidence.value == "potential"
    assert any("Separate source-backed read and write" in x for x in f.limitations)
    assert all("runtime verified" not in x.lower() for x in f.evidence)


def test_cap005_both_true_located_facts_keep_original_assessment(
    tmp_path: Path,
) -> None:
    loc = SourceLocation(tmp_path / "agent.py", 73)
    tl = SourceLocation(tmp_path / "agent.py", 33)
    tool = Tool(
        "read_write", "function", capabilities={"data.read", "data.write"},
        location=tl,
        provenance=[
            EvidenceFact("read_write", "capability=data.read", "observed", tl),
            EvidenceFact("read_write", "capability=data.write", "observed", tl),
        ],
    )
    f = _finding("CAP005", loc, agent="agent")
    attach_findings(Graph(agents=[Agent("agent", tools=[tool], location=loc)]), [f])
    assert {x.fact for x in f.provenance} == {
        "capability=data.read", "capability=data.write"
    }
    assert f.assessment == "static_configuration"
    assert f.confidence is None


def test_manifest_rule_must_not_borrow_agent_sources(tmp_path: Path) -> None:
    loc = SourceLocation(tmp_path / "ToolingManifest.json", 1)
    server = MCPServer("one", "http", url="https://mcp.example.test/api",
                       location=loc)
    other = Tool("noise", "function", location=loc,
                 provenance=[EvidenceFact("noise", "capability=process.execute",
                                          "observed", loc)])
    f = _finding("AGT032", loc)
    attach_findings(Graph(unbound_mcp_servers=[server], unbound_tools=[other]),
                    [f])
    assert len(f.provenance) == 1
    assert f.provenance[0].subject == "one"
    assert "process.execute" not in f.provenance[0].fact
