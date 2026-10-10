"""Finding-specific evidence must not be replaced by the whole agent inventory."""
from pathlib import Path

from horustrace.models import (
    Agent,
    AgentPolicy,
    AttackPath,
    DataSource,
    EvidenceFact,
    Finding,
    Graph,
    NetworkDestination,
    Severity,
    SourceLocation,
    Tool,
)
from horustrace.provenance import attach_findings, context


def _fixture():
    code = SourceLocation(Path("agent.py"), line=29)
    data_loc = SourceLocation(Path("horustrace.manifest.yaml"), line=1)
    shell_loc = SourceLocation(Path("agent.py"), line=14)
    send_loc = SourceLocation(Path("agent.py"), line=17)
    shell = Tool(
        name="shell",
        kind="function",
        capabilities={"process.execute"},
        location=shell_loc,
        provenance=[
            EvidenceFact("shell", "capability=process.execute", "observed", shell_loc),
            EvidenceFact("shell", "approval_configuration=True", "observed", shell_loc),
        ],
    )
    outbound = Tool(
        name="send",
        kind="function",
        capabilities={"network.external", "external.write"},
        location=send_loc,
        provenance=[
            EvidenceFact("send", "capability=network.external", "observed", send_loc),
            EvidenceFact("send", "capability=external.write", "observed", send_loc),
            EvidenceFact("send", "approval_configuration=False", "observed", send_loc),
        ],
    )
    noise = Tool(
        name="irrelevant_tool", kind="generic",
        provenance=[
            EvidenceFact("irrelevant_tool", f"unrelated_{i}={i}", "observed", code)
            for i in range(50)
        ],
        location=code,
    )
    sensitive = DataSource(
        name="finance", classification="confidential", location=data_loc,
        provenance=[
            EvidenceFact("finance", "classification=confidential", "declared", data_loc),
            EvidenceFact("finance", "capability=data.read", "declared", data_loc),
        ],
    )
    external = NetworkDestination(
        target="*", restricted=False, location=data_loc,
        provenance=[
            EvidenceFact("demo", "destination=*", "declared", data_loc),
            EvidenceFact("demo", "restriction_declaration=False", "declared", data_loc),
        ],
    )
    policy = AgentPolicy(
        denied_capabilities={"process.execute"},
        provenance=[
            EvidenceFact("demo", "denied=process.execute", "declared", data_loc)
        ],
    )
    agent = Agent(
        name="demo", tools=[shell, outbound, noise],
        data_sources=[sensitive], network=[external], policy=policy, location=code,
    )
    nodes = ["finance", "demo", "send", "external destination"]
    path = AttackPath(
        path_id="PATH003",
        title="Potential sensitive-data path to an external destination",
        agent="demo", nodes=nodes, severity=Severity.CRITICAL,
        rationale="Potential capability combination", location=send_loc,
        metadata={"basis": "capability_cooccurrence"},
    )
    def finding(rule, layer, evidence, location):
        return Finding(
            rule_id=rule, severity=Severity.CRITICAL, title=rule,
            message=rule, recommendation="Review", layer=layer, location=location,
            agent="demo", evidence=evidence,
        )
    findings = [
        finding("AGT010", 4, ["sensitive=finance", "outbound=send"], code),
        finding("CAP002", 2, ["denied=process.execute"], code),
        finding("DATA003", 4, ["sensitive=finance"], code),
        finding("PATH003", 5, [" -> ".join(nodes)], send_loc),
    ]
    return Graph(agents=[agent], attack_paths=[path]), findings


def test_finding_provenance_differs_by_rule_and_preserves_full_inventory():
    graph, findings = _fixture()
    original = context(graph.agents[0])
    assert len(original) >= 55

    attach_findings(graph, findings)
    selected = {
        finding.rule_id: {fact.fact for fact in finding.provenance}
        for finding in findings
    }
    assert all(0 < len(finding.provenance) < len(original) for finding in findings)
    assert len({frozenset(facts) for facts in selected.values()}) == 4

    assert "denied=process.execute" in selected["CAP002"]
    assert "capability=process.execute" in selected["CAP002"]
    assert "capability=network.external" not in selected["CAP002"]
    assert "approval_configuration=False" not in selected["CAP002"]

    assert "classification=confidential" in selected["AGT010"]
    assert "approval_configuration=False" in selected["AGT010"]
    assert "capability=process.execute" not in selected["AGT010"]
    assert "denied=process.execute" not in selected["AGT010"]

    assert "destination=*" in selected["DATA003"]
    assert "restriction_declaration=False" in selected["DATA003"]
    assert "approval_configuration=False" not in selected["DATA003"]
    assert "capability=process.execute" not in selected["DATA003"]

    assert "classification=confidential" in selected["PATH003"]
    assert "capability=network.external" in selected["PATH003"]
    assert "approval_configuration=False" in selected["PATH003"]
    assert "denied=process.execute" not in selected["PATH003"]

    for facts in selected.values():
        assert not any(fact.startswith("unrelated_") for fact in facts)

    # The source-backed inventory is intact, not deleted to make the UI shorter.
    assert context(graph.agents[0]) == original
    assert [f.rule_id for f in findings] == ["AGT010", "CAP002", "DATA003", "PATH003"]
    assert all(f.severity is Severity.CRITICAL for f in findings)


def test_path_provenance_uses_the_matched_path_not_another_tool():
    graph, findings = _fixture()
    outbound = graph.agents[0].tools[1]
    other = Tool(
        name="other_sender", kind="function",
        location=outbound.location,
        provenance=[
            EvidenceFact("other_sender", "capability=network.external",
                         "observed", outbound.location)
        ],
    )
    graph.agents[0].tools.append(other)

    attach_findings(graph, findings)
    path = next(f for f in findings if f.rule_id == "PATH003")
    assert all(fact.subject != "other_sender" for fact in path.provenance)


def test_unmatched_attack_path_does_not_borrow_agent_wide_facts():
    graph, findings = _fixture()
    path = next(f for f in findings if f.rule_id == "PATH003")
    path.evidence = ["unknown -> unmatched -> chain"]
    attach_findings(graph, [path])
    assert not path.provenance
    assert path.confidence is not None
    assert any("does not prove" in limit for limit in path.limitations)


def test_generic_finding_at_agent_location_does_not_inherit_other_tools():
    graph, _ = _fixture()
    generic = Finding(
        rule_id="CAP005", severity=Severity.HIGH, title="Read/write",
        message="Read/write", recommendation="Review",
        layer=2, location=graph.agents[0].location,
        agent="demo", evidence=["unexpected=process.execute"],
    )
    attach_findings(graph, [generic])
    assert len(generic.provenance) < len(context(graph.agents[0]))
    assert not any("unrelated_" in fact.fact for fact in generic.provenance)


def test_delegated_path_omits_unrelated_child_capabilities_and_approvals():
    graph, _ = _fixture()
    agent = graph.agents[0]
    location = SourceLocation(Path("agent.py"), line=26)
    delegate = Tool(
        name="delegate:worker",
        kind="delegated_agent",
        location=location,
        provenance=[
            EvidenceFact("shell", "capability=process.execute", "observed", location),
            EvidenceFact("shell", "approval_configuration=None", "observed", location),
            EvidenceFact("publish", "capability=external.write", "observed", location),
            EvidenceFact("publish", "approval_configuration=False", "observed", location),
            EvidenceFact("publish", "guardrail_hook_detected=False", "observed", location),
        ],
    )
    agent.tools.append(delegate)
    nodes = ["finance", "demo", "delegate:worker", "external destination"]
    graph.attack_paths.append(AttackPath(
        path_id="PATH003", title="Delegated external write", agent="demo",
        nodes=nodes, severity=Severity.CRITICAL, rationale="Potential authority",
        location=location, metadata={"basis": "capability_cooccurrence"},
    ))
    delegated = Finding(
        rule_id="PATH003", severity=Severity.CRITICAL, title="Delegated",
        message="Delegated", recommendation="Review", layer=5,
        agent="demo", location=location, evidence=[" -> ".join(nodes)],
    )
    attach_findings(graph, [delegated])
    supporting = {(f.subject, f.fact) for f in delegated.provenance}
    assert ("publish", "capability=external.write") in supporting
    assert ("publish", "approval_configuration=False") in supporting
    assert ("shell", "capability=process.execute") not in supporting
    assert ("shell", "approval_configuration=None") not in supporting

