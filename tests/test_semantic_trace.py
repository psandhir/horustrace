"""Passive semantic tracing must never change scanner security semantics."""
from __future__ import annotations

import json
from pathlib import Path

from horustrace.models import Agent, Graph, SourceLocation, Tool
from horustrace.scanner import scan
from horustrace.semantic_trace import SemanticTrace


def test_stage_trace_is_passive_on_real_scanner(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "def helper(payload):\n"
        "    return payload\n"
        "agent = Agent('test:model', tools=[helper])\n",
        encoding="utf-8",
    )
    baseline, base_findings = scan(tmp_path)
    tracer = SemanticTrace(tmp_path)
    traced, trace_findings = scan(tmp_path, trace=tracer)
    assert baseline == traced
    assert base_findings == trace_findings
    doc = tracer.as_dict()
    assert doc["schema_version"] == 1
    assert doc["accuracy_adjudicated"] is False
    assert doc["events_truncated"] is False
    assert [stage["stage"] for stage in doc["stages"]] == [
        "discovered", "initial_instances_consolidated",
        "mcp_context_resolved", "source_semantics_resolved",
        "delegation_projected", "skills_bound", "normalized",
        "flows_resolved", "attack_paths", "adg", "findings",
    ]
    assert any(row["stage"] == "discovered" for row in doc["events"])
    assert "agent.py" in json.dumps(doc)
    assert str(tmp_path) not in json.dumps(doc)


def test_trace_detects_mcp_and_tool_binding_stage_without_mutation(tmp_path: Path):
    source = SourceLocation(tmp_path / "agent.py", line=9)
    g = Graph(agents=[Agent(name="example", location=source)])
    trace = SemanticTrace(tmp_path)
    trace.capture("discovered", g)
    g.agents[0].tools.append(Tool(name="search", kind="function", capabilities={"data.read"}, location=source))
    trace.capture("bindings", g)
    assert any(
        e["action"] == "added"
        and e["observation"]["kind"] == "binds_tool"
        and e["observation"]["name"] == "search"
        and e["stage"] == "bindings"
        for e in trace.events
    )
    g.agents[0].tools.clear()
    trace.capture("removed", g)
    assert any(
        e["action"] == "removed"
        and e["observation"]["kind"] == "binds_tool"
        for e in trace.events
    )


def test_trace_budget_is_explicit_not_silent(tmp_path: Path):
    g = Graph(agents=[Agent(name="one"), Agent(name="two")])
    trace = SemanticTrace(tmp_path, max_events=1)
    trace.capture("discovered", g)
    doc = trace.as_dict()
    assert len(doc["events"]) == 1
    assert doc["events_truncated"] is True
    assert doc["stages"][0]["added"] == 2


def test_trace_does_not_expose_arbitrary_scanner_metadata(tmp_path: Path):
    secret = "TOP_SECRET_DO_NOT_PRINT"
    g = Graph(agents=[Agent(name="a", metadata={"private_token": secret})])
    trace = SemanticTrace(tmp_path)
    trace.capture("discovered", g)
    assert secret not in json.dumps(trace.as_dict())
