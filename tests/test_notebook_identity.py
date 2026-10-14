"""No ephemeral extracted-notebook identity may contaminate authority relations."""
from __future__ import annotations

import json
from pathlib import Path

from horustrace.effective_authority import effective_authority_relationships
from horustrace.models import Agent, Graph, SourceLocation, Tool
from horustrace.notebook_identity import remap_notebook_instance_metadata
from horustrace.scanner import scan


def _graph(source: Path):
    temp = source
    agent = Agent(
        name="request_approval",
        location=SourceLocation(temp, 3),
        tools=[Tool(
            name="handoff",
            kind="delegated_agent",
            metadata={"delegate_target_instance_key": f"{temp}:3",
                      "origin": {"instance_key": f"{temp}:3"}},
        )],
        metadata={"instance_key": f"{temp}:3"},
    )
    return Graph(agents=[agent])


def test_extract_paths_rewritten_to_same_cell_source_instance(tmp_path: Path):
    notebook = tmp_path / "app" / "review.ipynb"
    notebook.parent.mkdir()
    notebook.write_text("{}")
    results = []
    for index in (1, 2):
        folder = tmp_path / f"horustrace-notebooks-random{index}"
        folder.mkdir()
        temp = folder / "review-0.py"
        temp.write_text("# notebook-cell-0\ndef request_approval():\n    pass\n")
        graph = _graph(temp)
        changed = remap_notebook_instance_metadata(
            graph, temp, notebook, tmp_path,
        )
        assert changed >= 3
        agent = graph.agents[0]
        value = agent.metadata["instance_key"]
        assert value == "notebook:app/review.ipynb#cell-0:line-2"
        assert agent.tools[0].metadata["delegate_target_instance_key"] == value
        assert agent.tools[0].metadata["origin"]["instance_key"] == value
        assert str(temp) not in json.dumps(agent.metadata)
        assert str(temp) not in json.dumps(agent.tools[0].metadata)
        results.append(value)
    assert results[0] == results[1]


def test_real_notebook_double_scan_has_same_authority_instance_keys(tmp_path: Path):
    source = (
        "from agents import Agent, function_tool\n"
        "@function_tool\n"
        "def request_approval(command: str) -> str:\n"
        "    return command\n"
        "reviewer = Agent(name='reviewer', tools=[request_approval])\n"
    )
    (tmp_path / "agents.ipynb").write_text(json.dumps({
        "cells": [{"cell_type": "code", "source": source,
                   "metadata": {}, "outputs": [], "execution_count": None}],
        "metadata": {}, "nbformat": 4, "nbformat_minor": 5,
    }))
    left, left_findings = scan(tmp_path)
    right, right_findings = scan(tmp_path)
    assert left.agents, "fixture must actually produce a notebook-backed agent"
    assert right.agents
    keys_left = [a.metadata.get("instance_key") for a in left.agents]
    keys_right = [a.metadata.get("instance_key") for a in right.agents]
    assert keys_left == keys_right
    assert all("horustrace-notebooks-" not in str(key) for key in keys_left)
    left_edges = [r.as_dict() for r in effective_authority_relationships(left)]
    right_edges = [r.as_dict() for r in effective_authority_relationships(right)]
    assert left_edges == right_edges
    assert left_findings == right_findings
