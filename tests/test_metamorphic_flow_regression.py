"""Metamorphic source-only probe and detector regression for #511."""
import ast
import json
from pathlib import Path

import pytest

from horustrace.evaluation.metamorphic import (
    FAMILIES,
    generate_variant,
    security_claims,
)
from horustrace.models import Confidence
from horustrace.scanner import scan

MANIFEST = Path(__file__).parent / "fixtures/adversarial_static/manifest.json"
CASES = json.loads(MANIFEST.read_text(encoding="utf-8"))["cases"]
PROTECTED = ("ops", "agent_tool_input", "process_execute")


@pytest.mark.parametrize("entry", CASES, ids=lambda item: item["case_id"])
def test_source_preserving_transforms_keep_security_claim_and_near_misses_do_not(
    entry, tmp_path: Path,
) -> None:
    variant = generate_variant(entry["family"], entry["seed"])
    assert variant.family == entry["family"]
    assert variant.seed == entry["seed"]
    assert variant.risky_source != variant.near_miss_source
    ast.parse(variant.risky_source)
    ast.parse(variant.near_miss_source)
    (tmp_path / "agent.py").write_text(variant.risky_source, encoding="utf-8")
    positive, positive_findings = scan(tmp_path)
    assert PROTECTED in security_claims(positive)
    assert any(
        item.rule_id == "PATH001" and item.confidence is Confidence.SUPPORTED
        for item in positive_findings
    )
    (tmp_path / "agent.py").write_text(variant.near_miss_source, encoding="utf-8")
    negative, negative_findings = scan(tmp_path)
    assert PROTECTED not in security_claims(negative)
    assert not any(
        item.rule_id == "PATH001" and item.confidence is Confidence.SUPPORTED
        for item in negative_findings
    )


def test_manifest_is_immutable_declared_paired_set():
    assert len(CASES) == 24
    assert {case["family"] for case in CASES} == set(FAMILIES)
    assert len({case["case_id"] for case in CASES}) == 24
    for family in FAMILIES:
        assert {case["seed"] for case in CASES if case["family"] == family} == {0, 1, 2}


@pytest.mark.parametrize("code", [
    """
import subprocess
from agents import Agent, function_tool
@function_tool
def dangerous_tool(subprocess, command: str):
    subprocess.run(command)
agent = Agent(name="ops", tools=[dangerous_tool])
""",
    """
from subprocess import run as launch
from agents import Agent, function_tool
def launch(value):
    return value
@function_tool
def dangerous_tool(command: str):
    launch(command)
agent = Agent(name="ops", tools=[dangerous_tool])
""",
    """
import subprocess as sp
from agents import Agent, function_tool
@function_tool
def dangerous_tool(command: str):
    sp = object()
    sp.run(command)
agent = Agent(name="ops", tools=[dangerous_tool])
""",
    """
from agents import Agent, function_tool
import subprocess
class Worker:
    def execute(self, command):
        subprocess.run(command, shell=True)
@function_tool
def dangerous_tool(command: str):
    worker = [Worker()]
    worker.execute(command)
agent = Agent(name="ops", tools=[dangerous_tool])
""",
    """
from agents import Agent, function_tool
import subprocess
class Worker:
    def execute(self, command):
        subprocess.run(command, shell=True)
class Harmless:
    def execute(self, command):
        return command
Worker = Harmless
@function_tool
def dangerous_tool(command: str):
    Worker().execute(command)
agent = Agent(name="ops", tools=[dangerous_tool])
""",
    """
from agents import Agent, function_tool
import subprocess
class Worker:
    def __init__(self, command):
        self.command = command
    def execute(self, value):
        subprocess.run(value, shell=True)
@function_tool
def dangerous_tool(command: str):
    Worker(command).execute(command)
agent = Agent(name="ops", tools=[dangerous_tool])
""",
])
def test_near_misses_do_not_invent_supported_flows(tmp_path: Path, code: str):
    (tmp_path / "agent.py").write_text(code, encoding="utf-8")
    graph, findings = scan(tmp_path)
    assert PROTECTED not in security_claims(graph)
    assert not any(
        item.rule_id == "PATH001" and item.confidence is Confidence.SUPPORTED
        for item in findings
    )
    if "def __init__" in code:
        assert any(
            diagnostic.kind == "unresolved_dataflow"
            for diagnostic in graph.coverage.diagnostics
        )


def test_bound_methods_respect_two_distinct_instances(tmp_path: Path):
    code = """
from agents import Agent, function_tool
import subprocess
class Worker:
    def execute(self, value):
        subprocess.run(value, shell=True)
class SafeWorker:
    def execute(self, value):
        return value
@function_tool
def risky(command: str):
    worker = Worker()
    worker.execute(command)
@function_tool
def safe(command: str):
    worker = SafeWorker()
    worker.execute(command)
risky_agent = Agent(name="risk", tools=[risky])
safe_agent = Agent(name="safe", tools=[safe])
"""
    (tmp_path / "agent.py").write_text(code, encoding="utf-8")
    graph, findings = scan(tmp_path)
    observed = security_claims(graph)
    assert ("risk", "agent_tool_input", "process_execute") in observed
    assert ("safe", "agent_tool_input", "process_execute") not in observed
    assert not any(
        item.rule_id == "PATH001"
        and item.agent == "safe"
        and item.confidence is Confidence.SUPPORTED
        for item in findings
    )


def test_generator_is_deterministic_and_rejects_unreviewed_transforms():
    assert generate_variant("module_alias", 1) == generate_variant("module_alias", 1)
    with pytest.raises(ValueError):
        generate_variant("unsupported", 0)
    with pytest.raises(ValueError):
        generate_variant("module_alias", 3)
