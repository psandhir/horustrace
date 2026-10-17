"""Wave B rw-004: strict source import provenance, including hard negatives.

A source code shape called Agent is not enough to assert a supported Google ADK
principal or corresponding effective tool authority. No target code is run.
"""
from pathlib import Path

from horustrace.scanner import scan


def test_google_adk_source_agent_recognised_without_manifest_duplicate(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        'from google.adk.agents import LlmAgent\n'
        'funnel_agent = LlmAgent(name="FunnelAgent", model="gemini-2.0-flash")\n'
        'root_agent = funnel_agent\n',
        encoding="utf-8",
    )
    (tmp_path / "adk.yaml").write_text(
        'name: agentGemini\n'
        'agent:\n'
        '  entry_point: agent.py\n'
        '  root_agent: root_agent\n',
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert [a.name for a in graph.agents] == ["FunnelAgent"]
    assert all(a.name != "agentGemini" for a in graph.agents)


def test_inconsistent_google_genai_adk_namespace_does_not_gain_canonical_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        'from google.genai.adk import Agent\n'
        'root_agent = Agent(name="AgroAsesorIA", tools=[read_secrets])\n',
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    # The real pinned rw-004 source imports from google.genai.adk rather than
    # the documented Google ADK namespace google.adk. Do not infer effective
    # authority from an unverified module import.
    assert not graph.agents
    assert not any(f.agent == "AgroAsesorIA" for f in findings)


def test_other_sdk_agent_class_does_not_become_google_adk(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        'from another.sdk import Agent\n'
        'root_agent = Agent(name="NotGoogleADK", tools=[delete_everything])\n',
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    assert all(a.name != "NotGoogleADK" for a in graph.agents)
    assert not any(f.agent == "NotGoogleADK" for f in findings)


def test_two_source_files_give_no_phantom_agent_from_display_name(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        'from google.adk.agents import Agent\n'
        'root_agent = Agent(name="FunnelAgent", model="gemini-2.0-flash")\n',
        encoding="utf-8",
    )
    app = tmp_path / "agentGemini"
    app.mkdir()
    (app / "agent.py").write_text(
        'from google.genai.adk import Agent\n'
        'root_agent = Agent(name="AgroAsesorIA")\n',
        encoding="utf-8",
    )
    (tmp_path / "adk.yaml").write_text(
        'name: agentGemini\nagent:\n  entry_point: agent.py\n'
        '  root_agent: root_agent\n',
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert [a.name for a in graph.agents] == ["FunnelAgent"]
