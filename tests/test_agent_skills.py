from pathlib import Path

from horustrace.aibom import build_aibom
from horustrace.scanner import scan


def _skill(root: Path, name: str = "review", *, allowed_tools: str = "Read") -> Path:
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    skill = skill_dir / "SKILL.md"
    skill.write_text(
        f"""---
name: {name}
description: Review repository changes safely.
allowed-tools: {allowed_tools}
---
Read the repository and follow the review procedure.
""",
        encoding="utf-8",
    )
    return skill


def test_unbound_skill_is_inventory_not_authority(tmp_path: Path) -> None:
    _skill(tmp_path / "skills", allowed_tools="*")

    graph, findings = scan(tmp_path)

    assert [skill.name for skill in graph.unbound_skills] == ["review"]
    assert not any(finding.rule_id.startswith("SKL") for finding in findings)
    assert graph.adg is not None
    aibom = build_aibom(graph.adg)
    assert aibom["summary"]["by_kind"]["skill"] == 1


def test_claude_agent_definition_binds_named_skill(tmp_path: Path) -> None:
    _skill(tmp_path / ".claude" / "skills", allowed_tools="*")
    (tmp_path / "agent.py").write_text(
        """from claude_agent_sdk import AgentDefinition

reviewer = AgentDefinition(
    description="Reviews changes",
    prompt="Review this repository",
    skills=["review"],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    reviewer = next(agent for agent in graph.agents if agent.name == "reviewer")
    assert [skill.name for skill in reviewer.skills] == ["review"]
    assert graph.unbound_skills == []
    assert any(finding.rule_id == "SKL001" for finding in findings)


def test_openai_sandbox_agent_binds_literal_skill_directory(tmp_path: Path) -> None:
    _skill(tmp_path / "skills")
    (tmp_path / "agent.py").write_text(
        """from agents.sandbox import SandboxAgent
from agents.sandbox.capabilities import Skills
from agents.sandbox.entries import LocalDir

agent = SandboxAgent(
    name="sandbox",
    capabilities=[Skills(from_=LocalDir(src="skills"))],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(agent for agent in graph.agents if agent.name == "sandbox")
    assert [skill.name for skill in agent.skills] == ["review"]
    assert agent.metadata["sandbox_agent"] is True


def test_microsoft_agent_framework_binds_skills_provider_paths(tmp_path: Path) -> None:
    _skill(tmp_path / "skills")
    (tmp_path / "agent.py").write_text(
        """from agent_framework import Agent, SkillsProvider

skills_provider = SkillsProvider.from_paths(skill_paths="skills")
agent = Agent(
    name="microsoft",
    context_providers=[skills_provider],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(agent for agent in graph.agents if agent.name == "microsoft")
    assert [skill.name for skill in agent.skills] == ["review"]


def test_strands_harness_binds_configured_skill_directory(tmp_path: Path) -> None:
    _skill(tmp_path / "skills")
    (tmp_path / "agent.py").write_text(
        """from strands_harness import create_harness

agent = create_harness(skills=["skills"])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(agent for agent in graph.agents if agent.name == "agent")
    assert [skill.name for skill in agent.skills] == ["review"]


def test_skill_policy_allow_required_and_deny_are_evaluated(tmp_path: Path) -> None:
    _skill(tmp_path / "skills")
    (tmp_path / "agent.py").write_text(
        """from agents.sandbox import SandboxAgent
from agents.sandbox.capabilities import Skills
from agents.sandbox.entries import LocalDir

agent = SandboxAgent(
    name="sandbox",
    capabilities=[Skills(from_=LocalDir(src="skills"))],
)
""",
        encoding="utf-8",
    )
    (tmp_path / "horustrace.manifest.yaml").write_text(
        """version: 1
agents:
  - name: sandbox
    policy:
      allowed_skills: [approved-only]
      required_skills: [mandatory-review]
      denied_skills: [review]
""",
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert {"SKL010", "SKL011", "SKL012"} <= rule_ids


def test_invalid_skill_manifest_is_reported_without_inventory(tmp_path: Path) -> None:
    skill_dir = tmp_path / "skills" / "broken"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# no frontmatter\n", encoding="utf-8")

    graph, _ = scan(tmp_path)

    assert graph.unbound_skills == []
    diagnostic = next(
        item for item in graph.coverage.diagnostics
        if item.kind == "invalid_skill_manifest"
    )
    assert diagnostic.code == "ARG-COV-022"
