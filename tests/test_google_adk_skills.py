from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def _write_skill(
    root: Path,
    *,
    name: str = "review",
    metadata: str = "",
    instructions: str = "Review the repository safely.",
) -> Path:
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    metadata_block = f"metadata:\n{metadata}" if metadata else ""
    (skill_dir / "SKILL.md").write_text(
        f"""---
name: {name}
description: Security review skill.
{metadata_block}
---
{instructions}
""",
        encoding="utf-8",
    )
    return skill_dir


def test_adk_skilltoolset_binds_filesystem_skill_without_generic_tool(
    tmp_path: Path,
) -> None:
    _write_skill(tmp_path / "skills")
    (tmp_path / "agent.py").write_text(
        """
import pathlib

from google.adk import Agent
from google.adk.skills import load_skill_from_dir
from google.adk.tools.skill_toolset import SkillToolset

review_skill = load_skill_from_dir(
    pathlib.Path(__file__).parent / "skills" / "review"
)
skill_tools = SkillToolset(skills=[review_skill])
root_agent = Agent(
    name="reviewer",
    model="gemini-flash-latest",
    tools=[skill_tools],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "reviewer")

    assert [skill.name for skill in agent.skills] == ["review"]
    assert graph.unbound_skills == []
    assert not any(tool.name == "skill_tools" for tool in agent.tools)
    assert agent.metadata["skill_source_paths"] == ["skills/review"]
    assert agent.metadata["adk_skill_toolsets"][0]["alias"] == "skill_tools"
    assert agent.skills[0].metadata["adk_skilltoolset"] is True


def test_adk_skill_additional_tool_becomes_effective_only_when_requested(
    tmp_path: Path,
) -> None:
    _write_skill(
        tmp_path / "skills",
        metadata="  adk_additional_tools: [publish_event]",
    )
    (tmp_path / "agent.py").write_text(
        """
import pathlib
import requests

from google.adk import Agent
from google.adk.skills import load_skill_from_dir
from google.adk.tools.skill_toolset import SkillToolset

def publish_event(payload: dict):
    return requests.post("https://events.example.test/publish", json=payload)

def unused_delete():
    return requests.delete("https://events.example.test/all")

review_skill = load_skill_from_dir(
    pathlib.Path(__file__).parent / "skills" / "review"
)
skill_tools = SkillToolset(
    skills=[review_skill],
    additional_tools=[publish_event, unused_delete],
)
root_agent = Agent(name="reviewer", tools=[skill_tools])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    skill = next(item for item in graph.agents[0].skills if item.name == "review")

    assert "network.external" in skill.capabilities
    assert "external.write" in skill.capabilities
    assert "destructive.write" not in skill.capabilities
    assert skill.metadata["adk_resolved_additional_tools"] == ["publish_event"]
    assert skill.metadata["adk_requested_additional_tools"] == ["publish_event"]
    assert [item.target for item in skill.destinations] == [
        "https://events.example.test/publish"
    ]


def test_adk_skill_script_effects_promote_with_unsafe_local_executor(
    tmp_path: Path,
) -> None:
    skill_dir = _write_skill(
        tmp_path / "skills",
        instructions="Run the script to publish the result.",
    )
    scripts = skill_dir / "scripts"
    scripts.mkdir()
    (scripts / "publish.py").write_text(
        """
import subprocess
import requests

subprocess.run(["echo", "review"], check=True)
requests.post("https://hooks.example.test/review", json={"ok": True})
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
import pathlib

from google.adk import Agent
from google.adk.code_executors.unsafe_local_code_executor import (
    UnsafeLocalCodeExecutor,
)
from google.adk.skills import load_skill_from_dir
from google.adk.tools.skill_toolset import SkillToolset

review_skill = load_skill_from_dir(
    pathlib.Path(__file__).parent / "skills" / "review"
)
skill_tools = SkillToolset(
    skills=[review_skill],
    code_executor=UnsafeLocalCodeExecutor(),
)
root_agent = Agent(name="reviewer", tools=[skill_tools])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    skill = graph.agents[0].skills[0]

    assert {"process.execute", "network.external", "external.write"} <= skill.capabilities
    assert skill.metadata["adk_script_execution"]["state"] == "enabled"
    assert skill.metadata["adk_script_execution"]["sandboxed"] is False
    assert "network.external" in skill.metadata["adk_script_observed_capabilities"]
    assert [item.target for item in skill.destinations] == [
        "https://hooks.example.test/review"
    ]

    relationship = next(
        item
        for item in effective_authority_report(graph)["relationships"]
        if item["target"] == {"kind": "skill", "name": "review"}
    )
    assert "process.execute" in relationship["capabilities"]
    assert "network.external" in relationship["capabilities"]


def test_adk_skill_script_is_not_effective_without_executor(tmp_path: Path) -> None:
    skill_dir = _write_skill(
        tmp_path / "skills",
        instructions="Run the script to publish the result.",
    )
    scripts = skill_dir / "scripts"
    scripts.mkdir()
    (scripts / "publish.py").write_text(
        'import requests\nrequests.post("https://hooks.example.test/review")\n',
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
import pathlib

from google.adk import Agent
from google.adk.skills import load_skill_from_dir
from google.adk.tools.skill_toolset import SkillToolset

review_skill = load_skill_from_dir(
    pathlib.Path(__file__).parent / "skills" / "review"
)
skill_tools = SkillToolset(skills=[review_skill])
root_agent = Agent(name="reviewer", tools=[skill_tools])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    skill = graph.agents[0].skills[0]

    assert "process.execute" not in skill.capabilities
    assert "network.external" not in skill.capabilities
    assert skill.metadata["adk_script_execution"] == {
        "available": False,
        "state": "disabled_no_executor",
    }
    assert "network.external" in skill.metadata["adk_script_observed_capabilities"]


def test_adk_inline_skill_and_requested_tool_are_source_proven(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import requests

from google.adk import Agent
from google.adk.skills import models
from google.adk.tools.skill_toolset import SkillToolset

def lookup_status():
    return requests.get("https://status.example.test/api")

support_skill = models.Skill(
    frontmatter=models.Frontmatter(
        name="support-status",
        description="Check support status.",
        metadata={"adk_additional_tools": ["lookup_status"]},
    ),
    instructions="Use the status lookup tool.",
    resources=models.Resources(),
)
skill_tools = SkillToolset(
    skills=[support_skill],
    additional_tools=[lookup_status],
)
root_agent = Agent(name="support", tools=[skill_tools])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    skill = graph.agents[0].skills[0]

    assert skill.name == "support-status"
    assert skill.source == "inline"
    assert skill.metadata["binding_origin"] == "adk_inline_skilltoolset"
    assert skill.metadata["adk_resolved_additional_tools"] == ["lookup_status"]
    assert "network.external" in skill.capabilities
    assert [item.target for item in skill.destinations] == [
        "https://status.example.test/api"
    ]


def test_adk_skill_registry_remains_unresolved_catalogue(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk import Agent
from google.adk.skills import SkillRegistry
from google.adk.tools.skill_toolset import SkillToolset

registry = SkillRegistry(client=object())
skill_tools = SkillToolset(registry=registry)
root_agent = Agent(name="registry-user", tools=[skill_tools])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]

    assert agent.skills == []
    assert agent.metadata["remote_skill_sources"][0]["source"] == "SkillRegistry"
    assert any(
        item.kind == "unresolved_skill"
        and item.details.get("source", {}).get("source") == "SkillRegistry"
        for item in graph.coverage.diagnostics
    )
    report = effective_authority_report(graph)
    assert report["summary"]["unresolved_skill_catalogues"] == 1


def test_adk_load_skills_from_dir_binds_literal_directory_with_local_environment(
    tmp_path: Path,
) -> None:
    calc = _write_skill(
        tmp_path / "skills",
        name="calc",
        instructions="Run the calculation script.",
    )
    scripts = calc / "scripts"
    scripts.mkdir()
    (scripts / "calculate.py").write_text(
        """
import requests
requests.post("https://math.example.test/result", json={"value": 3})
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
import pathlib

from google.adk import Agent
from google.adk.environment import LocalEnvironment
from google.adk.skills import load_skills_from_dir
from google.adk.tools.skill_toolset import SkillToolset

skills = load_skills_from_dir(pathlib.Path(__file__).parent / "skills")
skill_toolset = SkillToolset(
    skills=skills,
    environment=LocalEnvironment(),
)
root_agent = Agent(name="local-skills", tools=[skill_toolset])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "local-skills")
    skill = next(item for item in agent.skills if item.name == "calc")

    assert graph.unbound_skills == []
    assert agent.metadata["skill_source_paths"] == ["skills"]
    assert agent.metadata.get("dynamic_skill_sources") is not True
    assert skill.metadata["binding_source_path"] == "skills"
    assert skill.metadata["adk_script_execution"]["state"] == "enabled"
    assert skill.metadata["adk_script_execution"]["sandboxed"] is False
    assert (
        skill.metadata["adk_script_execution"]["executor_kind"]
        == "local_environment"
    )
    assert {"process.execute", "network.external", "external.write"} <= skill.capabilities
    assert [item.target for item in skill.destinations] == [
        "https://math.example.test/result"
    ]


def test_adk_load_skills_from_dir_binds_e2b_environment_as_sandboxed(
    tmp_path: Path,
) -> None:
    calc = _write_skill(
        tmp_path / "skills",
        name="calc",
        instructions="Run the calculation script.",
    )
    scripts = calc / "scripts"
    scripts.mkdir()
    (scripts / "calculate.py").write_text(
        """
import requests
requests.post("https://math.example.test/result", json={"value": 3})
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
import pathlib

from google.adk import Agent
from google.adk.integrations.e2b import E2BEnvironment
from google.adk.skills import load_skills_from_dir
from google.adk.tools.skill_toolset import SkillToolset

skills = load_skills_from_dir(pathlib.Path(__file__).parent / "skills")
skill_toolset = SkillToolset(
    skills=skills,
    environment=E2BEnvironment(),
)
root_agent = Agent(name="sandboxed-skills", tools=[skill_toolset])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "sandboxed-skills")
    skill = next(item for item in agent.skills if item.name == "calc")

    assert graph.unbound_skills == []
    assert skill.metadata["adk_script_execution"]["state"] == "enabled"
    assert skill.metadata["adk_script_execution"]["sandboxed"] is True
    assert (
        skill.metadata["adk_script_execution"]["executor_kind"]
        == "remote_sandbox_environment"
    )
    assert "process.execute" in skill.capabilities
    assert "network.external" not in skill.capabilities
    assert skill.destinations == []
    assert "network.external" in skill.metadata["adk_script_observed_capabilities"]
    assert skill.metadata["adk_script_observed_destinations"] == [
        "https://math.example.test/result"
    ]


def test_adk_gcs_loaded_skill_collection_is_remote_unresolved_catalogue(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk import Agent
from google.adk.skills import list_skills_in_gcs_dir
from google.adk.skills import load_skill_from_gcs_dir
from google.adk.tools.skill_toolset import SkillToolset

BUCKET_NAME = "sample-skills"
SKILLS_PREFIX = "static-skills"

skills = []
available_skills = list_skills_in_gcs_dir(
    bucket_name=BUCKET_NAME,
    skills_base_path=SKILLS_PREFIX,
)
for skill_id in available_skills.keys():
    skills.append(
        load_skill_from_gcs_dir(
            bucket_name=BUCKET_NAME,
            skills_base_path=SKILLS_PREFIX,
            skill_id=skill_id,
        )
    )

skill_toolset = SkillToolset(skills=skills)
root_agent = Agent(name="gcs-skills", tools=[skill_toolset])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "gcs-skills")

    assert agent.skills == []
    assert graph.unbound_skills == []
    assert agent.metadata.get("dynamic_skill_sources") is not True
    assert agent.metadata["remote_skill_sources"] == [
        {
            "provider": "google-adk",
            "source": "Google Cloud Storage Skill catalogue",
            "bucket": "sample-skills",
            "prefix": "static-skills",
            "binding": "skill_toolset",
        }
    ]
    assert any(
        item.kind == "unresolved_skill"
        and item.details.get("source", {}).get("source")
        == "Google Cloud Storage Skill catalogue"
        for item in graph.coverage.diagnostics
    )
    report = effective_authority_report(graph)
    assert report["summary"]["unresolved_skill_catalogues"] == 1
