from __future__ import annotations

import json
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable

from horustrace.effective_authority import effective_authority_relationships
from horustrace.scanner import scan


STUDY = "pydantic-current-depth-parity-15"
INVARIANTS = (
    "agent_discovery",
    "authority_binding",
    "dynamic_visibility",
    "effect_semantics",
    "execution_boundary",
    "scope_provenance",
    "controls",
    "delegation_binding",
    "authority_projection",
)


def _agent(graph, name: str | None = None):
    candidates = [
        item for item in graph.agents
        if item.metadata.get("framework") == "pydantic-ai"
    ]
    if name is None:
        return candidates[0] if candidates else None
    return next(
        (
            item for item in candidates
            if item.name == name
            or item.metadata.get("configured_name") == name
            or item.metadata.get("agent_name") == name
        ),
        None,
    )


def _tool(agent, name: str):
    if agent is None:
        return None
    return next((item for item in agent.tools if item.name == name), None)


def _tool_with(agent, capability: str):
    if agent is None:
        return None
    return next(
        (item for item in agent.tools if capability in item.capabilities),
        None,
    )


def _server(agent, name: str | None = None):
    if agent is None:
        return None
    if name is None:
        return agent.mcp_servers[0] if agent.mcp_servers else None
    return next((item for item in agent.mcp_servers if item.name == name), None)


def _relationship(relationships, agent_name: str, target: str | None = None) -> bool:
    return any(
        item.agent == agent_name
        and (target is None or item.target_name == target)
        for item in relationships
    )


def _resource_selectors(tool) -> set[str]:
    return {item.selector for item in (tool.resources if tool else [])}


def _destinations(agent) -> set[str]:
    if agent is None:
        return set()
    values = {item.target for item in agent.effective_destinations}
    for tool in agent.tools:
        values.update(item.target for item in tool.destinations)
    for server in agent.mcp_servers:
        if server.url:
            values.add(server.url)
    return values


def _unmodeled(agent) -> set[str]:
    return set(agent.metadata.get("unmodeled_capabilities") or []) if agent else set()


def _metadata_has(value, *needles: str) -> bool:
    text = json.dumps(value, default=str).lower()
    return all(needle.lower() in text for needle in needles)


def _diag_text(graph) -> str:
    return "\n".join(
        f"{getattr(item, 'code', '')}: {getattr(item, 'message', '')}"
        for item in graph.coverage.diagnostics
    )


CASES: list[tuple[str, dict[str, str], Callable]] = []


def case(case_id: str, files: dict[str, str]):
    def decorate(fn: Callable):
        CASES.append((case_id, files, fn))
        return fn
    return decorate


@case(
    "pyd-current-01-local-workspace-filesystem",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai.capabilities import LocalWorkspace
from pydantic_ai_harness import FileSystem

agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[LocalWorkspace("/workspace"), FileSystem()],
)
""",
    },
)
def _check_01(graph, findings, relationships):
    agent = _agent(graph, "agent")
    fs = _tool(agent, "FileSystem")
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(fs),
        "dynamic_visibility": True,
        "effect_semantics": bool(fs and {"data.read", "data.write"} <= fs.capabilities),
        "execution_boundary": True,
        "scope_provenance": bool(fs and "/workspace" in _resource_selectors(fs)),
        "controls": True,
        "delegation_binding": True,
        "authority_projection": bool(agent and _relationship(relationships, agent.name, "FileSystem")),
    }


@case(
    "pyd-current-02-readonly-workspace",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai.capabilities import LocalWorkspace
from pydantic_ai_harness import FileSystem

agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[LocalWorkspace("/srv/read-only", read_only=True), FileSystem()],
)
""",
    },
)
def _check_02(graph, findings, relationships):
    agent = _agent(graph, "agent")
    fs = _tool(agent, "FileSystem")
    writes = {"data.write", "destructive.write", "external.write"}
    read_only_visible = bool(
        agent
        and (
            agent.metadata.get("workspace_read_only") is True
            or _metadata_has(agent.metadata, "read_only")
            or (fs and _metadata_has(fs.metadata, "read_only"))
        )
    )
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(fs),
        "dynamic_visibility": True,
        "effect_semantics": bool(fs and "data.read" in fs.capabilities and not (fs.capabilities & writes)),
        "execution_boundary": True,
        "scope_provenance": bool(fs and "/srv/read-only" in _resource_selectors(fs)),
        "controls": read_only_visible,
        "delegation_binding": True,
        "authority_projection": bool(fs and not (fs.capabilities & writes)),
    }


@case(
    "pyd-current-03-e2b-coder",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai_harness.coder import Coder
from pydantic_ai_harness.e2b_sandbox import E2BSandbox

agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[E2BSandbox(working_dir="/home/user/project"), Coder()],
)
""",
    },
)
def _check_03(graph, findings, relationships):
    agent = _agent(graph, "agent")
    coder = _tool(agent, "Coder")
    boundary = bool(
        agent
        and (
            _metadata_has(agent.metadata, "e2b")
            or (coder and _metadata_has(coder.metadata, "e2b"))
        )
    )
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(coder),
        "dynamic_visibility": True,
        "effect_semantics": bool(coder and {"process.execute", "data.read", "data.write"} <= coder.capabilities),
        "execution_boundary": boundary,
        "scope_provenance": bool(
            boundary
            and (
                _metadata_has(agent.metadata, "/home/user/project")
                or _metadata_has(coder.metadata, "/home/user/project")
                or "/home/user/project" in _resource_selectors(coder)
            )
        ),
        "controls": True,
        "delegation_binding": bool(coder and "agent.delegate" in coder.capabilities),
        "authority_projection": bool(agent and _relationship(relationships, agent.name, "Coder")),
    }


@case(
    "pyd-current-04-sprites-shell-filesystem",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai_harness.filesystem import FileSystem
from pydantic_ai_harness.shell import Shell
from pydantic_ai_harness.sprites_sandbox import SpritesSandbox

agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[
        SpritesSandbox(working_dir="/home/sprite/project"),
        Shell(),
        FileSystem(),
    ],
)
""",
    },
)
def _check_04(graph, findings, relationships):
    agent = _agent(graph, "agent")
    shell = _tool(agent, "Shell")
    fs = _tool(agent, "FileSystem")
    boundary = bool(
        agent
        and (
            _metadata_has(agent.metadata, "sprite")
            or (shell and _metadata_has(shell.metadata, "sprite"))
            or (fs and _metadata_has(fs.metadata, "sprite"))
        )
    )
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(shell and fs),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            shell and "process.execute" in shell.capabilities
            and fs and {"data.read", "data.write"} <= fs.capabilities
        ),
        "execution_boundary": boundary,
        "scope_provenance": bool(
            boundary
            and (
                _metadata_has(agent.metadata, "/home/sprite/project")
                or "/home/sprite/project" in _resource_selectors(fs)
            )
        ),
        "controls": True,
        "delegation_binding": True,
        "authority_projection": bool(agent and relationships),
    }


@case(
    "pyd-current-05-ssh-workspace",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai_harness import Coder, SSHWorkspace

agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[
        SSHWorkspace("dev@build-box", working_dir="/srv/app", env={"UV_OFFLINE": "1"}),
        Coder(),
    ],
)
""",
    },
)
def _check_05(graph, findings, relationships):
    agent = _agent(graph, "agent")
    coder = _tool(agent, "Coder")
    dests = _destinations(agent)
    host_visible = any("build-box" in value for value in dests) or _metadata_has(agent.metadata if agent else {}, "build-box")
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(coder),
        "dynamic_visibility": True,
        "effect_semantics": bool(coder and {"process.execute", "network.external"} <= coder.capabilities),
        "execution_boundary": bool(host_visible),
        "scope_provenance": bool(host_visible and (
            _metadata_has(agent.metadata, "/srv/app")
            or (coder and _metadata_has(coder.metadata, "/srv/app"))
        )),
        "controls": True,
        "delegation_binding": bool(coder and "agent.delegate" in coder.capabilities),
        "authority_projection": bool(agent and relationships),
    }


@case(
    "pyd-current-06-bubblewrap-network-isolation",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai_harness import BubblewrapSandbox, Coder, SSHWorkspace

agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[
        BubblewrapSandbox(SSHWorkspace("dev@build-box", working_dir="/srv/app")),
        Coder(),
    ],
)
""",
    },
)
def _check_06(graph, findings, relationships):
    agent = _agent(graph, "agent")
    coder = _tool(agent, "Coder")
    constrained = bool(
        agent
        and (
            _metadata_has(agent.metadata, "bubblewrap")
            or (coder and _metadata_has(coder.metadata, "bubblewrap"))
        )
    )
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(coder),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            coder
            and "process.execute" in coder.capabilities
            and "network.external" not in coder.capabilities
        ),
        "execution_boundary": constrained,
        "scope_provenance": bool(
            agent
            and (
                any("build-box" in value for value in _destinations(agent))
                or _metadata_has(agent.metadata, "build-box")
            )
        ),
        "controls": constrained,
        "delegation_binding": bool(coder and "agent.delegate" in coder.capabilities),
        "authority_projection": bool(coder and "network.external" not in coder.capabilities),
    }


@case(
    "pyd-current-07-explicit-subagents",
    {
        "agent.py": """
import requests
from pydantic_ai import Agent
from pydantic_ai_harness import SubAgent, SubAgents

def fetch_url(url: str) -> str:
    return requests.get(url).text

def write_report(path: str, content: str) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path

researcher = Agent("anthropic:claude-opus-5-5", name="researcher", tools=[fetch_url])
writer = Agent("anthropic:claude-opus-5-5", name="writer", tools=[write_report])
orchestrator = Agent(
    "anthropic:claude-opus-5-5",
    name="orchestrator",
    capabilities=[SubAgents(agents=[SubAgent(researcher), SubAgent(writer)])],
)
""",
    },
)
def _check_07(graph, findings, relationships):
    root = _agent(graph, "orchestrator")
    researcher = _agent(graph, "researcher")
    writer = _agent(graph, "writer")
    delegated = [tool for tool in (root.tools if root else []) if "agent.delegate" in tool.capabilities]
    targets = {
        value
        for tool in delegated
        for value in (
            [tool.metadata.get("delegate_target")]
            + list(tool.metadata.get("delegate_targets") or [])
        )
        if isinstance(value, str)
    }
    return {
        "agent_discovery": bool(root and researcher and writer),
        "authority_binding": bool(delegated),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            researcher and "network.external" in researcher.capabilities
            and writer and "data.write" in writer.capabilities
        ),
        "execution_boundary": True,
        "scope_provenance": True,
        "controls": True,
        "delegation_binding": {"researcher", "writer"} <= targets,
        "authority_projection": bool(
            root
            and {"network.external", "data.write"} <= root.capabilities
        ),
    }


@case(
    "pyd-current-08-self-subagent-depth",
    {
        "agent.py": """
import subprocess
from pydantic_ai import Agent
from pydantic_ai_harness import SubAgents

def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

agent = Agent(
    "anthropic:claude-opus-5-5",
    tools=[run_command],
    capabilities=[SubAgents(include_self=True, max_depth=2)],
)
""",
    },
)
def _check_08(graph, findings, relationships):
    agent = _agent(graph, "agent")
    delegated = _tool(agent, "SubAgents")
    if delegated is None:
        delegated = _tool_with(agent, "agent.delegate")
    depth_visible = bool(
        agent
        and (
            _metadata_has(agent.metadata, "max_depth", "2")
            or (delegated and _metadata_has(delegated.metadata, "max_depth", "2"))
        )
    )
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(delegated),
        "dynamic_visibility": bool(delegated),
        "effect_semantics": bool(
            agent and {"agent.delegate", "process.execute"} <= agent.capabilities
        ),
        "execution_boundary": True,
        "scope_provenance": True,
        "controls": depth_visible,
        "delegation_binding": bool(
            delegated
            and (
                delegated.metadata.get("delegate_target") == "self"
                or "self" in set(delegated.metadata.get("delegate_targets") or [])
                or _metadata_has(delegated.metadata, "include_self")
            )
        ),
        "authority_projection": bool(agent and "process.execute" in agent.capabilities),
    }


@case(
    "pyd-current-09-memory-filestore",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai.capabilities import LocalWorkspace
from pydantic_ai_harness import Memory
from pydantic_ai_harness.memory import FileStore

agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[LocalWorkspace("/workspace"), Memory(FileStore(".agent-memory"))],
)
""",
    },
)
def _check_09(graph, findings, relationships):
    agent = _agent(graph, "agent")
    memory = _tool(agent, "Memory") or _tool_with(agent, "data.write")
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(memory),
        "dynamic_visibility": True,
        "effect_semantics": bool(memory and {"data.read", "data.write"} <= memory.capabilities),
        "execution_boundary": True,
        "scope_provenance": bool(
            memory
            and (
                ".agent-memory" in _resource_selectors(memory)
                or _metadata_has(memory.metadata, ".agent-memory")
            )
        ),
        "controls": True,
        "delegation_binding": True,
        "authority_projection": bool(agent and relationships),
    }


@case(
    "pyd-current-10-skills-deferred-catalogue",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai.capabilities import LocalWorkspace
from pydantic_ai_harness import Skills

agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[LocalWorkspace("/workspace"), Skills(".agents/skills")],
)
""",
    },
)
def _check_10(graph, findings, relationships):
    agent = _agent(graph, "agent")
    skills = _tool(agent, "Skills")
    visible = bool(
        skills
        or "Skills" in _unmodeled(agent)
        or (agent and agent.metadata.get("dynamic_tools") is True)
    )
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(skills and "data.read" in skills.capabilities),
        "dynamic_visibility": visible,
        "effect_semantics": bool(skills and "data.read" in skills.capabilities),
        "execution_boundary": True,
        "scope_provenance": bool(
            skills
            and (
                ".agents/skills" in _resource_selectors(skills)
                or _metadata_has(skills.metadata, ".agents/skills")
            )
        ),
        "controls": True,
        "delegation_binding": True,
        "authority_projection": bool(skills and relationships),
    }


@case(
    "pyd-current-11-capability-creation",
    {
        "agent.py": """
from pathlib import Path
from pydantic_ai import Agent
from pydantic_ai.capabilities import LocalWorkspace
from pydantic_ai_harness import CapabilityCreation

creation = CapabilityCreation(directory=Path(".authored"))
agent = Agent(
    "anthropic:claude-sonnet-5",
    capabilities=[LocalWorkspace("/workspace"), creation],
)
""",
    },
)
def _check_11(graph, findings, relationships):
    agent = _agent(graph, "agent")
    creation = _tool(agent, "CapabilityCreation")
    visible = bool(
        creation
        or "CapabilityCreation" in _unmodeled(agent)
        or (agent and agent.metadata.get("dynamic_tools") is True)
    )
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(
            creation
            and {"process.execute", "data.write"} <= creation.capabilities
        ),
        "dynamic_visibility": visible,
        "effect_semantics": bool(
            creation
            and {"process.execute", "data.write"} <= creation.capabilities
        ),
        "execution_boundary": bool(
            creation
            and (
                creation.metadata.get("host_process_execution") is True
                or _metadata_has(creation.metadata, "local")
            )
        ),
        "scope_provenance": bool(
            creation
            and (
                ".authored" in _resource_selectors(creation)
                or _metadata_has(creation.metadata, ".authored")
            )
        ),
        "controls": bool(
            agent
            and (
                _metadata_has(agent.metadata, "writable", "local")
                or (creation and _metadata_has(creation.metadata, "writable", "local"))
            )
        ),
        "delegation_binding": True,
        "authority_projection": bool(creation and relationships),
    }


@case(
    "pyd-current-12-github-capability",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai_harness.github import GitHub

agent = Agent(
    "openai:gpt-5.6-sol",
    capabilities=[GitHub(auth="gh-token")],
)
""",
    },
)
def _check_12(graph, findings, relationships):
    agent = _agent(graph, "agent")
    github_tool = _tool(agent, "GitHub")
    server = _server(agent)
    bound = bool(github_tool or server)
    capabilities = set(github_tool.capabilities) if github_tool else set()
    authenticated = bool(
        server and server.authenticated is True
        or github_tool and _metadata_has(github_tool.metadata, "auth")
    )
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bound,
        "dynamic_visibility": bool(bound or "GitHub" in _unmodeled(agent)),
        "effect_semantics": bool(
            (github_tool and "network.external" in capabilities and (
                "external.write" in capabilities or "data.write" in capabilities
            ))
            or (server and server.transport != "stdio")
        ),
        "execution_boundary": True,
        "scope_provenance": bool(
            server and server.url
            or any("github" in value.lower() for value in _destinations(agent))
        ),
        "controls": authenticated,
        "delegation_binding": True,
        "authority_projection": bool(bound and relationships),
    }


@case(
    "pyd-current-13-slack-readonly",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai_harness.slack import Slack

agent = Agent(
    "openai:gpt-5.6-sol",
    capabilities=[Slack(auth="xoxp-token", read_only=True)],
)
""",
    },
)
def _check_13(graph, findings, relationships):
    agent = _agent(graph, "agent")
    slack = _tool(agent, "Slack")
    server = _server(agent)
    bound = bool(slack or server)
    writes = {"data.write", "external.write", "destructive.write"}
    write_free = bool(
        (slack and "network.external" in slack.capabilities and not (slack.capabilities & writes))
        or (server and server.metadata.get("read_only") is True)
    )
    authenticated = bool(
        server and server.authenticated is True
        or slack and _metadata_has(slack.metadata, "auth")
    )
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bound,
        "dynamic_visibility": bool(bound or "Slack" in _unmodeled(agent)),
        "effect_semantics": write_free,
        "execution_boundary": True,
        "scope_provenance": bool(
            server and server.url
            or any("slack" in value.lower() for value in _destinations(agent))
        ),
        "controls": bool(write_free and authenticated),
        "delegation_binding": True,
        "authority_projection": bool(write_free),
    }


@case(
    "pyd-current-14-temporal-durability",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai.durable_exec.temporal import TemporalDurability

agent = Agent(
    "openai:gpt-5.6-sol",
    name="geography",
    capabilities=[TemporalDurability()],
)
""",
    },
)
def _check_14(graph, findings, relationships):
    agent = _agent(graph, "agent") or _agent(graph, "geography")
    runtime_visible = bool(
        agent
        and (
            "TemporalDurability" in _unmodeled(agent)
            or _metadata_has(agent.metadata, "temporal")
        )
    )
    privileged = {
        "process.execute",
        "data.write",
        "external.write",
        "destructive.write",
        "network.external",
    }
    invented = [
        tool for tool in (agent.tools if agent else [])
        if tool.capabilities & privileged
    ]
    return {
        "agent_discovery": bool(agent),
        "authority_binding": True,
        "dynamic_visibility": runtime_visible,
        "effect_semantics": not invented,
        "execution_boundary": runtime_visible,
        "scope_provenance": True,
        "controls": True,
        "delegation_binding": True,
        "authority_projection": not invented,
    }


@case(
    "pyd-current-15-native-code-execution",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai.builtin_tools import CodeExecutionTool
from pydantic_ai.capabilities import NativeTool

agent = Agent(
    "openai:gpt-5.6-sol",
    capabilities=[NativeTool(CodeExecutionTool())],
)
""",
    },
)
def _check_15(graph, findings, relationships):
    agent = _agent(graph, "agent")
    code = _tool(agent, "CodeExecutionTool")
    return {
        "agent_discovery": bool(agent),
        "authority_binding": bool(code),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            code and {"process.execute", "data.read", "data.write"} <= code.capabilities
        ),
        "execution_boundary": bool(code and code.metadata.get("provider_managed") is True),
        "scope_provenance": True,
        "controls": True,
        "delegation_binding": True,
        "authority_projection": bool(agent and _relationship(relationships, agent.name, "CodeExecutionTool")),
    }


def _run_case(case_id: str, files: dict[str, str], check: Callable) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix=f"horustrace-{case_id}-") as raw:
        root = Path(raw)
        for relative, source in files.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.strip() + "\n", encoding="utf-8")

        try:
            graph, findings = scan(root)
            relationships = effective_authority_relationships(graph)
            checks = check(graph, findings, relationships)
            return {
                "case_id": case_id,
                "status": "completed",
                "checks": checks,
                "agents": [
                    {
                        "name": agent.name,
                        "capabilities": sorted(agent.capabilities),
                        "metadata": {
                            key: value for key, value in agent.metadata.items()
                            if key in {
                                "framework",
                                "dynamic_tools",
                                "unmodeled_capabilities",
                                "partially_resolved_capabilities",
                                "safety_capabilities",
                                "workspace",
                                "workspace_provider",
                                "workspace_read_only",
                                "execution_boundary",
                                "delegates_to",
                            }
                        },
                        "tools": [
                            {
                                "name": tool.name,
                                "kind": tool.kind,
                                "capabilities": sorted(tool.capabilities),
                                "approval": tool.approval,
                                "resources": [
                                    {
                                        "kind": resource.kind,
                                        "selector": resource.selector,
                                        "access": sorted(resource.access),
                                    }
                                    for resource in tool.resources
                                ],
                                "destinations": [dest.target for dest in tool.destinations],
                                "metadata": dict(tool.metadata),
                            }
                            for tool in agent.tools
                        ],
                        "mcp_servers": [
                            {
                                "name": server.name,
                                "transport": server.transport,
                                "url": server.url,
                                "authenticated": server.authenticated,
                                "approval": server.approval,
                                "metadata": dict(server.metadata),
                            }
                            for server in agent.mcp_servers
                        ],
                    }
                    for agent in graph.agents
                    if agent.metadata.get("framework") == "pydantic-ai"
                ],
                "authority_relationships": [
                    {
                        "agent": item.agent,
                        "target_kind": item.target_kind,
                        "target_name": item.target_name,
                        "resolution": item.resolution,
                        "unresolved": list(item.unresolved),
                    }
                    for item in relationships
                ],
                "findings": [
                    {
                        "rule_id": item.rule_id,
                        "agent": item.agent,
                        "title": item.title,
                    }
                    for item in findings
                ],
                "diagnostics": _diag_text(graph),
            }
        except Exception as exc:
            return {
                "case_id": case_id,
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "checks": {},
            }


def main() -> int:
    results = [_run_case(case_id, files, check) for case_id, files, check in CASES]
    invariant_totals = Counter()
    invariant_passed = Counter()
    failures: dict[str, list[str]] = defaultdict(list)

    for result in results:
        checks = result.get("checks") or {}
        for invariant in INVARIANTS:
            if invariant not in checks:
                continue
            invariant_totals[invariant] += 1
            if checks[invariant] is True:
                invariant_passed[invariant] += 1
            else:
                failures[invariant].append(str(result["case_id"]))

    completed = sum(result["status"] == "completed" for result in results)
    passed_cases = sum(
        result["status"] == "completed"
        and all(value is True for value in (result.get("checks") or {}).values())
        for result in results
    )
    summary = {
        "schema_version": 1,
        "study": STUDY,
        "cases": len(results),
        "completed": completed,
        "fully_passing_cases": passed_cases,
        "invariants": {
            invariant: {
                "passed": invariant_passed[invariant],
                "total": invariant_totals[invariant],
                "ratio": (
                    invariant_passed[invariant] / invariant_totals[invariant]
                    if invariant_totals[invariant]
                    else 1.0
                ),
                "failures": failures[invariant],
            }
            for invariant in INVARIANTS
        },
        "results": results,
    }

    out = Path(f"artifacts/{STUDY}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Pydantic AI current-surface depth parity",
        "",
        f"- Cases: {completed}/{len(results)} completed",
        f"- Fully passing cases: {passed_cases}/{len(results)}",
        "",
        "| Invariant | Passed | Total | Rate | Failing cases |",
        "|---|---:|---:|---:|---|",
    ]
    for invariant in INVARIANTS:
        item = summary["invariants"][invariant]
        lines.append(
            f"| {invariant} | {item['passed']} | {item['total']} | "
            f"{item['ratio']:.1%} | {', '.join(item['failures']) or '—'} |"
        )
    lines += ["", "## Case result", "", "| Case | Result | Failed invariants |", "|---|---|---|"]
    for result in results:
        failed = [
            key for key, value in (result.get("checks") or {}).items()
            if value is not True
        ]
        status = "PASS" if result["status"] == "completed" and not failed else "FAIL"
        if result["status"] == "error":
            failed = [str(result.get("error"))]
        lines.append(f"| {result['case_id']} | {status} | {', '.join(failed) or '—'} |")

    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
