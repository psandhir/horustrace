from __future__ import annotations

import json
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable

from horustrace.effective_authority import effective_authority_relationships
from horustrace.scanner import scan


INVARIANTS = (
    "agent_discovery",
    "tool_binding",
    "delegation_mcp_binding",
    "dynamic_visibility",
    "effect_semantics",
    "local_vs_external",
    "scope_provenance",
    "controls",
    "authority_projection",
)


def _agent(graph, name: str):
    return next((item for item in graph.agents if item.name == name), None)


def _framework_agents(graph, framework: str):
    return [item for item in graph.agents if item.metadata.get("framework") == framework]


def _tool(agent, name: str):
    return next((item for item in agent.tools if item.name == name), None) if agent else None


def _server(agent, name: str | None = None):
    if not agent:
        return None
    if name is None:
        return agent.mcp_servers[0] if agent.mcp_servers else None
    return next((item for item in agent.mcp_servers if item.name == name), None)


def _relationship(relationships, agent: str, target_name: str | None = None):
    for item in relationships:
        if item.agent != agent:
            continue
        if target_name is not None and item.target_name != target_name:
            continue
        return item
    return None


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
                        "framework": agent.metadata.get("framework"),
                        "capabilities": sorted(agent.capabilities),
                        "metadata": dict(agent.metadata),
                        "tools": [
                            {
                                "name": tool.name,
                                "kind": tool.kind,
                                "capabilities": sorted(tool.capabilities),
                                "approval": tool.approval,
                                "guardrails": tool.guardrails,
                                "identity": tool.identity,
                                "resources": [
                                    {
                                        "kind": resource.kind,
                                        "selector": resource.selector,
                                        "access": sorted(resource.access),
                                    }
                                    for resource in tool.resources
                                ],
                                "destinations": [
                                    {
                                        "target": destination.target,
                                        "restricted": destination.restricted,
                                        "metadata": dict(destination.metadata),
                                    }
                                    for destination in tool.destinations
                                ],
                                "metadata": dict(tool.metadata),
                            }
                            for tool in agent.tools
                        ],
                        "mcp_servers": [
                            {
                                "name": server.name,
                                "transport": server.transport,
                                "url": server.url,
                                "command": server.command,
                                "args": list(server.args),
                                "authenticated": server.authenticated,
                                "approval": server.approval,
                                "identity": server.identity,
                                "allowed_tools": list(server.allowed_tools),
                                "denied_tools": list(server.denied_tools),
                                "metadata": dict(server.metadata),
                            }
                            for server in agent.mcp_servers
                        ],
                    }
                    for agent in graph.agents
                ],
                "identities": [
                    {
                        "name": item.name,
                        "provider": item.provider,
                        "credential_source": item.credential_source,
                        "roles": sorted(item.roles),
                        "oauth_scopes": sorted(item.oauth_scopes),
                        "metadata": dict(item.metadata),
                    }
                    for item in graph.all_identities()
                ],
                "authority_relationships": [
                    {
                        "agent": item.agent,
                        "target_kind": item.target_kind,
                        "target_name": item.target_name,
                        "resolution": item.resolution,
                        "unresolved": list(item.unresolved),
                        "approval": item.approval,
                        "semantics": item.semantics,
                    }
                    for item in relationships
                ],
                "findings": [
                    {"rule_id": item.rule_id, "agent": item.agent, "title": item.title}
                    for item in findings
                ],
                "diagnostics": [
                    {
                        "kind": getattr(item, "kind", ""),
                        "message": getattr(item, "message", ""),
                        "details": getattr(item, "details", None),
                    }
                    for item in graph.coverage.diagnostics
                ],
            }
        except Exception as exc:
            return {
                "case_id": case_id,
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "checks": {},
            }


CASES: list[tuple[str, dict[str, str], Callable]] = []


def case(case_id: str, files: dict[str, str]):
    def decorate(fn: Callable):
        CASES.append((case_id, files, fn))
        return fn
    return decorate


@case(
    "anthropic-depth-01-python-builtins-permissions",
    {
        "agent.py": """
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    tools=["Read", "Write", "Bash", "WebFetch"],
    allowed_tools=["Read"],
    disallowed_tools=["Write"],
    permission_mode="default",
)

async def run():
    async for _ in query(prompt="inspect", options=options):
        pass
""",
    },
)
def _check_01(graph, findings, relationships):
    agent = _agent(graph, "options")
    read = _tool(agent, "Read")
    bash = _tool(agent, "Bash")
    web = _tool(agent, "WebFetch")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(read and bash and web and not _tool(agent, "Write")),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            bash and "process.execute" in bash.capabilities
            and web and {"data.read", "network.external"} <= web.capabilities
        ),
        "local_vs_external": bool(
            bash and "process.execute" in bash.capabilities
            and web and "process.execute" not in web.capabilities
        ),
        "scope_provenance": bool(
            web and any(
                d.target == "<model-selected-url>"
                and d.restricted is False
                for d in web.destinations
            )
        ),
        "controls": bool(
            read and read.approval is False
            and agent.metadata.get("permission_mode") == "default"
            and "Write" in agent.metadata.get("disallowed_tools", [])
        ),
        "authority_projection": bool(
            _relationship(relationships, "options", "Bash")
            and _relationship(relationships, "options", "WebFetch")
        ),
    }


@case(
    "anthropic-depth-02-python-default-surface",
    {
        "agent.py": """
from claude_agent_sdk import query

async def run():
    async for _ in query(prompt="fix the project"):
        pass
""",
    },
)
def _check_02(graph, findings, relationships):
    agent = next(iter(_framework_agents(graph, "claude-agent-sdk")), None)
    names = {tool.name for tool in agent.tools} if agent else set()
    return {
        "agent_discovery": bool(agent),
        "tool_binding": {"Read", "Write", "Edit", "Bash", "WebFetch", "WebSearch", "Agent"} <= names,
        "delegation_mcp_binding": bool(agent and _tool(agent, "Agent")),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            agent
            and "process.execute" in _tool(agent, "Bash").capabilities
            and "network.external" in _tool(agent, "WebSearch").capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            agent and _tool(agent, "WebFetch").destinations
        ),
        "controls": bool(agent and agent.metadata.get("tool_surface") == "runtime_default"),
        "authority_projection": bool(agent and _relationship(relationships, agent.name, "Bash")),
    }


@case(
    "anthropic-depth-03-python-sdk-mcp-custom-tool",
    {
        "agent.py": """
import subprocess
import requests
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, create_sdk_mcp_server, tool

@tool("deploy", "Deploy release", {"version": str})
async def deploy(args):
    subprocess.run(["deploy", args["version"]], check=True)
    return {"content": [{"type": "text", "text": requests.post(
        "https://deploy.example.com/release",
        json=args,
    ).text}]}

ops_server = create_sdk_mcp_server(
    name="ops",
    version="1.0",
    tools=[deploy],
)

options = ClaudeAgentOptions(
    mcp_servers={"ops": ops_server},
    allowed_tools=["mcp__ops__deploy"],
)

async def run():
    async with ClaudeSDKClient(options=options) as client:
        await client.query("deploy")
""",
    },
)
def _check_03(graph, findings, relationships):
    agent = _agent(graph, "options")
    server = _server(agent, "ops")
    caps = set(server.metadata.get("discovered_tool_capabilities") or []) if server else set()
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(server and "deploy" in (server.metadata.get("discovered_tools") or [])),
        "delegation_mcp_binding": bool(server and server.transport == "sdk"),
        "dynamic_visibility": True,
        "effect_semantics": bool({"process.execute", "network.external", "external.write"} <= caps),
        "local_vs_external": bool(server and server.metadata.get("in_process") is True),
        "scope_provenance": True,
        "controls": bool(
            server and server.metadata.get("auto_approved_tool_rules") == ["mcp__ops__deploy"]
        ),
        "authority_projection": bool(_relationship(relationships, "options", "ops")),
    }


@case(
    "anthropic-depth-04-python-stdio-mcp-rules",
    {
        "agent.py": """
from claude_agent_sdk import ClaudeAgentOptions, McpStdioServerConfig, query

mongo = McpStdioServerConfig(
    command="uvx",
    args=["mongodb-mcp-server"],
)
options = ClaudeAgentOptions(
    tools=["Read"],
    mcp_servers={"mongo": mongo},
    allowed_tools=["mcp__mongo__find"],
    disallowed_tools=["mcp__mongo__drop"],
    strict_mcp_config=True,
)
async def run():
    async for _ in query(prompt="inspect", options=options):
        pass
""",
    },
)
def _check_04(graph, findings, relationships):
    agent = _agent(graph, "options")
    server = _server(agent, "mongo")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(_tool(agent, "Read")),
        "delegation_mcp_binding": bool(server),
        "dynamic_visibility": True,
        "effect_semantics": True,
        "local_vs_external": bool(server and server.transport == "stdio"),
        "scope_provenance": bool(
            server and server.command == "uvx" and server.args == ["mongodb-mcp-server"]
        ),
        "controls": bool(
            agent and agent.metadata.get("strict_mcp_config") is True
            and server
            and server.metadata.get("auto_approved_tool_rules") == ["mcp__mongo__find"]
            and server.metadata.get("denied_tool_rules") == ["mcp__mongo__drop"]
        ),
        "authority_projection": bool(_relationship(relationships, "options", "mongo")),
    }


@case(
    "anthropic-depth-05-python-http-mcp-auth",
    {
        "agent.py": """
import os
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    mcp_servers={
        "fixed": {
            "type": "http",
            "url": "https://mcp.example.com/api",
            "headers": {"Authorization": "Bearer token"},
        },
        "dynamic": {
            "type": "http",
            "url": os.environ["MCP_URL"],
        },
    }
)
async def run():
    async for _ in query(prompt="inspect", options=options):
        pass
""",
    },
)
def _check_05(graph, findings, relationships):
    agent = _agent(graph, "options")
    fixed = _server(agent, "fixed")
    dynamic = _server(agent, "dynamic")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "delegation_mcp_binding": bool(fixed and dynamic),
        "dynamic_visibility": bool(dynamic and dynamic.metadata.get("dynamic_mcp_endpoint") is True),
        "effect_semantics": True,
        "local_vs_external": True,
        "scope_provenance": bool(
            fixed and fixed.url == "https://mcp.example.com/api"
            and dynamic and dynamic.url is None
        ),
        "controls": bool(fixed and fixed.authenticated is True),
        "authority_projection": bool(
            _relationship(relationships, "options", "fixed")
            and _relationship(relationships, "options", "dynamic")
        ),
    }


@case(
    "anthropic-depth-06-python-subagent-delegation",
    {
        "agent.py": """
from claude_agent_sdk import AgentDefinition, ClaudeAgentOptions, query

operator = AgentDefinition(
    description="operator",
    prompt="operate",
    tools=["Read", "Bash", "WebFetch"],
    permissionMode="default",
)
options = ClaudeAgentOptions(
    tools=["Read", "Agent"],
    agents={"operator": operator},
)
async def run():
    async for _ in query(prompt="delegate", options=options):
        pass
""",
    },
)
def _check_06(graph, findings, relationships):
    root = _agent(graph, "options")
    child = _agent(graph, "operator")
    delegated = next(
        (tool for tool in (root.tools if root else []) if tool.kind == "delegated_agent"),
        None,
    )
    return {
        "agent_discovery": bool(root and child),
        "tool_binding": bool(delegated and _tool(child, "Bash")),
        "delegation_mcp_binding": bool(
            delegated and delegated.metadata.get("delegate_target") == "operator"
        ),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            child and "process.execute" in child.capabilities
            and root and "process.execute" in root.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            child and any(d.target == "<model-selected-url>" for d in child.effective_destinations)
        ),
        "controls": bool(child and child.metadata.get("permission_mode") == "default"),
        "authority_projection": bool(root and "process.execute" in root.capabilities),
    }


@case(
    "anthropic-depth-07-python-dynamic-registries",
    {
        "agent.py": """
from claude_agent_sdk import ClaudeAgentOptions, query

def load_mcp():
    return discover_servers()

def load_agents():
    return discover_agents()

options = ClaudeAgentOptions(
    mcp_servers=load_mcp(),
    agents=load_agents(),
)
async def run():
    async for _ in query(prompt="run", options=options):
        pass
""",
    },
)
def _check_07(graph, findings, relationships):
    agent = _agent(graph, "options")
    dyn_mcp = _server(agent, "<dynamic-mcp>")
    dyn_agent = next(
        (
            tool for tool in (agent.tools if agent else [])
            if tool.metadata.get("delegate_target_unresolved") is True
        ),
        None,
    )
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(dyn_agent),
        "delegation_mcp_binding": bool(dyn_mcp and dyn_agent),
        "dynamic_visibility": bool(
            agent
            and agent.metadata.get("dynamic_mcp_servers") is True
            and agent.metadata.get("dynamic_subagents") is True
        ),
        "effect_semantics": bool(dyn_agent and "agent.delegate" in dyn_agent.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_projection": bool(
            _relationship(relationships, "options", "<dynamic-mcp>")
            and _relationship(relationships, "options", "<dynamic-subagents>")
        ),
    }


@case(
    "anthropic-depth-08-python-hook-control",
    {
        "agent.py": """
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, query

async def observer(input_data, tool_use_id, context):
    print(input_data)
    return {}

async def blocker(input_data, tool_use_id, context):
    if input_data.get("tool_name") == "Bash":
        return {"decision": "block", "reason": "approval required"}
    return {}

observer_options = ClaudeAgentOptions(
    tools=["Bash"],
    hooks={"PreToolUse": [HookMatcher(matcher="Bash", hooks=[observer])]},
)
guarded_options = ClaudeAgentOptions(
    tools=["Bash"],
    can_use_tool=blocker,
    hooks={"PreToolUse": [HookMatcher(matcher="Bash", hooks=[blocker])]},
)
async def run():
    async for _ in query(prompt="observe", options=observer_options):
        pass
    async for _ in query(prompt="guard", options=guarded_options):
        pass
""",
    },
)
def _check_08(graph, findings, relationships):
    observer = _agent(graph, "observer_options")
    guarded = _agent(graph, "guarded_options")
    return {
        "agent_discovery": bool(observer and guarded),
        "tool_binding": bool(_tool(observer, "Bash") and _tool(guarded, "Bash")),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(_tool(guarded, "Bash") and "process.execute" in _tool(guarded, "Bash").capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": bool(
            observer
            and observer.metadata.get("tool_control_state") == "non_enforcing"
            and guarded
            and guarded.metadata.get("tool_control_state") == "enforcing"
        ),
        "authority_projection": bool(_relationship(relationships, "guarded_options", "Bash")),
    }


@case(
    "anthropic-depth-09-python-sandbox-filesystem",
    {
        "agent.py": """
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    tools=["Read", "Write", "Bash"],
    permission_mode="bypassPermissions",
    sandbox={"enabled": True, "allowUnsandboxedCommands": True},
    cwd="/srv/app",
    add_dirs=["/srv/shared"],
    setting_sources=[],
)
async def run():
    async for _ in query(prompt="work", options=options):
        pass
""",
    },
)
def _check_09(graph, findings, relationships):
    agent = _agent(graph, "options")
    bash = _tool(agent, "Bash")
    selectors = {r.selector for r in bash.resources} if bash else set()
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(bash and _tool(agent, "Read") and _tool(agent, "Write")),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(bash and "process.execute" in bash.capabilities),
        "local_vs_external": bool(agent and agent.metadata.get("sandbox_enabled") is True),
        "scope_provenance": selectors == {"/srv/app", "/srv/shared"},
        "controls": bool(
            agent
            and agent.metadata.get("permission_mode") == "bypassPermissions"
            and agent.metadata.get("filesystem_settings_disabled") is True
            and agent.metadata.get("silent_sandbox_escape_possible") is True
        ),
        "authority_projection": bool(_relationship(relationships, "options", "Bash")),
    }


@case(
    "anthropic-depth-10-python-workflow",
    {
        "agent.py": """
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    allowed_tools=["Read", "Workflow"],
    permission_mode="acceptEdits",
    cwd="/workspace",
)
async def run():
    async for _ in query(
        prompt="Use a workflow to verify every item in the report",
        options=options,
    ):
        pass
""",
    },
)
def _check_10(graph, findings, relationships):
    agent = _agent(graph, "options")
    workflow = _tool(agent, "Workflow")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(workflow),
        "delegation_mcp_binding": bool(workflow and "agent.delegate" in workflow.capabilities),
        "dynamic_visibility": bool(
            workflow and (
                workflow.metadata.get("dynamic_workflow") is True
                or workflow.metadata.get("runtime_generated_workflow") is True
            )
        ),
        "effect_semantics": bool(
            workflow and {"agent.delegate", "process.execute"} <= workflow.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            workflow and any(r.selector == "/workspace" for r in workflow.resources)
        ),
        "controls": bool(
            workflow and workflow.approval is False
            and agent.metadata.get("permission_mode") == "acceptEdits"
        ),
        "authority_projection": bool(_relationship(relationships, "options", "Workflow")),
    }


@case(
    "anthropic-depth-11-typescript-builtins",
    {
        "agent.ts": """
import { query } from "@anthropic-ai/claude-agent-sdk";

const options = {
  tools: ["Read", "Bash", "WebFetch"],
  allowedTools: ["Read"],
  permissionMode: "default",
  cwd: "/workspace",
};

async function run() {
  for await (const message of query({ prompt: "inspect", options })) {
    console.log(message);
  }
}
""",
    },
)
def _check_11(graph, findings, relationships):
    agents = _framework_agents(graph, "claude-agent-sdk")
    agent = agents[0] if agents else None
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(_tool(agent, "Read") and _tool(agent, "Bash") and _tool(agent, "WebFetch")),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(agent and "process.execute" in _tool(agent, "Bash").capabilities),
        "local_vs_external": True,
        "scope_provenance": bool(
            agent and any(r.selector == "/workspace" for r in _tool(agent, "Bash").resources)
        ),
        "controls": bool(_tool(agent, "Read") and _tool(agent, "Read").approval is False),
        "authority_projection": bool(agent and _relationship(relationships, agent.name, "Bash")),
    }


@case(
    "anthropic-depth-12-typescript-mcp-subagent",
    {
        "agent.ts": """
import {
  query,
  tool,
  createSdkMcpServer,
} from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";

const deploy = tool(
  "deploy",
  "Deploy release",
  { version: z.string() },
  async ({ version }) => {
    await fetch("https://deploy.example.com/release", {
      method: "POST",
      body: JSON.stringify({ version }),
    });
    return { content: [{ type: "text", text: "ok" }] };
  },
);

const ops = createSdkMcpServer({
  name: "ops",
  version: "1.0",
  tools: [deploy],
});

const options = {
  tools: ["Read", "Agent"],
  mcpServers: { ops },
  allowedTools: ["mcp__ops__deploy"],
  agents: {
    reviewer: {
      description: "reviewer",
      prompt: "review",
      tools: ["Read", "WebFetch"],
    },
  },
};

async function run() {
  for await (const message of query({ prompt: "deploy and review", options })) {
    console.log(message);
  }
}
""",
    },
)
def _check_12(graph, findings, relationships):
    agents = _framework_agents(graph, "claude-agent-sdk")
    root = next((a for a in agents if a.metadata.get("sdk_entrypoint")), agents[0] if agents else None)
    child = next((a for a in agents if a.name == "reviewer"), None)
    server = _server(root, "ops")
    delegated = next(
        (tool for tool in (root.tools if root else []) if tool.kind == "delegated_agent"),
        None,
    )
    return {
        "agent_discovery": bool(root and child),
        "tool_binding": bool(server and delegated),
        "delegation_mcp_binding": bool(server and delegated),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            server and "external.write" in set(server.metadata.get("discovered_tool_capabilities") or [])
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            child and any(d.target == "<model-selected-url>" for d in child.effective_destinations)
        ),
        "controls": bool(
            server and server.metadata.get("auto_approved_tool_rules") == ["mcp__ops__deploy"]
        ),
        "authority_projection": bool(root and _relationship(relationships, root.name)),
    }


@case(
    "anthropic-depth-13-managed-tools-mcp",
    {
        "managed.py": """
from anthropic import Anthropic

client = Anthropic()

agent = client.beta.agents.create(
    name="ops-agent",
    model="claude-opus-5-5",
    tools=[
        {
            "type": "agent_toolset_20260401",
            "default_config": {
                "permission_policy": {"type": "auto"}
            },
            "configs": [
                {
                    "name": "bash",
                    "permission_policy": {"type": "always_ask"},
                },
                {
                    "name": "web_fetch",
                    "permission_policy": {"type": "always_allow"},
                    "allowed_domains": ["status.example.com"],
                },
            ],
        },
        {
            "type": "mcp_toolset",
            "mcp_server_name": "github",
            "default_config": {
                "permission_policy": {"type": "always_ask"}
            },
        },
    ],
    mcp_servers=[
        {
            "type": "url",
            "name": "github",
            "url": "https://mcp.example.com/github",
        }
    ],
)
""",
    },
)
def _check_13(graph, findings, relationships):
    agent = _agent(graph, "ops-agent")
    bash = _tool(agent, "bash")
    web = _tool(agent, "web_fetch")
    server = _server(agent, "github")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(bash and web),
        "delegation_mcp_binding": bool(server),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            bash and "process.execute" in bash.capabilities
            and web and "network.external" in web.capabilities
        ),
        "local_vs_external": bool(
            bash and bash.metadata.get("execution_boundary") in {"managed-sandbox", "server-managed"}
        ),
        "scope_provenance": bool(
            server and server.url == "https://mcp.example.com/github"
            and web and web.metadata.get("allowed_domains") == ["status.example.com"]
        ),
        "controls": bool(
            bash and bash.approval is True
            and web and web.approval is False
            and server and server.approval is True
        ),
        "authority_projection": bool(
            _relationship(relationships, "ops-agent", "bash")
            and _relationship(relationships, "ops-agent", "github")
        ),
    }


@case(
    "anthropic-depth-14-managed-multiagent-skills",
    {
        "agents.py": """
from anthropic import Anthropic

client = Anthropic()

coordinator = client.beta.agents.create(
    name="research-coordinator",
    model={"id": "claude-opus-5-5", "effort": "high"},
    skills=[
        {"type": "custom", "skill_id": "skill_sec_review", "version": "3"}
    ],
    multiagent={
        "type": "coordinator",
        "agents": [
            {"type": "agent", "id": "agent_search", "version": 4},
            {"type": "advisor", "model": "claude-sonnet-5"},
        ],
    },
    tools=[
        {"type": "agent_toolset_20260401"}
    ],
)
""",
    },
)
def _check_14(graph, findings, relationships):
    agent = _agent(graph, "research-coordinator")
    delegated = [
        t for t in (agent.tools if agent else []) if t.kind == "delegated_agent"
    ]
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(agent and agent.tools),
        "delegation_mcp_binding": len(delegated) >= 2,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            agent and "agent.delegate" in agent.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            agent
            and {"skill_sec_review"} <= set(agent.metadata.get("skills") or [])
            and {"agent_search", "claude-sonnet-5"} <= set(agent.metadata.get("delegates_to") or [])
        ),
        "controls": True,
        "authority_projection": bool(agent and "agent.delegate" in agent.capabilities),
    }


@case(
    "anthropic-depth-15-managed-environment-vault",
    {
        "runtime.py": """
from anthropic import Anthropic

client = Anthropic()

agent = client.beta.agents.create(
    name="partner-agent",
    model="claude-opus-5-5",
    mcp_servers=[
        {
            "type": "url",
            "name": "partner",
            "url": "https://mcp.partner.example/api",
        }
    ],
    tools=[
        {
            "type": "mcp_toolset",
            "mcp_server_name": "partner",
            "default_config": {
                "permission_policy": {"type": "always_ask"}
            },
        }
    ],
)

environment = client.beta.environments.create(
    name="restricted",
    config={
        "type": "cloud",
        "networking": {
            "type": "limited",
            "allowed_hosts": ["api.internal.example"],
            "allow_mcp_servers": True,
            "allow_package_managers": False,
        },
    },
)

session = client.beta.sessions.create(
    agent=agent.id,
    environment_id=environment.id,
    vault_ids=["vault_partner"],
)
""",
    },
)
def _check_15(graph, findings, relationships):
    agent = _agent(graph, "partner-agent")
    server = _server(agent, "partner")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "delegation_mcp_binding": bool(server),
        "dynamic_visibility": True,
        "effect_semantics": True,
        "local_vs_external": bool(
            agent and agent.metadata.get("environment_type") == "cloud"
        ),
        "scope_provenance": bool(
            agent
            and agent.metadata.get("networking_type") == "limited"
            and agent.metadata.get("allowed_hosts") == ["api.internal.example"]
            and server
            and server.url == "https://mcp.partner.example/api"
        ),
        "controls": bool(
            agent
            and agent.metadata.get("allow_mcp_servers") is True
            and agent.metadata.get("vault_ids") == ["vault_partner"]
            and server
            and server.approval is True
        ),
        "authority_projection": bool(_relationship(relationships, "partner-agent", "partner")),
    }


def main() -> int:
    results = [_run_case(case_id, files, check) for case_id, files, check in CASES]

    totals = Counter()
    passed = Counter()
    failures: dict[str, list[str]] = defaultdict(list)
    for result in results:
        checks = result.get("checks") or {}
        for invariant in INVARIANTS:
            value = checks.get(invariant)
            if value is None:
                continue
            totals[invariant] += 1
            if value is True:
                passed[invariant] += 1
            else:
                failures[invariant].append(str(result["case_id"]))

    completed = sum(result["status"] == "completed" for result in results)
    passing_cases = sum(
        result["status"] == "completed"
        and all(value is True for value in (result.get("checks") or {}).values())
        for result in results
    )

    summary = {
        "schema_version": 1,
        "study": "anthropic-depth-parity-15",
        "baseline_main": "195d5ad43b4b076b85792155a98048fe1c5f6196",
        "cases": len(results),
        "completed": completed,
        "fully_passing_cases": passing_cases,
        "invariants": {
            invariant: {
                "passed": passed[invariant],
                "total": totals[invariant],
                "ratio": passed[invariant] / totals[invariant] if totals[invariant] else 1.0,
                "failures": failures[invariant],
            }
            for invariant in INVARIANTS
        },
        "results": results,
    }

    out = Path("artifacts/anthropic-depth-parity-15")
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Anthropic depth-parity fundamentals",
        "",
        f"- Cases: {completed}/{len(results)} completed",
        f"- Fully passing cases: {passing_cases}/{len(results)}",
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
