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
                        "capabilities": sorted(agent.capabilities),
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
                                        "network_scope": destination.metadata.get("network_scope"),
                                        "source": destination.metadata.get("source"),
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
                        "identities": [
                            {
                                "name": identity.name,
                                "provider": identity.provider,
                                "credential_source": identity.credential_source,
                                "permissions": sorted(identity.permissions),
                                "roles": sorted(identity.roles),
                                "resource_scope": identity.resource_scope,
                                "metadata": dict(identity.metadata),
                            }
                            for identity in agent.identities
                        ],
                        "metadata": dict(agent.metadata),
                    }
                    for agent in graph.agents
                ],
                "unbound_tools": [
                    {
                        "name": tool.name,
                        "kind": tool.kind,
                        "capabilities": sorted(tool.capabilities),
                        "metadata": dict(tool.metadata),
                    }
                    for tool in graph.unbound_tools
                ],
                "unbound_mcp_servers": [
                    {
                        "name": server.name,
                        "transport": server.transport,
                        "url": server.url,
                        "authenticated": server.authenticated,
                        "metadata": dict(server.metadata),
                    }
                    for server in graph.unbound_mcp_servers
                ],
                "identities": [
                    {
                        "name": item.name,
                        "provider": item.provider,
                        "credential_source": item.credential_source,
                        "permissions": sorted(item.permissions),
                        "roles": sorted(item.roles),
                        "resource_scope": item.resource_scope,
                        "metadata": dict(item.metadata),
                    }
                    for item in graph.identities
                ],
                "authority_relationships": [
                    {
                        "agent": item.agent,
                        "target": {"kind": item.target_kind, "name": item.target_name},
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
                        "code": getattr(item, "code", ""),
                        "message": getattr(item, "message", ""),
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
    "amazon-depth-01-python-fixed-network",
    {
        "agent.py": """
import requests
from strands import Agent, tool

@tool
def publish_ticket(body: str) -> str:
    return requests.post(
        "https://tickets.example.com/api/tickets",
        json={"body": body},
    ).text

publisher = Agent(tools=[publish_ticket])
""",
    },
)
def _check_01(graph, findings, relationships):
    agent = _agent(graph, "publisher")
    tool = _tool(agent, "publish_ticket")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            tool
            and {"network.external", "data.write", "external.write"} <= tool.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            tool
            and any(
                destination.target == "https://tickets.example.com/api/tickets"
                and destination.restricted is True
                for destination in tool.destinations
            )
        ),
        "controls": True,
        "authority_projection": bool(_relationship(relationships, "publisher", "publish_ticket")),
    }


@case(
    "amazon-depth-02-aws-sdk-effects",
    {
        "agent.py": """
import boto3
from strands import Agent, tool

@tool
def mutate_order(order_id: str) -> dict:
    s3 = boto3.client("s3")
    table = boto3.client("dynamodb")
    current = s3.get_object(Bucket="orders", Key=f"{order_id}.json")
    table.update_item(
        TableName="orders",
        Key={"id": {"S": order_id}},
        UpdateExpression="SET #s = :s",
    )
    if order_id == "delete-me":
        table.delete_item(TableName="orders", Key={"id": {"S": order_id}})
    return {"current": str(current)}

ops = Agent(tools=[mutate_order])
""",
    },
)
def _check_02(graph, findings, relationships):
    agent = _agent(graph, "ops")
    tool = _tool(agent, "mutate_order")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            tool
            and {
                "data.read",
                "data.write",
                "destructive.write",
                "network.external",
            } <= tool.capabilities
        ),
        "local_vs_external": bool(tool and "process.execute" not in tool.capabilities),
        "scope_provenance": True,
        "controls": True,
        "authority_projection": bool(_relationship(relationships, "ops", "mutate_order")),
    }


@case(
    "amazon-depth-03-vended-high-authority",
    {
        "agent.py": """
from strands import Agent
from strands.vended_tools import file_editor, shell, use_aws

operator = Agent(tools=[file_editor, shell, use_aws])
""",
    },
)
def _check_03(graph, findings, relationships):
    agent = _agent(graph, "operator")
    shell = _tool(agent, "shell")
    editor = _tool(agent, "file_editor")
    aws = _tool(agent, "use_aws")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(shell and editor and aws),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            shell
            and {"process.execute", "data.read", "data.write", "destructive.write"} <= shell.capabilities
            and aws
            and {"network.external", "external.write"} <= aws.capabilities
        ),
        "local_vs_external": bool(
            shell
            and "process.execute" in shell.capabilities
            and aws
            and "network.external" in aws.capabilities
        ),
        "scope_provenance": True,
        "controls": True,
        "authority_projection": bool(
            _relationship(relationships, "operator", "shell")
            and _relationship(relationships, "operator", "use_aws")
        ),
    }


@case(
    "amazon-depth-04-stdio-mcp-filter",
    {
        "agent.py": """
from mcp import StdioServerParameters, stdio_client
from strands import Agent
from strands.tools.mcp import MCPClient

docs = MCPClient(
    lambda: stdio_client(
        StdioServerParameters(
            command="uvx",
            args=["awslabs.aws-documentation-mcp-server@latest"],
        )
    ),
    tool_filters={
        "allowed": ["search_documentation"],
        "denied": ["recommend"],
    },
)

assistant = Agent(tools=[docs])
""",
    },
)
def _check_04(graph, findings, relationships):
    agent = _agent(graph, "assistant")
    server = _server(agent, "docs")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "delegation_mcp_binding": bool(server),
        "dynamic_visibility": True,
        "effect_semantics": True,
        "local_vs_external": bool(server and server.transport == "stdio"),
        "scope_provenance": bool(
            server
            and server.command == "uvx"
            and server.args == ["awslabs.aws-documentation-mcp-server@latest"]
            and list(server.allowed_tools) == ["search_documentation"]
            and list(server.denied_tools) == ["recommend"]
        ),
        "controls": True,
        "authority_projection": bool(_relationship(relationships, "assistant", "docs")),
    }


@case(
    "amazon-depth-05-remote-mcp-auth",
    {
        "agent.py": """
from mcp.client.streamable_http import streamablehttp_client
from strands import Agent
from strands.tools.mcp import MCPClient

crm = MCPClient(
    lambda: streamablehttp_client(
        "https://mcp.example.com/mcp",
        headers={"Authorization": "Bearer runtime-token"},
    )
)

support = Agent(tools=[crm])
""",
    },
)
def _check_05(graph, findings, relationships):
    agent = _agent(graph, "support")
    server = _server(agent, "crm")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "delegation_mcp_binding": bool(server),
        "dynamic_visibility": True,
        "effect_semantics": True,
        "local_vs_external": True,
        "scope_provenance": bool(
            server
            and server.transport == "streamable-http"
            and server.url == "https://mcp.example.com/mcp"
            and server.authenticated is True
        ),
        "controls": True,
        "authority_projection": bool(_relationship(relationships, "support", "crm")),
    }


@case(
    "amazon-depth-06-dynamic-mcp-endpoint",
    {
        "agent.py": """
import os
from mcp.client.streamable_http import streamablehttp_client
from strands import Agent
from strands.tools.mcp import MCPClient

MCP_URL = os.environ["MCP_URL"]

crm = MCPClient(lambda: streamablehttp_client(MCP_URL))
support = Agent(tools=[crm])
""",
    },
)
def _check_06(graph, findings, relationships):
    agent = _agent(graph, "support")
    server = _server(agent, "crm")
    dynamic = bool(
        server
        and server.url is None
        and (
            server.metadata.get("dynamic_mcp_endpoint") is True
            or server.metadata.get("dynamic_mcp_endpoint_basis")
        )
    )
    relation = _relationship(relationships, "support", "crm")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "delegation_mcp_binding": bool(server),
        "dynamic_visibility": dynamic,
        "effect_semantics": True,
        "local_vs_external": True,
        "scope_provenance": bool(
            server
            and server.metadata.get("network_scope") == "operator_configured_destination"
        ),
        "controls": True,
        "authority_projection": bool(relation),
    }


@case(
    "amazon-depth-07-direct-agent-delegation",
    {
        "agent.py": """
import subprocess
from strands import Agent, tool

@tool
def run_command(command: str) -> str:
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    ).stdout

specialist = Agent(tools=[run_command])
coordinator = Agent(tools=[specialist])
""",
    },
)
def _check_07(graph, findings, relationships):
    root = _agent(graph, "coordinator")
    child = _agent(graph, "specialist")
    delegated = next(
        (tool for tool in root.tools if tool.kind == "delegated_agent"),
        None,
    ) if root else None
    return {
        "agent_discovery": bool(root and child),
        "tool_binding": bool(delegated),
        "delegation_mcp_binding": bool(
            delegated and delegated.metadata.get("delegate_target") == "specialist"
        ),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            child
            and "process.execute" in child.capabilities
            and root
            and "process.execute" in root.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_projection": bool(
            root
            and "process.execute" in root.capabilities
            and _relationship(relationships, "coordinator")
        ),
    }


@case(
    "amazon-depth-08-as-tool-delegation",
    {
        "agent.py": """
import requests
from strands import Agent, tool

@tool
def publish(body: str) -> str:
    return requests.post("https://specialist.example.com/publish", json={"body": body}).text

specialist = Agent(tools=[publish])
coordinator = Agent(tools=[specialist.as_tool(name="publisher")])
""",
    },
)
def _check_08(graph, findings, relationships):
    root = _agent(graph, "coordinator")
    child = _agent(graph, "specialist")
    delegated = next(
        (
            tool for tool in (root.tools if root else [])
            if tool.kind == "delegated_agent"
            or tool.metadata.get("delegate_target") == "specialist"
        ),
        None,
    )
    return {
        "agent_discovery": bool(root and child),
        "tool_binding": bool(delegated),
        "delegation_mcp_binding": bool(delegated),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            root and "network.external" in root.capabilities
            and "external.write" in root.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            root
            and any(
                destination.target == "https://specialist.example.com/publish"
                for destination in root.effective_destinations
            )
        ),
        "controls": True,
        "authority_projection": bool(_relationship(relationships, "coordinator")),
    }


@case(
    "amazon-depth-09-graph-topology",
    {
        "agent.py": """
import subprocess
from strands import Agent, tool
from strands.multiagent import GraphBuilder

@tool
def run_job(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

planner = Agent(name="planner")
executor = Agent(name="executor", tools=[run_job])
reviewer = Agent(name="reviewer")

builder = GraphBuilder()
builder.add_node(planner, "planner")
builder.add_node(executor, "executor")
builder.add_node(reviewer, "reviewer")
builder.add_edge("planner", "executor")
builder.add_edge("executor", "reviewer")
builder.set_entry_point("planner")
builder.set_max_node_executions(5)
workflow = builder.build()
""",
    },
)
def _check_09(graph, findings, relationships):
    planner = _agent(graph, "planner")
    executor = _agent(graph, "executor")
    reviewer = _agent(graph, "reviewer")
    orchestration = next(
        (
            agent for agent in graph.agents
            if agent.metadata.get("multiagent_type") == "graph"
            or agent.metadata.get("workflow") == "graph"
            or agent.name == "workflow"
        ),
        None,
    )
    edges = list(orchestration.metadata.get("workflow_edges") or []) if orchestration else []
    return {
        "agent_discovery": bool(planner and executor and reviewer),
        "tool_binding": bool(executor and _tool(executor, "run_job")),
        "delegation_mcp_binding": bool(
            orchestration
            and edges
            and set(orchestration.metadata.get("delegates_to") or []) >= {
                "planner", "executor", "reviewer"
            }
        ),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            orchestration and "process.execute" in orchestration.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            orchestration
            and orchestration.metadata.get("entry_point") in {"planner", ["planner"]}
        ),
        "controls": bool(
            orchestration
            and (
                orchestration.metadata.get("max_node_executions") == 5
                or orchestration.metadata.get("execution_limit") == 5
            )
        ),
        "authority_projection": bool(orchestration and "process.execute" in orchestration.capabilities),
    }


@case(
    "amazon-depth-10-swarm-topology",
    {
        "agent.py": """
from strands import Agent
from strands.multiagent import Swarm
from strands.vended_tools import shell

researcher = Agent(name="researcher")
operator = Agent(name="operator", tools=[shell])
reviewer = Agent(name="reviewer")

team = Swarm(
    [researcher, operator, reviewer],
    max_handoffs=8,
    max_iterations=10,
    execution_timeout=300.0,
    node_timeout=60.0,
)
""",
    },
)
def _check_10(graph, findings, relationships):
    researcher = _agent(graph, "researcher")
    operator = _agent(graph, "operator")
    reviewer = _agent(graph, "reviewer")
    swarm = next(
        (
            agent for agent in graph.agents
            if agent.metadata.get("multiagent_type") == "swarm"
            or agent.metadata.get("workflow") == "swarm"
            or agent.name == "team"
        ),
        None,
    )
    members = set(swarm.metadata.get("delegates_to") or []) if swarm else set()
    return {
        "agent_discovery": bool(researcher and operator and reviewer),
        "tool_binding": bool(operator and _tool(operator, "shell")),
        "delegation_mcp_binding": bool(
            swarm and members >= {"researcher", "operator", "reviewer"}
        ),
        "dynamic_visibility": True,
        "effect_semantics": bool(swarm and "process.execute" in swarm.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": bool(
            swarm
            and swarm.metadata.get("max_handoffs") == 8
            and swarm.metadata.get("max_iterations") == 10
        ),
        "authority_projection": bool(swarm and "process.execute" in swarm.capabilities),
    }


@case(
    "amazon-depth-11-a2a-provider",
    {
        "agent.py": """
import boto3
from strands import Agent
from strands_tools.a2a_client import A2AClientToolProvider

ORDER_AGENT_URL = get_runtime_url("order")
PRODUCT_AGENT_URL = get_runtime_url("product")

session = boto3.Session()
auth = SigV4HTTPXAuth(
    credentials=session.get_credentials(),
    service="bedrock-agentcore",
    region=session.region_name or "us-west-2",
)

a2a_provider = A2AClientToolProvider(
    known_agent_urls=[ORDER_AGENT_URL, PRODUCT_AGENT_URL],
    httpx_client_args={"auth": auth},
)

orchestrator = Agent(tools=a2a_provider.tools)
""",
    },
)
def _check_11(graph, findings, relationships):
    agent = _agent(graph, "orchestrator")
    candidate = next(
        (
            tool for tool in (agent.tools if agent else [])
            if tool.metadata.get("a2a")
            or "a2a" in tool.kind.lower()
            or "a2a" in tool.name.lower()
        ),
        None,
    )
    relation = _relationship(relationships, "orchestrator")
    dynamic = bool(
        candidate
        and (
            candidate.metadata.get("binding_unresolved") is True
            or candidate.metadata.get("dynamic_bound_collection") is True
            or candidate.metadata.get("remote_catalogue_unresolved") is True
        )
    )
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(candidate),
        "delegation_mcp_binding": bool(candidate and "agent.delegate" in candidate.capabilities),
        "dynamic_visibility": dynamic,
        "effect_semantics": bool(
            candidate
            and {"agent.delegate", "network.external", "external.write"} <= candidate.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            candidate
            and (
                candidate.metadata.get("destination_provenance")
                or candidate.destinations
                or candidate.metadata.get("dynamic_destination")
            )
        ),
        "controls": bool(
            candidate
            and (
                candidate.metadata.get("authenticated") is True
                or candidate.metadata.get("auth_scheme") == "sigv4"
                or candidate.metadata.get("authentication") == "sigv4"
            )
        ),
        "authority_projection": bool(relation),
    }


@case(
    "amazon-depth-12-hook-enforcement",
    {
        "agent.py": """
from strands import Agent, tool
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry

@tool
def delete_order(order_id: str) -> None:
    store.delete(order_id)

class Observer(HookProvider):
    def register_hooks(self, registry: HookRegistry, **kwargs):
        registry.add_callback(BeforeToolCallEvent, self.observe)

    def observe(self, event: BeforeToolCallEvent):
        print(event.tool_use)

class Approval(HookProvider):
    def register_hooks(self, registry: HookRegistry, **kwargs):
        registry.add_callback(BeforeToolCallEvent, self.approve)

    def approve(self, event: BeforeToolCallEvent):
        if event.tool_use.get("name") == "delete_order":
            event.cancel_tool = "approval required"

observer_agent = Agent(tools=[delete_order], hooks=[Observer()])
guarded_agent = Agent(tools=[delete_order], hooks=[Approval()])
""",
    },
)
def _check_12(graph, findings, relationships):
    observer = _agent(graph, "observer_agent")
    guarded = _agent(graph, "guarded_agent")
    observer_state = (
        observer.metadata.get("tool_control_state")
        or observer.metadata.get("hook_control_state")
        if observer else None
    )
    guarded_state = (
        guarded.metadata.get("tool_control_state")
        or guarded.metadata.get("hook_control_state")
        if guarded else None
    )
    return {
        "agent_discovery": bool(observer and guarded),
        "tool_binding": bool(_tool(observer, "delete_order") and _tool(guarded, "delete_order")),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            _tool(guarded, "delete_order")
            and "destructive.write" in _tool(guarded, "delete_order").capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": bool(
            observer_state in {"non_enforcing", "observer"}
            and guarded_state in {"enforcing", "interrupting"}
        ),
        "authority_projection": bool(_relationship(relationships, "guarded_agent", "delete_order")),
    }


@case(
    "amazon-depth-13-typescript-parity",
    {
        "agent.ts": """
import { Agent, McpClient, tool } from '@strands-agents/sdk'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import z from 'zod'

const publishTicket = tool({
  name: 'publish_ticket',
  description: 'Publish support ticket',
  inputSchema: z.object({ body: z.string() }),
  callback: async ({ body }) => {
    return fetch('https://tickets.example.com/api', {
      method: 'POST',
      body: JSON.stringify({ body }),
    })
  },
})

const docs = new McpClient({
  transport: new StdioClientTransport({
    command: 'uvx',
    args: ['awslabs.aws-documentation-mcp-server@latest'],
  }),
})

const specialist = new Agent({
  name: 'specialist',
  tools: [publishTicket],
})

const root = new Agent({
  name: 'root',
  tools: [docs, specialist.asTool({ name: 'specialist_tool' })],
})
""",
    },
)
def _check_13(graph, findings, relationships):
    root = _agent(graph, "root")
    specialist = _agent(graph, "specialist")
    server = _server(root, "docs")
    delegated = next(
        (tool for tool in (root.tools if root else []) if tool.kind == "delegated_agent"),
        None,
    )
    publish = _tool(specialist, "publish_ticket")
    return {
        "agent_discovery": bool(root and specialist),
        "tool_binding": bool(server and delegated and publish),
        "delegation_mcp_binding": bool(server and delegated),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            publish
            and {"network.external", "external.write"} <= publish.capabilities
        ),
        "local_vs_external": bool(server and server.transport == "stdio"),
        "scope_provenance": bool(
            publish
            and any(
                destination.target == "https://tickets.example.com/api"
                for destination in publish.destinations
            )
        ),
        "controls": True,
        "authority_projection": bool(
            _relationship(relationships, "root")
            and _relationship(relationships, "specialist", "publish_ticket")
        ),
    }


@case(
    "amazon-depth-14-bedrock-agent-iac",
    {
        "template.yaml": """
Resources:
  OrderAgent:
    Type: AWS::Bedrock::Agent
    Properties:
      AgentName: order-agent
      AgentResourceRoleArn: arn:aws:iam::111122223333:role/BedrockAgentRole
      FoundationModel: anthropic.claude-sonnet-4-6-v1:0
      GuardrailConfiguration:
        GuardrailIdentifier: guardrail-123
        GuardrailVersion: "1"
      ActionGroups:
        - ActionGroupName: refund_order
          ActionGroupExecutor:
            Lambda: arn:aws:lambda:eu-west-2:111122223333:function:refund-order
        - ActionGroupName: code
          ParentActionGroupSignature: AMAZON.CodeInterpreter
      KnowledgeBases:
        - KnowledgeBaseId: KB12345678
          Description: order docs
      AgentCollaborators:
        - CollaboratorName: fraud-agent
          AgentDescriptor:
            AliasArn: arn:aws:bedrock:eu-west-2:111122223333:agent-alias/ABC/DEF
""",
    },
)
def _check_14(graph, findings, relationships):
    agent = _agent(graph, "order-agent")
    refund = _tool(agent, "refund_order")
    code = _tool(agent, "code")
    delegated = _tool(agent, "fraud-agent")
    identity = agent.identities[0] if agent and agent.identities else None
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(refund and code),
        "delegation_mcp_binding": bool(
            delegated and delegated.metadata.get("delegate_target") == "fraud-agent"
        ),
        "dynamic_visibility": True,
        "effect_semantics": bool(code and "process.execute" in code.capabilities),
        "local_vs_external": True,
        "scope_provenance": bool(
            refund
            and any(
                resource.selector.endswith(":function:refund-order")
                for resource in refund.resources
            )
            and agent
            and any(source.selector == "KB12345678" for source in agent.data_sources)
        ),
        "controls": bool(
            agent and agent.metadata.get("guardrail_configured") is True
        ),
        "authority_projection": bool(
            identity
            and identity.provider == "aws"
            and delegated
        ),
    }


@case(
    "amazon-depth-15-agentcore-iam",
    {
        "agentcore.json": """
{
  "name": "OrdersProject",
  "version": 1,
  "runtimes": [
    {
      "name": "OrdersAgent",
      "entrypoint": "main.py",
      "networkMode": "VPC",
      "protocol": "HTTP",
      "executionRoleArn": "arn:aws:iam::111122223333:role/OrdersAgentRole"
    }
  ],
  "credentials": [
    {"name": "PartnerOAuth", "type": "OAUTH"}
  ],
  "agentCoreGateways": [
    {
      "name": "OrdersGateway",
      "roleArn": "arn:aws:iam::111122223333:role/GatewayRole",
      "authorizerType": "AWS_IAM",
      "targets": [
        {
          "name": "PartnerTools",
          "targetType": "mcpServer",
          "endpoint": "https://partner.example.com/mcp",
          "outboundAuth": {
            "type": "OAUTH",
            "credentialName": "PartnerOAuth",
            "scopes": ["orders:write"]
          }
        }
      ]
    }
  ],
  "knowledgeBases": [
    {
      "name": "OrderDocs",
      "dataSources": [
        {"type": "S3", "uri": "s3://order-docs/manuals/"}
      ]
    }
  ]
}
""",
        "runtime.tf": """
data "aws_iam_policy_document" "runtime_access" {
  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "dynamodb:UpdateItem"
    ]
    resources = [
      "arn:aws:s3:::order-docs/*",
      "arn:aws:dynamodb:*:*:table/orders"
    ]
  }
}

resource "aws_iam_role" "runtime" {
  name = "OrdersAgentRole"
}

resource "aws_iam_role_policy" "runtime_access" {
  role   = aws_iam_role.runtime.id
  policy = data.aws_iam_policy_document.runtime_access.json
}
""",
        ".bedrock_agentcore.yaml": """
default_agent: legacy
agents:
  legacy:
    name: legacy
    entrypoint: legacy.py
    deployment_type: direct_code_deploy
    aws:
      execution_role: arn:aws:iam::111122223333:role/LegacyRole
      network_configuration:
        network_mode: VPC
      protocol_configuration:
        server_protocol: HTTP
    memory:
      mode: STM_AND_LTM
      memory_id: order-memory
""",
    },
)
def _check_15(graph, findings, relationships):
    runtime = _agent(graph, "OrdersAgent")
    legacy = _agent(graph, "legacy")
    identity = runtime.identities[0] if runtime and runtime.identities else None
    memory = _tool(legacy, "order-memory")
    partner = next(
        (server for server in graph.unbound_mcp_servers if server.name == "PartnerTools"),
        None,
    )
    kb = next(
        (tool for tool in graph.unbound_tools if tool.name == "retrieve:OrderDocs"),
        None,
    )
    permissions = set(identity.permissions) if identity else set()
    resources = set(identity.metadata.get("iam_resource_scopes") or []) if identity else set()
    return {
        "agent_discovery": bool(runtime and legacy),
        "tool_binding": bool(memory and kb),
        "delegation_mcp_binding": bool(partner),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            memory
            and {"data.read", "data.write"} <= memory.capabilities
            and kb
            and kb.capabilities == {"data.read"}
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            partner
            and partner.url == "https://partner.example.com/mcp"
            and partner.authenticated is True
            and partner.identity == "PartnerOAuth"
            and kb
            and any(resource.selector == "s3://order-docs/manuals/" for resource in kb.resources)
            and "arn:aws:s3:::order-docs/*" in resources
        ),
        "controls": bool(
            runtime
            and runtime.metadata.get("networkMode") == "VPC"
            and partner
            and partner.metadata.get("outbound_auth") == "OAUTH"
        ),
        "authority_projection": bool(
            identity
            and {"s3:GetObject", "s3:PutObject", "dynamodb:UpdateItem"} <= permissions
        ),
    }


def main() -> int:
    results = [_run_case(case_id, files, check) for case_id, files, check in CASES]

    invariant_totals = Counter()
    invariant_passed = Counter()
    failures: dict[str, list[str]] = defaultdict(list)
    for result in results:
        checks = result.get("checks") or {}
        for invariant in INVARIANTS:
            value = checks.get(invariant)
            if value is None:
                continue
            invariant_totals[invariant] += 1
            if value is True:
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
        "study": "amazon-sdk-depth-parity-15",
        "purpose": "Validate canonical current Amazon Strands/Bedrock/AgentCore authority constructs and HorusTrace depth-parity invariants.",
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

    out = Path("artifacts/amazon-sdk-depth-parity-15")
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Amazon SDK depth-parity fundamentals",
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
