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


def _tool_with_capability(agent, capability: str):
    if not agent:
        return None
    return next((item for item in agent.tools if capability in item.capabilities), None)


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


def _rules(findings):
    return {item.rule_id for item in findings}


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
                                "destinations": [
                                    {
                                        "target": destination.target,
                                        "restricted": destination.restricted,
                                        "network_scope": destination.metadata.get("network_scope"),
                                        "source": destination.metadata.get("source"),
                                    }
                                    for destination in tool.destinations
                                ],
                                "metadata": {
                                    key: value
                                    for key, value in tool.metadata.items()
                                    if key in {
                                        "adk_builtin",
                                        "binding_unresolved",
                                        "dynamic_bound_collection",
                                        "delegate_target",
                                        "authority_binding",
                                        "authority_binding_basis",
                                        "network_scope",
                                        "provider_network_scope",
                                        "model_selected_url_fetch",
                                        "destination_provenance",
                                        "openapi_servers",
                                        "tool_filter",
                                        "dynamic_tool_filter",
                                        "executor_kind",
                                        "execution_boundary",
                                        "sandboxed",
                                        "write_mode",
                                        "required_roles",
                                        "additional_scopes",
                                        "interactive_control",
                                    }
                                },
                            }
                            for tool in agent.tools
                        ],
                        "mcp_servers": [
                            {
                                "name": server.name,
                                "transport": server.transport,
                                "url": server.url,
                                "command": server.command,
                                "authenticated": server.authenticated,
                                "approval": server.approval,
                                "allowed_tools": list(server.allowed_tools),
                                "metadata": {
                                    key: value
                                    for key, value in server.metadata.items()
                                    if key in {
                                        "dynamic_mcp_endpoint",
                                        "dynamic_mcp_endpoint_basis",
                                        "configuration_source",
                                        "connection_type",
                                        "dynamic_tool_filter",
                                    }
                                },
                            }
                            for server in agent.mcp_servers
                        ],
                        "metadata": {
                            key: value
                            for key, value in agent.metadata.items()
                            if key in {
                                "agent_type",
                                "delegates_to",
                                "workflow",
                                "workflow_edges",
                                "callbacks",
                                "tool_control_state",
                                "tool_control_enforcing",
                                "disallow_transfer_to_parent",
                                "disallow_transfer_to_peers",
                                "remote_a2a",
                                "agent_card",
                                "authenticated",
                                "configuration_source",
                            }
                        },
                    }
                    for agent in graph.agents
                ],
                "identities": [
                    {
                        "name": item.name,
                        "provider": item.provider,
                        "credential_source": item.credential_source,
                        "oauth_scopes": sorted(item.oauth_scopes),
                        "roles": sorted(item.roles),
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
    "adk-depth-01-plain-function-fixed-network",
    {
        "agent.py": """
import requests
from google.adk import Agent

def fetch_status() -> str:
    return requests.get("https://status.example.com/health").text

root_agent = Agent(
    name="status",
    model="gemini-2.5-flash",
    tools=[fetch_status],
)
""",
    },
)
def _check_01(graph, findings, relationships):
    agent = _agent(graph, "status")
    tool = _tool(agent, "fetch_status")
    fixed = bool(
        tool
        and any(
            destination.target == "https://status.example.com/health"
            and destination.metadata.get("network_scope") == "fixed_literal_destination"
            for destination in tool.destinations
        )
    )
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(tool and "network.external" in tool.capabilities and "data.read" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": fixed,
        "controls": True,
        "authority_projection": bool(_relationship(relationships, "status", "fetch_status")),
    }


@case(
    "adk-depth-02-function-confirmation-destructive",
    {
        "agent.py": """
import requests
from google.adk import Agent
from google.adk.tools import FunctionTool

def delete_customer(customer_id: str):
    return requests.delete(f"https://api.example.com/customers/{customer_id}")

delete_tool = FunctionTool(
    func=delete_customer,
    require_confirmation=True,
)
root_agent = Agent(
    name="customer-ops",
    model="gemini-2.5-flash",
    tools=[delete_tool],
)
""",
    },
)
def _check_02(graph, findings, relationships):
    agent = _agent(graph, "customer-ops")
    tool = _tool(agent, "delete_customer")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(tool and "destructive.write" in tool.capabilities and "network.external" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": bool(
            tool and any(destination.target == "https://api.example.com" for destination in tool.destinations)
        ),
        "controls": bool(tool and tool.approval is True),
        "authority_projection": bool(_relationship(relationships, "customer-ops", "delete_customer")),
    }


@case(
    "adk-depth-03-execution-boundaries",
    {
        "agent.py": """
from google.adk import Agent
from google.adk.code_executors import BuiltInCodeExecutor, UnsafeLocalCodeExecutor

unsafe_agent = Agent(
    name="unsafe-local",
    model="gemini-2.5-flash",
    code_executor=UnsafeLocalCodeExecutor(),
)

managed_agent = Agent(
    name="managed-code",
    model="gemini-2.5-flash",
    code_executor=BuiltInCodeExecutor(),
)
""",
    },
)
def _check_03(graph, findings, relationships):
    unsafe = _agent(graph, "unsafe-local")
    managed = _agent(graph, "managed-code")
    unsafe_tool = _tool_with_capability(unsafe, "process.execute")
    managed_tool = _tool_with_capability(managed, "provider.code.execute")
    return {
        "agent_discovery": bool(unsafe and managed),
        "tool_binding": bool(unsafe_tool and managed_tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            unsafe_tool
            and {"process.execute", "data.read", "data.write"} <= unsafe_tool.capabilities
            and managed_tool
            and "process.execute" not in managed_tool.capabilities
        ),
        "local_vs_external": bool(
            unsafe_tool
            and unsafe_tool.metadata.get("executor_kind") == "local"
            and managed_tool
            and managed_tool.metadata.get("execution_boundary") == "provider-managed"
        ),
        "scope_provenance": True,
        "controls": bool(managed_tool and managed_tool.guardrails is True),
        "authority_projection": bool(
            _relationship(relationships, "unsafe-local")
            and _relationship(relationships, "managed-code")
        ),
    }


@case(
    "adk-depth-04-computer-use",
    {
        "agent.py": """
from google.adk import Agent
from google.adk.tools.computer_use.computer_use_toolset import ComputerUseToolset

computer = ComputerUseToolset(computer=PlaywrightComputer())
root_agent = Agent(
    name="browser-operator",
    model="gemini-2.5-computer-use",
    tools=[computer],
)
""",
    },
)
def _check_04(graph, findings, relationships):
    agent = _agent(graph, "browser-operator")
    tool = _tool(agent, "computer")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            tool
            and {"computer.control", "network.external", "external.write"} <= tool.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(tool and tool.metadata.get("interactive_control") is True),
        "controls": True,
        "authority_projection": bool(_relationship(relationships, "browser-operator", "computer")),
    }


@case(
    "adk-depth-05-url-context-destination",
    {
        "agent.py": """
from google.adk import Agent
from google.adk.tools import UrlContextTool

url_context = UrlContextTool()
root_agent = Agent(
    name="url-reader",
    model="gemini-2.5-flash",
    tools=[url_context],
)
""",
    },
)
def _check_05(graph, findings, relationships):
    agent = _agent(graph, "url-reader")
    tool = _tool(agent, "url_context")
    if tool is None and agent:
        tool = next((item for item in agent.tools if item.metadata.get("adk_builtin") == "UrlContextTool"), None)
    model_selected = bool(
        tool
        and any(
            destination.target == "<model-selected-url>"
            and destination.restricted is False
            and destination.metadata.get("network_scope") == "dynamic_destination"
            for destination in tool.destinations
        )
    )
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": model_selected,
        "effect_semantics": bool(tool and {"data.read", "network.external"} <= tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": bool(
            tool
            and tool.metadata.get("provider_network_scope") == "fixed_managed_service"
            and model_selected
        ),
        "controls": True,
        "authority_projection": bool(_relationship(relationships, "url-reader")),
    }


@case(
    "adk-depth-06-remote-mcp-controls",
    {
        "agent.py": """
from google.adk import Agent
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams

mcp = McpToolset(
    connection_params=StreamableHTTPConnectionParams(
        url="https://mcp.example.com/mcp",
        headers={"Authorization": "Bearer runtime-token"},
    ),
    tool_filter=["read_ticket"],
    require_confirmation=True,
)
root_agent = Agent(
    name="support",
    model="gemini-2.5-flash",
    tools=[mcp],
)
""",
    },
)
def _check_06(graph, findings, relationships):
    agent = _agent(graph, "support")
    server = _server(agent)
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
            and list(server.allowed_tools) == ["read_ticket"]
        ),
        "controls": bool(server and server.approval is True),
        "authority_projection": bool(_relationship(relationships, "support")),
    }


@case(
    "adk-depth-07-local-stdio-mcp",
    {
        "agent.py": """
from google.adk import Agent
from google.adk.tools.mcp_tool import McpToolset, StdioConnectionParams, StdioServerParameters

params = StdioConnectionParams(
    server_params=StdioServerParameters(
        command="python",
        args=["server.py"],
    )
)
mcp = McpToolset(
    connection_params=params,
    tool_filter=["read_file"],
)
root_agent = Agent(
    name="local-mcp",
    model="gemini-2.5-flash",
    tools=[mcp],
)
""",
    },
)
def _check_07(graph, findings, relationships):
    agent = _agent(graph, "local-mcp")
    server = _server(agent)
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "delegation_mcp_binding": bool(server),
        "dynamic_visibility": True,
        "effect_semantics": True,
        "local_vs_external": bool(server and server.transport == "stdio"),
        "scope_provenance": bool(
            server
            and server.command == "python"
            and server.args == ["server.py"]
            and list(server.allowed_tools) == ["read_file"]
        ),
        "controls": True,
        "authority_projection": bool(_relationship(relationships, "local-mcp")),
    }


@case(
    "adk-depth-08-agent-tool-delegation",
    {
        "agent.py": """
import subprocess
from google.adk import Agent
from google.adk.tools import AgentTool

def run_command(command: str):
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

specialist = Agent(
    name="specialist",
    model="gemini-2.5-flash",
    tools=[run_command],
)
specialist_tool = AgentTool(
    agent=specialist,
    skip_summarization=True,
)
root_agent = Agent(
    name="coordinator",
    model="gemini-2.5-flash",
    tools=[specialist_tool],
)
""",
    },
)
def _check_08(graph, findings, relationships):
    root = _agent(graph, "coordinator")
    child = _agent(graph, "specialist")
    delegated = _tool(root, "specialist_tool")
    return {
        "agent_discovery": bool(root and child),
        "tool_binding": bool(delegated),
        "delegation_mcp_binding": bool(
            delegated
            and delegated.metadata.get("delegate_target") == "specialist"
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
        "authority_projection": bool(root and "process.execute" in root.capabilities),
    }


@case(
    "adk-depth-09-subagent-transfer",
    {
        "agent.py": """
from google.adk import Agent
from google.adk.tools.bash_tool import ExecuteBashTool

child = Agent(
    name="privileged-child",
    model="gemini-2.5-flash",
    tools=[ExecuteBashTool()],
)
root_agent = Agent(
    name="coordinator",
    model="gemini-2.5-flash",
    sub_agents=[child],
    disallow_transfer_to_parent=True,
    disallow_transfer_to_peers=True,
)
""",
    },
)
def _check_09(graph, findings, relationships):
    root = _agent(graph, "coordinator")
    child = _agent(graph, "privileged-child")
    delegates = set(root.metadata.get("delegates_to") or []) if root else set()
    delegated = next((item for item in root.tools if item.kind == "delegated_agent"), None) if root else None
    return {
        "agent_discovery": bool(root and child),
        "tool_binding": bool(delegated),
        "delegation_mcp_binding": bool(delegated and "privileged-child" in delegates),
        "dynamic_visibility": True,
        "effect_semantics": bool(root and "process.execute" in root.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": bool(
            root
            and root.metadata.get("disallow_transfer_to_parent") is True
            and root.metadata.get("disallow_transfer_to_peers") is True
        ),
        "authority_projection": bool(root and "process.execute" in root.capabilities),
    }


@case(
    "adk-depth-10-workflow-v2-routing",
    {
        "agent.py": """
from google.adk import Event
from google.adk.agents import LlmAgent
from google.adk.tools.bash_tool import ExecuteBashTool
from google.adk.workflow import Workflow

def router(node_input: str):
    if node_input == "ops":
        return Event(route="RUN_OPS")
    return Event(route="RUN_REVIEW")

ops = LlmAgent(
    name="ops",
    model="gemini-2.5-flash",
    tools=[ExecuteBashTool()],
)
review = LlmAgent(
    name="review",
    model="gemini-2.5-flash",
)
root_agent = Workflow(
    name="routing-workflow",
    edges=[
        ("START", router),
        (router, {"RUN_OPS": ops, "RUN_REVIEW": review}),
    ],
)
""",
    },
)
def _check_10(graph, findings, relationships):
    root = _agent(graph, "routing-workflow")
    edges = list(root.metadata.get("workflow_edges") or []) if root else []
    delegates = set(root.metadata.get("delegates_to") or []) if root else set()
    route_ok = {
        ("router", "ops", "RUN_OPS"),
        ("router", "review", "RUN_REVIEW"),
    } <= {
        (item.get("source"), item.get("target"), item.get("route"))
        for item in edges
    }
    return {
        "agent_discovery": bool(root and _agent(graph, "ops") and _agent(graph, "review")),
        "tool_binding": True,
        "delegation_mcp_binding": bool(route_ok and delegates == {"ops", "review"}),
        "dynamic_visibility": True,
        "effect_semantics": bool(root and "process.execute" in root.capabilities),
        "local_vs_external": True,
        "scope_provenance": route_ok,
        "controls": True,
        "authority_projection": bool(root and "process.execute" in root.capabilities),
    }


@case(
    "adk-depth-11-callback-enforcement",
    {
        "agent.py": """
from google.adk import Agent

def noop_callback(tool, args, context):
    return None

def enforcing_callback(tool, args, context):
    if tool.name == "delete_customer":
        return {"error": "blocked"}
    return None

def delete_customer(customer_id: str):
    store.delete(customer_id)

noop_agent = Agent(
    name="noop-agent",
    model="gemini-2.5-flash",
    tools=[delete_customer],
    before_tool_callback=noop_callback,
)
root_agent = Agent(
    name="guarded-agent",
    model="gemini-2.5-flash",
    tools=[delete_customer],
    before_tool_callback=enforcing_callback,
)
""",
    },
)
def _check_11(graph, findings, relationships):
    noop = _agent(graph, "noop-agent")
    guarded = _agent(graph, "guarded-agent")
    return {
        "agent_discovery": bool(noop and guarded),
        "tool_binding": bool(_tool(noop, "delete_customer") and _tool(guarded, "delete_customer")),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            _tool(guarded, "delete_customer")
            and "destructive.write" in _tool(guarded, "delete_customer").capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": bool(
            noop
            and noop.metadata.get("tool_control_state") == "non_enforcing"
            and guarded
            and guarded.metadata.get("tool_control_state") == "enforcing"
            and guarded.metadata.get("tool_control_enforcing") is True
        ),
        "authority_projection": bool(_relationship(relationships, "guarded-agent", "delete_customer")),
    }


@case(
    "adk-depth-12-remote-a2a",
    {
        "agent.py": """
from google.adk import Agent
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent

remote = RemoteA2aAgent(
    name="remote-billing",
    agent_card="https://billing.example.com/.well-known/agent-card.json",
    auth_scheme="oauth2",
    credential_key="BILLING_TOKEN",
)
root_agent = Agent(
    name="router",
    model="gemini-2.5-flash",
    sub_agents=[remote],
)
""",
    },
)
def _check_12(graph, findings, relationships):
    remote = _agent(graph, "remote-billing")
    root = _agent(graph, "router")
    a2a = next((item for item in remote.tools if item.kind == "adk_a2a_remote"), None) if remote else None
    return {
        "agent_discovery": bool(remote and root),
        "tool_binding": bool(a2a),
        "delegation_mcp_binding": bool(
            root and "remote-billing" in set(root.metadata.get("delegates_to") or [])
        ),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            a2a and {"agent.delegate", "network.external", "external.write"} <= a2a.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            a2a
            and any(
                destination.target == "https://billing.example.com/.well-known/agent-card.json"
                and destination.restricted is True
                for destination in a2a.destinations
            )
        ),
        "controls": bool(remote and remote.metadata.get("authenticated") is True),
        "authority_projection": bool(root and "network.external" in root.capabilities),
    }


@case(
    "adk-depth-13-openapi-operation-semantics",
    {
        "agent.py": """
from google.adk import Agent
from google.adk.tools.openapi_tool import OpenAPIToolset

spec = {
    "openapi": "3.0.0",
    "info": {"title": "Accounts API", "version": "1.0"},
    "servers": [{"url": "https://api.accounts.example.com/v1"}],
    "paths": {
        "/accounts/{account_id}": {
            "get": {
                "operationId": "getAccount",
                "responses": {"200": {"description": "ok"}},
            },
            "delete": {
                "operationId": "deleteAccount",
                "responses": {"204": {"description": "deleted"}},
            },
        }
    },
}
accounts = OpenAPIToolset(spec_dict=spec)
root_agent = Agent(
    name="account-admin",
    model="gemini-2.5-flash",
    tools=[accounts],
)
""",
    },
)
def _check_13(graph, findings, relationships):
    agent = _agent(graph, "account-admin")
    tool = _tool(agent, "accounts")
    fixed_server = bool(
        tool
        and any(
            destination.target == "https://api.accounts.example.com"
            and destination.restricted is True
            for destination in tool.destinations
        )
    )
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            tool
            and "data.read" in tool.capabilities
            and "data.write" in tool.capabilities
            and "destructive.write" in tool.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": fixed_server,
        "controls": True,
        "authority_projection": bool(_relationship(relationships, "account-admin", "accounts")),
    }


@case(
    "adk-depth-14-dynamic-tool-binding",
    {
        "catalog.py": """
def safe_read():
    return "ok"

def build_tools():
    return [safe_read]

DYNAMIC_TOOLS = build_tools()
""",
        "agent.py": """
from google.adk import Agent
from catalog import DYNAMIC_TOOLS

root_agent = Agent(
    name="dynamic-agent",
    model="gemini-2.5-flash",
    tools=DYNAMIC_TOOLS,
)
""",
    },
)
def _check_14(graph, findings, relationships):
    agent = _agent(graph, "dynamic-agent")
    dynamic = _tool(agent, "DYNAMIC_TOOLS")
    relation = _relationship(relationships, "dynamic-agent", "DYNAMIC_TOOLS")
    unresolved = set(relation.unresolved) if relation else set()
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(dynamic),
        "delegation_mcp_binding": True,
        "dynamic_visibility": bool(
            dynamic
            and dynamic.metadata.get("binding_unresolved") is True
            and dynamic.metadata.get("dynamic_bound_collection") is True
            and "capabilities" in unresolved
        ),
        "effect_semantics": bool(dynamic and not dynamic.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_projection": bool(relation),
    }


@case(
    "adk-depth-15-google-identity-bigquery-restriction",
    {
        "agent.py": """
import google.auth
from google.adk import Agent
from google.adk.tools.bigquery import BigQueryToolset
from google.adk.tools.bigquery.config import BigQueryToolConfig, WriteMode

credentials = google.auth.default(
    scopes=["https://www.googleapis.com/auth/bigquery.readonly"]
)
config = BigQueryToolConfig(write_mode=WriteMode.BLOCKED)
bq = BigQueryToolset(
    bigquery_tool_config=config,
    project="analytics-project",
    dataset="finance",
)
root_agent = Agent(
    name="analyst",
    model="gemini-2.5-flash",
    tools=[bq],
)
""",
    },
)
def _check_15(graph, findings, relationships):
    agent = _agent(graph, "analyst")
    tool = _tool(agent, "bq")
    identity = next(
        (
            item
            for item in graph.identities
            if item.provider == "gcp"
            and "https://www.googleapis.com/auth/bigquery.readonly" in item.oauth_scopes
        ),
        None,
    )
    resources = {(item.kind, item.selector) for item in tool.resources} if tool else set()
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            tool
            and "data.read" in tool.capabilities
            and "data.write" not in tool.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            identity
            and ("gcp-project", "analytics-project") in resources
            and ("bigquery", "finance") in resources
        ),
        "controls": bool(
            tool and str(tool.metadata.get("write_mode") or "").lower().endswith("blocked")
        ),
        "authority_projection": bool(_relationship(relationships, "analyst", "bq")),
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
        "study": "google-adk-depth-parity-15",
        "purpose": "Validate canonical Google ADK authority constructs and HorusTrace depth-parity invariants without chasing arbitrary Python corner cases.",
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

    out = Path("artifacts/google-adk-depth-parity-15")
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Google ADK depth-parity fundamentals",
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
