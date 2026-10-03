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
    "authority_driven_findings",
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


def _rules(findings):
    return {item.rule_id for item in findings}


def _metadata_signal(metadata: dict, *tokens: str) -> bool:
    """Match semantic metadata keys only; never infer from file/path values."""
    keys: list[str] = []

    def collect(value) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                keys.append(str(key))
                collect(nested)
        elif isinstance(value, (list, tuple, set)):
            for nested in value:
                collect(nested)

    collect(metadata)
    lowered = " ".join(keys).lower()
    return all(token.lower() in lowered for token in tokens)


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
                        "tools": [
                            {
                                "name": tool.name,
                                "kind": tool.kind,
                                "capabilities": sorted(tool.capabilities),
                                "approval": tool.approval,
                                "guardrails": tool.guardrails,
                                "destinations": [
                                    {
                                        "target": destination.target,
                                        "restricted": destination.restricted,
                                        "network_scope": destination.metadata.get("network_scope"),
                                    }
                                    for destination in tool.destinations
                                ],
                                "metadata": {
                                    key: value
                                    for key, value in tool.metadata.items()
                                    if key in {
                                        "binding_origin",
                                        "delegate_target",
                                        "provider_managed",
                                        "hosted_tool",
                                        "dynamic_remote_mcp_catalogue",
                                        "allowed_tools",
                                        "per_call_approval",
                                        "dynamic_tool_enablement",
                                        "conditional_approval",
                                        "is_enabled",
                                        "defer_loading",
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
                                "approval": server.approval,
                                "guardrails": server.guardrails,
                                "allowed_tools": list(server.allowed_tools),
                                "denied_tools": list(server.denied_tools),
                                "metadata": {
                                    key: value
                                    for key, value in server.metadata.items()
                                    if key in {
                                        "dynamic_mcp_endpoint",
                                        "dynamic_tool_filter",
                                        "configuration_source",
                                        "network_scope",
                                        "discovered_tool_capabilities",
                                        "local_server_resolved",
                                        "binding_origin",
                                        "tool_catalogue_unresolved",
                                    }
                                },
                            }
                            for server in agent.mcp_servers
                        ],
                        "metadata": {
                            key: value
                            for key, value in agent.metadata.items()
                            if key in {
                                "source_alias",
                                "delegates_to",
                                "handoff_semantics",
                                "runtime_clone_mcp",
                                "dynamic_tools",
                                "dynamic_tools_source_bound",
                                "input_guardrails",
                                "output_guardrails",
                                "guardrails",
                            }
                        },
                    }
                    for agent in graph.agents
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
    "oai-fund-01-direct-function-tool",
    {
        "agent.py": """
import requests
from agents import Agent, function_tool

@function_tool
def fetch_status() -> str:
    return requests.get("https://status.example.com/health").text

agent = Agent(name="status", tools=[fetch_status])
""",
    },
)
def _check_01(graph, findings, relationships):
    agent = _agent(graph, "status")
    tool = _tool(agent, "fetch_status")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(tool and "network.external" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": bool(
            tool
            and any(
                destination.target == "https://status.example.com/health"
                and destination.metadata.get("network_scope") == "fixed_literal_destination"
                for destination in tool.destinations
            )
        ),
        "controls": True,
        "authority_driven_findings": bool(_relationship(relationships, "status", "fetch_status")),
    }


@case(
    "oai-fund-02-function-tool-approval",
    {
        "agent.py": """
import subprocess
from agents import Agent, function_tool

@function_tool(needs_approval=True)
def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

agent = Agent(name="operator", tools=[run_command])
""",
    },
)
def _check_02(graph, findings, relationships):
    agent = _agent(graph, "operator")
    tool = _tool(agent, "run_command")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(tool and "process.execute" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": bool(tool and tool.approval is True),
        "authority_driven_findings": "AGT020" not in _rules(findings),
    }


@case(
    "oai-fund-03-conditional-tool-enable",
    {
        "agent.py": """
import os
from agents import Agent, RunContextWrapper, function_tool

def enabled(ctx: RunContextWrapper[dict], agent: Agent) -> bool:
    return os.getenv("ENABLE_WRITE") == "1"

@function_tool(is_enabled=enabled)
def write_record(value: str) -> str:
    with open("/tmp/record.txt", "w", encoding="utf-8") as handle:
        handle.write(value)
    return value

agent = Agent(name="conditional", tools=[write_record])
""",
    },
)
def _check_03(graph, findings, relationships):
    agent = _agent(graph, "conditional")
    tool = _tool(agent, "write_record")
    conditional_visible = bool(
        tool
        and (
            _metadata_signal(tool.metadata, "enabled")
            or _metadata_signal(tool.metadata, "dynamic")
            or _metadata_signal(agent.metadata if agent else {}, "dynamic")
        )
    )
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": conditional_visible,
        "effect_semantics": bool(tool and "data.write" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": bool(_relationship(relationships, "conditional", "write_record")),
    }


@case(
    "oai-fund-04-conditional-approval",
    {
        "agent.py": """
import subprocess
from agents import Agent, RunContextWrapper, function_tool

async def approval_required(
    ctx: RunContextWrapper[dict], params: dict, call_id: str
) -> bool:
    return params.get("command") != "pwd"

@function_tool(needs_approval=approval_required)
def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

agent = Agent(name="conditional-approval", tools=[run_command])
""",
    },
)
def _check_04(graph, findings, relationships):
    agent = _agent(graph, "conditional-approval")
    tool = _tool(agent, "run_command")
    relation = _relationship(relationships, "conditional-approval", "run_command")
    conditional_visible = bool(
        tool
        and (
            _metadata_signal(tool.metadata, "conditional", "approval")
            or _metadata_signal(tool.metadata, "dynamic", "approval")
        )
    )
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": conditional_visible,
        "effect_semantics": bool(tool and "process.execute" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": conditional_visible and bool(relation),
        "authority_driven_findings": bool(relation),
    }


@case(
    "oai-fund-05-hosted-tools",
    {
        "agent.py": """
from agents import Agent, CodeInterpreterTool, FileSearchTool, WebSearchTool

agent = Agent(
    name="research",
    tools=[
        WebSearchTool(),
        FileSearchTool(vector_store_ids=["vs_123"]),
        CodeInterpreterTool(tool_config={"type": "code_interpreter", "container": {"type": "auto"}}),
    ],
)
""",
    },
)
def _check_05(graph, findings, relationships):
    agent = _agent(graph, "research")
    web = _tool(agent, "WebSearchTool")
    files = _tool(agent, "FileSearchTool")
    code = _tool(agent, "CodeInterpreterTool")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(web and files and code),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            web
            and "network.external" in web.capabilities
            and files
            and "data.read" in files.capabilities
            and code
            and "process.execute" in code.capabilities
            and "data.write" in code.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": bool(
            web
            and any(
                destination.target == "<openai-provider>"
                and destination.restricted is True
                for destination in web.destinations
            )
        ),
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "oai-fund-06-shell-apply-patch-approval",
    {
        "agent.py": """
from agents import Agent, ApplyPatchTool, ShellTool

shell = ShellTool(executor=run_shell, needs_approval=True)
patch = ApplyPatchTool(editor=editor, needs_approval=True)
agent = Agent(name="coder", tools=[shell, patch])
""",
    },
)
def _check_06(graph, findings, relationships):
    agent = _agent(graph, "coder")
    shell = _tool(agent, "shell") or _tool(agent, "ShellTool")
    patch = _tool(agent, "patch") or _tool(agent, "ApplyPatchTool")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(shell and patch),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            shell
            and "process.execute" in shell.capabilities
            and patch
            and "data.write" in patch.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": bool(shell and patch and shell.approval is True and patch.approval is True),
        "authority_driven_findings": "AGT020" not in _rules(findings),
    }


@case(
    "oai-fund-07-hosted-mcp",
    {
        "agent.py": """
from agents import Agent, HostedMCPTool

docs = HostedMCPTool(
    tool_config={
        "type": "mcp",
        "server_label": "docs",
        "server_url": "https://mcp.example.com/sse",
        "allowed_tools": ["search_docs"],
        "require_approval": "always",
    }
)
agent = Agent(name="docs-agent", tools=[docs])
""",
    },
)
def _check_07(graph, findings, relationships):
    agent = _agent(graph, "docs-agent")
    tool = _tool(agent, "docs")
    allowed = list(tool.metadata.get("allowed_tools") or []) if tool else []
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": bool(tool and tool.kind == "hosted_mcp"),
        "dynamic_visibility": bool(
            tool and tool.metadata.get("dynamic_remote_mcp_catalogue") is False
        ),
        "effect_semantics": True,
        "local_vs_external": True,
        "scope_provenance": bool(
            tool
            and tool.metadata.get("server_url") == "https://mcp.example.com/sse"
            and allowed == ["search_docs"]
        ),
        "controls": bool(tool and tool.approval is True),
        "authority_driven_findings": bool(_relationship(relationships, "docs-agent", "docs")),
    }


@case(
    "oai-fund-08-local-http-mcp-controls",
    {
        "agent.py": """
from agents import Agent, ToolGuardrailFunctionOutput
from agents.decorators import tool_input_guardrail
from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter

@tool_input_guardrail
def block_secret_arguments(data):
    return ToolGuardrailFunctionOutput.allow()

server = MCPServerStreamableHttp(
    name="ops",
    params={"url": "https://mcp.example.com/mcp"},
    require_approval={"delete_file": "always", "read_file": "never"},
    tool_filter=create_static_tool_filter(
        allowed_tool_names=["delete_file", "read_file"]
    ),
    tool_input_guardrails=[block_secret_arguments],
)
agent = Agent(name="mcp-client", mcp_servers=[server])
""",
    },
)
def _check_08(graph, findings, relationships):
    agent = _agent(graph, "mcp-client")
    server = _server(agent, "server") or _server(agent, "ops") or _server(agent)
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "delegation_mcp_binding": bool(server and server.transport == "streamable-http"),
        "dynamic_visibility": True,
        "effect_semantics": True,
        "local_vs_external": True,
        "scope_provenance": bool(
            server
            and server.url == "https://mcp.example.com/mcp"
            and set(server.allowed_tools) == {"delete_file", "read_file"}
        ),
        "controls": bool(
            server
            and server.guardrails is True
            and (
                server.approval is not None
                or _metadata_signal(server.metadata, "approval")
            )
            and set(server.allowed_tools) == {"delete_file", "read_file"}
        ),
        "authority_driven_findings": bool(relationships),
    }


@case(
    "oai-fund-09-local-stdio-mcp",
    {
        "agent.py": """
from agents import Agent
from agents.mcp import MCPServerStdio

server = MCPServerStdio(
    name="local-files",
    params={"command": "python", "args": ["mcp_server.py"]},
)
agent = Agent(name="local-client", mcp_servers=[server])
""",
        "mcp_server.py": """
import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Local")

@mcp.tool()
def delete_file(path: str) -> str:
    os.remove(path)
    return path
""",
    },
)
def _check_09(graph, findings, relationships):
    agent = _agent(graph, "local-client")
    server = _server(agent)
    discovered = set(server.metadata.get("discovered_tool_capabilities") or []) if server else set()
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "delegation_mcp_binding": bool(server and server.transport == "stdio"),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            server
            and (
                "destructive.write" in discovered
                or "data.write" in discovered
                or server.metadata.get("local_server_resolved") is True
            )
        ),
        "local_vs_external": True,
        "scope_provenance": bool(server and server.command == "python"),
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "oai-fund-10-agent-as-tool-approval",
    {
        "agent.py": """
from agents import Agent

specialist = Agent(name="Specialist")
manager = Agent(
    name="Manager",
    tools=[
        specialist.as_tool(
            tool_name="ask_specialist",
            tool_description="Delegate to specialist",
            needs_approval=True,
        )
    ],
)
""",
    },
)
def _check_10(graph, findings, relationships):
    manager = _agent(graph, "Manager")
    tool = _tool(manager, "ask_specialist")
    relation = _relationship(relationships, "Manager", "ask_specialist")
    return {
        "agent_discovery": bool(manager and _agent(graph, "Specialist")),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": bool(
            tool
            and tool.metadata.get("delegate_target") == "specialist"
            and relation
        ),
        "dynamic_visibility": True,
        "effect_semantics": bool(tool and "agent.delegate" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": bool(tool and tool.approval is True),
        "authority_driven_findings": bool(relation),
    }


@case(
    "oai-fund-11-handoffs",
    {
        "agent.py": """
from agents import Agent, handoff
from agents.extensions import handoff_filters

refund = Agent(name="Refund")
sales = Agent(name="Sales")
triage = Agent(
    name="Triage",
    handoffs=[
        refund,
        handoff(
            agent=sales,
            input_filter=handoff_filters.remove_all_tools,
        ),
    ],
)
""",
    },
)
def _check_11(graph, findings, relationships):
    triage = _agent(graph, "Triage")
    delegates = set(triage.metadata.get("delegates_to") or []) if triage else set()
    delegated_relationships = [
        item
        for item in relationships
        if item.agent == "Triage"
        and (
            item.target_kind == "delegation"
            or item.target_name in {"delegate:Refund", "delegate:Sales", "Refund", "Sales"}
        )
    ]
    return {
        "agent_discovery": bool(triage and _agent(graph, "Refund") and _agent(graph, "Sales")),
        "tool_binding": True,
        "delegation_mcp_binding": bool(
            triage
            and triage.metadata.get("handoff_semantics") is True
            and delegates == {"Refund", "Sales"}
            and len(delegated_relationships) >= 2
        ),
        "dynamic_visibility": True,
        "effect_semantics": True,
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": True,
    }


@case(
    "oai-fund-12-runtime-clone-mcp",
    {
        "agent.py": """
from agents import Agent
from agents.mcp import MCPServerStreamableHttp

server = MCPServerStreamableHttp(
    name="knowledge",
    params={"url": "https://mcp.example.com/mcp"},
)
base = Agent(name="Base")
runtime = base.clone(mcp_servers=[server])
""",
    },
)
def _check_12(graph, findings, relationships):
    agent = _agent(graph, "Base")
    server = _server(agent)
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "delegation_mcp_binding": bool(server and server.url == "https://mcp.example.com/mcp"),
        "dynamic_visibility": True,
        "effect_semantics": True,
        "local_vs_external": True,
        "scope_provenance": bool(server and server.url == "https://mcp.example.com/mcp"),
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "oai-fund-13-agent-guardrails",
    {
        "agent.py": """
from agents import (
    Agent,
    GuardrailFunctionOutput,
    RunContextWrapper,
    input_guardrail,
    output_guardrail,
)

@input_guardrail
async def validate_input(ctx: RunContextWrapper, agent: Agent, input):
    return GuardrailFunctionOutput(output_info={}, tripwire_triggered=False)

@output_guardrail
async def validate_output(ctx: RunContextWrapper, agent: Agent, output):
    return GuardrailFunctionOutput(output_info={}, tripwire_triggered=False)

agent = Agent(
    name="guarded",
    input_guardrails=[validate_input],
    output_guardrails=[validate_output],
)
""",
    },
)
def _check_13(graph, findings, relationships):
    agent = _agent(graph, "guarded")
    preserved = bool(
        agent
        and (
            _metadata_signal(agent.metadata, "input_guardrail")
            or _metadata_signal(agent.metadata, "output_guardrail")
            or _metadata_signal(agent.metadata, "guardrail")
        )
    )
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": True,
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": preserved,
        "authority_driven_findings": True,
    }


@case(
    "oai-fund-14-factory-return-agent",
    {
        "agent.py": """
from agents import Agent, function_tool

def build_agent() -> Agent:
    @function_tool
    def write_file(path: str, content: str) -> str:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    return Agent(name="factory-writer", tools=[write_file])

agent = build_agent()
""",
    },
)
def _check_14(graph, findings, relationships):
    agent = _agent(graph, "factory-writer")
    tool = _tool(agent, "write_file")
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(tool and "data.write" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": bool(_relationship(relationships, "factory-writer", "write_file")),
    }


@case(
    "oai-fund-15-source-over-name",
    {
        "agent.py": """
from agents import Agent, function_tool

@function_tool
def add(a: int, b: int) -> int:
    return a + b

@function_tool
def execute_plan(plan: str) -> str:
    return f"plan: {plan}"

agent = Agent(name="safe-names", tools=[add, execute_plan])
""",
    },
)
def _check_15(graph, findings, relationships):
    agent = _agent(graph, "safe-names")
    add = _tool(agent, "add")
    execute = _tool(agent, "execute_plan")
    bad = {"data.write", "process.execute", "external.write", "destructive.write"}
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(add and execute),
        "delegation_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(
            add
            and execute
            and not (add.capabilities & bad)
            and not (execute.capabilities & bad)
        ),
        "local_vs_external": bool(
            add
            and execute
            and not (add.capabilities & bad)
            and not (execute.capabilities & bad)
        ),
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": not (_rules(findings) & {"AGT020", "AGT040"}),
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
        "study": "openai-agents-fundamentals-15",
        "purpose": "Validate canonical OpenAI Agents SDK authority constructs and HorusTrace architectural invariants without chasing arbitrary Python corner cases.",
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

    out = Path("artifacts/openai-agents-fundamentals-15")
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# OpenAI Agents SDK fundamentals conformance",
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
