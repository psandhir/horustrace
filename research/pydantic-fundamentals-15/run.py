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
    "toolset_mcp_binding",
    "dynamic_visibility",
    "effect_semantics",
    "local_vs_external",
    "scope_provenance",
    "controls",
    "authority_driven_findings",
)


def _tool(agent, name: str):
    return next((item for item in agent.tools if item.name == name), None)


def _server(agent):
    return agent.mcp_servers[0] if agent.mcp_servers else None


def _rules(findings):
    return {item.rule_id for item in findings}


def _diag_text(graph) -> str:
    return "\n".join(
        f"{getattr(item, 'code', '')}: {getattr(item, 'message', '')}"
        for item in graph.coverage.diagnostics
    )


def _run_case(
    case_id: str,
    files: dict[str, str],
    check: Callable,
) -> dict[str, object]:
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
                                "resources": [
                                    {
                                        "kind": resource.kind,
                                        "selector": resource.selector,
                                        "access": sorted(resource.access),
                                    }
                                    for resource in tool.resources
                                ],
                                "metadata": {
                                    key: value
                                    for key, value in tool.metadata.items()
                                    if key in {
                                        "binding_origin",
                                        "dynamic_tool_filter",
                                        "conditional_approval",
                                        "capability",
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
                                "allowed_tools": list(server.allowed_tools),
                                "metadata": {
                                    key: value
                                    for key, value in server.metadata.items()
                                    if key in {
                                        "dynamic_mcp_endpoint",
                                        "native",
                                        "discovered_tool_capabilities",
                                        "local_server_resolved",
                                    }
                                },
                            }
                            for server in agent.mcp_servers
                        ],
                        "metadata": {
                            key: value
                            for key, value in agent.metadata.items()
                            if key in {
                                "dynamic_tools",
                                "runtime_toolsets",
                                "safety_capabilities",
                                "unmodeled_capabilities",
                                "factory_return",
                                "binding_origin",
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
    "pyd-fund-01-direct-tools",
    {
        "agent.py": """
import requests
from pydantic_ai import Agent

def fetch_url(url: str) -> str:
    return requests.get(url).text

agent = Agent("openai:gpt-5.2", tools=[fetch_url])
""",
    },
)
def _check_01(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    tool = _tool(agent, "fetch_url") if agent else None
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "effect_semantics": bool(tool and "network.external" in tool.capabilities),
        "toolset_mcp_binding": True,
        "dynamic_visibility": True,
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "pyd-fund-02-decorator-approval",
    {
        "agent.py": """
import subprocess
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-5.2")

@agent.tool(requires_approval=True)
def run_command(ctx: RunContext[dict], command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
""",
    },
)
def _check_02(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    tool = _tool(agent, "run_command") if agent else None
    rules = _rules(findings)
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "toolset_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(tool and "process.execute" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": bool(tool and tool.approval is True),
        "authority_driven_findings": "AGT020" not in rules,
    }


@case(
    "pyd-fund-03-post-construction-registration",
    {
        "agent.py": """
from pydantic_ai import Agent

def write_file(path: str, content: str) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path

agent = Agent("openai:gpt-5.2")
agent.tool_plain(write_file)
""",
    },
)
def _check_03(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    tool = _tool(agent, "write_file") if agent else None
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "toolset_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(tool and "data.write" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "pyd-fund-04-function-toolset",
    {
        "agent.py": """
import requests
from pydantic_ai import Agent, FunctionToolset

toolset = FunctionToolset()

@toolset.tool_plain
def fetch_status(url: str) -> str:
    return requests.get(url).text

def read_secret(name: str) -> str | None:
    import os
    return os.getenv(name)

toolset.add_function(read_secret)
agent = Agent("openai:gpt-5.2", toolsets=[toolset])
""",
    },
)
def _check_04(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    fetch = _tool(agent, "fetch_status") if agent else None
    secret = _tool(agent, "read_secret") if agent else None
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(fetch and secret),
        "toolset_mcp_binding": bool(fetch and secret),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            fetch
            and "network.external" in fetch.capabilities
            and secret
            and "secrets.read" in secret.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "pyd-fund-05-combined-approval-toolset",
    {
        "agent.py": """
import subprocess
from pydantic_ai import Agent, FunctionToolset
from pydantic_ai.toolsets import CombinedToolset, ApprovalRequiredToolset

def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

def read_file(path: str) -> str:
    return open(path, encoding="utf-8").read()

commands = FunctionToolset(tools=[run_command])
files = FunctionToolset(tools=[read_file])
combined = CombinedToolset([commands, files])
protected = ApprovalRequiredToolset(combined)
agent = Agent("openai:gpt-5.2", toolsets=[protected])
""",
    },
)
def _check_05(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    run = _tool(agent, "run_command") if agent else None
    read = _tool(agent, "read_file") if agent else None
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(run and read),
        "toolset_mcp_binding": bool(run and read),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            run
            and "process.execute" in run.capabilities
            and read
            and "data.read" in read.capabilities
        ),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": bool(run and read and run.approval is True and read.approval is True),
        "authority_driven_findings": "AGT020" not in _rules(findings),
    }


@case(
    "pyd-fund-06-filtered-deferred-toolset",
    {
        "agent.py": """
import requests
from pydantic_ai import Agent, FunctionToolset

def fetch_url(url: str) -> str:
    return requests.get(url).text

base = FunctionToolset(tools=[fetch_url])
wrapped = base.filtered(lambda ctx, tool: True).defer_loading()
agent = Agent("openai:gpt-5.2", toolsets=[wrapped])
""",
    },
)
def _check_06(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    tool = _tool(agent, "fetch_url") if agent else None
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "toolset_mcp_binding": bool(tool),
        "dynamic_visibility": bool(
            agent
            and agent.metadata.get("dynamic_tools") is True
            and tool
            and tool.metadata.get("dynamic_tool_filter") is True
        ),
        "effect_semantics": bool(tool and "network.external" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "pyd-fund-07-remote-mcp",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset

mcp = MCPToolset("https://mcp.example.com/api")
agent = Agent("openai:gpt-5.2", toolsets=[mcp])
""",
    },
)
def _check_07(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    server = _server(agent) if agent else None
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "toolset_mcp_binding": bool(
            server
            and server.url == "https://mcp.example.com/api"
            and server.transport == "streamable-http"
        ),
        "dynamic_visibility": True,
        "effect_semantics": True,
        "local_vs_external": True,
        "scope_provenance": bool(server and server.url == "https://mcp.example.com/api"),
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "pyd-fund-08-local-stdio-mcp",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

server = MCPServerStdio("python", ["mcp_server.py"])
agent = Agent("openai:gpt-5.2", mcp_servers=[server])
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
def _check_08(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    server = _server(agent) if agent else None
    discovered = set((server.metadata.get("discovered_tool_capabilities") or [])) if server else set()
    return {
        "agent_discovery": bool(agent),
        "tool_binding": True,
        "toolset_mcp_binding": bool(server and server.command == "python"),
        "dynamic_visibility": True,
        "effect_semantics": bool(
            server
            and (
                "destructive.write" in discovered
                or "data.write" in discovered
            )
        ),
        "local_vs_external": True,
        "scope_provenance": bool(server and server.command == "python"),
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "pyd-fund-09-runtime-toolsets",
    {
        "agent.py": """
import subprocess
from pydantic_ai import Agent, FunctionToolset

def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

runtime_tools = FunctionToolset(tools=[run_command])
agent = Agent("openai:gpt-5.2")
result = agent.run_sync("do the task", toolsets=[runtime_tools])
""",
    },
)
def _check_09(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    tool = _tool(agent, "run_command") if agent else None
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "toolset_mcp_binding": bool(tool),
        "dynamic_visibility": bool(agent and agent.metadata.get("runtime_toolsets") is True),
        "effect_semantics": bool(tool and "process.execute" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "pyd-fund-10-dynamic-agent-toolset",
    {
        "agent.py": """
import subprocess
from pydantic_ai import Agent, FunctionToolset, RunContext

def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

agent = Agent("openai:gpt-5.2")

@agent.toolset
def dynamic_tools(ctx: RunContext[dict]):
    return FunctionToolset(tools=[run_command])
""",
    },
)
def _check_10(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    diagnostic = "dynamic @agent.toolset" in _diag_text(graph).lower()
    tool = _tool(agent, "run_command") if agent else None
    # Fundamental invariant: when an explicit dynamic toolset binding cannot be
    # enumerated, the binding itself must remain visible in the authority model,
    # not only in a diagnostic side channel.
    visible_authority = bool(
        tool
        or relationships
        or (agent and agent.metadata.get("dynamic_tools") is True)
    )
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool) or diagnostic,
        "toolset_mcp_binding": visible_authority,
        "dynamic_visibility": visible_authority and diagnostic,
        "effect_semantics": bool(tool and "process.execute" in tool.capabilities) or diagnostic,
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": True,
    }


@case(
    "pyd-fund-11-capabilities",
    {
        "agent.py": """
from pydantic_ai import Agent
from pydantic_ai.capabilities import MCP, WebSearch
from pydantic_ai_harness import FileSystem, Guardrails

agent = Agent(
    "openai:gpt-5.2",
    capabilities=[
        WebSearch(),
        FileSystem("/workspace"),
        Guardrails(),
        MCP(url="https://mcp.example.com/api", native=True),
    ],
)
""",
    },
)
def _check_11(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    web = _tool(agent, "WebSearch") if agent else None
    fs = _tool(agent, "FileSystem") if agent else None
    server = _server(agent) if agent else None
    controls = set(agent.metadata.get("safety_capabilities") or []) if agent else set()
    fs_scope = (
        fs.resources[0].selector
        if fs and fs.resources
        else None
    )
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(web and fs),
        "toolset_mcp_binding": bool(server),
        "dynamic_visibility": True,
        "effect_semantics": bool(web and "network.external" in web.capabilities),
        "local_vs_external": True,
        "scope_provenance": fs_scope == "/workspace",
        "controls": "Guardrails" in controls,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "pyd-fund-12-capability-bundle",
    {
        "agent.py": """
import requests
from pydantic_ai import Agent
from pydantic_ai.capabilities import Capability

refunds = Capability(
    id="orders",
    description="Order operations",
    instructions="Use these tools for order work.",
)

@refunds.tool_plain
def lookup_order(order_id: str) -> str:
    return requests.get(f"https://orders.example.com/{order_id}").text

agent = Agent("openai:gpt-5.2", capabilities=[refunds])
""",
    },
)
def _check_12(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    tool = _tool(agent, "lookup_order") if agent else None
    unmodeled = set(agent.metadata.get("unmodeled_capabilities") or []) if agent else set()
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "toolset_mcp_binding": True,
        "dynamic_visibility": bool(tool) or "Capability" in unmodeled,
        "effect_semantics": bool(tool and "network.external" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": bool(tool and relationships),
    }


@case(
    "pyd-fund-13-factory-return",
    {
        "agent.py": """
import subprocess
from pydantic_ai import Agent, FunctionToolset

def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

def build_agent():
    local_tools = FunctionToolset(tools=[run_command])
    return Agent("openai:gpt-5.2", toolsets=[local_tools])

root_agent = build_agent()
""",
    },
)
def _check_13(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    tool = _tool(agent, "run_command") if agent else None
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "toolset_mcp_binding": bool(tool),
        "dynamic_visibility": True,
        "effect_semantics": bool(tool and "process.execute" in tool.capabilities),
        "local_vs_external": True,
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": bool(relationships),
    }


@case(
    "pyd-fund-14-runcontext-local-state",
    {
        "agent.py": """
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-5.2")

@agent.tool
def update_state(ctx: RunContext[dict], value: str) -> str:
    ctx.deps["value"] = value
    return value
""",
    },
)
def _check_14(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    tool = _tool(agent, "update_state") if agent else None
    privileged = {"data.write", "external.write", "destructive.write"}
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(tool),
        "toolset_mcp_binding": True,
        "dynamic_visibility": True,
        "effect_semantics": bool(tool and not (tool.capabilities & privileged)),
        "local_vs_external": bool(tool and not (tool.capabilities & privileged)),
        "scope_provenance": True,
        "controls": True,
        "authority_driven_findings": "AGT040" not in _rules(findings),
    }


@case(
    "pyd-fund-15-source-over-name",
    {
        "agent.py": """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool_plain
def add(a: int, b: int) -> int:
    return a + b

@agent.tool_plain
def execute_plan(plan: str) -> str:
    return f"plan: {plan}"
""",
    },
)
def _check_15(graph, findings, relationships):
    agent = graph.agents[0] if graph.agents else None
    add = _tool(agent, "add") if agent else None
    execute = _tool(agent, "execute_plan") if agent else None
    bad = {"data.write", "process.execute", "external.write", "destructive.write"}
    return {
        "agent_discovery": bool(agent),
        "tool_binding": bool(add and execute),
        "toolset_mcp_binding": True,
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
        "study": "pydantic-fundamentals-15",
        "purpose": "Validate canonical Pydantic AI authority constructs and HorusTrace architectural invariants without chasing arbitrary Python corner cases.",
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

    out = Path("artifacts/pydantic-fundamentals-15")
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Pydantic AI fundamentals conformance",
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
