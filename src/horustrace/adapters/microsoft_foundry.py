"""Microsoft Foundry hosted-agent configuration semantics.

The Azure Developer CLI writes hosted-agent and Toolbox topology into azure.yaml.
This adapter treats that file as deployment evidence. It does not execute azd,
resolve cloud state, or infer permissions that are not present in source.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from horustrace.models import (
    Agent,
    Graph,
    Identity,
    MCPServer,
    NetworkDestination,
    SourceLocation,
    Tool,
)

_AGENT_HOSTS = {"azure.ai.agent", "azure.ai.hostedagent", "azure.ai.hosted-agent"}
_TOOLBOX_HOSTS = {"azure.ai.toolbox"}

_TOOLBOX_CAPABILITIES: dict[str, tuple[str, set[str]]] = {
    "code_interpreter": (
        "foundry_code_interpreter",
        {"process.execute", "data.read", "data.write"},
    ),
    "code-interpreter": (
        "foundry_code_interpreter",
        {"process.execute", "data.read", "data.write"},
    ),
    "web_search": ("foundry_web_search", {"data.read", "network.external"}),
    "web-search": ("foundry_web_search", {"data.read", "network.external"}),
    "file_search": ("foundry_file_search", {"data.read"}),
    "file-search": ("foundry_file_search", {"data.read"}),
    "image_generation": (
        "foundry_image_generation",
        {"external.write", "network.external"},
    ),
    "image-generation": (
        "foundry_image_generation",
        {"external.write", "network.external"},
    ),
    "mcp": ("foundry_mcp_tool", {"network.external"}),
    "openapi": ("foundry_openapi", {"network.external"}),
    "azure_function": ("foundry_azure_function", {"network.external"}),
    "azure-function": ("foundry_azure_function", {"network.external"}),
}


def _location(path: Path) -> SourceLocation:
    return SourceLocation(path=path, line=1, column=1)


def _service_host(service: dict[str, Any]) -> str:
    return str(service.get("host") or "").strip().lower()


def _tool_from_config(path: Path, toolbox: str, item: dict[str, Any]) -> Tool:
    raw_type = str(item.get("type") or item.get("kind") or "tool").strip().lower()
    kind, capabilities = _TOOLBOX_CAPABILITIES.get(
        raw_type,
        ("foundry_toolbox_tool", set()),
    )
    name = str(item.get("name") or raw_type or "tool")
    tool = Tool(
        name=name,
        kind=kind,
        capabilities=set(capabilities),
        location=_location(path),
        metadata={
            "framework": "microsoft-foundry",
            "provider": "microsoft-foundry",
            "foundry_toolbox": toolbox,
            "foundry_tool_type": raw_type,
            "provider_managed": True,
            "deployment_evidence": "azure.yaml",
        },
    )

    endpoint = item.get("url") or item.get("endpoint") or item.get("serverUrl")
    if isinstance(endpoint, str) and endpoint:
        tool.destinations.append(
            NetworkDestination(
                target=endpoint,
                restricted=True,
                location=tool.location,
                metadata={
                    "source": "foundry_toolbox_configuration",
                    "network_scope": "fixed_destination",
                    "toolbox": toolbox,
                },
            )
        )
    elif "network.external" in tool.capabilities:
        tool.destinations.append(
            NetworkDestination(
                target="<microsoft-foundry-managed>",
                restricted=True,
                location=tool.location,
                metadata={
                    "source": "provider_managed",
                    "network_scope": "fixed_provider_network",
                    "provider": "microsoft-foundry",
                    "toolbox": toolbox,
                },
            )
        )
    return tool


def _toolbox_server(path: Path, name: str, service: dict[str, Any]) -> MCPServer:
    endpoint = service.get("endpoint") or service.get("url")
    server = MCPServer(
        name=name,
        transport="foundry-toolbox",
        url=endpoint if isinstance(endpoint, str) and endpoint else None,
        authenticated=True,
        location=_location(path),
        metadata={
            "framework": "microsoft-foundry",
            "provider": "microsoft-foundry",
            "foundry_toolbox": True,
            "deployment_evidence": "azure.yaml",
            "authentication": "entra",
        },
    )
    if server.url:
        server.metadata["network_scope"] = "fixed_destination"
    else:
        server.metadata.update(
            {
                "dynamic_mcp_endpoint_basis": "operator_configuration",
                "configuration_source": "foundry_project_toolbox_endpoint",
                "network_scope": "operator_configured_destination",
            }
        )
    return server


def _environment_names(service: dict[str, Any]) -> list[str]:
    raw = service.get("environmentVariables")
    if not isinstance(raw, list):
        return []
    names: list[str] = []
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
    return sorted(set(names))


def scan_foundry_config(path: Path) -> Graph:
    graph = Graph()
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return graph
    if not isinstance(document, dict):
        return graph

    services = document.get("services")
    if not isinstance(services, dict):
        return graph

    toolboxes: dict[str, dict[str, Any]] = {
        str(name): service
        for name, service in services.items()
        if isinstance(service, dict) and _service_host(service) in _TOOLBOX_HOSTS
    }
    if not toolboxes and not any(
        isinstance(service, dict) and _service_host(service) in _AGENT_HOSTS
        for service in services.values()
    ):
        return graph

    toolbox_tools: dict[str, list[Tool]] = {}
    for name, service in toolboxes.items():
        raw_tools = service.get("tools")
        tools: list[Tool] = []
        if isinstance(raw_tools, list):
            for item in raw_tools:
                if isinstance(item, dict):
                    tools.append(_tool_from_config(path, name, item))
        toolbox_tools[name] = tools
        graph.unbound_mcp_servers.append(_toolbox_server(path, name, service))

    for raw_name, raw_service in services.items():
        if not isinstance(raw_service, dict) or _service_host(raw_service) not in _AGENT_HOSTS:
            continue
        name = str(raw_name)
        uses = raw_service.get("uses")
        uses_list = [str(item) for item in uses] if isinstance(uses, list) else []

        agent = Agent(
            name=name,
            location=_location(path),
            metadata={
                "framework": "microsoft-foundry-hosted",
                "provider": "microsoft-foundry",
                "hosted_agent": True,
                "runtime_host": _service_host(raw_service),
                "project_path": raw_service.get("project"),
                "uses": uses_list,
                "protocols": deepcopy(raw_service.get("protocols") or []),
                "environment_variables": _environment_names(raw_service),
                "deployment_evidence": "azure.yaml",
            },
        )

        # Foundry hosted agents receive an Entra agent identity. The source file
        # does not contain the runtime object id, so preserve identity existence
        # without inventing permissions or a principal identifier.
        agent.identities.append(
            Identity(
                name=f"{name}:agent-identity",
                provider="azure",
                location=_location(path),
                metadata={
                    "identity_kind": "foundry_agent_identity",
                    "runtime_resolved": False,
                    "deployment_evidence": "azure.yaml",
                },
            )
        )

        for dependency in uses_list:
            if dependency not in toolboxes:
                continue
            agent.mcp_servers.append(
                deepcopy(_toolbox_server(path, dependency, toolboxes[dependency]))
            )
            agent.tools.extend(deepcopy(toolbox_tools.get(dependency, [])))

        graph.agents.append(agent)

    return graph
