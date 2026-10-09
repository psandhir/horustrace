"""Source-backed Idun-style ADK MCP registry configuration correlation.

The runtime registry and its transport enforcement cannot be verified by
static inspection. A YAML app entrypoint proves only which endpoints are
*configured*, not what hosts a deployed process can actually contact.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from horustrace.models import Graph


def _entrypoint(path: Path, root: Path, doc: Any) -> tuple[Path, str] | None:
    if not isinstance(doc, dict):
        return None
    agent = doc.get("agent")
    if not isinstance(agent, dict) or str(agent.get("type") or "").upper() != "ADK":
        return None
    config = agent.get("config")
    if not isinstance(config, dict):
        return None
    reference = config.get("agent")
    if not isinstance(reference, str) or ":" not in reference:
        return None
    source, alias = reference.rsplit(":", 1)
    if not source.endswith(".py") or not alias.isidentifier():
        return None
    resolved = (path.parent / source).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        return None
    return resolved, alias


def correlate_adk_registry_mcp_config(
    graph: Graph, root: Path, config_paths: list[Path],
) -> None:
    """Attach declared MCP endpoints only to explicitly referenced ADK agents."""
    configs: dict[tuple[Path, str], list[list[dict[str, str]]]] = {}
    for path in sorted(config_paths):
        if path.name not in {"config.yaml", "config.yml"}:
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            continue
        ref = _entrypoint(path, root, doc)
        if ref is None or not isinstance(doc, dict):
            continue
        servers = doc.get("mcp_servers")
        if not isinstance(servers, list) or not servers:
            continue
        entries: list[dict[str, str]] = []
        valid = True
        for server in servers:
            if not isinstance(server, dict):
                valid = False
                break
            target, name = server.get("url"), server.get("name")
            if not isinstance(target, str) or not target.startswith(("https://", "http://")):
                valid = False
                break
            if not isinstance(name, str) or not name.strip():
                valid = False
                break
            entries.append({
                "name": name,
                "target": target,
                "transport": str(server.get("transport") or "unknown"),
                "config_path": path.relative_to(root).as_posix(),
            })
        if valid and entries:
            configs.setdefault(ref, []).append(entries)

    for agent in graph.agents:
        if agent.metadata.get("framework") != "google-adk" or agent.location is None:
            continue
        ref = (agent.location.path.resolve(), agent.metadata.get("source_alias"))
        config_sets = configs.get(ref, [])
        # Multiple competing registries for a single entrypoint are ambiguous.
        if len(config_sets) != 1:
            continue
        for server in agent.mcp_servers:
            if server.name != "get_adk_tools":
                continue
            server.metadata["configured_mcp_endpoints"] = config_sets[0]
            server.metadata["network_scope"] = "registry_configured_destinations"
            server.metadata["registry_configuration_resolution"] = "declared_only"
            server.metadata["runtime_registry_membership_verified"] = False
