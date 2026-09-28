from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from horustrace.models import Graph, MCPServer, SourceLocation

MCP_FILENAMES = {"mcp.json", ".mcp.json", "mcp-config.json", "mcp_config.json"}

_CREDENTIAL_FLAGS = {
    "--access-token",
    "--api-key",
    "--apikey",
    "--auth-token",
    "--password",
    "--secret",
    "--token",
}
_CREDENTIAL_KEYS = {
    "access_token",
    "accesstoken",
    "api_key",
    "apikey",
    "authorization",
    "password",
    "secret",
    "token",
}


def _looks_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        not lowered
        or lowered.startswith(("$", "${", "env:", "<"))
        or "getenv(" in lowered
        or "environ[" in lowered
    )


def _redact_args(args: list[Any]) -> tuple[list[str], list[str], bool]:
    redacted: list[str] = []
    credential_sources: list[str] = []
    broad_tool_surface = False
    index = 0
    while index < len(args):
        raw = str(args[index])
        lowered = raw.lower()
        if lowered == "--tools=all":
            broad_tool_surface = True
        matched_inline = False
        for flag in _CREDENTIAL_FLAGS:
            prefix = flag + "="
            if lowered.startswith(prefix):
                value = raw[len(prefix):]
                if not _looks_placeholder(value):
                    credential_sources.append(flag)
                redacted.append(flag + "=<redacted>")
                matched_inline = True
                break
        if matched_inline:
            index += 1
            continue
        if lowered in _CREDENTIAL_FLAGS:
            redacted.append(raw)
            if index + 1 < len(args):
                value = str(args[index + 1])
                if not _looks_placeholder(value):
                    credential_sources.append(lowered)
                redacted.append("<redacted>")
                index += 2
                continue
        redacted.append(raw)
        index += 1
    return redacted, sorted(set(credential_sources)), broad_tool_surface


def _literal_config_credentials(config: dict[str, Any]) -> list[str]:
    sources: list[str] = []
    for key, value in config.items():
        normalized = str(key).lower().replace("-", "_")
        if (
            normalized in _CREDENTIAL_KEYS
            and isinstance(value, str)
            and not _looks_placeholder(value)
        ):
            sources.append(f"field:{normalized}")
    headers = config.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            normalized = str(key).lower()
            if normalized in {
                "authorization",
                "proxy-authorization",
                "x-api-key",
                "x-goog-api-key",
            } and isinstance(value, str) and not _looks_placeholder(value):
                sources.append(f"header:{normalized}")
    return sorted(set(sources))


def _auth_from_config(config: dict[str, Any]) -> tuple[bool | None, list[str]]:
    headers = config.get("headers")
    auth_keys: list[str] = []
    if isinstance(headers, dict):
        normalized = {str(key).lower() for key in headers}
        auth_keys = sorted(
            normalized
            & {
                "authorization",
                "proxy-authorization",
                "x-api-key",
                "x-goog-api-key",
            }
        )
        if auth_keys:
            return True, auth_keys
    if config.get("authorization"):
        return True, ["authorization"]
    if config.get("oauth"):
        return True, ["oauth"]
    if config.get("token"):
        return True, ["token"]
    # A parsed static MCP configuration with no recognised auth field
    # is evidence that authentication is absent. None is reserved for
    # genuinely dynamic/unresolved authentication configuration.
    return False, auth_keys


def scan_mcp_config(path: Path) -> Graph:
    graph = Graph()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return graph

    servers = raw.get("mcpServers") or raw.get("servers") or {}
    if not isinstance(servers, dict):
        return graph

    for name, config in servers.items():
        if not isinstance(config, dict):
            continue
        url = config.get("url") or config.get("serverUrl")
        command = config.get("command")
        args = config.get("args") or []
        if not isinstance(args, list):
            args = []
        redacted_args, arg_credential_sources, broad_tool_surface = _redact_args(
            args
        )
        literal_credentials = sorted(
            set(_literal_config_credentials(config) + arg_credential_sources)
        )
        transport = str(config.get("transport") or ("stdio" if command else "http" if url else "unknown"))
        authenticated, auth_keys = _auth_from_config(config)
        allowed_tools = config.get("allowedTools") or config.get("allowed_tools") or []
        denied_tools = config.get("deniedTools") or config.get("denied_tools") or []
        graph.unbound_mcp_servers.append(
            MCPServer(
                name=str(name),
                transport=transport,
                url=str(url) if url else None,
                command=str(command) if command else None,
                args=redacted_args,
                authenticated=authenticated,
                approval=None,
                allowed_tools=[str(v) for v in allowed_tools] if isinstance(allowed_tools, list) else [],
                denied_tools=[str(v) for v in denied_tools] if isinstance(denied_tools, list) else [],
                location=SourceLocation(path=path),
                metadata={
                    "raw_keys": sorted(config.keys()),
                    "auth_keys": auth_keys,
                    "framework": "mcp",
                    "topology_visible_unbound": True,
                    "binding_state": "unbound",
                    "discovery_source": "mcp_config",
                    "literal_credential_sources": literal_credentials,
                    "credential_values_redacted": bool(literal_credentials),
                    "broad_tool_surface": broad_tool_surface,
                },
            )
        )
    return graph
