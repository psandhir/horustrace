"""Static FastAgent YAML MCP configuration adapter.

Parses FastAgent's local configuration without importing or executing target code.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import yaml

from horustrace.models import Graph, MCPServer, SourceLocation

FAST_AGENT_CONFIG_FILENAMES = {
    "fast-agent.yaml",
    "fast-agent.yml",
    "fastagent.config.yaml",
    "fastagent.config.yml",
}
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _auth(headers: Any) -> tuple[bool | None, list[str], str | None]:
    if not isinstance(headers, dict):
        return False, [], None
    keys = sorted(str(key).lower() for key in headers)
    auth_keys = [
        key
        for key in keys
        if key
        in {
            "authorization",
            "proxy-authorization",
            "x-api-key",
            "x-goog-api-key",
        }
    ]
    credential_source = None
    for value in headers.values():
        if not isinstance(value, str):
            continue
        match = _ENV_REF.search(value)
        if match:
            credential_source = f"env:{match.group(1)}"
            break
    return bool(auth_keys), auth_keys, credential_source


def _server_from_config(
    path: Path,
    name: str,
    config: dict[str, Any],
) -> MCPServer:
    target = config.get("target")
    url = config.get("url") or config.get("server_url")
    command = config.get("command")
    args = config.get("args") or []

    if isinstance(target, str) and target.strip():
        target = target.strip()
        if target.startswith(("http://", "https://")):
            url = target
        elif command is None:
            try:
                parts = shlex.split(target)
            except ValueError:
                parts = [target]
            if parts:
                command = parts[0]
                args = parts[1:]

    if not isinstance(args, list):
        args = []

    header_authenticated, auth_keys, credential_source = _auth(
        config.get("headers")
    )
    transport = str(
        config.get("transport")
        or ("stdio" if command else "http" if url else "unknown")
    )

    auth_config = config.get("auth")
    oauth_enabled = False
    if url and transport.lower() in {
        "http",
        "sse",
        "streamable_http",
        "streamable-http",
    }:
        oauth_enabled = not (
            isinstance(auth_config, dict)
            and auth_config.get("oauth") is False
        )

    authenticated = header_authenticated
    if oauth_enabled:
        authenticated = True
        auth_keys = sorted({*auth_keys, "oauth"})
        if credential_source is None:
            persist = (
                auth_config.get("persist")
                if isinstance(auth_config, dict)
                else None
            )
            credential_source = (
                f"oauth:{persist}"
                if isinstance(persist, str) and persist
                else "oauth:keyring"
            )

    metadata: dict[str, Any] = {
        "framework": "fast-agent",
        "source": "fast_agent_yaml",
        "config_scope": str(path.parent.resolve()),
        "raw_keys": sorted(str(key) for key in config),
        "auth_keys": auth_keys,
    }
    if credential_source:
        metadata["credential_source"] = credential_source
    protocol_mode = config.get("protocol_mode")
    if isinstance(protocol_mode, str):
        metadata["protocol_mode"] = protocol_mode

    return MCPServer(
        name=name,
        transport=transport,
        url=str(url) if isinstance(url, str) and url else None,
        command=str(command) if isinstance(command, str) and command else None,
        args=[str(item) for item in args],
        authenticated=authenticated,
        location=SourceLocation(path=path),
        metadata=metadata,
    )


def scan_fast_agent_config(path: Path) -> Graph:
    graph = Graph()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return graph
    if not isinstance(raw, dict):
        return graph

    mcp = raw.get("mcp")
    if not isinstance(mcp, dict):
        return graph
    servers = mcp.get("servers")
    if not isinstance(servers, dict):
        return graph

    for name, config in servers.items():
        if not isinstance(name, str) or not isinstance(config, dict):
            continue
        graph.unbound_mcp_servers.append(
            _server_from_config(path, name, config)
        )
    return graph
