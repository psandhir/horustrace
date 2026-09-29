from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from urllib.parse import urlparse

from horustrace.models import Agent, Graph, Identity, MCPServer


def _module_name(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _module_matches(path: Path, root: Path, import_module: str) -> bool:
    module = _module_name(path, root)
    return module == import_module or module.endswith(f".{import_module}")


def _unresolved_reference(
    *,
    agent: Agent,
    name: str,
    framework: str,
    reason_hint: str,
    location,
    metadata: dict | None = None,
) -> MCPServer:
    return MCPServer(
        name=name,
        transport="reference",
        authenticated=None,
        location=location,
        metadata={
            "framework": framework,
            "reference_only": True,
            "reference_agent": agent.name,
            "context_binding": reason_hint,
            **(metadata or {}),
        },
    )


def resolve_imported_mcp_placeholders(graph: Graph, root: Path) -> None:
    """Bind imported MCP server objects only when the repository match is unique."""
    concrete = [
        server
        for server in graph.unbound_mcp_servers
        if not server.metadata.get("placeholder")
        and not server.metadata.get("reference_only")
    ]
    used: set[int] = set()
    unresolved: list[MCPServer] = []

    for agent in graph.agents:
        retained: list[MCPServer] = []
        for server in agent.mcp_servers:
            if not server.metadata.get("placeholder"):
                retained.append(server)
                continue

            import_module = server.metadata.get("import_module")
            matches = []
            if isinstance(import_module, str) and import_module:
                import_symbol = str(
                    server.metadata.get("import_symbol") or server.name
                )
                matches = [
                    candidate
                    for candidate in concrete
                    if (
                        candidate.name == server.name
                        or str(candidate.metadata.get("alias") or "")
                        == import_symbol
                    )
                    and candidate.location is not None
                    and _module_matches(candidate.location.path, root, import_module)
                ]

            if len(matches) == 1:
                source = matches[0]
                resolved = deepcopy(source)
                resolved.metadata = {
                    **resolved.metadata,
                    "repository_resolved": True,
                    "import_module": import_module,
                    "import_symbol": server.metadata.get("import_symbol"),
                    "local_alias": server.metadata.get("local_alias"),
                    "imported_binding": True,
                    "binding_origin": "repository_import_reference",
                }
                retained.append(resolved)
                used.add(id(source))
                continue

            if not isinstance(import_module, str) or not import_module:
                reason_hint = "unsupported_import_reference"
            elif len(matches) > 1:
                reason_hint = "ambiguous_imported_reference"
            else:
                reason_hint = "unresolved_imported_reference"

            unresolved.append(
                _unresolved_reference(
                    agent=agent,
                    name=server.name,
                    framework=str(server.metadata.get("framework") or "unknown"),
                    reason_hint=reason_hint,
                    location=server.location,
                    metadata={
                        "import_module": import_module,
                        "candidate_count": len(matches),
                        "candidate_declarations": [
                            {
                                "server": candidate.name,
                                "transport": candidate.transport,
                                "destination": candidate.url or candidate.command,
                                "location": (
                                    {
                                        "path": str(candidate.location.path),
                                        "line": candidate.location.line,
                                        "column": candidate.location.column,
                                    }
                                    if candidate.location is not None
                                    else None
                                ),
                            }
                            for candidate in matches
                        ],
                    },
                )
            )
        agent.mcp_servers = retained

    graph.unbound_mcp_servers = [
        server for server in graph.unbound_mcp_servers if id(server) not in used
    ]
    graph.unresolved_mcp_references.extend(unresolved)



def _fast_agent_scoped_matches(
    agent: Agent,
    matches: list[MCPServer],
) -> list[MCPServer]:
    if agent.location is None:
        return []
    agent_path = agent.location.path.resolve()
    scoped: list[tuple[int, MCPServer]] = []
    for server in matches:
        scope = server.metadata.get("config_scope")
        if not isinstance(scope, str) or not scope:
            continue
        scope_path = Path(scope)
        try:
            agent_path.relative_to(scope_path)
        except ValueError:
            continue
        scoped.append((len(scope_path.parts), server))
    if not scoped:
        return []
    max_depth = max(depth for depth, _ in scoped)
    return [server for depth, server in scoped if depth == max_depth]


def resolve_fast_agent_mcp_references(graph: Graph) -> None:
    """Bind FastAgent servers=[...] using nearest config scope or unique fallback."""
    concrete_by_name: dict[str, list[MCPServer]] = {}
    for server in graph.unbound_mcp_servers:
        if server.metadata.get("placeholder") or server.metadata.get("reference_only"):
            continue
        concrete_by_name.setdefault(server.name, []).append(server)

    used: set[int] = set()
    unresolved: list[MCPServer] = []
    for agent in graph.agents:
        if agent.metadata.get("framework") != "fast-agent":
            continue
        refs = agent.metadata.get("mcp_server_refs")
        if not isinstance(refs, list):
            refs = []

        tool_filters = agent.metadata.get("mcp_tool_filters")
        if not isinstance(tool_filters, dict):
            tool_filters = {}

        for ref in refs:
            if not isinstance(ref, str) or not ref:
                continue
            matches = concrete_by_name.get(ref, [])
            scoped = _fast_agent_scoped_matches(agent, matches)
            selected = scoped if scoped else matches
            if len(selected) != 1:
                unresolved.append(
                    _unresolved_reference(
                        agent=agent,
                        name=ref,
                        framework="fast-agent",
                        reason_hint=(
                            "ambiguous_fast_agent_reference"
                            if len(selected) > 1
                            else "missing_fast_agent_declaration"
                        ),
                        location=agent.location,
                        metadata={
                            "candidate_count": len(selected),
                            "candidate_declarations": [
                                {
                                    "server": candidate.name,
                                    "transport": candidate.transport,
                                    "destination": candidate.url or candidate.command,
                                    "location": (
                                        {
                                            "path": str(candidate.location.path),
                                            "line": candidate.location.line,
                                            "column": candidate.location.column,
                                        }
                                        if candidate.location is not None
                                        else None
                                    ),
                                }
                                for candidate in selected
                            ],
                        },
                    )
                )
                continue

            source = selected[0]
            resolved = deepcopy(source)
            configured_filter = tool_filters.get(ref)
            if isinstance(configured_filter, list) and all(
                isinstance(item, str) for item in configured_filter
            ):
                if resolved.allowed_tools:
                    configured = set(configured_filter)
                    resolved.allowed_tools = [
                        item
                        for item in resolved.allowed_tools
                        if item in configured
                    ]
                else:
                    resolved.allowed_tools = list(configured_filter)
                resolved.metadata["fast_agent_tool_filter"] = list(
                    configured_filter
                )

            resolved.metadata = {
                **resolved.metadata,
                "binding_origin": "fast_agent_servers_reference",
                "effective_agent": agent.name,
                "fast_agent_server_reference": ref,
                "repository_resolved": True,
            }
            agent.mcp_servers.append(resolved)
            used.add(id(source))

        if agent.metadata.get("dynamic_mcp_servers") is True:
            unresolved.append(
                _unresolved_reference(
                    agent=agent,
                    name="<dynamic>",
                    framework="fast-agent",
                    reason_hint="dynamic_server_selection",
                    location=agent.location,
                )
            )

    graph.unbound_mcp_servers = [
        server
        for server in graph.unbound_mcp_servers
        if id(server) not in used
    ]
    graph.unresolved_mcp_references.extend(unresolved)


def resolve_model_tool_loop_default_mcp_config(
    graph: Graph,
    root: Path,
) -> None:
    """Bind source-visible fallback MCP config to a proven custom model/tool loop.

    This is intentionally narrower than repository co-presence. A binding is
    created only when:
    - the agent is a source-proven model-tool-loop with dynamic MCP catalogue/
      dispatch semantics;
    - the fallback declaration is in the same source module;
    - the declaration is enabled by default and not gated by an enabled_env;
    - no checked-in default mcp_config.json overrides the fallback.

    The concrete stdio implementation is resolved in the normal
    resolve_local_stdio_implementations pass.
    """
    root = root.resolve()
    if (root / "mcp_config.json").exists():
        return

    candidates = [
        server
        for server in graph.unbound_mcp_servers
        if server.metadata.get("source") == "python_default_mcp_config"
        and server.metadata.get("default_configuration") is True
        and server.metadata.get("default_enabled") is True
        and not server.metadata.get("enabled_env")
        and server.location is not None
    ]
    if not candidates:
        return

    used: set[int] = set()
    for agent in graph.agents:
        if (
            agent.metadata.get("framework") != "model-tool-loop"
            or agent.metadata.get("dynamic_mcp_servers") is not True
            or agent.location is None
        ):
            continue

        same_module = [
            server
            for server in candidates
            if server.location is not None
            and server.location.path.resolve() == agent.location.path.resolve()
        ]
        if not same_module:
            continue

        retained = [
            server
            for server in agent.mcp_servers
            if server.name != "<dynamic-stdio-mcp>"
        ]
        for source in same_module:
            resolved = deepcopy(source)
            resolved.metadata = {
                **resolved.metadata,
                "repository_resolved": True,
                "binding_origin": "model_tool_loop_default_config",
                "effective_agent": agent.name,
                "context_binding": "bound",
            }
            retained.append(resolved)
            used.add(id(source))
        agent.mcp_servers = retained

    if used:
        graph.unbound_mcp_servers = [
            server
            for server in graph.unbound_mcp_servers
            if id(server) not in used
        ]


def _local_stdio_script_candidates(
    server: MCPServer,
    root: Path,
) -> set[Path]:
    """Return concrete in-repository Python scripts named by a stdio binding."""
    if server.transport != "stdio" or server.location is None:
        return set()

    candidates: set[Path] = set()
    for arg in server.args:
        if not isinstance(arg, str) or not arg or arg.startswith("-"):
            continue
        script = Path(arg)
        if script.suffix.lower() != ".py":
            continue
        if script.is_absolute():
            resolved = script.resolve()
            try:
                resolved.relative_to(root.resolve())
            except ValueError:
                continue
            candidates.add(resolved)
            continue
        candidates.add((server.location.path.parent / script).resolve())
        candidates.add((root / script).resolve())
    return candidates


def resolve_local_stdio_implementations(graph: Graph, root: Path) -> None:
    """Bind a local stdio client declaration to its in-repo MCP implementation.

    The binding is source-proven only when a bound stdio server names a concrete
    Python script and exactly one discovered in-repository MCP server with an
    exposed tool catalogue lives in that script. The client-side transport
    identity is retained while implementation capabilities are projected onto it.
    """
    root = root.resolve()
    implementations_by_path: dict[Path, list[MCPServer]] = {}
    for implementation in graph.unbound_mcp_servers:
        if (
            implementation.location is None
            or not isinstance(
                implementation.metadata.get("discovered_tools"),
                list,
            )
            or not implementation.metadata.get("discovered_tools")
            or implementation.metadata.get("source")
            not in {"FastMCP", "Server"}
        ):
            continue
        implementations_by_path.setdefault(
            implementation.location.path.resolve(),
            [],
        ).append(implementation)

    if not implementations_by_path:
        return

    used: set[int] = set()
    bound_implementation_tools: set[tuple[Path, str]] = set()

    for agent in graph.agents:
        for server in agent.mcp_servers:
            script_candidates = _local_stdio_script_candidates(server, root)
            if not script_candidates:
                continue
            matches = [
                implementation
                for candidate_path in script_candidates
                for implementation in implementations_by_path.get(
                    candidate_path,
                    [],
                )
            ]
            if len(matches) != 1:
                if len(matches) > 1:
                    server.metadata["local_stdio_resolution"] = "ambiguous"
                    server.metadata["local_stdio_candidate_count"] = len(matches)
                continue

            implementation = matches[0]
            discovered_tools = implementation.metadata.get("discovered_tools")
            discovered_capabilities = implementation.metadata.get(
                "discovered_tool_capabilities"
            )
            if not isinstance(discovered_tools, list) or not discovered_tools:
                continue

            if isinstance(discovered_capabilities, list):
                server.metadata["discovered_tool_capabilities"] = list(
                    discovered_capabilities
                )
            server.metadata["discovered_tools"] = deepcopy(discovered_tools)
            if implementation.metadata.get("shadowed_constructions"):
                server.metadata["shadowed_constructions"] = deepcopy(
                    implementation.metadata["shadowed_constructions"]
                )
            server.metadata.update(
                {
                    "repository_resolved": True,
                    "binding_origin": "local_stdio_script",
                    "implementation_name": implementation.name,
                    "implementation_path": implementation.location.path.resolve().as_posix(),
                    "implementation_line": implementation.location.line,
                    "implementation_framework": implementation.metadata.get("framework"),
                    "implementation_source": implementation.metadata.get("source"),
                }
            )
            if server.authenticated is None and implementation.authenticated is not None:
                server.authenticated = implementation.authenticated
            if server.approval is None and implementation.approval is not None:
                server.approval = implementation.approval
            server.guardrails = server.guardrails or implementation.guardrails
            for resource in implementation.resources:
                if resource not in server.resources:
                    server.resources.append(deepcopy(resource))
            used.add(id(implementation))
            implementation_alias = str(
                implementation.metadata.get("alias") or implementation.name
            )
            if implementation.location is not None and implementation_alias:
                bound_implementation_tools.add(
                    (implementation.location.path.resolve(), implementation_alias)
                )

    if used:
        graph.unbound_mcp_servers = [
            server
            for server in graph.unbound_mcp_servers
            if id(server) not in used
        ]
        graph.unbound_tools = [
            tool
            for tool in graph.unbound_tools
            if not (
                tool.location is not None
                and (
                    tool.location.path.resolve(),
                    str(tool.metadata.get("server") or ""),
                )
                in bound_implementation_tools
            )
        ]


def _authority_scope(server: MCPServer) -> str:
    if server.allowed_tools:
        return "explicit_allowlist"
    if server.denied_tools:
        return "denylist_only"
    if server.metadata.get("dynamic_tool_filter"):
        return "dynamic_filter"
    return "unrestricted_or_unknown"


def _provider(server: MCPServer) -> str:
    if server.url:
        hostname = urlparse(server.url).hostname or ""
        if hostname:
            return hostname
    return "mcp"


def reconstruct_mcp_context(graph: Graph) -> None:
    """Attach effective-agent, auth, tool-scope and destination context to MCP."""
    for server in graph.unbound_mcp_servers:
        server.metadata.setdefault("context_binding", "unbound")

    for agent in graph.agents:
        known_identity_names = {identity.name for identity in agent.identities}
        for server in agent.mcp_servers:
            server.metadata["context_binding"] = "bound"
            server.metadata["effective_agent"] = agent.name
            server.metadata["authority_scope"] = _authority_scope(server)
            server.metadata["tool_authority"] = {
                "allowed": list(server.allowed_tools),
                "denied": list(server.denied_tools),
            }
            server.metadata["destination"] = server.url or server.command
            server.metadata["auth_state"] = (
                "authenticated"
                if server.authenticated is True
                else "unauthenticated"
                if server.authenticated is False
                else "unknown"
            )

            credential_source = server.metadata.get("credential_source")
            if (
                isinstance(credential_source, str)
                and credential_source
                and server.identity is None
            ):
                identity_name = f"{agent.name}:{server.name}:mcp-auth"
                server.identity = identity_name
                if identity_name not in known_identity_names:
                    agent.identities.append(
                        Identity(
                            name=identity_name,
                            provider=_provider(server),
                            credential_source=credential_source,
                            location=server.location,
                            metadata={
                                "framework": server.metadata.get("framework"),
                                "source": "mcp_auth",
                                "mcp_server": server.name,
                                "effective_agent": agent.name,
                            },
                        )
                    )
                    known_identity_names.add(identity_name)
