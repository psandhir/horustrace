from __future__ import annotations

import re
from pathlib import Path

from horustrace.adapters.csharp_source import location, mask_non_code
from horustrace.models import Agent, Graph, Identity, InputSource

FRAMEWORK = "microsoft-365-agents-sdk-dotnet"

_ROUTE_RE = re.compile(
    r"\[(?P<route>"
    r"MessageRoute|MembersAddedRoute|"
    r"Teams[A-Za-z0-9_]*Route"
    r")(?P<args>[^\]]*)\]"
)

_CLASS_RE = re.compile(
    r"\bclass\s+(?P<class>[A-Za-z_]\w*)"
    r"(?P<header>[^\{;]*?)"
    r":\s*AgentApplication\b",
    re.DOTALL,
)

_CLASS_MODIFIERS = {
    "public",
    "internal",
    "private",
    "protected",
    "sealed",
    "partial",
    "abstract",
    "static",
}


def is_microsoft_365_agents_dotnet_file(path: Path) -> bool:
    if path.suffix.lower() != ".cs":
        return False
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return (
        "Microsoft.Agents." in source
        and (
            "AgentApplication" in source
            or ".AddAgent<" in source
            or ".AddAgent(" in source
            or "MapDefaultAgentEndpoints" in source
        )
    )


def _leading_agent_attribute(
    source: str,
    masked: str,
    class_start: int,
) -> str:
    """Return a directly attached [Agent(...)] attribute without nested regexes."""
    window_start = max(0, class_start - 2048)
    masked_prefix = masked[window_start:class_start]
    original_prefix = source[window_start:class_start]
    search_end = len(masked_prefix)

    while True:
        start = masked_prefix.rfind("[Agent", 0, search_end)
        if start < 0:
            return ""
        end = masked_prefix.find("]", start + len("[Agent"))
        if end < 0:
            search_end = start
            continue

        tail = masked_prefix[end + 1:]
        tokens = tail.split()
        if all(token in _CLASS_MODIFIERS for token in tokens):
            return original_prefix[start:end + 1]
        search_end = start


def _declared_agent_name(attrs: str, class_name: str) -> str:
    match = re.search(
        r"\[Agent\s*\([^\]]*?\bname\s*:\s*\"([^\"]+)\"",
        attrs,
        re.DOTALL,
    )
    return match.group(1) if match else class_name


def _route_input(
    path: Path,
    source: str,
    route: str,
    args: str,
    offset: int,
) -> InputSource:
    teams = route.startswith("Teams")
    message = "Message" in route
    agentic_only = bool(
        re.search(r"\bisAgenticOnly\s*:\s*true\b", args, re.IGNORECASE)
    )
    handler = re.search(
        r"\bautoSignInHandlers\s*:\s*\"([^\"]+)\"",
        args,
    )
    return InputSource(
        name=f"{route}:activity",
        trust="untrusted",
        kind="teams" if teams else "m365_activity",
        location=location(path, source, offset),
        metadata={
            "framework": FRAMEWORK,
            "basis": "m365_agents_route_attribute",
            "route_attribute": route,
            "message_route": message,
            "teams_channel": teams,
            "runtime_ingress": True,
            "agentic_only": agentic_only,
            "auto_sign_in_handler": handler.group(1) if handler else None,
            "content_trust": "untrusted",
        },
    )


def _turn_identity(path: Path, source: str, offset: int) -> Identity:
    return Identity(
        name="signed-in-turn-user",
        provider="microsoft-entra",
        credential_source="m365-turn-context",
        location=location(path, source, offset),
        metadata={
            "framework": FRAMEWORK,
            "identity_type": "delegated_user",
            "permission_model": "delegated",
            "token_subject": "signed_in_user",
            "runtime_resolved": True,
        },
    )


def _class_agents(path: Path, source: str) -> list[Agent]:
    result: list[Agent] = []
    masked = mask_non_code(source)
    for match in _CLASS_RE.finditer(masked):
        attrs = _leading_agent_attribute(
            source,
            masked,
            match.start(),
        )
        class_name = match.group("class")
        name = _declared_agent_name(attrs, class_name)

        # Limit route/authorization evidence to this class body when possible.
        body_start = masked.find("{", match.end() - 1)
        if body_start < 0:
            body_end = len(source)
        else:
            depth = 0
            body_end = len(source)
            for index in range(body_start, len(masked)):
                if masked[index] == "{":
                    depth += 1
                elif masked[index] == "}":
                    depth -= 1
                    if depth == 0:
                        body_end = index + 1
                        break
        class_source = source[match.start():body_end]

        agent = Agent(
            name=name,
            location=location(path, source, match.start()),
            metadata={
                "framework": FRAMEWORK,
                "language": "csharp",
                "agent_type": "AgentApplication",
                "class_name": class_name,
                "source_aliases": [class_name],
                "channel_runtime": True,
            },
        )

        for route_match in _ROUTE_RE.finditer(class_source):
            agent.inputs.append(_route_input(
                path,
                source,
                route_match.group("route"),
                route_match.group("args") or "",
                match.start() + route_match.start(),
            ))

        if (
            "GetTurnTokenAsync" in class_source
            or "ExchangeTurnTokenAsync" in class_source
            or "UserAuthorization" in class_source
        ):
            agent.identities.append(_turn_identity(
                path,
                source,
                match.start()
                + max(
                    class_source.find("GetTurnTokenAsync"),
                    class_source.find("ExchangeTurnTokenAsync"),
                    class_source.find("UserAuthorization"),
                    0,
                ),
            ))
            agent.metadata["turn_user_authorization"] = True

        result.append(agent)
    return result


def _hosting_agents(path: Path, source: str) -> list[Agent]:
    result: list[Agent] = []
    authenticated = (
        "AddAgentAuthorization" in source
        and "AddAgentAspNetAuthentication" in source
        and "UseAgents()" in source
    )
    endpoints = "MapDefaultAgentEndpoints" in source

    registered: list[tuple[str, int]] = []
    for match in re.finditer(
        r"\.AddAgent\s*<\s*([A-Za-z_]\w*)\s*>\s*\(",
        source,
    ):
        registered.append((match.group(1), match.start()))

    # Factory registrations are first-class agent containers even when there is
    # no named AgentApplication subclass in the same file.
    if (
        not registered
        and re.search(r"\.AddAgent\s*\(", source)
        and "new AgentApplication" in source
    ):
        registered.append((f"{path.stem}:AgentApplication", source.find(".AddAgent(")))

    for name, offset in registered:
        agent = Agent(
            name=name,
            location=location(path, source, offset),
            metadata={
                "framework": FRAMEWORK,
                "language": "csharp",
                "agent_type": "HostedAgentApplication",
                "hosting_registration": True,
                "source_aliases": [name],
                "default_endpoints_mapped": endpoints,
                "authentication_configured": authenticated,
                "authorization_middleware": "UseAgents()" in source,
            },
        )
        if endpoints:
            agent.inputs.append(InputSource(
                name="m365-agent-default-message-endpoint",
                trust="untrusted",
                kind="m365_activity",
                location=location(
                    path,
                    source,
                    source.find("MapDefaultAgentEndpoints"),
                ),
                metadata={
                    "framework": FRAMEWORK,
                    "basis": "MapDefaultAgentEndpoints",
                    "runtime_ingress": True,
                    "authenticated": authenticated,
                    "authentication_basis": (
                        "AddAgentAuthorization+AddAgentAspNetAuthentication+UseAgents"
                        if authenticated else "not_source_proven"
                    ),
                    "content_trust": "untrusted",
                },
            ))

        if ".OnMessage(" in source or ".AddRoute(" in source:
            agent.inputs.append(InputSource(
                name="programmatic-agent-route",
                trust="untrusted",
                kind="m365_activity",
                location=location(
                    path,
                    source,
                    max(source.find(".OnMessage("), source.find(".AddRoute("), 0),
                ),
                metadata={
                    "framework": FRAMEWORK,
                    "basis": "AgentApplication_programmatic_route",
                    "runtime_ingress": True,
                    "authenticated": authenticated,
                    "content_trust": "untrusted",
                },
            ))

        if (
            "GetTurnTokenAsync" in source
            or "ExchangeTurnTokenAsync" in source
            or "UserAuthorization" in source
        ):
            agent.identities.append(_turn_identity(path, source, offset))
            agent.metadata["turn_user_authorization"] = True

        result.append(agent)
    return result


def scan_microsoft_365_agents_dotnet_file(path: Path) -> Graph:
    graph = Graph()
    if not is_microsoft_365_agents_dotnet_file(path):
        return graph
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return graph

    graph.agents.extend(_class_agents(path, source))
    graph.agents.extend(_hosting_agents(path, source))
    return graph
