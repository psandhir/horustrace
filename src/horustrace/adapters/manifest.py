from __future__ import annotations

from pathlib import Path

import yaml

from horustrace.heuristics import infer_capabilities
from horustrace.models import (
    Agent,
    AgentPolicy,
    AuthorityContract,
    AuthorityScope,
    DataSource,
    Graph,
    Identity,
    InputSource,
    MCPServer,
    MCPToolContract,
    NetworkDestination,
    ResourceScope,
    SourceLocation,
    Tool,
)

MANIFEST_FILENAMES = {"horustrace.manifest.yaml", "horustrace.manifest.yml"}


class ManifestError(ValueError):
    """A policy manifest could not be read or interpreted safely."""


class _ManifestLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in keys
                keys.add(key)
            except TypeError as exc:
                raise yaml.YAMLError("invalid mapping key") from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None, None, "duplicate mapping key", key_node.start_mark,
                )
        return super().construct_mapping(node, deep=deep)


def _manifest_positions(path: Path, text: str) -> dict[str, object]:
    positions: dict[str, object] = {}

    def visit(node, field="document", ancestors=frozenset()):
        if id(node) in ancestors:
            raise ManifestError(f"{path}: invalid manifest: cyclic YAML aliases are unsupported")
        ancestors = ancestors | {id(node)}
        positions[field] = node.start_mark
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                child = key.value if field == "document" else f"{field}.{key.value}"
                visit(value, child, ancestors)
        elif isinstance(node, yaml.SequenceNode):
            for index, value in enumerate(node.value):
                visit(value, f"{field}[{index}]", ancestors)

    node = yaml.compose(text, Loader=_ManifestLoader)
    if node is not None:
        visit(node)
    return positions


def _source_location(
    path: Path,
    positions: dict[str, object],
    field: str,
) -> SourceLocation | None:
    mark = positions.get(field)
    if mark is None:
        return None
    return SourceLocation(
        path=path,
        line=mark.line + 1,
        column=mark.column + 1,
    )


def _validate_manifest(
    raw: object,
    path: Path,
    text: str,
) -> dict[str, object]:
    from horustrace.manifest_schema import validate

    positions = _manifest_positions(path, text)

    def fail(field, message):
        mark = positions.get(field)
        position = f":{mark.line + 1}:{mark.column + 1}" if mark else ""
        raise ManifestError(f"{path}{position}: invalid manifest: {field} {message}")

    validate(raw, fail)
    return positions


def _strings(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _identity(raw: dict, path: Path) -> Identity:
    return Identity(
        name=str(raw.get("name") or raw.get("service_account") or raw.get("principal") or "identity"),
        provider=str(raw.get("provider") or "generic").lower(),
        roles=set(_strings(raw.get("roles"))),
        permissions=set(_strings(raw.get("permissions"))),
        oauth_scopes=set(_strings(raw.get("oauth_scopes") or raw.get("scopes"))),
        resource_scope=str(raw.get("resource_scope")) if raw.get("resource_scope") is not None else None,
        credential_source=str(raw.get("credential_source")) if raw.get("credential_source") else None,
        location=SourceLocation(path=path),
        metadata={k: v for k, v in raw.items() if k not in {"roles", "permissions", "oauth_scopes", "scopes"}},
    )


def _authority_scope(raw: object) -> AuthorityScope:
    if not isinstance(raw, dict):
        return AuthorityScope()
    return AuthorityScope(
        capabilities=set(_strings(raw.get("capabilities"))),
        identities=set(_strings(raw.get("identities"))),
        resources=set(_strings(raw.get("resources"))),
        destinations=set(_strings(raw.get("destinations"))),
        iam_roles=set(_strings(raw.get("iam_roles"))),
        permissions=set(_strings(raw.get("permissions"))),
        oauth_scopes=set(_strings(raw.get("oauth_scopes"))),
        mcp_servers=set(_strings(raw.get("mcp_servers"))),
        skills=set(_strings(raw.get("skills"))),
    )


def _authority_contract(
    raw: object,
    path: Path,
    positions: dict[str, object],
    field_prefix: str,
) -> AuthorityContract | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        return None

    clause_locations: dict[str, SourceLocation] = {}
    for mode in ("allow", "deny"):
        scope = raw.get(mode)
        if not isinstance(scope, dict):
            continue
        for dimension in (
            "capabilities",
            "identities",
            "resources",
            "destinations",
            "iam_roles",
            "permissions",
            "oauth_scopes",
            "mcp_servers",
            "skills",
        ):
            if dimension not in scope:
                continue
            location = _source_location(
                path,
                positions,
                f"{field_prefix}.{mode}.{dimension}",
            )
            if location is not None:
                clause_locations[f"{mode}.{dimension}"] = location

    if "require_approval_for" in raw:
        location = _source_location(
            path,
            positions,
            f"{field_prefix}.require_approval_for",
        )
        if location is not None:
            clause_locations["require_approval_for"] = location

    mcp_tools = []
    for index, item in enumerate(raw.get("mcp_tools", []) or []):
        if not isinstance(item, dict):
            continue
        server = str(item.get("server"))
        mcp_tools.append(
            MCPToolContract(
                server=server,
                allowed_tools=set(_strings(item.get("allow"))),
                denied_tools=set(_strings(item.get("deny"))),
            )
        )
        for mode in ("allow", "deny"):
            if mode not in item:
                continue
            location = _source_location(
                path,
                positions,
                f"{field_prefix}.mcp_tools[{index}].{mode}",
            )
            if location is not None:
                clause_locations[f"mcp_tools.{server}.{mode}"] = location

    return AuthorityContract(
        allow=_authority_scope(raw.get("allow")),
        deny=_authority_scope(raw.get("deny")),
        require_approval_for=set(_strings(raw.get("require_approval_for"))),
        mcp_tools=sorted(mcp_tools, key=lambda item: item.server),
        location=(
            _source_location(path, positions, field_prefix)
            or SourceLocation(path=path)
        ),
        clause_locations=clause_locations,
    )


def scan_manifest(path: Path) -> Graph:
    graph = Graph()
    try:
        text = path.read_text(encoding="utf-8")
        raw = yaml.load(text, Loader=_ManifestLoader)
    except yaml.YAMLError as exc:
        # Parser exception text can include manifest contents, including secrets.
        mark = getattr(exc, "problem_mark", None)
        position = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ManifestError(f"{path}: invalid manifest YAML{position}") from exc
    except UnicodeDecodeError as exc:
        raise ManifestError(f"{path}: manifest is not valid UTF-8") from exc
    except OSError as exc:
        raise ManifestError(f"{path}: cannot read manifest") from exc
    positions = _validate_manifest(raw, path, text)

    for raw_identity in raw.get("identities", []) or []:
        if isinstance(raw_identity, dict):
            graph.identities.append(_identity(raw_identity, path))

    agent_items = raw.get("agents")
    agent_prefixes: list[str] = []
    if not agent_items and raw.get("agent"):
        agent_items = [raw.get("agent")]
        agent_prefixes = ["agent"]
    elif isinstance(agent_items, list):
        agent_prefixes = [
            f"agents[{index}]"
            for index in range(len(agent_items))
        ]
    if not isinstance(agent_items, list):
        return graph

    for item, agent_prefix in zip(agent_items, agent_prefixes, strict=True):
        if not isinstance(item, dict):
            continue
        agent = Agent(name=str(item.get("name") or "unnamed-agent"), location=SourceLocation(path=path))
        deployment = item.get("deployment")
        if isinstance(deployment, dict):
            workload_id = deployment.get("workload_id")
            deployment_name = deployment.get("name")
            if isinstance(workload_id, str) and workload_id.strip():
                agent.metadata["workload_id"] = workload_id.strip()
            if isinstance(deployment_name, str) and deployment_name.strip():
                agent.metadata["deployment_name"] = deployment_name.strip()
            agent.metadata["deployment_binding"] = {
                "source": "manifest",
                "workload_id": agent.metadata.get("workload_id"),
                "name": agent.metadata.get("deployment_name"),
            }

        for source in item.get("data", []) or []:
            if isinstance(source, str):
                agent.data_sources.append(DataSource(name=source, location=SourceLocation(path=path)))
            elif isinstance(source, dict):
                agent.data_sources.append(
                    DataSource(
                        name=str(source.get("name") or source.get("source") or "data-source"),
                        classification=str(source.get("classification") or "internal").lower(),
                        capability=str(source.get("capability") or "data.read"),
                        selector=str(source.get("selector") or source.get("path") or source.get("resource") or source.get("name") or "data-source"),
                        location=SourceLocation(path=path),
                    )
                )

        for raw_input in item.get("inputs", []) or []:
            if isinstance(raw_input, str):
                agent.inputs.append(InputSource(name=raw_input, location=SourceLocation(path=path)))
            elif isinstance(raw_input, dict):
                agent.inputs.append(
                    InputSource(
                        name=str(raw_input.get("name") or raw_input.get("source") or "input"),
                        trust=str(raw_input.get("trust") or "trusted").lower(),
                        kind=str(raw_input.get("kind") or "user").lower(),
                        location=SourceLocation(path=path),
                    )
                )

        for raw_identity in item.get("identities", []) or []:
            if isinstance(raw_identity, dict):
                agent.identities.append(_identity(raw_identity, path))
            elif isinstance(raw_identity, str):
                linked = next((i for i in graph.identities if i.name == raw_identity), None)
                if linked:
                    agent.identities.append(linked)
                else:
                    agent.identities.append(Identity(name=raw_identity, location=SourceLocation(path=path)))

        for raw_network in item.get("network", []) or []:
            if isinstance(raw_network, str):
                agent.network.append(NetworkDestination(target=raw_network, restricted=raw_network not in {"*", "internet", "all"}, location=SourceLocation(path=path)))
            elif isinstance(raw_network, dict):
                target = str(raw_network.get("target") or raw_network.get("destination") or raw_network.get("host") or "*")
                agent.network.append(
                    NetworkDestination(
                        target=target,
                        direction=str(raw_network.get("direction") or "outbound"),
                        restricted=bool(raw_network.get("restricted", target not in {"*", "internet", "all"})),
                        location=SourceLocation(path=path),
                    )
                )

        for raw_tool in item.get("tools", []) or []:
            if not isinstance(raw_tool, dict):
                continue
            name = str(raw_tool.get("name") or "tool")
            caps = raw_tool.get("capabilities") or raw_tool.get("capability") or []
            if isinstance(caps, str):
                caps = [caps]
            capabilities = {str(cap) for cap in caps} or infer_capabilities(name)
            approval = raw_tool.get("approval")
            if approval is None:
                approval = raw_tool.get("human_approval")
            if not isinstance(approval, bool):
                approval = None
            tool = Tool(
                name=name,
                kind=str(raw_tool.get("kind") or "generic"),
                capabilities=capabilities,
                approval=approval,
                guardrails=bool(raw_tool.get("guardrails", False)),
                identity=str(raw_tool.get("identity")) if raw_tool.get("identity") else None,
                location=SourceLocation(path=path),
                metadata={"capability_origin": "declared" if caps else "inferred"},
            )
            for raw_resource in raw_tool.get("resources", []) or []:
                if isinstance(raw_resource, str):
                    tool.resources.append(ResourceScope(kind="generic", selector=raw_resource, location=SourceLocation(path=path)))
                elif isinstance(raw_resource, dict):
                    tool.resources.append(
                        ResourceScope(
                            kind=str(raw_resource.get("kind") or "generic"),
                            selector=str(raw_resource.get("selector") or raw_resource.get("path") or raw_resource.get("resource") or "*"),
                            access=set(_strings(raw_resource.get("access"))),
                            classification=str(raw_resource.get("classification") or "internal").lower(),
                            location=SourceLocation(path=path),
                        )
                    )
            for destination in _strings(raw_tool.get("destinations") or raw_tool.get("destination")):
                tool.destinations.append(
                    NetworkDestination(
                        target=destination,
                        restricted=destination not in {"*", "internet", "all"},
                        location=SourceLocation(path=path),
                    )
                )
            agent.tools.append(tool)

        for raw_server in item.get("mcp_servers", []) or []:
            if not isinstance(raw_server, dict):
                continue
            agent.mcp_servers.append(
                MCPServer(
                    name=str(raw_server.get("name") or "mcp"),
                    transport=str(raw_server.get("transport") or "unknown"),
                    url=raw_server.get("url"),
                    command=raw_server.get("command"),
                    args=[str(x) for x in (raw_server.get("args") or [])],
                    authenticated=raw_server.get("authenticated") if isinstance(raw_server.get("authenticated"), bool) else None,
                    approval=raw_server.get("approval") if isinstance(raw_server.get("approval"), bool) else None,
                    guardrails=bool(raw_server.get("guardrails", False)),
                    allowed_tools=_strings(raw_server.get("allowed_tools")),
                    denied_tools=_strings(raw_server.get("denied_tools")),
                    identity=str(raw_server.get("identity")) if raw_server.get("identity") else None,
                    location=SourceLocation(path=path),
                )
            )

        policy_raw = item.get("policy") or item.get("permissions") or {}
        if isinstance(policy_raw, dict):
            agent.policy = AgentPolicy(
                required_capabilities=set(_strings(policy_raw.get("required") or policy_raw.get("required_capabilities"))),
                denied_capabilities=set(_strings(policy_raw.get("deny") or policy_raw.get("denied_capabilities"))),
                required_skills=set(_strings(policy_raw.get("required_skills"))),
                allowed_skills=set(_strings(policy_raw.get("allowed_skills"))),
                denied_skills=set(_strings(policy_raw.get("denied_skills"))),
                allowed_resources=_strings(policy_raw.get("allowed_resources") or policy_raw.get("resources")),
                allowed_destinations=_strings(policy_raw.get("allowed_destinations") or policy_raw.get("destinations")),
                require_approval_for=set(_strings(policy_raw.get("require_approval_for"))),
                max_privileged_capabilities=int(policy_raw["max_privileged_capabilities"])
                if isinstance(policy_raw.get("max_privileged_capabilities"), int)
                else None,
                authority=_authority_contract(
                    policy_raw.get("authority"),
                    path,
                    positions,
                    f"{agent_prefix}.policy.authority",
                ),
            )
        graph.agents.append(agent)

    return graph
