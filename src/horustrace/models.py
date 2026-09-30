from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown severity: {value}") from exc

    def label(self) -> str:
        return self.name.lower()


class Confidence(str, Enum):
    POTENTIAL = "potential"
    SUPPORTED = "supported"
    AUTHORITY_CONFIRMED = "authority_confirmed"
    RUNTIME_VERIFIED = "runtime_verified"


class FlowExecutionContext(str, Enum):
    AGENT_TOOL = "agent_tool"
    CLI = "cli"
    TEST = "test"
    EXAMPLE = "example"
    TUTORIAL = "tutorial"
    NOTEBOOK = "notebook"
    TEMPLATE_GENERATED = "template-generated"
    APPLICATION_SUPPORT = "application_support"
    RUNTIME = "runtime"
    UNKNOWN = "unknown"


class AgentReachability(str, Enum):
    PROVEN_AGENT_REACHABLE = "proven_agent_reachable"
    PROVEN_NON_AGENT = "proven_non_agent"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class SourceLocation:
    path: Path
    line: int = 1
    column: int = 1


@dataclass(slots=True)
class EvidenceFact:
    subject: str
    fact: str
    origin: str
    location: SourceLocation | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "fact": self.fact, "origin": self.origin,
                "location": ({"path": str(self.location.path), "line": self.location.line,
                              "column": self.location.column} if self.location else None)}


@dataclass(slots=True)
class ResourceScope:
    kind: str
    selector: str
    access: set[str] = field(default_factory=set)
    classification: str = "internal"
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: list[EvidenceFact] = field(default_factory=list)



@dataclass(slots=True)
class NetworkDestination:
    target: str
    direction: str = "outbound"
    restricted: bool = True
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: list[EvidenceFact] = field(default_factory=list)



@dataclass(slots=True)
class InputSource:
    name: str
    trust: str = "trusted"
    kind: str = "user"
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: list[EvidenceFact] = field(default_factory=list)



@dataclass(slots=True)
class Identity:
    name: str
    provider: str = "generic"
    roles: set[str] = field(default_factory=set)
    permissions: set[str] = field(default_factory=set)
    oauth_scopes: set[str] = field(default_factory=set)
    resource_scope: str | None = None
    credential_source: str | None = None
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    provenance: list[EvidenceFact] = field(default_factory=list)

    @property
    def effective_permissions(self) -> set[str]:
        return set(self.permissions) | {f"role:{role}" for role in self.roles} | {
            f"oauth:{scope}" for scope in self.oauth_scopes
        }


@dataclass(slots=True)
class Tool:
    name: str
    kind: str
    capabilities: set[str] = field(default_factory=set)
    approval: bool | None = None
    guardrails: bool = False
    resources: list[ResourceScope] = field(default_factory=list)
    destinations: list[NetworkDestination] = field(default_factory=list)
    identity: str | None = None
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: list[EvidenceFact] = field(default_factory=list)



@dataclass(slots=True)
class MCPServer:
    name: str
    transport: str
    url: str | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    authenticated: bool | None = None
    approval: bool | None = None
    guardrails: bool = False
    allowed_tools: list[str] = field(default_factory=list)
    denied_tools: list[str] = field(default_factory=list)
    resources: list[ResourceScope] = field(default_factory=list)
    identity: str | None = None
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: list[EvidenceFact] = field(default_factory=list)



@dataclass(slots=True)
class DataSource:
    name: str
    classification: str = "internal"
    capability: str = "data.read"
    selector: str | None = None
    location: SourceLocation | None = None
    provenance: list[EvidenceFact] = field(default_factory=list)



@dataclass(slots=True)
class AuthorityScope:
    capabilities: set[str] = field(default_factory=set)
    identities: set[str] = field(default_factory=set)
    resources: set[str] = field(default_factory=set)
    destinations: set[str] = field(default_factory=set)
    iam_roles: set[str] = field(default_factory=set)
    permissions: set[str] = field(default_factory=set)
    oauth_scopes: set[str] = field(default_factory=set)
    mcp_servers: set[str] = field(default_factory=set)

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "capabilities": sorted(self.capabilities),
            "identities": sorted(self.identities),
            "resources": sorted(self.resources),
            "destinations": sorted(self.destinations),
            "iam_roles": sorted(self.iam_roles),
            "permissions": sorted(self.permissions),
            "oauth_scopes": sorted(self.oauth_scopes),
            "mcp_servers": sorted(self.mcp_servers),
        }


@dataclass(slots=True)
class MCPToolContract:
    server: str
    allowed_tools: set[str] = field(default_factory=set)
    denied_tools: set[str] = field(default_factory=set)

    def as_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "allow": sorted(self.allowed_tools),
            "deny": sorted(self.denied_tools),
        }


@dataclass(slots=True)
class AuthorityContract:
    allow: AuthorityScope = field(default_factory=AuthorityScope)
    deny: AuthorityScope = field(default_factory=AuthorityScope)
    require_approval_for: set[str] = field(default_factory=set)
    mcp_tools: list[MCPToolContract] = field(default_factory=list)
    location: SourceLocation | None = None
    clause_locations: dict[str, SourceLocation] = field(default_factory=dict)
    schema_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "allow": self.allow.as_dict(),
            "deny": self.deny.as_dict(),
            "require_approval_for": sorted(self.require_approval_for),
            "mcp_tools": [
                item.as_dict()
                for item in sorted(self.mcp_tools, key=lambda item: item.server)
            ],
            "location": (
                {
                    "path": str(self.location.path),
                    "line": self.location.line,
                    "column": self.location.column,
                }
                if self.location
                else None
            ),
            "clause_locations": {
                key: {
                    "path": str(value.path),
                    "line": value.line,
                    "column": value.column,
                }
                for key, value in sorted(self.clause_locations.items())
            },
        }


@dataclass(slots=True)
class AgentPolicy:
    required_capabilities: set[str] = field(default_factory=set)
    denied_capabilities: set[str] = field(default_factory=set)
    allowed_resources: list[str] = field(default_factory=list)
    allowed_destinations: list[str] = field(default_factory=list)
    require_approval_for: set[str] = field(default_factory=set)
    max_privileged_capabilities: int | None = None
    provenance: list[EvidenceFact] = field(default_factory=list)
    authority: AuthorityContract | None = None



@dataclass(slots=True)
class Agent:
    name: str
    tools: list[Tool] = field(default_factory=list)
    mcp_servers: list[MCPServer] = field(default_factory=list)
    data_sources: list[DataSource] = field(default_factory=list)
    inputs: list[InputSource] = field(default_factory=list)
    identities: list[Identity] = field(default_factory=list)
    network: list[NetworkDestination] = field(default_factory=list)
    policy: AgentPolicy = field(default_factory=AgentPolicy)
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    provenance: list[EvidenceFact] = field(default_factory=list)

    @property
    def capabilities(self) -> set[str]:
        result: set[str] = set()
        for tool in self.tools:
            result.update(tool.capabilities)
        for source in self.data_sources:
            result.add(source.capability)
        for server in self.mcp_servers:
            result.add("mcp.remote" if server.url else "mcp.local")
            if server.url:
                result.add("network.external")
        return result

    @property
    def effective_resources(self) -> list[ResourceScope]:
        resources: list[ResourceScope] = []
        resources.extend(
            ResourceScope(
                kind="data",
                selector=source.selector or source.name,
                access={source.capability},
                classification=source.classification,
                location=source.location, provenance=list(source.provenance),
            )
            for source in self.data_sources
        )
        for tool in self.tools:
            resources.extend(tool.resources)
        for server in self.mcp_servers:
            resources.extend(server.resources)
        return resources

    @property
    def sensitive_data_sources(self) -> list[DataSource]:
        """Sensitive data reachable directly or through tool/delegated resources."""
        from horustrace.heuristics import SENSITIVE_CLASSES

        sources = [d for d in self.data_sources if d.classification in SENSITIVE_CLASSES]
        for tool in self.tools:
            for resource in tool.resources:
                access = resource.access or tool.capabilities
                if resource.classification not in SENSITIVE_CLASSES:
                    continue
                if not {"data.read", "secrets.read"} & access:
                    continue
                source = DataSource(
                    name=resource.selector, classification=resource.classification,
                    selector=resource.selector, location=resource.location,
                    provenance=list(resource.provenance),
                )
                if source not in sources:
                    sources.append(source)
        return sources

    @property
    def effective_destinations(self) -> list[NetworkDestination]:
        destinations = list(self.network)
        for tool in self.tools:
            destinations.extend(tool.destinations)
        for server in self.mcp_servers:
            if server.url:
                destinations.append(
                    NetworkDestination(
                        target=server.url,
                        direction="outbound",
                        restricted=True,
                        location=server.location,
                        metadata={"source": "mcp"}, provenance=list(server.provenance),
                    )
                )
            elif (
                server.metadata.get("dynamic_mcp_endpoint_basis")
                == "operator_configuration"
            ):
                destinations.append(
                    NetworkDestination(
                        target="<operator-configured-mcp>",
                        direction="outbound",
                        restricted=True,
                        location=server.location,
                        metadata={
                            "source": "operator_configuration",
                            "network_scope": "operator_configured_destination",
                            "configuration_source": server.metadata.get(
                                "configuration_source"
                            ),
                        },
                        provenance=list(server.provenance),
                    )
                )
        return destinations


@dataclass(slots=True)
class FlowStep:
    kind: str
    label: str
    location: SourceLocation | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "location": (
                {
                    "path": str(self.location.path),
                    "line": self.location.line,
                    "column": self.location.column,
                }
                if self.location
                else None
            ),
        }


@dataclass(slots=True)
class FlowPath:
    flow_id: str
    source_kind: str
    sink_kind: str
    source_label: str
    sink_label: str
    steps: list[FlowStep]
    agent: str | None = None
    basis: str = "static_dataflow"
    confidence: Confidence = Confidence.SUPPORTED
    metadata: dict[str, Any] = field(default_factory=dict)
    execution_context: FlowExecutionContext = FlowExecutionContext.UNKNOWN
    agent_reachability: AgentReachability = AgentReachability.UNKNOWN

    @property
    def nodes(self) -> list[str]:
        return [step.label for step in self.steps]

    def as_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "source_kind": self.source_kind,
            "sink_kind": self.sink_kind,
            "source_label": self.source_label,
            "sink_label": self.sink_label,
            "agent": self.agent,
            "basis": self.basis,
            "confidence": self.confidence.value,
            "execution_context": self.execution_context.value,
            "agent_reachability": self.agent_reachability.value,
            "steps": [step.as_dict() for step in self.steps],
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class AttackPath:
    path_id: str
    title: str
    agent: str
    nodes: list[str]
    severity: Severity
    rationale: str
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanDiagnostic:
    code: str
    message: str
    location: SourceLocation | None = None
    diagnostic_id: str | None = None
    kind: str | None = None
    incomplete: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        mapping = {
            "parse_error": "ARG-COV-001",
            "unresolved_tool": "ARG-COV-002",
            "unresolved_delegation": "ARG-COV-003",
            "dynamic_configuration": "ARG-COV-004",
            "dynamic_mcp_endpoint": "ARG-COV-005",
            "dynamic_tool_filter": "ARG-COV-006",
            "unsupported_security_construct": "ARG-COV-007",
            "external_helper_semantics_unresolved": "ARG-COV-008",
            "no_targets": "ARG-COV-009",
            "authentication_unknown": "ARG-COV-010",
            "unresolved_call": "ARG-COV-011",
            "unresolved_dataflow": "ARG-COV-012",
            "dynamic_memory_target": "ARG-COV-013",
            "unresolved_handoff": "ARG-COV-014",
            "framework_not_normalized": "ARG-COV-015",
            "notebook_non_python_cell": "ARG-COV-016",
            "templated_source": "ARG-COV-017",
            "source_fragment": "ARG-COV-018",
            "unreadable_path": "ARG-COV-019",
        }
        self.kind = self.kind or self.code
        self.diagnostic_id = self.diagnostic_id or mapping.get(self.kind, "ARG-COV-007")

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "diagnostic_id": self.diagnostic_id, "kind": self.kind,
                "incomplete": self.incomplete, "message": self.message,
                "details": self.details, "location": (
            {"path": str(self.location.path), "line": self.location.line,
             "column": self.location.column} if self.location else None
        )}


@dataclass(slots=True)
class ScanCoverage:
    files_considered: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    diagnostics: list[ScanDiagnostic] = field(default_factory=list)
    resolution: dict[str, Any] = field(default_factory=dict)

    @property
    def incomplete(self) -> bool:
        return any(diagnostic.incomplete for diagnostic in self.diagnostics)

    def as_dict(self) -> dict[str, Any]:
        return {"files_considered": self.files_considered, "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped, "files_failed": self.files_failed,
                "incomplete": self.incomplete,
                "resolution": self.resolution,
                "diagnostics": [d.as_dict() for d in self.diagnostics]}


@dataclass(slots=True)
class WorkflowNode:
    """Non-principal workflow topology entity.

    Workflow nodes describe graph execution structure without implying autonomous
    agent authority. Adapters may classify their semantic role while security rules
    continue to operate on Graph.agents and their explicitly bound capabilities.
    """

    name: str
    role: str = "unknown"
    framework: str = "generic"
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: list[EvidenceFact] = field(default_factory=list)


@dataclass(slots=True)
class Graph:
    coverage: ScanCoverage = field(default_factory=ScanCoverage)
    agents: list[Agent] = field(default_factory=list)
    unbound_tools: list[Tool] = field(default_factory=list)
    unbound_mcp_servers: list[MCPServer] = field(default_factory=list)
    unresolved_mcp_references: list[MCPServer] = field(default_factory=list)
    identities: list[Identity] = field(default_factory=list)
    flow_paths: list[FlowPath] = field(default_factory=list)
    adg: Any | None = None
    attack_paths: list[AttackPath] = field(default_factory=list)
    suppressed_findings: list[Any] = field(default_factory=list)
    suppression_diagnostics: list[dict[str, Any]] = field(default_factory=list)
    configuration_audit: dict[str, Any] = field(default_factory=dict)
    workflow_nodes: list[WorkflowNode] = field(default_factory=list)

    def all_tools(self) -> list[Tool]:
        tools = list(self.unbound_tools)
        for agent in self.agents:
            tools.extend(agent.tools)
        return tools

    def all_mcp_servers(self) -> list[MCPServer]:
        servers = list(self.unbound_mcp_servers)
        for agent in self.agents:
            servers.extend(agent.mcp_servers)
        return servers

    def all_identities(self) -> list[Identity]:
        identities = list(self.identities)
        for agent in self.agents:
            identities.extend(agent.identities)
        return identities


@dataclass(slots=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    recommendation: str
    layer: int = 1
    location: SourceLocation | None = None
    agent: str | None = None
    evidence: list[str] = field(default_factory=list)
    standards: dict[str, list[str]] = field(default_factory=lambda: {"owasp_agentic": []})
    assessment: str = "static_configuration"
    provenance: list[EvidenceFact] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    confidence: Confidence | None = None
    source_context: str = "unknown"
    authority_relationship_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        from horustrace.rule_registry import get_rule_metadata
        try:
            default_severity = get_rule_metadata(self.rule_id).default_severity.label()
        except KeyError:
            default_severity = self.severity.label()
        return {
            "rule_id": self.rule_id,
            "default_severity": default_severity,
            "severity": self.severity.label(),
            "title": self.title,
            "message": self.message,
            "recommendation": self.recommendation,
            "layer": self.layer,
            "agent": self.agent,
            "evidence": self.evidence,
            "standards": self.standards,
            "assessment": self.assessment,
            "source_context": self.source_context,
            "provenance": [fact.as_dict() for fact in self.provenance],
            "limitations": self.limitations,
            "fingerprint": self.fingerprint,
            "confidence": self.confidence.value if self.confidence else None,
            "location": (
                {
                    "path": str(self.location.path),
                    "line": self.location.line,
                    "column": self.location.column,
                }
                if self.location
                else None
            ),
        }
