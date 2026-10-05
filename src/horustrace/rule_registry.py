"""Canonical metadata for every security rule emitted by HorusTrace."""

from __future__ import annotations

from dataclasses import dataclass, replace

from horustrace.models import Severity


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    layer: int
    title: str
    default_severity: Severity
    category: str
    assessment: str
    rationale: str
    remediation: str
    references: tuple[str, ...] = ()
    owasp_agentic: tuple[str, ...] = ()


def _rule(
    rule_id: str,
    layer: int,
    severity: Severity,
    category: str,
    assessment: str,
    title: str,
    rationale: str,
    remediation: str,
) -> RuleMetadata:
    return RuleMetadata(
        rule_id=rule_id,
        layer=layer,
        title=title,
        default_severity=severity,
        category=category,
        assessment=assessment,
        rationale=rationale,
        remediation=remediation,
    )


RULE_REGISTRY: dict[str, RuleMetadata] = {
    rule.rule_id: rule
    for rule in (
        _rule("AGT001", 1, Severity.MEDIUM, "mcp", "static_configuration", "Broad local MCP filesystem scope", "A local MCP server can expose more of the filesystem than the agent requires.", "Restrict filesystem MCP access to the smallest application-specific directory."),
        _rule("AGT020", 1, Severity.HIGH, "execution", "static_configuration", "Shell or process execution without approval", "Process execution without an approval requirement can perform high-impact actions.", "Require approval for process execution and run the tool inside a constrained sandbox."),
        _rule("AGT021", 1, Severity.HIGH, "agent_config", "static_configuration", "Destructive action without human approval", "Destructive writes without approval can alter or delete state without review.", "Gate destructive operations with human approval and least-privilege authorization."),
        _rule("AGT022", 1, Severity.MEDIUM, "agent_config", "static_configuration", "State-changing tool without approval", "State-changing tools can make material changes without an explicit review boundary.", "Require approval for material state changes or constrain the tool to low-risk, reversible operations."),
        _rule("AGT023", 1, Severity.HIGH, "agent_config", "static_configuration", "Computer-control action lacks explicit boundary", "State-changing computer or browser actions can click, type, upload, or otherwise act without a detected review boundary.", "Require confirmation or a policy guardrail before state-changing computer actions."),
        _rule("AGT030", 1, Severity.HIGH, "mcp", "static_configuration", "Remote MCP server has no detected authentication", "An unauthenticated remote MCP endpoint can expose agent tools to unauthorized callers.", "Require authenticated MCP access using a scoped token, OAuth, or workload identity."),
        _rule("AGT031", 1, Severity.HIGH, "mcp", "static_configuration", "Unencrypted remote MCP transport", "Plaintext MCP transport can expose requests, responses, and credentials in transit.", "Use HTTPS or WSS with certificate validation for remote MCP connections."),
        _rule("AGT032", 1, Severity.MEDIUM, "mcp", "static_configuration", "Remote MCP lacks an explicit tool allowlist", "Without an explicit allowlist, the MCP tool surface may include unreviewed operations.", "Use an explicit MCP tool allowlist for production agents, especially for privileged servers."),
        _rule("AGT040", 1, Severity.MEDIUM, "agent_config", "static_configuration", "Privileged tool lacks explicit guardrail or approval", "Privileged tools need an explicit control boundary before they perform sensitive actions.", "Add tool input/output guardrails and/or explicit approval appropriate to the action."),
        _rule("AGT050", 1, Severity.MEDIUM, "mcp", "static_configuration", "Unpinned MCP package execution", "Unpinned package execution can install an unreviewed or changed MCP server version.", "Pin MCP server packages to a reviewed version or immutable digest."),
        _rule("AGT051", 1, Severity.HIGH, "mcp", "static_configuration", "Literal credential in MCP configuration", "Embedding credential material directly in MCP configuration exposes it to source, artifact, and workstation compromise.", "Inject MCP credentials through environment variables, a managed secret store, or workload identity instead of committed configuration."),
        _rule("AGT052", 1, Severity.MEDIUM, "mcp", "static_configuration", "MCP configured with broad tool surface", "Explicitly enabling all MCP tools can expose unreviewed or unnecessary operations.", "Restrict the MCP server to the smallest explicit tool allowlist required by the workflow."),
        _rule("AGT053", 1, Severity.MEDIUM, "mcp", "static_configuration", "MCP exposes privileged tools without an explicit action boundary", "A bound MCP server exposes privileged tool capabilities without detected approval or guardrail controls.", "Add an MCP tool allowlist and require approval or equivalent policy controls for mutating, destructive, execution, or credential-access tools."),
        _rule("AGT054", 1, Severity.MEDIUM, "mcp", "static_configuration", "Dynamic remote MCP catalogue has no per-call approval", "A source-bound remote MCP catalogue is dynamically imported into an effective agent without a per-call approval boundary.", "Restrict the remote MCP catalogue to an explicit allowlist and require per-call approval or an equivalent policy boundary."),
        _rule("SKL001", 1, Severity.MEDIUM, "skill", "static_configuration", "Bound skill declares broad tool access", "A bound skill declares an unrestricted or wildcard allowed-tools surface.", "Restrict the skill allowed-tools declaration to the smallest explicit set required by the workflow."),
        _rule("ADK001", 1, Severity.MEDIUM, "agent_config", "static_configuration", "Privileged ADK agent has no detected tool-control callback/plugin", "Privileged ADK capabilities lack a detected callback, plugin, or confirmation control boundary.", "Add before-tool callback or security plugin controls and require confirmation for high-impact tools."),
        _rule("ADK002", 1, Severity.CRITICAL, "execution", "static_configuration", "Unsafe local ADK code execution", "Unsandboxed local execution can access host processes, files, and credentials.", "Use Agent Runtime, GKE, or built-in sandboxed execution and apply resource, timeout, network, and approval controls."),
        _rule("ADK003", 1, Severity.HIGH, "execution", "static_configuration", "ADK LocalEnvironment exposes shell and file I/O", "LocalEnvironment exposes host command execution and file operations to the agent.", "Run execution in a disposable sandbox, constrain working_dir, remove secrets, and gate mutating actions."),
        _rule("ADK004", 1, Severity.HIGH, "execution", "static_configuration", "ADK Bash tool lacks a restrictive policy", "Bash execution without both command allowlist and blocklist controls can run unsafe commands.", "Configure BashToolPolicy with allowed command prefixes and blocked operators or commands."),
        _rule("ADK005", 1, Severity.HIGH, "agent_config", "static_configuration", "Computer-use agent lacks an explicit action boundary", "Computer control can navigate, type, download, upload, and change state without a detected boundary.", "Add action confirmation or guardrails for sensitive UI actions and isolate the browser profile."),
        _rule("ADK006", 1, Severity.MEDIUM, "agent_config", "static_configuration", "BigQuery toolset permits write-capable operation", "A BigQuery toolset can modify data when write operations are not statically blocked.", "Use BigQueryToolConfig(write_mode=WriteMode.BLOCKED) for read-only agents and least-privilege IAM."),
        _rule("ADK007", 1, Severity.MEDIUM, "agent_config", "static_configuration", "Broad ADK toolset surface", "An unfiltered generated or API toolset can expose more operations than intended.", "Restrict available tools to the exact operations required by the agent."),
        _rule("ADK008", 1, Severity.MEDIUM, "agent_config", "static_configuration", "Delegated ADK AgentTool disables inherited plugins", "A delegated agent that disables inherited plugins can bypass parent safety and observability controls.", "Ensure the child has equivalent security plugins or inherit parent plugins."),
        _rule("ADK009", 1, Severity.HIGH, "agent_config", "static_configuration", "Remote A2A agent uses plaintext HTTP", "A plaintext A2A agent card can be intercepted or modified in transit.", "Use HTTPS with certificate validation and authenticate card retrieval and A2A requests."),
        _rule("ADK010", 1, Severity.HIGH, "agent_config", "static_configuration", "Remote A2A agent has no detected authentication", "An unauthenticated A2A agent can accept requests without a detected caller identity boundary.", "Configure A2A authentication and scope credentials to the intended remote agent and audience."),
        _rule("ADK011", 1, Severity.HIGH, "agent_config", "static_configuration", "Privileged ADK agent is exposed over A2A without detected safety control", "An A2A-exposed privileged agent lacks a detected safety callback or plugin.", "Authenticate and authorize the A2A endpoint and enforce tool-level policy before privileged actions."),
        _rule("ADK012", 1, Severity.MEDIUM, "execution", "static_configuration", "Sandboxed ADK executor lacks explicit limits", "A sandbox without explicit timeout, network, and filesystem limits can retain broad execution authority.", "Configure a positive timeout, restrict network access, and constrain the executor workspace or allowed paths."),
        _rule("CAP001", 2, Severity.HIGH, "capability", "policy_violation", "Agent exceeds declared capability budget", "The normalized agent exposes capabilities beyond its declared business requirement.", "Remove unnecessary tools or capabilities, or update the budget only after security review."),
        _rule("CAP002", 2, Severity.CRITICAL, "capability", "policy_violation", "Agent has explicitly forbidden capability", "The agent exposes a capability that its policy explicitly forbids.", "Remove the tool or capability, or change policy through an explicit risk-acceptance process."),
        _rule("CAP003", 2, Severity.HIGH, "capability", "heuristic_risk", "High aggregate agent authority", "Combining multiple privileged capability classes increases the potential impact of compromise.", "Split duties across narrower agents or tools and introduce explicit control boundaries."),
        _rule("CAP004", 2, Severity.HIGH, "capability", "heuristic_risk", "Command execution combined with external network access", "Execution plus network access can create a pathway for remote command retrieval or exfiltration.", "Sandbox execution and restrict egress to an explicit destination allowlist."),
        _rule("CAP005", 2, Severity.MEDIUM, "capability", "heuristic_risk", "Combined read and write authority", "An agent that reads and changes data has a larger authority surface than a read-only agent.", "Apply resource-level least privilege and separate analysis from mutation where practical."),
        _rule("CAP006", 2, Severity.HIGH, "capability", "policy_violation", "Policy-required approval is not configured on every tool", "At least one tool exposes a capability that policy requires to be approved without that setting.", "Enforce approval on each tool providing this capability."),
        _rule("SKL010", 2, Severity.HIGH, "skill", "policy_violation", "Agent uses skill outside declared allowlist", "The agent has a source-proven skill binding that is outside its policy allowlist.", "Remove the skill binding or add it to policy only after explicit security review."),
        _rule("SKL011", 2, Severity.MEDIUM, "skill", "policy_violation", "Required skill is not bound", "Policy requires a skill that was not found among the agent's source-proven skill bindings.", "Bind the required reviewed skill or update the policy if the requirement is no longer valid."),
        _rule("SKL012", 2, Severity.CRITICAL, "skill", "policy_violation", "Agent binds explicitly denied skill", "The agent has a source-proven binding to a skill that policy explicitly denies.", "Remove the denied skill binding or change policy through an explicit risk-acceptance process."),
        _rule("IDN001", 3, Severity.HIGH, "identity", "static_configuration", "Broad administrative identity role", "Broad administrative roles grant more authority than a workload should usually require.", "Replace broad roles with workload-specific least-privilege roles scoped to required resources."),
        _rule("IDN002", 3, Severity.CRITICAL, "identity", "static_configuration", "Wildcard identity permission", "Wildcard permissions grant actions beyond a narrowly reviewed set.", "Enumerate the exact API actions required by the agent and remove wildcard permissions."),
        _rule("IDN003", 3, Severity.HIGH, "identity", "static_configuration", "Broad OAuth scope", "Broad OAuth scopes can authorize access outside the agent's required data boundary.", "Use narrow OAuth scopes and resource-level authorization appropriate to the tool action."),
        _rule("IDN004", 3, Severity.HIGH, "identity", "static_configuration", "Unsafe credential source", "Static or plaintext credentials are exposed to source and filesystem compromise.", "Use workload identity or a managed secret store; do not embed long-lived credentials in source or configuration."),
        _rule("IDN005", 3, Severity.HIGH, "identity", "policy_violation", "Unauthenticated realtime session reaches state-changing agent authority", "A public endpoint can mint a publish-capable realtime session credential that feeds an agent with state-changing MCP-backed tools without a detected authentication boundary.", "Authenticate and authorize session issuance, bind the participant identity to permitted resources, and require explicit approval for high-impact state changes."),
        _rule("AGT010", 4, Severity.CRITICAL, "data", "heuristic_risk", "Potential sensitive-data exfiltration path", "Sensitive data and outbound capability can form an exfiltration path when approval is not detected on every outbound tool.", "Restrict outbound destinations, reduce data scope, or require human approval before sensitive information leaves the trust boundary."),
        _rule("DATA001", 4, Severity.HIGH, "data", "heuristic_risk", "Broad resource scope", "Broad resource selectors can expose data beyond the intended workload boundary.", "Constrain files, data stores, buckets, or records to the smallest required resource scope."),
        _rule("DATA002", 4, Severity.HIGH, "data", "policy_violation", "Resource access exceeds declared allowlist", "The agent can reach resources outside its declared allowlist.", "Narrow tool and resource configuration to the declared resource boundary."),
        _rule("DATA003", 4, Severity.CRITICAL, "data", "heuristic_risk", "Sensitive data has broad egress reachability", "Sensitive data combined with broad or unconstrained outbound capability creates potential exposure.", "Restrict outbound destinations and require approval or DLP controls before sensitive data leaves the trust boundary."),
        _rule("DATA004", 4, Severity.MEDIUM, "authorization", "policy_violation", "Model-callable object mutation bypasses owner scope", "A model-callable tool can select and mutate an owner-scoped object by identifier without the owner check enforced by the repository's normal application path.", "Carry the authenticated principal into the tool boundary and scope object lookup/mutation to the authorized owner or tenant."),
        _rule("NET001", 4, Severity.HIGH, "network", "heuristic_risk", "Outbound reachability lacks a detected restriction", "Broad or unrestrained destinations can allow data to leave the intended trust boundary.", "Use egress allowlists or proxies and restrict outbound connectivity to required hosts."),
        _rule("NET002", 4, Severity.MEDIUM, "network", "heuristic_risk", "Outbound capability has no destination constraint", "An outbound-capable agent without a declared destination constraint has unknown egress scope.", "Declare and enforce permitted destinations for outbound tools."),
        _rule("NET003", 4, Severity.HIGH, "network", "policy_violation", "Network destination exceeds declared allowlist", "The agent can reach a destination outside its declared network allowlist.", "Restrict tool and MCP egress to the approved destination set."),
        _rule("NET004", 4, Severity.MEDIUM, "network", "heuristic_risk", "MCP tool exposes model-selected URL destination authority", "A bound MCP tool accepts model-selected URL parameters that source-proven provider fetch/crawl/map/extract operations use as remote destinations without a detected allowlist.", "Restrict URL-bearing MCP tools to approved schemes and destinations and enforce destination validation before provider operations."),
        _rule("PATH001", 5, Severity.CRITICAL, "attack_path", "potential_risk", "Potential untrusted-input path to command execution", "Untrusted input and process execution coexist without a detected approval requirement.", "Break the path by validating untrusted input, reducing execution authority, sandboxing, or enforcing approval."),
        _rule("PATH002", 5, Severity.HIGH, "attack_path", "potential_risk", "Potential untrusted-input path to destructive action", "Untrusted input and destructive-write capability coexist without a detected approval requirement.", "Break the path by validating untrusted input, reducing write authority, or enforcing approval."),
        _rule("PATH003", 5, Severity.CRITICAL, "attack_path", "potential_risk", "Potential sensitive-data path to an external destination", "Sensitive-data access and outbound capability coexist without a detected approval requirement.", "Break the path by reducing data access, restricting egress, or enforcing approval."),
        _rule("PATH004", 5, Severity.CRITICAL, "attack_path", "potential_risk", "Potential combination of untrusted input, sensitive data and execution", "Untrusted input, sensitive data, and execution capability coexist in the same normalized agent model.", "Break the path by separating duties, reducing privilege, validating input, and sandboxing execution."),
        _rule("PATH005", 5, Severity.HIGH, "attack_path", "potential_risk", "Potential untrusted-input path to secret access and egress", "Untrusted input, secret-reading capability, and outbound capability coexist in the same normalized agent model.", "Break the path by isolating secret access, validating input, and restricting egress."),
        _rule("PATH006", 5, Severity.HIGH, "attack_path", "potential_risk", "Potential untrusted-input exposure to multiple high-risk capabilities", "Untrusted input can reach an agent that combines multiple high-risk capability classes.", "Break the path by narrowing the agent's capability set and validating untrusted input."),
        _rule("PATH007", 5, Severity.HIGH, "attack_path", "potential_risk", "Potential untrusted-input path to persistent memory write", "Untrusted input that reaches persistent agent memory or checkpoint state can influence later agent behavior.", "Validate and constrain untrusted content before persistent memory writes; isolate memory scope and require review for high-impact state."),
        _rule("PATH008", 5, Severity.HIGH, "attack_path", "potential_risk", "Potential untrusted-input path through delegated agent to privileged action", "Untrusted input can reach an agent that delegates to another agent exposing a high-risk capability without detected approval.", "Constrain delegation targets, narrow child-agent authority, validate untrusted input, and enforce approval at the privileged action boundary."),
        _rule("PATH009", 5, Severity.MEDIUM, "attack_path", "potential_risk", "Potential untrusted-input path through delegated agent to unconstrained egress", "Untrusted input can reach a delegated agent with outbound authority and no detected destination constraint.", "Restrict delegated outbound tools to explicit destinations and validate untrusted input before external actions."),
        _rule("PATH010", 5, Severity.HIGH, "attack_path", "potential_risk", "Potential untrusted-input local file read to external service", "A model-selected local file path can be read and the resulting data can reach an external service without a detected filesystem containment boundary.", "Constrain model-selected paths to an explicit workspace or allowlist and prevent local file contents from reaching external services unless that transfer is explicitly intended and controlled."),
        _rule("PATH011", 5, Severity.HIGH, "attack_path", "potential_risk", "Potential untrusted-input path to server-side URL fetch", "Source-bound untrusted input reaches an agent with a model-selected URL parameter that is passed to a direct server-side HTTP client without a detected destination restriction.", "Restrict server-side fetch tools to approved schemes and destinations, block private/link-local address ranges as appropriate, validate redirects, and require explicit controls for sensitive fetches."),
        _rule("PATH012", 5, Severity.HIGH, "attack_path", "potential_risk", "Potential indirect tool-content path to unconstrained filesystem access", "Source-proven local or repository content can re-enter the model context while the same effective agent can select filesystem paths that reach read/write sinks without detected containment.", "Treat tool-returned repository content as untrusted model input and enforce resolved-path containment for every model-selected filesystem read/write tool."),
        _rule("PATH013", 5, Severity.HIGH, "attack_path", "potential_risk", "Potential user-selected server directory exposure through RAG", "A user-selected server-side directory can be recursively ingested into a RAG corpus and retrieved through the same effective agent without a detected filesystem containment boundary.", "Constrain document roots to an approved base directory, enforce resolved-path containment before indexing, authenticate the application surface, and limit retrieval scope to intended documents."),
        _rule("PATH014", 5, Severity.MEDIUM, "attack_path", "potential_risk", "Potential model-driven cross-owner object mutation", "Source-bound user input reaches an agent with a model-callable object mutation that omits the owner-scoping check enforced by the repository's normal application path.", "Carry the authenticated principal into the tool boundary and enforce owner/tenant scoping before every model-driven object mutation."),
        _rule("PATH015", 5, Severity.HIGH, "attack_path", "potential_risk", "Potential unauthenticated realtime path to MCP-backed state mutation", "A public realtime-session credential can admit participant input to an agent that exposes MCP-backed state-changing tools without a detected authentication or per-action approval boundary.", "Authenticate session issuance, bind the realtime participant to authorized resource scope, and require approval or equivalent controls before state-changing MCP actions."),
    )
}

OWASP_AGENTIC_TAXONOMY: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

OWASP_AGENTIC_IDS = frozenset(OWASP_AGENTIC_TAXONOMY)

_OWASP_MAPPINGS = {
    "AGT020": ("ASI05",),
    "AGT021": ("ASI02",),
    "AGT022": ("ASI02",),
    "AGT023": ("ASI02",),
    "AGT030": ("ASI07",),
    "AGT031": ("ASI07",),
    "AGT032": ("ASI02",),
    "AGT040": ("ASI02",),
    "AGT050": ("ASI04",),
    "AGT051": ("ASI03", "ASI04"),
    "AGT052": ("ASI02",),
    "AGT053": ("ASI02",),
    "AGT054": ("ASI02",),
    "SKL001": ("ASI02",),
    "SKL010": ("ASI02",),
    "SKL011": ("ASI02",),
    "SKL012": ("ASI02",),
    "ADK001": ("ASI02",),
    "ADK002": ("ASI05",),
    "ADK003": ("ASI05",),
    "ADK004": ("ASI05",),
    "ADK005": ("ASI02",),
    "ADK006": ("ASI02",),
    "ADK007": ("ASI02",),
    "ADK009": ("ASI07",),
    "ADK010": ("ASI07",),
    "ADK011": ("ASI07",),
    "ADK012": ("ASI05",),
    "CAP001": ("ASI02",),
    "CAP002": ("ASI02",),
    "CAP003": ("ASI02",),
    "CAP005": ("ASI02",),
    "CAP006": ("ASI02",),
    "IDN001": ("ASI03",),
    "IDN002": ("ASI03",),
    "IDN003": ("ASI03",),
    "IDN004": ("ASI03",),
    "IDN005": ("ASI01", "ASI02", "ASI03"),
    "PATH001": ("ASI01", "ASI05"),
    "PATH002": ("ASI01", "ASI02"),
    "PATH004": ("ASI01", "ASI05"),
    "PATH005": ("ASI01",),
    "PATH006": ("ASI01", "ASI02"),
    "PATH007": ("ASI06",),
    "PATH008": ("ASI01", "ASI02", "ASI07"),
    "PATH009": ("ASI01", "ASI02", "ASI07"),
    "PATH010": ("ASI01", "ASI02"),
    "PATH011": ("ASI01", "ASI02"),
    "PATH012": ("ASI01", "ASI02", "ASI06"),
    "PATH013": ("ASI02",),
    "PATH014": ("ASI01", "ASI02", "ASI03"),
    "PATH015": ("ASI01", "ASI02", "ASI03"),
    "NET004": ("ASI02",),
}

RULE_REGISTRY = {
    rule_id: replace(metadata, owasp_agentic=_OWASP_MAPPINGS.get(rule_id, ()))
    for rule_id, metadata in RULE_REGISTRY.items()
}


def get_rule_metadata(rule_id: str) -> RuleMetadata:
    """Return metadata for a known rule, raising KeyError for an unknown ID."""
    return RULE_REGISTRY[rule_id]


def iter_rule_metadata() -> tuple[RuleMetadata, ...]:
    """Return metadata ordered by analysis layer and rule identifier."""
    return tuple(sorted(RULE_REGISTRY.values(), key=lambda rule: (rule.layer, rule.rule_id)))
