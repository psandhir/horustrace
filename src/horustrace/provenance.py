"""Evidence origins and static control observations; neither proves runtime enforcement."""
import fnmatch

from horustrace.adapters.google_adk import BUILTIN_TOOL_CAPABILITIES
from horustrace.models import Confidence, EvidenceFact, Graph, SourceLocation
from horustrace.rule_registry import get_rule_metadata

MANIFEST_NAMES = {'horustrace.manifest.yaml', 'horustrace.manifest.yml'}


def annotate(graph: Graph, path) -> None:
    declared = path.name in MANIFEST_NAMES
    location = SourceLocation(path)

    def facts(entity, subject, values, inferred=False, origin=None):
        origin = origin or ('declared' if declared else 'inferred' if inferred else 'observed')
        for value in values:
            fact = EvidenceFact(subject, value, origin, getattr(entity, 'location', None) or location)
            if fact not in entity.provenance:
                entity.provenance.append(fact)

    def tool_facts(tool):
        heuristic = tool.kind in {'function', 'adk_function', 'generic'} or (
            tool.kind in {'adk_builtin', 'adk_config_tool'}
            and (tool.metadata.get('adk_builtin') or tool.name) not in BUILTIN_TOOL_CAPABILITIES
        )
        facts(tool, tool.name, [f'capability={c}' for c in sorted(tool.capabilities)], heuristic,
              origin=tool.metadata.get('capability_origin'))
        facts(tool, tool.name, [f'approval_configuration={tool.approval}'])
        facts(tool, tool.name, [f'guardrail_hook_detected={tool.guardrails}'],
              inferred=bool(tool.metadata.get('guardrail_origin')))
        for resource in tool.resources:
            facts(resource, resource.selector,
                  [f'resource_selector={resource.selector}', f'classification={resource.classification}'])
        for destination in tool.destinations:
            # A literal URL in a function is evidence of a possible destination,
            # not an enforced network restriction.
            facts(destination, tool.name, [f'destination={destination.target}'], heuristic)

    for tool in graph.all_tools():
        tool_facts(tool)
    for skill in graph.all_skills():
        facts(skill, skill.name, [f'allowed_tool={value}' for value in sorted(skill.allowed_tools)])
        facts(skill, skill.name, [f'script={value}' for value in sorted(skill.scripts)])
    for server in graph.all_mcp_servers():
        facts(server, server.name, [f'transport={server.transport}',
                                   f'authentication_configuration={server.authenticated}',
                                   f'approval_configuration={server.approval}'])
    for identity in graph.all_identities():
        facts(identity, identity.name,
              [f'role={v}' for v in sorted(identity.roles)] +
              [f'permission={v}' for v in sorted(identity.permissions)] +
              [f'oauth_scope={v}' for v in sorted(identity.oauth_scopes)] +
              ([f'credential_source={identity.credential_source}'] if identity.credential_source else []))
    for agent in graph.agents:
        facts(agent, agent.name, ['agent_configuration_detected'])
        facts(agent, agent.name, [f'callback_hook={c}' for c in sorted(
            agent.metadata.get('callbacks') or {}
        )])
        if agent.metadata.get('safety_plugin'):
            facts(agent, agent.name, ['safety_plugin_name_detected'], inferred=True)
        for source in agent.data_sources:
            facts(source, source.name, [f'classification={source.classification}',
                                       f'capability={source.capability}'])
        for source in agent.inputs:
            facts(source, source.name, [f'input_trust={source.trust}', f'input_kind={source.kind}'],
                  bool(source.metadata.get('inferred')))
        for destination in agent.network:
            facts(destination, agent.name, [f'destination={destination.target}',
                                           f'restriction_declaration={destination.restricted}'])
        policy = agent.policy
        values = [f'required={c}' for c in sorted(policy.required_capabilities)]
        values += [f'denied={c}' for c in sorted(policy.denied_capabilities)]
        values += [f'required_skill={s}' for s in sorted(policy.required_skills)]
        values += [f'allowed_skill={s}' for s in sorted(policy.allowed_skills)]
        values += [f'denied_skill={s}' for s in sorted(policy.denied_skills)]
        values += [f'approval_required_for={c}' for c in sorted(policy.require_approval_for)]
        values += [f'allowed_resource={v}' for v in policy.allowed_resources]
        values += [f'allowed_destination={v}' for v in policy.allowed_destinations]
        if policy.max_privileged_capabilities is not None:
            values.append(f'max_privileged_capabilities={policy.max_privileged_capabilities}')
        facts(policy, agent.name, values)


def context(agent):
    entities = [agent, agent.policy, *agent.tools, *agent.skills, *agent.mcp_servers,
                *agent.identities, *agent.inputs, *agent.data_sources, *agent.network]
    for tool in agent.tools:
        entities.extend([*tool.resources, *tool.destinations])
    facts = []
    for entity in entities:
        for fact in entity.provenance:
            if fact not in facts:
                facts.append(fact)
    return facts



def _evidence_values(finding, key):
    """Read rule evidence without treating arbitrary message text as a source reference."""
    values = []
    prefix = key + "="
    for item in finding.evidence:
        if item.startswith(prefix):
            values.extend(value.strip() for value in item[len(prefix):].split(",") if value.strip())
    return set(values)


def _relevant_provenance(agent, finding, attack_path):
    """Attach facts supporting this finding; never substitute the agent-wide inventory.

    Rule-evidence names and path nodes are explicit references. Matching the
    finding's agent location alone is insufficient: many different entities
    may share that location, particularly manifest-derived constructs.
    """
    result = []

    def add(entity, predicate=None):
        if entity is None:
            return
        for fact in getattr(entity, "provenance", ()):
            if (predicate is None or predicate(fact)) and fact not in result:
                result.append(fact)

    def key_is(fact, *keys):
        return any(fact.fact.startswith(key + "=") for key in keys)

    def capability_is(fact, allowed):
        return fact.fact.startswith("capability=") and fact.fact[11:] in allowed

    def source_named(names):
        for source in agent.sensitive_data_sources:
            if source.name in names or source.selector in names:
                add(source, lambda fact: key_is(fact, "classification", "capability", "resource_selector"))

    def outbound_named(names):
        for tool in agent.tools:
            if tool.name in names:
                add(tool, lambda fact: capability_is(fact, {"network.external", "external.write"})
                    or key_is(fact, "approval_configuration"))
                for destination in tool.destinations:
                    add(destination, lambda fact: key_is(fact, "destination"))
        for server in agent.mcp_servers:
            if server.name in names:
                add(server, lambda fact: key_is(fact, "transport", "approval_configuration"))

    def broad_destinations():
        for destination in agent.network:
            if not destination.restricted or destination.target in {"*", "**"}:
                add(destination, lambda fact: key_is(fact, "destination", "restriction_declaration"))
        for tool in agent.tools:
            for destination in tool.destinations:
                if not destination.restricted or destination.target in {"*", "**"}:
                    add(destination, lambda fact: key_is(fact, "destination", "restriction_declaration"))

    if finding.rule_id == "CAP002":
        denied = _evidence_values(finding, "denied")
        add(agent.policy, lambda fact: fact.fact.startswith("denied=")
            and fact.fact[7:] in denied)
        for tool in agent.tools:
            add(tool, lambda fact: capability_is(fact, denied))
        for source in agent.data_sources:
            add(source, lambda fact: capability_is(fact, denied))
        for server in agent.mcp_servers:
            if "network.external" in denied and server.url:
                add(server, lambda fact: key_is(fact, "transport"))
        return result

    if finding.rule_id == "AGT010":
        source_named(_evidence_values(finding, "sensitive"))
        outbound_named(_evidence_values(finding, "outbound"))
        return result

    if finding.rule_id == "DATA003":
        source_named(_evidence_values(finding, "sensitive"))
        broad_destinations()
        # Where no destination is declared, the outbound capability itself
        # is the available source evidence (absence is not a provenance fact).
        for tool in agent.tools:
            if not tool.destinations:
                add(tool, lambda fact: capability_is(
                    fact, {"network.external", "external.write"}))
        return result

    if finding.rule_id.startswith("PATH"):
        if attack_path is None:
            return result
        # Path-specific evidence must belong to the actual matched path, not
        # to a different PATH occurrence for the same agent.
        nodes = set(attack_path.nodes)
        source_named(nodes)
        for source in agent.inputs:
            if source.name in nodes:
                add(source, lambda fact: key_is(fact, "input_trust", "input_kind"))
        for tool in agent.tools:
            if tool.name in nodes:
                add(tool, lambda fact: key_is(
                    fact, "capability", "approval_configuration", "guardrail_hook_detected"))
                for destination in tool.destinations:
                    add(destination, lambda fact: key_is(fact, "destination"))
        for server in agent.mcp_servers:
            if server.name in nodes:
                add(server, lambda fact: key_is(
                    fact, "transport", "authentication_configuration", "approval_configuration"))
        for destination in agent.network:
            if destination.target in nodes:
                add(destination, lambda fact: key_is(
                    fact, "destination", "restriction_declaration"))
        if finding.rule_id == "PATH003":
            # Co-occurrence PATH003 uses a generic destination label; when
            # present the broad agent egress declaration qualifies that leg.
            if "external destination" in nodes:
                broad_destinations()
        return result

    # Generic conservative fallback for other rules: match explicit evidence
    # tokens to source facts or exact entity names. It is better to expose an
    # unresolved evidence association than imply 55 unrelated facts prove it.
    tokens = set()
    for entry in finding.evidence:
        if "=" in entry:
            key, value = entry.split("=", 1)
            tokens.add(entry)
            if key not in {"flow_id", "authority_relationship"}:
                tokens.update(value.split(","))
    for entity in [
        agent, agent.policy, *agent.tools, *agent.skills, *agent.mcp_servers,
        *agent.identities, *agent.inputs, *agent.data_sources, *agent.network,
    ]:
        exact_location = (
            finding.location is not None
            and getattr(entity, "location", None) == finding.location
        )
        named = getattr(entity, "name", None) in tokens
        add(entity, lambda fact: fact.fact in tokens or (
            named and key_is(fact, "capability", "approval_configuration",
                             "guardrail_hook_detected", "transport", "role", "permission")
        ) or (
            exact_location and finding.layer in {1, 3}
            and key_is(fact, "capability", "approval_configuration",
                       "guardrail_hook_detected", "authentication_configuration",
                       "role", "permission", "oauth_scope", "credential_source")
        ))
    return result


def attach_findings(graph, findings):
    by_name = {agent.name: agent for agent in graph.agents}
    for finding in findings:
        finding.standards = {
            'owasp_agentic': list(get_rule_metadata(finding.rule_id).owasp_agentic),
        }
        agent = by_name.get(finding.agent)
        # Preserve the previous assessment semantics separately from the
        # evidence display; changing provenance presentation must not change
        # scan conclusions or findings counts.
        legacy_inferred = bool(agent and any(
            fact.origin == 'inferred' for fact in context(agent)
        ))
        attack_path = None
        if finding.rule_id.startswith('PATH'):
            attack_path = next((
                path for path in graph.attack_paths
                if path.path_id == finding.rule_id
                and path.agent == finding.agent
                and " -> ".join(path.nodes) in finding.evidence
            ), None)
        if agent:
            finding.provenance = _relevant_provenance(agent, finding, attack_path)
        else:
            # Unbound constructs retain only source-local evidence.
            entities = [
                *graph.all_tools(), *graph.all_skills(),
                *graph.all_mcp_servers(), *graph.all_identities(),
            ]
            finding.provenance = [
                fact for entity in entities
                if entity.location == finding.location
                for fact in entity.provenance
            ]
        if finding.rule_id.startswith('PATH') or finding.rule_id in {'AGT010', 'DATA003'}:
            finding.assessment = 'potential_risk'
        if finding.rule_id.startswith('PATH'):
            basis = attack_path.metadata.get('basis') if attack_path else 'capability_cooccurrence'
            finding.confidence = (
                Confidence.SUPPORTED if basis == 'static_dataflow' else Confidence.POTENTIAL
            )
            if attack_path:
                for limitation in attack_path.metadata.get('limitations', []):
                    if limitation not in finding.limitations:
                        finding.limitations.append(limitation)
            elif basis != 'static_dataflow':
                finding.limitations.append(
                    'Capability co-occurrence does not prove an executable data-flow path or exploitability.'
                )
        elif finding.rule_id in {'AGT010', 'DATA003'}:
            finding.limitations.append(
                'Capability co-occurrence does not prove an executable data-flow path or exploitability.'
            )
        elif get_rule_metadata(finding.rule_id).assessment == 'policy_violation':
            finding.assessment = 'policy_violation'
        elif finding.rule_id == 'IDN001' or legacy_inferred:
            finding.assessment = 'heuristic_risk'
        runtime_limit = 'Runtime authorization and control effectiveness are not verified by this static scan.'
        if runtime_limit not in finding.limitations:
            finding.limitations.append(runtime_limit)


def control_observations(graph):
    observations = []

    def add(subject, control, status, location):
        observations.append({'subject': subject, 'control': control, 'configuration': status,
                             'effectiveness': 'not_verified', 'location': (
                                 {'path': str(location.path), 'line': location.line} if location else None)})

    for agent in graph.agents:
        for callback in sorted(agent.metadata.get('callbacks') or {}):
            add(agent.name, callback, 'hook_detected', agent.location)
        if agent.metadata.get('safety_plugin'):
            add(agent.name, 'safety_plugin', 'name_inferred', agent.location)
    for tool in [*graph.all_tools(), *graph.all_mcp_servers()]:
        add(tool.name, 'approval', 'required' if tool.approval is True else
            'disabled' if tool.approval is False else 'unknown', tool.location)
        if tool.guardrails:
            add(tool.name, 'guardrail', 'boundary_or_hook_detected', tool.location)
        if tool.metadata.get('approval_hook_detected'):
            add(tool.name, 'approval_callback', 'hook_detected', tool.location)
        if tool.metadata.get('sandboxed') is not None:
            add(tool.name, 'sandbox', 'configured' if tool.metadata['sandboxed'] else
                'disabled', tool.location)
        if getattr(tool, 'kind', None) == 'adk_code_executor' and tool.metadata.get('sandboxed') is True:
            if tool.metadata.get('sandbox_constraints_applicable', True) is False:
                add(tool.name, 'sandbox_limits', 'provider_managed', tool.location)
            else:
                add(tool.name, 'sandbox_limits',
                    'timeout_network_filesystem_configured'
                    if tool.metadata.get('sandbox_constraints_complete')
                    else 'limits_incomplete', tool.location)
        if tool.metadata.get('adk_builtin') == 'ExecuteBashTool':
            add(tool.name, 'bash_policy',
                'allowlist_and_blocklist_detected'
                if tool.metadata.get('bash_policy_restrictive')
                else 'restrictive_policy_not_detected', tool.location)
        if hasattr(tool, 'allowed_tools'):
            add(tool.name, 'mcp_tool_allowlist',
                'configured' if tool.allowed_tools else 'not_detected', tool.location)
    for agent in graph.agents:
        for destination in agent.effective_destinations:
            add(agent.name, 'network_destination',
                'possible_destination_only' if destination.metadata.get('source') == 'literal_url'
                else 'restriction_configured' if destination.restricted else 'restriction_not_detected',
                destination.location)
        if agent.policy.allowed_destinations:
            destinations = agent.effective_destinations
            all_allowed = bool(destinations) and all(
                any(fnmatch.fnmatch(destination.target, pattern)
                    for pattern in agent.policy.allowed_destinations)
                for destination in destinations
            )
            add(agent.name, 'egress_allowlist',
                'all_discovered_destinations_allowed' if all_allowed
                else 'declared_allowlist_does_not_cover_all_destinations', agent.location)
    deduplicated = []
    seen = set()
    for observation in observations:
        location = observation.get("location") or {}
        key = (
            observation["subject"],
            observation["control"],
            observation["configuration"],
            location.get("path"),
            location.get("line"),
        )
        if key not in seen:
            seen.add(key)
            deduplicated.append(observation)
    return deduplicated
