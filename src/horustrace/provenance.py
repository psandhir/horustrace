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


def attach_findings(graph, findings):
    by_name = {agent.name: agent for agent in graph.agents}
    for finding in findings:
        finding.standards = {
            'owasp_agentic': list(get_rule_metadata(finding.rule_id).owasp_agentic),
        }
        agent = by_name.get(finding.agent)
        if agent:
            if finding.layer in {1, 3}:
                entities = [*agent.tools, *agent.skills, *agent.mcp_servers, *agent.identities]
                selected = [entity for entity in entities if entity.location == finding.location]
                finding.provenance = ([fact for entity in selected for fact in entity.provenance]
                                      if selected else list(agent.provenance))
            else:
                finding.provenance = context(agent)
        else:
            entities = [
                *graph.all_tools(),
                *graph.all_skills(),
                *graph.all_mcp_servers(),
                *graph.all_identities(),
            ]
            finding.provenance = [fact for entity in entities if entity.location == finding.location
                                  for fact in entity.provenance]
        attack_path = None
        if finding.rule_id.startswith('PATH'):
            attack_path = next((
                path for path in graph.attack_paths
                if path.path_id == finding.rule_id
                and path.agent == finding.agent
                and " -> ".join(path.nodes) in finding.evidence
            ), None)
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
        elif finding.rule_id == 'IDN001' or any(f.origin == 'inferred' for f in finding.provenance):
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
