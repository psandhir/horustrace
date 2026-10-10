import json
from pathlib import Path

import pytest

from horustrace.cli import main
from horustrace.provenance import context, control_observations
from horustrace.scanner import scan


def test_source_policy_and_inference_survive_merging(tmp_path: Path):
    source = tmp_path / 'agent.py'
    source.write_text('''
from agents import Agent, ShellTool, function_tool
@function_tool
def delete_record():
    pass
shell = ShellTool()
agent = Agent(name="ops", tools=[shell, delete_record])
''')
    manifest = tmp_path / 'horustrace.manifest.yaml'
    manifest.write_text('''
version: 1
agents:
  - name: ops
    policy:
      denied_capabilities: [process.execute]
''')
    graph, findings = scan(tmp_path)
    policy = next(f for f in findings if f.rule_id == 'CAP002')
    assert policy.assessment == 'policy_violation'
    # Only denied policy and matching execution tools substantiate CAP002.
    assert {f.origin for f in policy.provenance} == {'observed', 'declared'}
    # Unrelated inferred destruction is still retained in the agent inventory.
    assert any(f.fact == 'capability=destructive.write' and f.origin == 'inferred'
               for f in context(graph.agents[0]))
    assert any(f.fact == 'denied=process.execute' and f.location.path == manifest
               for f in policy.provenance)
    destructive = next(f for f in findings if f.rule_id == 'AGT021')
    assert destructive.assessment == 'heuristic_risk'
    assert any(f.fact == 'capability=destructive.write' and f.origin == 'inferred'
               and f.location.path == source for f in destructive.provenance)


def test_manifest_name_inference_is_not_an_explicit_declaration(tmp_path: Path):
    (tmp_path / 'horustrace.manifest.yaml').write_text('''
agents:
  - name: ops
    tools:
      - name: delete_record
''')
    _, findings = scan(tmp_path)
    finding = next(f for f in findings if f.rule_id == 'AGT021')
    assert any(f.fact == 'capability=destructive.write' and f.origin == 'inferred'
               for f in finding.provenance)


def test_aliased_builtin_capabilities_are_observed(tmp_path: Path):
    (tmp_path / 'agent.py').write_text('''
from google.adk import Agent
from google.adk.tools.bigquery import BigQueryToolset
bq = BigQueryToolset()
agent = Agent(name="analyst", tools=[bq])
''')
    graph, _ = scan(tmp_path)
    capabilities = [f for f in graph.agents[0].tools[0].provenance
                    if f.fact.startswith('capability=')]
    assert capabilities
    assert {f.origin for f in capabilities} == {'observed'}


@pytest.mark.parametrize('tool_class', ['ShellTool', 'ApplyPatchTool'])
def test_approval_callback_does_not_establish_approval_requirement(tmp_path: Path, tool_class):
    (tmp_path / 'agent.py').write_text(f'''
from agents import Agent, {tool_class}
agent = Agent(name="ops", tools=[{tool_class}(on_approval=callback)])
''')
    graph, findings = scan(tmp_path)
    assert graph.agents[0].tools[0].approval is None
    assert any(f.rule_id in {'AGT020', 'AGT022'} for f in findings)
    controls = control_observations(graph)
    assert any(c['control'] == 'approval_callback' and c['configuration'] == 'hook_detected'
               for c in controls)
    assert all(c['effectiveness'] == 'not_verified' for c in controls)


def test_adk_callback_presence_does_not_remove_execution_risk(tmp_path: Path):
    (tmp_path / 'agent.py').write_text('''
from google.adk import Agent
from google.adk.code_executors import UnsafeLocalCodeExecutor
root_agent = Agent(
    name="ops",
    code_executor=UnsafeLocalCodeExecutor(),
    before_tool_callback=policy_gate,
)
''')
    graph, findings = scan(tmp_path)
    assert any(f.rule_id == 'PATH001' for f in findings)
    assert any(f.rule_id == 'ADK001' for f in findings)
    assert any(c['control'] == 'before_tool_callback' and c['effectiveness'] == 'not_verified'
               for c in control_observations(graph))


def test_partial_hosted_approval_policy_is_not_blanket_approval(tmp_path: Path):
    (tmp_path / 'agent.py').write_text('''
from agents import Agent, HostedMCPTool
mcp = HostedMCPTool(tool_config={
    "server_label": "remote",
    "require_approval": {"always": ["read"], "never": ["write"]},
})
agent = Agent(name="ops", tools=[mcp])
''')
    graph, _ = scan(tmp_path)
    assert graph.agents[0].tools[0].approval is None


@pytest.mark.parametrize('framework', ['openai', 'adk'])
def test_literal_url_is_not_an_egress_allowlist(tmp_path: Path, framework):
    imports = ('from agents import Agent, function_tool' if framework == 'openai'
               else 'from google.adk import Agent')
    decorator = '@function_tool\n' if framework == 'openai' else ''
    (tmp_path / 'agent.py').write_text(f'''
{imports}
{decorator}def fetch_data(url):
    default_url = "https://approved.example/read"
    return requests.get(url or default_url)
agent = Agent(name="ops", tools=[fetch_data])
''')
    graph, findings = scan(tmp_path)
    assert any(f.rule_id == 'NET001' for f in findings)
    assert not graph.agents[0].effective_destinations[0].restricted
    assert any(c['control'] == 'network_destination'
               and c['configuration'] == 'possible_destination_only'
               for c in control_observations(graph))


@pytest.mark.parametrize('output_format', ['json', 'sarif', 'console'])
def test_reports_explain_potential_paths_and_unverified_controls(tmp_path: Path, capsys, output_format):
    (tmp_path / 'horustrace.manifest.yaml').write_text('''
agents:
  - name: ops
    inputs:
      - name: web
        trust: untrusted
    tools:
      - name: shell
        capabilities: [process.execute]
''')
    assert main(['scan', str(tmp_path), '--format', output_format, '--fail-on', 'none']) == 0
    output = capsys.readouterr().out
    if output_format == 'console':
        assert 'Potential untrusted-input path' in output
        assert 'potential_risk' in output
        assert 'Evidence origins: declared' in output
        assert 'runtime effectiveness not verified' in output
        return
    report = json.loads(output)
    if output_format == 'json':
        path = report['attack_paths'][0]
        assert path['basis'] == 'capability_cooccurrence'
        assert path['exploitability'] == 'not_verified'
        finding = next(f for f in report['findings'] if f['rule_id'] == 'PATH001')
        controls = report['control_observations']
    else:
        run = report['runs'][0]
        finding = next(f['properties'] for f in run['results'] if f['ruleId'] == 'PATH001')
        controls = run['properties']['control_observations']
    assert finding['assessment'] == 'potential_risk'
    assert finding['provenance']
    assert finding['limitations']
    assert all(c['effectiveness'] == 'not_verified' for c in controls)


def test_delegation_preserves_original_evidence_location(tmp_path: Path):
    source = tmp_path / 'agent.py'
    source.write_text('''
from google.adk import Agent
from google.adk.tools.bash_tool import ExecuteBashTool
child = Agent(name="child", tools=[ExecuteBashTool()])
root_agent = Agent(name="root", sub_agents=[child])
''')
    _, findings = scan(tmp_path)
    finding = next(f for f in findings if f.rule_id == 'CAP004' and f.agent == 'root')
    assert any(f.fact == 'capability=process.execute' and f.origin == 'observed'
               and f.location.path == source and f.location.line == 4 for f in finding.provenance)


def test_reports_do_not_serialize_instruction_or_auth_secret(tmp_path: Path, capsys):
    (tmp_path / 'agent.py').write_text("""
from google.adk import Agent
from google.adk.tools import GoogleApiToolset
api = GoogleApiToolset(client_secret="TOP_SECRET_VALUE")
root_agent = Agent(name="ops", instruction="PRIVATE_INSTRUCTIONS", tools=[api])
""")
    main(['scan', str(tmp_path), '--format', 'json', '--fail-on', 'none'])
    output = capsys.readouterr().out
    assert 'TOP_SECRET_VALUE' not in output
    assert 'PRIVATE_INSTRUCTIONS' not in output
