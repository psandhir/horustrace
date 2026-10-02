from pathlib import Path

from horustrace.provenance import control_observations
from horustrace.scanner import scan


def write(tmp_path: Path, contents: str, name: str = "agent.py") -> None:
    (tmp_path / name).write_text(contents, encoding="utf-8")


def test_bash_policy_requires_allowlist_and_blocklist(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.bash_tool import BashToolPolicy, ExecuteBashTool
policy = BashToolPolicy(
    allowed_command_prefixes=["git status", "pytest"],
    blocked_operators=[";", "&&", "|"],
)
root_agent = Agent(name="ops", tools=[ExecuteBashTool(policy=policy)])
''')
    graph, findings = scan(tmp_path)
    assert not any(f.rule_id == "ADK004" for f in findings)
    tool = graph.agents[0].tools[0]
    assert tool.metadata["bash_policy_restrictive"] is True
    assert any(
        control["control"] == "bash_policy"
        and control["configuration"] == "allowlist_and_blocklist_detected"
        and control["effectiveness"] == "not_verified"
        for control in control_observations(graph)
    )


def test_bash_policy_with_only_allowlist_remains_insufficient(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.bash_tool import BashToolPolicy, ExecuteBashTool
policy = BashToolPolicy(allowed_command_prefixes=["git status"])
root_agent = Agent(name="ops", tools=[ExecuteBashTool(policy=policy)])
''')
    _, findings = scan(tmp_path)
    finding = next(f for f in findings if f.rule_id == "ADK004")
    assert "blocked_operators" in finding.evidence[0]


def test_unbound_mcp_denylist_remains_inventory_only(tmp_path: Path) -> None:
    write(tmp_path, '''
{
  "mcpServers": {
    "remote": {
      "url": "https://mcp.example.test",
      "headers": {"Authorization": "Bearer runtime"},
      "deniedTools": ["delete_everything"]
    }
  }
}
''', "mcp.json")
    graph, findings = scan(tmp_path)
    server = next(item for item in graph.unbound_mcp_servers if item.name == "remote")
    assert server.denied_tools == ["delete_everything"]
    assert server.allowed_tools == []
    assert server.metadata["binding_state"] == "unbound"
    assert not any(f.rule_id == "AGT032" for f in findings)


def test_mcp_allowlist_suppresses_tool_surface_finding(tmp_path: Path) -> None:
    write(tmp_path, '''
{
  "mcpServers": {
    "remote": {
      "url": "https://mcp.example.test",
      "headers": {"Authorization": "Bearer runtime"},
      "allowedTools": ["read_ticket"]
    }
  }
}
''', "mcp.json")
    graph, findings = scan(tmp_path)
    assert not any(f.rule_id == "AGT032" for f in findings)
    assert any(
        control["control"] == "mcp_tool_allowlist"
        and control["configuration"] == "configured"
        for control in control_observations(graph)
    )


def test_sandbox_requires_timeout_network_and_filesystem_evidence(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.code_executors import AgentEngineSandboxCodeExecutor
root_agent = Agent(name="coder", code_executor=AgentEngineSandboxCodeExecutor())
''')
    _, findings = scan(tmp_path)
    finding = next(f for f in findings if f.rule_id == "ADK012")
    assert finding.evidence == ["missing=timeout,network_restriction,filesystem_restriction"]


def test_sandbox_with_all_static_limits_avoids_limit_finding(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.code_executors import AgentEngineSandboxCodeExecutor
executor = AgentEngineSandboxCodeExecutor(
    timeout_seconds=60,
    allow_network=False,
    working_dir="/workspace/project",
)
root_agent = Agent(name="coder", code_executor=executor)
''')
    graph, findings = scan(tmp_path)
    assert not any(f.rule_id == "ADK012" for f in findings)
    assert any(
        control["control"] == "sandbox_limits"
        and control["configuration"] == "timeout_network_filesystem_configured"
        for control in control_observations(graph)
    )


def test_adk_yaml_sandbox_limit_evidence(tmp_path: Path) -> None:
    write(tmp_path, '''
name: coder
model: gemini
code_executor:
  name: GkeCodeExecutor
  args:
    timeout_seconds: 120
    allow_network: false
    working_dir: /workspace/project
''', "root_agent.yaml")
    _, findings = scan(tmp_path)
    assert not any(f.rule_id == "ADK012" for f in findings)


def test_egress_observation_requires_all_discovered_destinations_to_match_policy(tmp_path: Path) -> None:
    write(tmp_path, '''
agents:
  - name: reports
    network:
      - target: https://api.example.test/upload
        restricted: true
    policy:
      allowed_destinations: [https://api.example.test/**]
''', "horustrace.manifest.yaml")
    graph, _ = scan(tmp_path)
    assert any(
        control["control"] == "egress_allowlist"
        and control["configuration"] == "all_discovered_destinations_allowed"
        for control in control_observations(graph)
    )
