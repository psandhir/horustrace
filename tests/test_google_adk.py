from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def write(tmp_path: Path, text: str, name: str = "agent.py") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_adk_function_tool_confirmation(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools import FunctionTool

def delete_customer(customer_id: str):
    pass

root_agent = Agent(name="ops", model="gemini-flash-latest", tools=[
    FunctionTool(delete_customer, require_confirmation=True)
])
''')
    graph, findings = scan(tmp_path)
    assert len(graph.agents) == 1
    assert graph.agents[0].metadata["framework"] == "google-adk"
    assert not any(f.rule_id == "AGT021" for f in findings)


def test_adk_unsafe_local_code_executor(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.code_executors import UnsafeLocalCodeExecutor
root_agent = Agent(name="coder", model="gemini-flash-latest", code_executor=UnsafeLocalCodeExecutor())
''')
    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "ADK002" in ids
    assert "PATH001" in ids


def test_adk_environment_local_detected(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.environment import LocalEnvironment
from google.adk.tools.environment import EnvironmentToolset
local = LocalEnvironment(working_dir="/")
env_tools = EnvironmentToolset(environment=local)
root_agent = Agent(name="coder", model="gemini-flash-latest", tools=[env_tools])
''')
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "ADK003" for f in findings)


def test_adk_bash_policy_missing(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.bash_tool import ExecuteBashTool
bash = ExecuteBashTool()
root_agent = Agent(name="ops", model="gemini-flash-latest", tools=[bash])
''')
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "ADK004" for f in findings)


def test_adk_mcp_remote_auth_filter_confirmation(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
mcp = McpToolset(
  connection_params=StreamableHTTPConnectionParams(
    url="https://mcp.example.com/mcp",
    headers={"Authorization": "Bearer dynamic"},
  ),
  tool_filter=["read_ticket"],
  require_confirmation=True,
)
root_agent = Agent(name="support", model="gemini-flash-latest", tools=[mcp])
''')
    graph, findings = scan(tmp_path)
    assert graph.agents[0].mcp_servers[0].authenticated is True
    ids = {f.rule_id for f in findings}
    assert "AGT030" not in ids
    assert "AGT032" not in ids


def test_adk_bigquery_blocked_write_removes_data_write(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.bigquery import BigQueryToolset
from google.adk.tools.bigquery.config import BigQueryToolConfig, WriteMode
cfg = BigQueryToolConfig(write_mode=WriteMode.BLOCKED)
bq = BigQueryToolset(bigquery_tool_config=cfg)
root_agent = Agent(name="analyst", model="gemini-flash-latest", tools=[bq])
''')
    graph, findings = scan(tmp_path)
    assert "data.write" not in graph.agents[0].capabilities
    assert not any(f.rule_id == "ADK006" for f in findings)


def test_adk_computer_use_detected(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.computer_use.computer_use_toolset import ComputerUseToolset
computer = ComputerUseToolset(computer=PlaywrightComputer())
root_agent = Agent(name="browser", model="gemini-computer-use", tools=[computer])
''')
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "ADK005" for f in findings)


def test_adk_subagent_delegation_propagates_privilege(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.bash_tool import ExecuteBashTool
child = Agent(name="privileged_child", model="gemini-flash-latest", tools=[ExecuteBashTool()])
root_agent = Agent(name="coordinator", model="gemini-flash-latest", sub_agents=[child])
''')
    graph, findings = scan(tmp_path)
    parent = next(a for a in graph.agents if a.name == "coordinator")
    assert "process.execute" in parent.capabilities
    delegated = next(tool for tool in parent.tools if tool.kind == "delegated_agent")
    assert delegated.approval is True
    assert delegated.metadata["authority_binding"] == "delegation_projection"
    assert delegated.metadata["authority_binding_basis"] == "adk_delegates_to"
    assert "process.execute" in delegated.capabilities

    authority = effective_authority_report(graph)
    assert not any(
        item["agent"] == "coordinator"
        and item["target"]["name"] == "delegate:privileged_child"
        for item in authority["relationships"]
    )
    assert graph.adg is not None
    delegated_node = next(
        node
        for node in graph.adg.nodes
        if node.kind == "delegation"
        and node.attributes.get("tool_name") == "delegate:privileged_child"
    )
    assert delegated_node.attributes["authority_binding"] == "delegation_projection"
    assert delegated_node.attributes["authority_binding_basis"] == "adk_delegates_to"
    assert not any(
        edge.kind == "INVOKES" and edge.target == delegated_node.node_id
        for edge in graph.adg.edges
    )
    assert any(edge.kind == "DELEGATES_TO" for edge in graph.adg.edges)
    assert not any(f.rule_id == "PATH001" and f.agent == "coordinator" for f in findings)


def test_adk_remote_a2a_http_unauthenticated(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
remote = RemoteA2aAgent(name="remote", agent_card="http://remote.example/.well-known/agent-card.json")
''')
    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "ADK009" in ids
    assert "ADK010" in ids


def test_adk_yaml_config(tmp_path: Path) -> None:
    write(tmp_path, '''
name: search_agent
model: gemini-flash-latest
instruction: Search the web.
tools:
  - name: GoogleSearchTool
''', "root_agent.yaml")
    graph, _ = scan(tmp_path)
    assert len(graph.agents) == 1
    assert graph.agents[0].metadata["adk_config"] is True
    assert "network.external" in graph.agents[0].capabilities


def test_adk_env_secret_redacted_finding(tmp_path: Path) -> None:
    write(tmp_path, 'GOOGLE_API_KEY="test-placeholder-not-a-real-key"\n', ".env")
    _, findings = scan(tmp_path)
    finding = next(f for f in findings if f.rule_id == "IDN004")
    assert "test-placeholder-not-a-real-key" not in " ".join(finding.evidence)


def test_adk_google_api_toolset_broad_oauth_scope_reaches_identity_layer(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.google_api_tool import GoogleApiToolset
api = GoogleApiToolset(
    additional_scopes=["https://www.googleapis.com/auth/cloud-platform"],
    client_secret="test-placeholder-not-a-real-secret",
)
root_agent = Agent(name="api_agent", model="gemini-flash-latest", tools=[api])
''')
    graph, findings = scan(tmp_path)
    assert any(i.oauth_scopes == {"https://www.googleapis.com/auth/cloud-platform"} for i in graph.identities)
    ids = {f.rule_id for f in findings}
    assert "IDN003" in ids
    assert "IDN004" in ids
    assert not any("test-placeholder-not-a-real-secret" in " ".join(f.evidence) for f in findings)


def test_adk_noop_before_tool_callback_is_not_credited_as_enforcement(tmp_path: Path) -> None:
    write(tmp_path, '''
import subprocess
from google.adk import Agent

def run_command(command: str):
    return subprocess.run(command, shell=True)

def security_gate(tool, args, context):
    return None

root_agent = Agent(
    name="controlled_ops",
    model="gemini-flash-latest",
    tools=[run_command],
    before_tool_callback=security_gate,
)
''')
    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "controlled_ops")
    assert agent.metadata["tool_control_state"] == "non_enforcing"
    assert agent.metadata["tool_control_enforcing"] is False
    assert any(f.rule_id == "ADK001" for f in findings)

    relationship = next(
        item
        for item in effective_authority_report(graph)["relationships"]
        if item["agent"] == "controlled_ops" and item["target"]["kind"] == "tool"
    )
    assert relationship["dimensions"]["approval"] == "unknown"
    assert relationship["approval"]["inherited_control"] is False


def test_adk_blocking_before_tool_callback_is_credited_as_control(tmp_path: Path) -> None:
    write(tmp_path, '''
import subprocess
from google.adk import Agent

def run_command(command: str):
    return subprocess.run(command, shell=True)

def security_gate(tool, args, context):
    if getattr(tool, "name", "") == "run_command":
        return {"error": "blocked by policy"}
    return None

root_agent = Agent(
    name="controlled_ops",
    model="gemini-flash-latest",
    tools=[run_command],
    before_tool_callback=security_gate,
)
''')
    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "controlled_ops")
    assert agent.metadata["tool_control_state"] == "enforcing"
    assert agent.metadata["tool_control_enforcing"] is True
    assert not any(f.rule_id == "ADK001" for f in findings)

    relationship = next(
        item
        for item in effective_authority_report(graph)["relationships"]
        if item["agent"] == "controlled_ops" and item["target"]["kind"] == "tool"
    )
    assert relationship["dimensions"]["approval"] == "resolved"
    assert relationship["approval"]["inherited_control"] is True
    assert relationship["approval"]["mechanism"] == "adk_before_tool_callback"


def test_adk_agenttool_plugin_isolation_detected(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.agent_tool import AgentTool
child = Agent(name="child", model="gemini-flash-latest")
delegate = AgentTool(agent=child, include_plugins=False)
root_agent = Agent(name="parent", model="gemini-flash-latest", tools=[delegate])
''')
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "ADK008" for f in findings)


def test_adk_secure_remote_a2a_does_not_emit_transport_auth_findings(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
remote = RemoteA2aAgent(
    name="remote",
    agent_card="https://remote.example/.well-known/agent-card.json",
    auth_scheme=object(),
    auth_credential=object(),
)
''')
    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "ADK009" not in ids
    assert "ADK010" not in ids


def test_adk_yaml_cross_file_subagent_privilege_propagates(tmp_path: Path) -> None:
    child_dir = tmp_path / "privileged_worker"
    child_dir.mkdir()
    (child_dir / "agent.yaml").write_text('''
name: shell_specialist
model: gemini-flash-latest
code_executor:
  name: UnsafeLocalCodeExecutor
''', encoding="utf-8")
    (tmp_path / "root_agent.yaml").write_text('''
name: coordinator
model: gemini-flash-latest
sub_agents:
  - config_path: privileged_worker/agent.yaml
''', encoding="utf-8")
    graph, findings = scan(tmp_path)
    parent = next(a for a in graph.agents if a.name == "coordinator")
    assert "process.execute" in parent.capabilities
    assert any(f.rule_id == "PATH001" and f.agent == "coordinator" for f in findings)


def test_adk_workflow_agent_is_first_class(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk.agents import Agent, ParallelAgent
research = Agent(name="research", model="gemini-flash-latest")
review = Agent(name="review", model="gemini-flash-latest")
root_agent = ParallelAgent(name="workflow", sub_agents=[research, review])
''')
    graph, _ = scan(tmp_path)
    workflow = next(a for a in graph.agents if a.name == "workflow")
    assert workflow.metadata.get("workflow") == "ParallelAgent"
    assert set(workflow.metadata.get("delegates_to") or []) == {"research", "review"}


def test_adk_re_compile_is_not_process_execution(tmp_path: Path) -> None:
    write(tmp_path, '''
import re
from google.adk import Agent

def send_email(address: str) -> bool:
    pattern = re.compile(r"^[^@]+@[^@]+$")
    return bool(pattern.match(address))

root_agent = Agent(name="mail", model="gemini-flash-latest", tools=[send_email])
''')
    graph, findings = scan(tmp_path)
    tool = next(t for t in graph.agents[0].tools if t.name == "send_email")
    assert "process.execute" not in tool.capabilities
    assert not any(f.rule_id == "AGT020" for f in findings)


def test_adk_builtin_compile_is_process_execution(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent

def compile_expression(source: str):
    return compile(source, "<agent>", "eval")

root_agent = Agent(name="compiler", model="gemini-flash-latest", tools=[compile_expression])
''')
    graph, findings = scan(tmp_path)
    tool = next(t for t in graph.agents[0].tools if t.name == "compile_expression")
    assert "process.execute" in tool.capabilities
    assert any(f.rule_id == "AGT020" for f in findings)



def test_adk_prompt_defense_plugin_is_not_action_approval(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent, App
from trustworthy import SoftInstructionDefensePlugin

def delete_user(user_id: str):
    return {"deleted": user_id}

root_agent = Agent(name="admin", tools=[delete_user])
app = App(root_agent=root_agent, plugins=[SoftInstructionDefensePlugin()])
''')
    graph, findings = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "admin")
    tool = next(t for t in agent.tools if t.name == "delete_user")

    assert agent.metadata.get("safety_plugin") is True
    assert agent.metadata.get("approval_plugin") is not True
    assert tool.approval is not True
    assert tool.guardrails is False
    assert any(f.rule_id == "ADK001" and f.agent == "admin" for f in findings)


def test_adk_hitl_plugin_without_explicit_scope_is_not_global_control(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent, App
from trustworthy import HITLToolPlugin

def delete_user(user_id: str):
    return {"deleted": user_id}

root_agent = Agent(name="admin", tools=[delete_user])
app = App(root_agent=root_agent, plugins=[HITLToolPlugin()])
''')
    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "admin")
    assert agent.metadata.get("approval_plugin") is True
    assert agent.metadata.get("approval_plugin_scope_unresolved") is True
    assert agent.metadata.get("tool_control_enforcing") is not True
    assert any(f.rule_id == "ADK001" and f.agent == "admin" for f in findings)


def test_adk_hitl_plugin_approves_only_named_sensitive_tools(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent, App
from trustworthy import HITLToolPlugin

def delete_user(user_id: str):
    return {"deleted": user_id}

def update_note(note: str):
    return {"note": note}

root_agent = Agent(name="admin", tools=[delete_user, update_note])
app = App(
    root_agent=root_agent,
    plugins=[HITLToolPlugin(sensitive_tools=["delete_user"])],
)
''')
    graph, _ = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "admin")
    delete_tool = next(t for t in agent.tools if t.name == "delete_user")
    note_tool = next(t for t in agent.tools if t.name == "update_note")

    assert agent.metadata.get("approval_plugin") is True
    assert delete_tool.approval is True
    assert delete_tool.metadata.get("approval_mechanism") == "adk_hitl_tool_plugin"
    assert graph.adg is not None
    controls = [
        node
        for node in graph.adg.nodes
        if node.kind == "approval_control"
    ]
    assert len(controls) == 1
    assert controls[0].attributes["mechanism"] == "adk_hitl_tool_plugin"
    assert controls[0].attributes["protects_tool"] == "delete_user"
    assert controls[0].attributes["mandatory"] is True
    assert any(
        edge.kind == "GUARDED_BY" and edge.target == controls[0].node_id
        for edge in graph.adg.edges
    )
    assert note_tool.approval is not True
    assert note_tool.guardrails is False



def test_adk_env_example_placeholder_is_not_runtime_credential(tmp_path: Path) -> None:
    write(tmp_path, 'GEMINI_API_KEY="your-gemini-key-here"\n', ".env.example")
    _, findings = scan(tmp_path)
    assert not any(f.rule_id == "IDN004" for f in findings)



def test_repository_import_resolution_does_not_confuse_re_with_core_module(tmp_path: Path) -> None:
    """Regression for frozen trustworthy-adk: re.compile must stay stdlib regex."""
    write(tmp_path, '''
def compile(source: str):
    return eval(source)
''', "core.py")
    write(tmp_path, '''
import re

def send_email(address: str) -> bool:
    pattern = re.compile(r"^[^@]+@[^@]+$")
    return bool(pattern.match(address))
''', "email_tool.py")
    write(tmp_path, '''
from google.adk import Agent
import email_tool

root_agent = Agent(
    name="workspace_agent",
    model="gemini-flash-latest",
    tools=[email_tool.send_email],
)
''', "agent.py")

    graph, findings = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "workspace_agent")
    tool = next(t for t in agent.tools if t.name == "send_email")

    assert "process.execute" not in tool.capabilities
    assert not any(
        f.rule_id == "AGT020" and f.agent == "workspace_agent"
        for f in findings
    )


def test_adk_fixed_literal_destination_is_not_broad_egress(tmp_path: Path) -> None:
    write(tmp_path, '''
import requests
from google.adk import Agent

def publish_event(payload: dict):
    return requests.post("https://api.example.com/events", json=payload)

root_agent = Agent(name="publisher", model="gemini-flash-latest", tools=[publish_event])
''')
    graph, findings = scan(tmp_path)
    tool = next(t for t in graph.agents[0].tools if t.name == "publish_event")

    assert any(
        d.target == "https://api.example.com/events"
        and d.metadata.get("network_scope") == "fixed_literal_destination"
        for d in tool.destinations
    )
    assert not any(f.rule_id == "NET001" for f in findings)


def test_adk_dynamic_destination_remains_broad_egress(tmp_path: Path) -> None:
    write(tmp_path, '''
import requests
from google.adk import Agent

def publish_event(url: str, payload: dict):
    return requests.post(url, json=payload)

root_agent = Agent(name="publisher", model="gemini-flash-latest", tools=[publish_event])
''')
    graph, findings = scan(tmp_path)
    tool = next(t for t in graph.agents[0].tools if t.name == "publish_event")

    assert any(
        d.metadata.get("network_scope") == "dynamic_destination"
        for d in tool.destinations
    )
    assert any(f.rule_id == "NET001" for f in findings)


def test_adk_v2_workflow_root_is_first_class(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk.agents import LlmAgent
from google.adk.workflow import Workflow, START, Edge

risk_reviewer = LlmAgent(
    name="risk_reviewer",
    model="gemini-flash-latest",
)

root_agent = Workflow(
    name="root_agent",
    edges=[
        Edge(from_node=START, to_node=risk_reviewer),
    ],
)
''')
    graph, _ = scan(tmp_path)

    root = next(a for a in graph.agents if a.name == "root_agent")
    reviewer = next(a for a in graph.agents if a.name == "risk_reviewer")

    assert root.metadata["framework"] == "google-adk"
    assert root.metadata["agent_type"] == "Workflow"
    assert root.metadata["workflow"] == "Workflow"
    assert root.metadata["workflow_edges"] == [
        {"source": "START", "target": "risk_reviewer"}
    ]
    assert root.metadata["delegates_to"] == ["risk_reviewer"]
    assert reviewer.metadata["agent_type"] == "LlmAgent"

    assert graph.adg is not None
    root_node = next(
        node for node in graph.adg.nodes
        if node.kind == "agent" and node.name == "root_agent"
    )
    reviewer_node = next(
        node for node in graph.adg.nodes
        if node.kind == "agent" and node.name == "risk_reviewer"
    )
    assert any(
        edge.kind == "WORKFLOW_FLOWS_TO"
        and edge.source == root_node.node_id
        and edge.target == reviewer_node.node_id
        for edge in graph.adg.edges
    )


def test_adk_v2_workflow_routes_preserve_function_nodes_and_routes(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Event, Workflow
from google.adk.agents import LlmAgent

def router(node_input: str):
    if node_input == "b":
        return Event(route="RUN_B")
    return Event(route="RUN_C")

task_b = LlmAgent(name="task_b", model="gemini-flash-latest")
task_c = LlmAgent(name="task_c", model="gemini-flash-latest")

root_agent = Workflow(
    name="routing_workflow",
    edges=[
        ("START", router),
        (router, {"RUN_B": task_b, "RUN_C": task_c}),
    ],
)
''')
    graph, _ = scan(tmp_path)
    root = next(item for item in graph.agents if item.name == "routing_workflow")

    assert root.metadata["workflow_edges"] == [
        {"source": "START", "target": "router"},
        {"source": "router", "target": "task_b", "route": "RUN_B"},
        {"source": "router", "target": "task_c", "route": "RUN_C"},
    ]
    assert set(root.metadata["delegates_to"]) == {"task_b", "task_c"}

    assert graph.adg is not None
    router_node = next(
        node
        for node in graph.adg.nodes
        if node.kind == "workflow_node"
        and node.attributes.get("node_name") == "router"
    )
    task_b_node = next(
        node for node in graph.adg.nodes
        if node.kind == "agent" and node.name == "task_b"
    )
    assert any(
        edge.kind == "WORKFLOW_FLOWS_TO"
        and edge.source == router_node.node_id
        and edge.target == task_b_node.node_id
        and edge.attributes.get("route") == "RUN_B"
        for edge in graph.adg.edges
    )


def test_adk_same_alias_constructions_keep_source_instance_identity(
    tmp_path: Path,
) -> None:
    write(tmp_path, '''
from google.adk.agents import LlmAgent

def build_left(model):
    agent = LlmAgent(model=model, name=f"left_{model}")
    return agent

def build_right(model):
    agent = LlmAgent(model=model, name=f"right_{model}")
    return agent
''', "left.py")
    write(tmp_path, '''
from google.adk.agents import LlmAgent

def build_summary(model):
    agent = LlmAgent(model=model, name=f"summary_{model}")
    return agent
''', "right.py")

    graph, _ = scan(tmp_path)

    agents = [item for item in graph.agents if item.metadata.get("agent_type") == "LlmAgent"]
    assert len(agents) == 3
    assert len({item.metadata["instance_key"] for item in agents}) == 3
    assert {item.location.path.name for item in agents if item.location} == {
        "left.py",
        "right.py",
    }


def test_adk_reused_mcp_alias_resolves_within_lexical_scope(
    tmp_path: Path,
) -> None:
    write(tmp_path, '''
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool import McpToolset, StdioConnectionParams

def build_docs(model):
    params = StdioConnectionParams(server_params={"command": "python", "args": ["docs.py"]})
    mcp = McpToolset(connection_params=params, tool_filter=["read_docs"])
    agent = LlmAgent(model=model, name=f"docs_{model}", tools=[mcp])
    return agent

def build_data(model):
    params = StdioConnectionParams(server_params={"command": "python", "args": ["data.py"]})
    mcp = McpToolset(connection_params=params, tool_filter=["read_data"])
    agent = LlmAgent(model=model, name=f"data_{model}", tools=[mcp])
    return agent
''')

    graph, _ = scan(tmp_path)

    agents = [item for item in graph.agents if item.metadata.get("agent_type") == "LlmAgent"]
    assert len(agents) == 2
    servers = [server for agent in agents for server in agent.mcp_servers]
    assert len(servers) == 2
    assert len({server.location.line for server in servers if server.location}) == 2
    assert {tuple(server.allowed_tools) for server in servers} == {
        ("read_docs",),
        ("read_data",),
    }


def test_adk_repository_resolves_imported_composed_tool_lists(tmp_path: Path) -> None:
    write(tmp_path, '''
def get_balance(account_id: str):
    return ledger.get(account_id)

def transfer_money(account_id: str, amount: float):
    return ledger.update(account_id, amount)

BANKING_TOOLS = [get_balance, transfer_money]
''', "banking.py")
    write(tmp_path, '''
def safety_check(action: str):
    return {"allowed": True}

def resolve_escalation(ticket_id: str):
    return store.update(ticket_id, {"resolved": True})

OBSERVABILITY_TOOLS = [safety_check, resolve_escalation]
''', "observability.py")
    write(tmp_path, '''
from banking import BANKING_TOOLS
from observability import OBSERVABILITY_TOOLS

ALL_TOOLS = BANKING_TOOLS + OBSERVABILITY_TOOLS
''', "catalog.py")
    write(tmp_path, '''
from google.adk import Agent
from catalog import ALL_TOOLS

root_agent = Agent(
    name="scope_safety_router",
    model="gemini-flash-latest",
    tools=ALL_TOOLS,
)
''', "agent.py")

    graph, findings = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "scope_safety_router")
    assert {tool.name for tool in agent.tools} == {
        "get_balance",
        "transfer_money",
        "safety_check",
        "resolve_escalation",
    }
    transfer = next(
        tool for tool in agent.tools if tool.name == "transfer_money"
    )
    assert "data.write" in transfer.capabilities
    assert any(
        f.rule_id == "ADK001" and f.agent == "scope_safety_router"
        for f in findings
    )
    assert any(
        f.rule_id == "CAP005" and f.agent == "scope_safety_router"
        for f in findings
    )


def test_adk_repository_does_not_execute_dynamic_tool_sequence_builders(
    tmp_path: Path,
) -> None:
    write(tmp_path, '''
def safe_read():
    return "ok"

def build_tools():
    return [safe_read]

DYNAMIC_TOOLS = build_tools()
''', "catalog.py")
    write(tmp_path, '''
from google.adk import Agent
from catalog import DYNAMIC_TOOLS

root_agent = Agent(
    name="safe_agent",
    model="gemini-flash-latest",
    tools=DYNAMIC_TOOLS,
)
''', "agent.py")

    graph, _ = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "safe_agent")
    assert len(agent.tools) == 1
    dynamic = agent.tools[0]
    assert dynamic.name == "DYNAMIC_TOOLS"
    assert dynamic.metadata.get("binding_unresolved") is True
    assert dynamic.metadata.get("dynamic_bound_collection") is True
    assert dynamic.capabilities == set()

    relationship = next(
        item
        for item in effective_authority_report(graph)["relationships"]
        if item["agent"] == "safe_agent"
        and item["target"] == {"kind": "tool", "name": "DYNAMIC_TOOLS"}
    )
    assert relationship["dimensions"]["target"] == "resolved"
    assert "capabilities" in relationship["unresolved"]

def test_adk_repository_infers_qualified_mutation_method_calls(
    tmp_path: Path,
) -> None:
    write(tmp_path, """
class Ledger:
    def get_account(self, account_id: str):
        return account_id

    def update_account(self, account_id: str, amount: float):
        return None

    def create_transaction(self, account_id: str, amount: float):
        return None

ledger = Ledger()

def get_account_balance(account_id: str):
    return ledger.get_account(account_id)

def transfer_money(account_id: str, amount: float):
    ledger.update_account(account_id, amount)
    ledger.create_transaction(account_id, amount)
    return "ok"

BANKING_TOOLS = [get_account_balance, transfer_money]
""", "banking.py")
    write(tmp_path, """
from google.adk import Agent
from banking import BANKING_TOOLS

root_agent = Agent(
    name="scope_safety_router",
    model="gemini-flash-latest",
    tools=BANKING_TOOLS,
)
""", "agent.py")

    graph, findings = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "scope_safety_router")
    balance = next(t for t in agent.tools if t.name == "get_account_balance")
    transfer = next(t for t in agent.tools if t.name == "transfer_money")

    assert "data.read" in balance.capabilities
    assert "data.write" in transfer.capabilities
    assert any(
        f.rule_id == "ADK001" and f.agent == "scope_safety_router"
        for f in findings
    )
    assert any(
        f.rule_id == "CAP005" and f.agent == "scope_safety_router"
        for f in findings
    )



def test_adk_model_selected_file_read_to_document_ai_is_proven_path(
    tmp_path: Path,
) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "__init__.py").write_text("", encoding="utf-8")
    (tools / "document_ocr.py").write_text(
        """
import os
from google.cloud import documentai_v1 as documentai


def process_document_with_ocr(document_path: str) -> str:
    if not os.path.isabs(document_path):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        document_path = os.path.join(project_root, document_path)

    with open(document_path, "rb") as handle:
        document_content = handle.read()

    raw_document = documentai.RawDocument(
        content=document_content,
        mime_type="application/pdf",
    )
    request = documentai.ProcessRequest(
        name="projects/p/locations/us/processors/x",
        raw_document=raw_document,
    )
    client = documentai.DocumentProcessorServiceClient()
    return client.process_document(request=request)
""",
        encoding="utf-8",
    )
    write(
        tmp_path,
        """
from google.adk.agents import Agent
from tools.document_ocr import process_document_with_ocr

root_agent = Agent(
    name="document_processing_agent",
    model="gemini-flash-latest",
    tools=[process_document_with_ocr],
)
""",
        "agent.py",
    )

    graph, findings = scan(tmp_path)

    agent = next(a for a in graph.agents if a.name == "document_processing_agent")
    tool = next(t for t in agent.tools if t.name == "process_document_with_ocr")

    assert tool.metadata["model_selected_file_read"] is True
    assert tool.metadata["filesystem_path_constrained"] is False
    assert tool.metadata["file_read_external_transfer"] is True
    assert any(
        item.kind == "file" and item.selector == "<model-selected-file>"
        for item in tool.resources
    )
    assert any(
        item.target == "https://documentai.googleapis.com/"
        and item.metadata.get("network_scope") == "fixed_managed_service"
        for item in tool.destinations
    )
    assert not any(
        f.rule_id == "DATA001" and f.agent == "document_processing_agent"
        for f in findings
    )
    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH010"
        and item.agent == "document_processing_agent"
    )
    assert path.metadata["basis"] == "source_proven_tool_dataflow"
    assert path.metadata["path_containment"] == "not_detected"
    assert any(
        f.rule_id == "PATH010" and f.agent == "document_processing_agent"
        for f in findings
    )


def test_adk_explicit_file_containment_suppresses_file_transfer_path(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
from pathlib import Path
import requests
from google.adk.agents import Agent


def upload_document(document_path: str):
    root = Path("data").resolve()
    resolved = (root / document_path).resolve()
    resolved.relative_to(root)
    with open(resolved, "rb") as handle:
        content = handle.read()
    return requests.post("https://upload.example.com/document", data=content)


root_agent = Agent(
    name="contained_reader",
    model="gemini-flash-latest",
    tools=[upload_document],
)
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "contained_reader")
    tool = next(t for t in agent.tools if t.name == "upload_document")

    assert tool.metadata["model_selected_file_read"] is True
    assert tool.metadata["filesystem_path_constrained"] is True
    assert tool.metadata["file_read_external_transfer"] is True
    assert not any(f.rule_id == "DATA001" for f in findings)
    assert not any(f.rule_id == "PATH010" for f in findings)
    assert not any(item.path_id == "PATH010" for item in graph.attack_paths)


def test_adk_unrelated_network_call_does_not_create_file_transfer_path(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
import requests
from google.adk.agents import Agent


def inspect_document(document_path: str):
    with open(document_path, "rb") as handle:
        content = handle.read()
    requests.post("https://metrics.example.com/events", json={"event": "read"})
    return len(content)


root_agent = Agent(
    name="reader",
    model="gemini-flash-latest",
    tools=[inspect_document],
)
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "reader")
    tool = next(t for t in agent.tools if t.name == "inspect_document")

    assert tool.metadata["model_selected_file_read"] is True
    assert tool.metadata.get("file_read_external_transfer") is not True
    assert any(
        resource.selector == "<model-selected-file>"
        for resource in tool.resources
    )
    assert not any(f.rule_id == "DATA001" for f in findings)
    assert not any(f.rule_id == "PATH010" for f in findings)
    assert not any(item.path_id == "PATH010" for item in graph.attack_paths)


def test_adk_provider_managed_code_executor_is_not_host_process_authority(
    tmp_path: Path,
) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.code_executors import BuiltInCodeExecutor

root_agent = Agent(
    name="auditor",
    model="gemini-flash-latest",
    code_executor=BuiltInCodeExecutor(),
)
''')
    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "auditor")
    executor = next(item for item in agent.tools if item.kind == "adk_code_executor")

    assert executor.metadata["execution_boundary"] == "provider-managed"
    assert executor.capabilities == {"provider.code.execute"}
    assert "process.execute" not in agent.capabilities
    assert not any(
        finding.rule_id in {"AGT020", "CAP005", "PATH001", "PATH006", "PATH008"}
        for finding in findings
    )


def test_adk_policy_read_name_does_not_imply_identity_admin(
    tmp_path: Path,
) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools import FunctionTool

def check_company_policy(topic: str) -> str:
    return "Travel policy: economy class."

policy = FunctionTool(check_company_policy)
root_agent = Agent(
    name="policy_helper",
    model="gemini-flash-latest",
    tools=[policy],
)
''')
    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "policy_helper")
    tool = next(item for item in agent.tools if item.name == "check_company_policy")

    assert "identity.admin" not in tool.capabilities
    assert not any(
        finding.rule_id in {"AGT040", "ADK001"}
        and finding.agent == "policy_helper"
        for finding in findings
    )


def test_adk_function_tool_dynamic_path_keeps_fixed_provider_destination(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import requests
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

def fetch_repo(repo_url: str):
    owner, repo = repo_url.replace("https://github.com/", "").split("/")[:2]
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
    return requests.get(api_url).json()

agent = LlmAgent(
    name="reader",
    model="gemini-3.1-flash-lite",
    tools=[FunctionTool(func=fetch_repo)],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "reader")
    tool = next(item for item in agent.tools if item.name == "fetch_repo")
    assert any(
        destination.target == "https://api.github.com"
        and destination.restricted is True
        and destination.metadata.get("network_scope") == "fixed_provider_network"
        for destination in tool.destinations
    )
    assert not any(finding.rule_id in {"NET001", "NET002"} for finding in findings)
    assert not any(path.path_id == "PATH009" for path in graph.attack_paths)


def test_adk_imported_function_tool_keeps_fixed_provider_destination(
    tmp_path: Path,
) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "__init__.py").write_text("", encoding="utf-8")
    (tools / "github_tool.py").write_text(
        """
import requests

def fetch_iac_files(repo_url: str):
    owner, repo = repo_url.replace("https://github.com/", "").split("/")[:2]
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
    response = requests.get(api_url, timeout=15)
    items = response.json()
    for item in items:
        requests.get(item["url"], timeout=15)
    return items
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from tools.github_tool import fetch_iac_files

agent = LlmAgent(
    name="reader",
    model="gemini-3.1-flash-lite",
    tools=[FunctionTool(func=fetch_iac_files)],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "reader")
    tool = next(item for item in agent.tools if item.name == "fetch_iac_files")
    assert tool.metadata["network_scope"] == "fixed_provider_network"
    assert any(
        destination.target == "https://api.github.com"
        and destination.restricted is True
        for destination in tool.destinations
    )
    assert not any(finding.rule_id in {"NET001", "NET002"} for finding in findings)
    assert not any(path.path_id == "PATH009" for path in graph.attack_paths)

def test_adk_delegation_projection_preserves_fixed_provider_destination(
    tmp_path: Path,
) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "__init__.py").write_text("", encoding="utf-8")
    (tools / "github_tool.py").write_text(
        """
import requests

def fetch_repo(repo_url: str):
    owner, repo = repo_url.replace("https://github.com/", "").split("/")[:2]
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
    return requests.get(api_url, timeout=15).json()
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from tools.github_tool import fetch_repo

reader = LlmAgent(
    name="reader",
    model="gemini-3.1-flash-lite",
    tools=[FunctionTool(func=fetch_repo)],
)

root_agent = LlmAgent(
    name="root_agent",
    model="gemini-3.1-flash-lite",
    sub_agents=[reader],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    root = next(item for item in graph.agents if item.name == "root_agent")
    delegated = next(
        item for item in root.tools if item.kind == "delegated_agent"
    )
    assert "network.external" in delegated.capabilities
    assert any(
        destination.target == "https://api.github.com"
        and destination.restricted is True
        for destination in delegated.destinations
    )
    assert not any(
        finding.rule_id == "NET002" and finding.agent == "root_agent"
        for finding in findings
    )
    assert not any(
        path.path_id == "PATH009" and path.agent == "root_agent"
        for path in graph.attack_paths
    )

def test_adk_url_context_keeps_model_selected_target_through_agent_tool_delegation(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import LlmAgent
from google.adk.tools import AgentTool, url_context

url_reader = LlmAgent(
    name="url_reader",
    model="gemini-3-flash-preview",
    instruction="Retrieve content from URLs supplied by the caller.",
    tools=[url_context],
)

root_agent = LlmAgent(
    name="root_agent",
    model="gemini-3-flash-preview",
    tools=[AgentTool(agent=url_reader)],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    child = next(item for item in graph.agents if item.name == "url_reader")
    tool = next(item for item in child.tools if item.name == "url_context")

    assert tool.metadata["provider_network_scope"] == "fixed_managed_service"
    assert tool.metadata["network_scope"] == "dynamic_destination"
    assert tool.metadata["model_selected_url_fetch"] is True
    assert tool.metadata["destination_provenance"] == "model_selected_url_argument"
    assert any(
        destination.target == "<model-selected-url>"
        and destination.restricted is False
        and destination.metadata.get("network_scope") == "dynamic_destination"
        for destination in tool.destinations
    )

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH011"
        and item.agent == "root_agent"
        and item.metadata.get("network_abstraction") == "url_context"
    )
    assert path.metadata["basis"] == "source_bound_delegated_authority"
    assert path.metadata["provider_network_scope"] == "fixed_managed_service"
    assert "delegate:url_reader" in path.nodes
    assert "<model-selected-url>" in path.nodes
    assert not any(
        item.path_id == "PATH009"
        and item.agent == "root_agent"
        and "url_context" in item.nodes
        for item in graph.attack_paths
    )




def test_adk_delegation_preserves_operator_configured_network_scope() -> None:
    from horustrace.analysis import build_attack_paths
    from horustrace.models import Agent, Graph, InputSource, Tool
    from horustrace.rules.builtin import evaluate
    from horustrace.scanner import _propagate_adk_delegation

    child = Agent(
        name="child",
        metadata={"framework": "google-adk"},
        tools=[
            Tool(
                name="configured_remote_call",
                kind="adk_function",
                capabilities={"network.external", "data.read"},
                metadata={"network_scope": "operator_configured_destination"},
            )
        ],
    )
    parent = Agent(
        name="parent",
        inputs=[InputSource(name="user", trust="untrusted")],
        metadata={
            "framework": "google-adk",
            "delegates_to": ["child"],
        },
    )
    graph = Graph(agents=[parent, child])

    _propagate_adk_delegation(graph)

    delegated = next(
        tool for tool in parent.tools if tool.kind == "delegated_agent"
    )
    assert delegated.metadata["network_scope"] == "operator_configured_destination"
    assert not any(
        finding.rule_id == "NET002" and finding.agent == "parent"
        for finding in evaluate(graph)
    )
    assert not any(
        path.path_id == "PATH009" and path.agent == "parent"
        for path in build_attack_paths(graph)
    )

def test_adk_custom_base_agent_subclass_is_discovered(tmp_path: Path) -> None:
    write(
        tmp_path,
        """
from google.adk.agents import BaseAgent

class AlphaBotAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="AlphaBot")

    async def _run_async_impl(self, ctx):
        return ctx

root_agent = AlphaBotAgent()
""",
        "agent.py",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.metadata.get("source_alias") == "root_agent")
    assert agent.metadata["agent_type"] == "AlphaBotAgent"
    assert agent.metadata["custom_base_agent"] is True
    assert agent.metadata["semantic_entrypoints"] == ["_run_async_impl"]
    assert any(item.trust == "untrusted" for item in agent.inputs)



def test_adk_env_configured_remote_mcp_is_not_caller_selected(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        """
import os
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset

MCP_URL = os.environ.get("MCP_SERVER_URL", "https://mcp.example.invalid/mcp")

toolset = McpToolset(
    connection_params=StreamableHTTPConnectionParams(url=MCP_URL),
)

root_agent = LlmAgent(
    name="configured_mcp_agent",
    model="gemini-flash-latest",
    tools=[toolset],
)
""",
        "agent.py",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "configured_mcp_agent")
    server = next(item for item in agent.mcp_servers if item.name == "toolset")

    assert server.metadata["dynamic_mcp_endpoint"] is True
    assert server.metadata["dynamic_mcp_endpoint_basis"] == "operator_configuration"
    assert server.metadata["configuration_source"] == "MCP_SERVER_URL"
    assert any(
        destination.target == "<operator-configured-mcp>"
        and destination.restricted is True
        for destination in agent.effective_destinations
    )
    assert not any(
        finding.rule_id == "NET001" and finding.agent == "configured_mcp_agent"
        for finding in findings
    )


def test_adk_openapi_toolset_preserves_fixed_server_origins(
    tmp_path: Path,
) -> None:
    (tmp_path / "account_api_spec.json").write_text(
        """
{
  "openapi": "3.0.0",
  "servers": [
    {"url": "https://api.accountservice.com/v1"},
    {"url": "https://staging.api.accountservice.com/v1"}
  ],
  "paths": {
    "/accounts/{accountId}": {
      "get": {"responses": {"200": {"description": "ok"}}},
      "delete": {"responses": {"204": {"description": "deleted"}}}
    }
  }
}
""",
        encoding="utf-8",
    )
    write(
        tmp_path,
        """
import json
from pathlib import Path
from google.adk.agents import LlmAgent
from google.adk.tools.openapi_tool.openapi_spec_parser.openapi_toolset import OpenAPIToolset

def load_openapi_spec():
    spec_file = Path(__file__).parent / "account_api_spec.json"
    with open(spec_file, "r", encoding="utf-8") as handle:
        return json.load(handle)

open_api_spec = load_openapi_spec()
toolset = OpenAPIToolset(spec_dict=open_api_spec)

root_agent = LlmAgent(
    name="api_interacting_agent",
    model="gemini-flash-latest",
    tools=[toolset],
)
""",
        "agent.py",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "api_interacting_agent")
    tool = next(item for item in agent.tools if item.name == "toolset")

    assert tool.metadata["network_scope"] == "explicit_destination"
    assert set(tool.metadata["openapi_servers"]) == {
        "https://api.accountservice.com",
        "https://staging.api.accountservice.com",
    }
    assert {
        destination.target
        for destination in tool.destinations
        if destination.restricted is True
    } == {
        "https://api.accountservice.com",
        "https://staging.api.accountservice.com",
    }
    assert not any(
        finding.rule_id == "NET002" and finding.agent == "api_interacting_agent"
        for finding in findings
    )


def test_adk_openapi_named_spec_preserves_operations_and_server(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.openapi_tool import OpenAPIToolset

spec = {
    "openapi": "3.0.0",
    "info": {"title": "Accounts", "version": "1.0"},
    "servers": [{"url": "https://api.accounts.example.com/v1"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"}
        }
    },
    "security": [{"bearerAuth": []}],
    "paths": {
        "/accounts/{account_id}": {
            "get": {
                "operationId": "getAccount",
                "responses": {"200": {"description": "ok"}},
            },
            "delete": {
                "operationId": "deleteAccount",
                "responses": {"204": {"description": "deleted"}},
            },
        }
    },
}
accounts = OpenAPIToolset(spec_dict=spec)
root_agent = Agent(
    name="account-admin",
    model="gemini-flash-latest",
    tools=[accounts],
)
''')

    graph, findings = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "account-admin")
    tool = next(t for t in agent.tools if t.name == "accounts")

    assert "data.read" in tool.capabilities
    assert "data.write" in tool.capabilities
    assert "external.write" in tool.capabilities
    assert "destructive.write" in tool.capabilities
    assert tool.metadata["openapi_methods"] == ["DELETE", "GET"]
    assert tool.metadata["openapi_security_schemes"] == ["bearerAuth"]
    assert tool.metadata["openapi_auth_required"] is True
    assert any(
        destination.target == "https://api.accounts.example.com"
        and destination.restricted is True
        and destination.metadata.get("network_scope") == "explicit_destination"
        for destination in tool.destinations
    )
    assert not any(
        f.rule_id == "NET002" and f.agent == "account-admin"
        for f in findings
    )


def test_adk_openapi_get_only_does_not_invent_write_authority(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.openapi_tool import OpenAPIToolset

spec = {
    "openapi": "3.0.0",
    "info": {"title": "Directory", "version": "1.0"},
    "servers": [{"url": "https://directory.example.com/api"}],
    "paths": {
        "/users": {
            "get": {
                "operationId": "listUsers",
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}
directory = OpenAPIToolset(spec_dict=spec)
root_agent = Agent(
    name="directory-reader",
    model="gemini-flash-latest",
    tools=[directory],
)
''')

    graph, _ = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "directory-reader")
    tool = next(t for t in agent.tools if t.name == "directory")

    assert "data.read" in tool.capabilities
    assert "network.external" in tool.capabilities
    assert "data.write" not in tool.capabilities
    assert "external.write" not in tool.capabilities
    assert "destructive.write" not in tool.capabilities
    assert tool.metadata["openapi_methods"] == ["GET"]


def test_adk_repository_resolves_imported_sub_agents_across_packages(
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "agents" / "catalog"
    pipeline = tmp_path / "agents" / "pipelines" / "full_review"
    catalog.mkdir(parents=True)
    pipeline.mkdir(parents=True)
    (tmp_path / "agents" / "__init__.py").write_text("", encoding="utf-8")
    (catalog / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "agents" / "pipelines" / "__init__.py").write_text("", encoding="utf-8")
    (pipeline / "__init__.py").write_text("", encoding="utf-8")

    for filename, alias, runtime_name in (
        ("clinical_librarian.py", "librarian_agent", "librarian_agent"),
        ("evidence_analyst.py", "analyst_agent", "analyst_agent"),
        ("reporter.py", "reporter_agent", "reporter_agent"),
    ):
        (catalog / filename).write_text(
            f"""from google.adk.agents import LlmAgent\n\n{alias} = LlmAgent(name=\"{runtime_name}\", model=\"gemini-flash-latest\")\n""",
            encoding="utf-8",
        )

    (pipeline / "agent.py").write_text(
        """
from google.adk.agents import SequentialAgent
from agents.catalog.clinical_librarian import librarian_agent
from agents.catalog.evidence_analyst import analyst_agent
from agents.catalog.reporter import reporter_agent

root_agent = SequentialAgent(
    name="pubmed_full_review",
    sub_agents=[librarian_agent, analyst_agent, reporter_agent],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    root = next(item for item in graph.agents if item.name == "pubmed_full_review")
    assert set(root.metadata.get("delegates_to") or []) == {
        "librarian_agent",
        "analyst_agent",
        "reporter_agent",
    }
    assert graph.adg is not None
    root_node = next(
        node for node in graph.adg.nodes
        if node.kind == "agent" and node.name == "pubmed_full_review"
    )
    targets = {
        node.node_id: node.name
        for node in graph.adg.nodes
        if node.kind == "agent"
    }
    delegated = {
        targets[edge.target]
        for edge in graph.adg.edges
        if edge.kind == "DELEGATES_TO"
        and edge.source == root_node.node_id
        and edge.target in targets
    }
    assert delegated == {
        "librarian_agent",
        "analyst_agent",
        "reporter_agent",
    }
