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
        if node.kind == "tool"
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


def test_adk_before_tool_callback_counts_as_agent_safety_control(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.bash_tool import ExecuteBashTool

def security_gate(tool, args, context):
    return None

root_agent = Agent(
    name="controlled_ops",
    model="gemini-flash-latest",
    tools=[ExecuteBashTool()],
    before_tool_callback=security_gate,
)
''')
    _, findings = scan(tmp_path)
    assert not any(f.rule_id == "ADK001" for f in findings)


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
    assert reviewer.metadata["agent_type"] == "LlmAgent"


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
    assert any(
        f.rule_id == "AGT022" and f.agent == "scope_safety_router"
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
    assert agent.tools == []
