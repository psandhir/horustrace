import json
from pathlib import Path

from horustrace.cli import main
from horustrace.scanner import scan


def write(root: Path, rel: str, text: str):
    p=root/rel; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(text,encoding="utf-8")

def test_dynamic_authorization_header(tmp_path):
    write(tmp_path,"agent.py",'import os\nfrom google.adk import Agent\nfrom google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams\nmcp=McpToolset(connection_params=StreamableHTTPConnectionParams(url="https://api.example/mcp",headers={"Authorization":"Bearer "+os.getenv("TOKEN","")}),tool_filter=["read"])\nroot_agent=Agent(name="root",tools=[mcp])\n')
    graph,findings=scan(tmp_path)
    assert graph.agents[0].mcp_servers[0].authenticated is True
    assert not any(f.rule_id=="AGT030" for f in findings)

def test_bash_builtin_confirmation(tmp_path):
    write(tmp_path,"agent.py",'from google.adk import Agent\nfrom google.adk.tools.bash_tool import ExecuteBashTool\nroot_agent=Agent(name="ops",tools=[ExecuteBashTool()])\n')
    graph,findings=scan(tmp_path)
    bash=next(t for t in graph.agents[0].tools if t.metadata.get("adk_builtin")=="ExecuteBashTool")
    assert bash.approval is True
    assert "AGT020" not in {f.rule_id for f in findings}
    assert "ADK004" in {f.rule_id for f in findings}

def test_simple_factory(tmp_path):
    write(tmp_path,"agent.py",'from google.adk import Agent\ndef helper(): return "ok"\ndef create_agent(): return Agent(name="factory_agent",tools=[helper])\nroot_agent=create_agent()\n')
    graph,_=scan(tmp_path)
    assert any(a.name=="factory_agent" for a in graph.agents)
    assert not any(d.kind=="no_targets" for d in graph.coverage.diagnostics)

def test_cross_file_function(tmp_path):
    write(tmp_path,"pkg/tools.py",'import httpx\ndef search_records(q): return httpx.get("https://records.example/search").json()\n')
    write(tmp_path,"pkg/agent.py",'from google.adk import Agent\nfrom .tools import search_records\nroot_agent=Agent(name="records",tools=[search_records])\n')
    graph,_=scan(tmp_path); agent=next(a for a in graph.agents if a.name=="records")
    assert "network.external" in next(t for t in agent.tools if t.name=="search_records").capabilities

def test_effective_strict_json(tmp_path,capsys):
    write(tmp_path,"agent.py","from google.adk import Agent\nroot_agent=Agent(name='root')\n")
    main(["scan",str(tmp_path),"--strict","--format","json","--fail-on","none"])
    assert json.loads(capsys.readouterr().out)["configuration"]["effective"]["strict"] is True


def test_provider_managed_builtin_executor_does_not_require_local_sandbox_knobs(tmp_path):
    write(
        tmp_path,
        "agent.py",
        """from google.adk import Agent
from google.adk.code_executors import BuiltInCodeExecutor
root_agent = Agent(name="coder", code_executor=BuiltInCodeExecutor())
""",
    )
    graph, findings = scan(tmp_path)
    executor = next(tool for tool in graph.agents[0].tools if tool.kind == "adk_code_executor")
    assert executor.metadata["execution_boundary"] == "provider-managed"
    assert not any(f.rule_id == "ADK012" for f in findings)


def test_loopback_mcp_is_not_treated_as_unencrypted_remote_transport(tmp_path):
    write(
        tmp_path,
        "agent.py",
        """from google.adk import Agent
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
mcp = McpToolset(connection_params=StreamableHTTPConnectionParams(url="http://localhost:3000/mcp"))
root_agent = Agent(name="root", tools=[mcp])
""",
    )
    _, findings = scan(tmp_path)
    ids = {finding.rule_id for finding in findings}
    assert "AGT030" not in ids
    assert "AGT031" not in ids
    assert "AGT032" not in ids


def test_unknown_mcp_auth_is_coverage_gap_not_high_finding(tmp_path):
    write(
        tmp_path,
        "agent.py",
        """from google.adk import Agent
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
mcp = McpToolset(connection_params=StreamableHTTPConnectionParams(
    url="https://mcp.example.test/mcp",
    headers=get_runtime_headers(),
))
root_agent = Agent(name="root", tools=[mcp])
""",
    )
    graph, findings = scan(tmp_path)
    assert not any(f.rule_id == "AGT030" for f in findings)
    assert any(d.diagnostic_id == "ARG-COV-010" for d in graph.coverage.diagnostics)


def test_google_search_managed_service_does_not_emit_generic_net002(tmp_path):
    write(
        tmp_path,
        "agent.py",
        """from google.adk import Agent
from google.adk.tools import google_search
root_agent = Agent(name="search", tools=[google_search])
""",
    )
    _, findings = scan(tmp_path)
    assert not any(f.rule_id == "NET002" for f in findings)


def test_named_literal_tool_filter_is_resolved(tmp_path):
    write(
        tmp_path,
        "agent.py",
        """from google.adk import Agent
from google.adk.tools.bigquery import BigQueryToolset
ALLOWED = ["execute_sql"]
bq = BigQueryToolset(tool_filter=ALLOWED)
root_agent = Agent(name="analyst", tools=[bq])
""",
    )
    graph, _ = scan(tmp_path)
    tool = next(tool for tool in graph.agents[0].tools if tool.metadata.get("adk_builtin") == "BigQueryToolset")
    assert tool.metadata["tool_filter"] == ["execute_sql"]
    assert not any(d.kind == "dynamic_tool_filter" for d in graph.coverage.diagnostics)


def test_nested_workflow_agent_is_materialized_for_delegation(tmp_path):
    write(
        tmp_path,
        "agent.py",
        """from google.adk import Agent, LoopAgent, SequentialAgent
worker = Agent(name="worker")
root_agent = SequentialAgent(
    name="pipeline",
    sub_agents=[LoopAgent(name="loop", sub_agents=[worker])],
)
""",
    )
    graph, _ = scan(tmp_path)
    assert any(agent.name == "loop" for agent in graph.agents)
    assert not any(d.kind == "unresolved_delegation" for d in graph.coverage.diagnostics)


def test_repository_oauth_helper_scope_is_linked_to_function_tool(tmp_path):
    write(
        tmp_path,
        "pkg/auths.py",
        """SCOPES = {"https://www.googleapis.com/auth/drive.readonly": "Drive read"}
""",
    )
    write(
        tmp_path,
        "pkg/tools.py",
        """from . import auths
def negotiate_creds(ctx):
    return list(auths.SCOPES.keys())
def read_drive_file(file_id, ctx):
    negotiate_creds(ctx)
    return build("drive", "v3").files().get(fileId=file_id).execute()
""",
    )
    write(
        tmp_path,
        "pkg/agent.py",
        """from google.adk import Agent
from .tools import read_drive_file
root_agent = Agent(name="drive", tools=[read_drive_file])
""",
    )
    graph, _ = scan(tmp_path)
    identity = next(identity for identity in graph.identities if identity.name == "read_drive_file:oauth")
    assert "https://www.googleapis.com/auth/drive.readonly" in identity.oauth_scopes


def test_google_api_execute_method_is_not_process_execution(tmp_path):
    write(
        tmp_path,
        "pkg/tools.py",
        '''from googleapiclient.discovery import build
def read_drive_file(file_id):
    service = build("drive", "v3")
    return service.files().get(fileId=file_id).execute()
''',
    )
    write(
        tmp_path,
        "pkg/agent.py",
        '''from google.adk import Agent
from .tools import read_drive_file
root_agent = Agent(name="drive", tools=[read_drive_file])
''',
    )
    graph, findings = scan(tmp_path)
    tool = next(tool for tool in graph.agents[0].tools if tool.name == "read_drive_file")
    assert "process.execute" not in tool.capabilities
    assert not any(f.rule_id in {"AGT020", "PATH001"} for f in findings)


def test_url_in_error_message_is_not_network_destination(tmp_path):
    write(
        tmp_path,
        "agent.py",
        '''from google.adk import Agent
def explain():
    return "Visit https://example.test/docs for help"
root_agent = Agent(name="root", tools=[explain])
''',
    )
    graph, findings = scan(tmp_path)
    tool = next(tool for tool in graph.agents[0].tools if tool.name == "explain")
    assert "network.external" not in tool.capabilities
    assert not tool.destinations
    assert not any(f.rule_id in {"NET001", "NET002"} for f in findings)


def test_dictionary_key_lookup_is_not_secret_access(tmp_path):
    write(
        tmp_path,
        "agent.py",
        '''from google.adk import Agent
OUTPUT_KEY_MAP = {"a": "b"}
def status():
    return OUTPUT_KEY_MAP.get("a")
root_agent = Agent(name="root", tools=[status])
''',
    )
    graph, _ = scan(tmp_path)
    tool = next(tool for tool in graph.agents[0].tools if tool.name == "status")
    assert "secrets.read" not in tool.capabilities


def test_noop_before_tool_callback_does_not_count_as_tool_guardrail(tmp_path):
    write(
        tmp_path,
        "agent.py",
        '''from google.adk import Agent
def mutate():
    open("state.txt", "w").write("x")
def gate(tool, args, tool_context):
    return None
root_agent = Agent(name="root", tools=[mutate], before_tool_callback=gate)
''',
    )
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "AGT040" and f.agent == "root" for f in findings)


def test_load_artifacts_direct_export_is_resolved(tmp_path):
    write(
        tmp_path,
        "agent.py",
        '''from google.adk import Agent
from google.adk.tools import load_artifacts
root_agent = Agent(name="root", tools=[load_artifacts])
''',
    )
    graph, _ = scan(tmp_path)
    assert any(tool.name == "load_artifacts" for tool in graph.agents[0].tools)
    assert not any(d.kind == "unresolved_tool" for d in graph.coverage.diagnostics)


def test_factory_local_tool_lists_and_conditional_tools_are_resolved(tmp_path):
    write(tmp_path, "pkg/tools.py", "def a(): return 1\ndef b(): return 2\n")
    write(
        tmp_path,
        "pkg/agent.py",
        '''from google.adk import Agent
from . import tools
def create():
    configured = [tools.a if FLAG else tools.b]
    extras = []
    extras.append(tools.a)
    configured.extend(extras)
    agent = Agent(name="root", tools=configured)
    return agent
root_agent = create()
''',
    )
    graph, _ = scan(tmp_path)
    root = next(agent for agent in graph.agents if agent.name == "root")
    assert {"a", "b"} <= {tool.name for tool in root.tools}


def test_repository_resolver_uses_only_scanner_approved_files(tmp_path):
    write(tmp_path, "agent.py", "from google.adk import Agent\nroot_agent=Agent(name='root')\n")
    ignored = tmp_path / "benchmarks"
    ignored.mkdir()
    (ignored / ".horustrace-ignore").write_text("", encoding="utf-8")
    write(
        tmp_path,
        "benchmarks/ignored.py",
        "from google.adk import Agent\nignored=Agent(name='must_not_appear')\n",
    )
    graph, _ = scan(tmp_path)
    assert "must_not_appear" not in {agent.name for agent in graph.agents}



def test_static_module_constant_mcp_url_is_resolved(tmp_path):
    write(
        tmp_path,
        "pkg/tools.py",
        '''from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams

MAPS_MCP_URL = "https://mapstools.googleapis.com/mcp"


def get_places_toolset():
    return McpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=MAPS_MCP_URL,
            headers={"X-Goog-Api-Key": "test-key"},
        )
    )
''',
    )
    write(
        tmp_path,
        "pkg/agent.py",
        '''from google.adk import Agent
from .tools import get_places_toolset

root_agent = Agent(name="travel", tools=[get_places_toolset()])
''',
    )
    graph, _ = scan(tmp_path)
    servers = graph.all_mcp_servers()
    assert any(server.url == "https://mapstools.googleapis.com/mcp" for server in servers)
    assert not any(
        diagnostic.kind == "dynamic_mcp_endpoint"
        for diagnostic in graph.coverage.diagnostics
    )


def test_runtime_mcp_url_remains_dynamic_coverage_gap(tmp_path):
    write(
        tmp_path,
        "pkg/tools.py",
        '''import os
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams

MCP_URL = os.getenv("MCP_URL")


def get_runtime_toolset():
    return McpToolset(
        connection_params=StreamableHTTPConnectionParams(url=MCP_URL)
    )
''',
    )
    write(
        tmp_path,
        "pkg/agent.py",
        '''from google.adk import Agent
from .tools import get_runtime_toolset

root_agent = Agent(name="runtime", tools=[get_runtime_toolset()])
''',
    )
    graph, _ = scan(tmp_path)
    assert any(
        diagnostic.kind == "dynamic_mcp_endpoint"
        for diagnostic in graph.coverage.diagnostics
    )


def test_delegated_process_capability_does_not_duplicate_agt020(tmp_path):
    write(
        tmp_path,
        "agent.py",
        '''from google.adk import Agent


def execute_code(code):
    exec(code, {})


worker = Agent(name="worker", tools=[execute_code])
root_agent = Agent(name="root", sub_agents=[worker])
''',
    )
    _, findings = scan(tmp_path)
    agt020 = [finding for finding in findings if finding.rule_id == "AGT020"]
    assert len(agt020) == 1
    assert agt020[0].agent == "worker"
    assert any(
        finding.rule_id == "PATH001" and finding.agent == "root"
        for finding in findings
    )
