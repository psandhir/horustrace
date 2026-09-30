from pathlib import Path

from horustrace.adapters.registry import detect_python_frameworks
from horustrace.scanner import scan


def test_pydantic_ai_decorator_tool_with_approval(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
import subprocess
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool(requires_approval=True)
def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    assert detect_python_frameworks(source) == ["pydantic-ai"]
    assert len(graph.agents) == 1
    assert graph.agents[0].metadata["framework"] == "pydantic-ai"

    tool = next(tool for tool in graph.agents[0].tools if tool.name == "run_command")
    assert "process.execute" in tool.capabilities
    assert tool.approval is True
    assert not any(f.rule_id == "AGT020" for f in findings)


def test_pydantic_ai_unapproved_process_tool_is_flagged(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool
def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
""",
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    assert any(f.rule_id == "AGT020" and f.agent == "agent" for f in findings)


def test_pydantic_ai_conditional_approval_is_not_treated_as_universal(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from pydantic_ai import Agent, ApprovalRequired

agent = Agent("openai:gpt-5.2")

@agent.tool
def run_command(command: str) -> str:
    if command.startswith("sudo"):
        raise ApprovalRequired
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(tool for tool in graph.agents[0].tools if tool.name == "run_command")
    assert tool.metadata["conditional_approval"] is True
    assert tool.approval is not True
    assert any(f.rule_id == "AGT020" for f in findings)


def test_pydantic_ai_tool_wrapper_and_function_toolset_approval(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent, FunctionToolset, Tool

def write_record(value: str) -> str:
    return store.write(value)

wrapped = Tool(write_record, requires_approval=True)
toolset = FunctionToolset(tools=[write_record]).approval_required()
agent = Agent("openai:gpt-5.2", tools=[wrapped], toolsets=[toolset])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]
    tool = next(tool for tool in agent.tools if tool.name == "write_record")
    assert "data.write" in tool.capabilities
    assert tool.approval is True
    assert not any(d.code == "unresolved_tool" for d in graph.coverage.diagnostics)


def test_pydantic_ai_remote_mcp_toolset_is_normalized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset

mcp = MCPToolset("https://mcp.example.com/api")
agent = Agent("openai:gpt-5.2", toolsets=[mcp])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    server = graph.agents[0].mcp_servers[0]
    assert server.url == "https://mcp.example.com/api"
    assert server.transport == "streamable-http"
    assert server.authenticated is False
    assert any(f.rule_id == "AGT030" for f in findings)
    assert any(f.rule_id == "AGT032" for f in findings)


def test_pydantic_ai_mcp_capability_and_harness_capabilities(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.capabilities import MCP, WebSearch
from pydantic_ai_harness import Coder

agent = Agent(
    "openai:gpt-5.2",
    capabilities=[
        Coder(),
        WebSearch(),
        MCP(url="https://mcp.example.com/api", native=True),
    ],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = graph.agents[0]
    assert {"process.execute", "data.read", "data.write", "network.external"} <= (
        agent.capabilities
    )
    assert any(source.trust == "untrusted" for source in agent.inputs)
    assert agent.mcp_servers[0].metadata["native"] is True
    assert any(f.rule_id == "CAP004" for f in findings)


def test_pydantic_ai_filesystem_scope_reaches_layer_four(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai_harness import FileSystem

agent = Agent("openai:gpt-5.2", capabilities=[FileSystem("/")])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(tool for tool in graph.agents[0].tools if tool.name == "FileSystem")
    assert tool.resources[0].selector == "/"
    assert any(f.rule_id == "DATA001" for f in findings)


def test_pydantic_ai_dynamic_toolsets_are_visible_in_coverage(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

def build_toolsets():
    return []

agent = Agent("openai:gpt-5.2", toolsets=build_toolsets())
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    assert graph.coverage.incomplete
    assert any(
        d.code == "dynamic_configuration"
        and "toolsets" in d.message.lower()
        for d in graph.coverage.diagnostics
    )


def test_plain_pydantic_model_is_not_detected_as_pydantic_ai(tmp_path: Path) -> None:
    source = tmp_path / "model.py"
    source.write_text(
        """
from pydantic import BaseModel

class Item(BaseModel):
    name: str
""",
        encoding="utf-8",
    )

    assert "pydantic-ai" not in detect_python_frameworks(source)


def test_pydantic_ai_direct_agent_tool_registration_is_authority(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

def create_plan(value: str) -> str:
    return value

def read_file(path: str) -> str:
    return path

agent = Agent("openai:gpt-5.2")
agent.tool(create_plan)
agent.tool_plain(read_file)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]

    assert {tool.name for tool in agent.tools} == {"create_plan", "read_file"}
    assert {
        tool.metadata.get("binding_origin")
        for tool in agent.tools
    } == {"agent.tool", "agent.tool_plain"}

    assert graph.adg is not None
    invoked = {
        node.attributes.get("tool_name")
        for edge in graph.adg.edges
        if edge.kind == "INVOKES"
        for node in graph.adg.nodes
        if node.node_id == edge.target and node.kind == "tool"
    }
    assert {"create_plan", "read_file"} <= invoked


def test_pydantic_ai_cli_input_reaches_agent_run(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

async def main():
    agent = Agent("openai:gpt-5.2")
    user_input = input("> ")
    return await agent.run(user_input)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]

    source = next(item for item in agent.inputs if item.name == "cli-input")
    assert source.trust == "untrusted"
    assert source.kind == "user"
    assert source.metadata["basis"] == "pydantic_ai_cli_input_to_run"


def test_pydantic_ai_local_stdio_resolves_in_repo_fastmcp_and_path002(
    tmp_path: Path,
) -> None:
    (tmp_path / "mcp_server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Local Tools")

@mcp.tool()
def delete_record(record_id: str):
    return storage.delete(record_id)

if __name__ == "__main__":
    mcp.run()
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

async def main():
    mcp_server = MCPServerStdio("python", ["mcp_server.py"])
    agent = Agent("openai:gpt-5.2", mcp_servers=[mcp_server])
    user_input = input("> ")
    return await agent.run(user_input)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.metadata["repository_resolved"] is True
    assert server.metadata["binding_origin"] == "local_stdio_script"
    assert server.metadata["implementation_name"] == "Local Tools"
    assert "destructive.write" in server.metadata["discovered_tool_capabilities"]
    assert not graph.unbound_mcp_servers
    assert any(
        finding.rule_id == "PATH002" and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_ai_local_stdio_does_not_guess_ambiguous_mcp_implementation(
    tmp_path: Path,
) -> None:
    (tmp_path / "mcp_server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

left = FastMCP("Left")
right = FastMCP("Right")

@left.tool()
def delete_left(record_id: str):
    return storage.delete(record_id)

@right.tool()
def delete_right(record_id: str):
    return storage.delete(record_id)
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

mcp_server = MCPServerStdio("python", ["mcp_server.py"])
agent = Agent("openai:gpt-5.2", mcp_servers=[mcp_server])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    server = agent.mcp_servers[0]
    assert server.metadata.get("repository_resolved") is not True
    assert server.metadata["local_stdio_resolution"] == "ambiguous"
    assert server.metadata["local_stdio_candidate_count"] == 2
    assert len(graph.unbound_mcp_servers) == 2

def test_pydantic_ai_cross_file_click_input_reaches_imported_agent_state_write(
    tmp_path: Path,
) -> None:
    package = tmp_path / "ramon"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from .agent import agent\n",
        encoding="utf-8",
    )
    (package / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool_plain
def update_record(record_id: str, value: str) -> str:
    return store.update(record_id, value)
""",
        encoding="utf-8",
    )
    (package / "cli.py").write_text(
        """
import click
from ramon import agent

def chat() -> None:
    prompt = click.prompt("", prompt_suffix="> ")
    agent.run_sync(prompt)
""",
        encoding="utf-8",
    )

    graph, findings = scan(package)
    agent = next(item for item in graph.agents if item.name == "agent")
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis")
        == "repository_pydantic_cli_input_to_run"
    )

    assert ingress.trust == "untrusted"
    assert ingress.metadata["runtime_invocation_proven"] is True
    assert "data.write" in next(
        tool for tool in agent.tools if tool.name == "update_record"
    ).capabilities

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH002"
        and item.metadata.get("basis") == "source_bound_ingress_authority"
    )
    assert path.agent == "agent"
    assert path.nodes[-2:] == ["update_record", "data.write"]
    assert path.metadata["ingress_basis"] == (
        "repository_pydantic_cli_input_to_run"
    )
    assert any(
        finding.rule_id == "PATH002" and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_ai_cross_file_click_input_requires_concrete_agent_run(
    tmp_path: Path,
) -> None:
    package = tmp_path / "ramon"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from .agent import agent\n",
        encoding="utf-8",
    )
    (package / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool_plain
def update_record(record_id: str, value: str) -> str:
    return store.update(record_id, value)
""",
        encoding="utf-8",
    )
    (package / "cli.py").write_text(
        """
import click
from ramon import agent

def chat() -> None:
    prompt = click.prompt("", prompt_suffix="> ")
    print(prompt)
""",
        encoding="utf-8",
    )

    graph, findings = scan(package)
    agent = next(item for item in graph.agents if item.name == "agent")

    assert not any(
        item.metadata.get("basis") == "repository_pydantic_cli_input_to_run"
        for item in agent.inputs
    )
    assert not any(
        finding.rule_id == "PATH002" and finding.agent == "agent"
        for finding in findings
    )



def test_pydantic_ai_streamlit_input_reaches_model_selected_server_fetch(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text(
        """
import httpx
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-5.2")

@agent.tool
async def fetch_curriculum(ctx: RunContext, url: str) -> str:
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=15.0,
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.text
""",
        encoding="utf-8",
    )
    (package / "app.py").write_text(
        """
import streamlit as st
from src.agent import agent

def chat_page():
    if user_input := st.chat_input("Type your response..."):
        get_bot_response(user_input)

def get_bot_response(user_input: str):
    return agent.run_sync(user_input)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis")
        == "repository_pydantic_streamlit_input_to_run"
    )
    tool = next(
        item for item in agent.tools if item.name == "fetch_curriculum"
    )

    assert ingress.trust == "untrusted"
    assert ingress.kind == "web"
    assert ingress.metadata["runtime_invocation_proven"] is True
    assert ingress.metadata["ingress_framework"] == "streamlit"

    assert tool.metadata["model_selected_url_fetch"] is True
    assert tool.metadata["model_selected_url_parameters"] == ["url"]
    assert tool.metadata["server_side_fetch"] is True
    assert tool.metadata["follow_redirects"] is True
    assert any(
        destination.target == "<dynamic-url>"
        and destination.metadata.get("source")
        == "model_selected_url_argument"
        and destination.metadata.get("network_scope")
        == "dynamic_destination"
        for destination in tool.destinations
    )

    assert any(
        finding.rule_id == "NET001" and finding.agent == "agent"
        for finding in findings
    )
    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH011" and item.agent == "agent"
    )
    assert path.metadata["basis"] == "source_bound_ingress_authority"
    assert path.metadata["ingress_basis"] == (
        "repository_pydantic_streamlit_input_to_run"
    )
    assert path.metadata["url_parameters"] == ["url"]
    assert path.metadata["follow_redirects"] is True
    assert any(
        finding.rule_id == "PATH011" and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_ai_provider_search_is_not_arbitrary_server_fetch(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool
def research_domain(query: str):
    client = TavilyClient()
    return client.search(query=query)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "research_domain")

    assert tool.metadata.get("model_selected_url_fetch") is not True
    assert not any(
        destination.metadata.get("source") == "model_selected_url_argument"
        for destination in tool.destinations
    )
    assert not any(item.path_id == "PATH011" for item in graph.attack_paths)
    assert not any(finding.rule_id == "PATH011" for finding in findings)


def test_pydantic_ai_streamlit_input_requires_concrete_agent_run(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text(
        """
import httpx
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool_plain
async def fetch_url(url: str) -> str:
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.text
""",
        encoding="utf-8",
    )
    (package / "app.py").write_text(
        """
import streamlit as st
from src.agent import agent

def chat_page():
    if user_input := st.chat_input("Message"):
        print(user_input)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "fetch_url")

    assert tool.metadata["model_selected_url_fetch"] is True
    assert not any(
        item.metadata.get("basis")
        == "repository_pydantic_streamlit_input_to_run"
        for item in agent.inputs
    )
    assert not any(item.path_id == "PATH011" for item in graph.attack_paths)
    assert not any(finding.rule_id == "PATH011" for finding in findings)


def test_pydantic_ai_wrapper_attribute_agent_and_tool_are_discovered(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent, RunContext

class ResearchAgent:
    def __post_init__(self):
        self.agent = Agent("openai:gpt-5.2")

        @self.agent.tool
        async def search_documents(ctx: RunContext, query: str) -> str:
            return query
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "pydantic-ai"
    )
    assert agent.name == "self.agent"
    assert [tool.name for tool in agent.tools] == ["search_documents"]


def test_pydantic_ai_streamlit_input_reaches_wrapped_agent_run(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "agent.py").write_text(
        """
from pydantic_ai import Agent

class ResearchAgent:
    def __post_init__(self):
        self.agent = Agent("openai:gpt-5.2")

    def get_streaming_chat_handler(self):
        def chat_stream(question: str):
            return self.agent.run_stream_sync(question)
        return chat_stream

def create_research_agent():
    return ResearchAgent()
""",
        encoding="utf-8",
    )
    (package / "app.py").write_text(
        """
import streamlit as st
from src.agent import create_research_agent

st.session_state.agent = create_research_agent()

if prompt := st.chat_input("Question"):
    stream = st.session_state.agent.get_streaming_chat_handler()(prompt)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "pydantic-ai"
    )
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis")
        == "repository_pydantic_streamlit_wrapper_to_run"
    )

    assert agent.name == "self.agent"
    assert ingress.trust == "untrusted"
    assert ingress.kind == "web"
    assert ingress.metadata["runtime_invocation_proven"] is True
    assert ingress.metadata["wrapper_method"] == "get_streaming_chat_handler"


def _write_streamlit_rag_wrapper_fixture(
    tmp_path: Path,
    *,
    contained: bool,
) -> None:
    package = tmp_path / "src"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "document_loader.py").write_text(
        """
from pathlib import Path

def load_documents(path: str):
    root = Path(path)
    return [item.read_text() for item in root.rglob("*.txt")]
""",
        encoding="utf-8",
    )
    containment = (
        """
    from pathlib import Path
    resolved = Path(documents_path).resolve()
    resolved.relative_to(Path("Research").resolve())
    documents_path = str(resolved)
"""
        if contained
        else ""
    )
    (package / "agent.py").write_text(
        f"""
from pydantic_ai import Agent, RunContext
from src.document_loader import load_documents

class Store:
    def search(self, query):
        return self

    def to_list(self):
        return [{{"text": "example"}}]

class ResearchAgent:
    def __init__(self):
        self.vector_store = Store()
        self.agent = Agent("openai:gpt-5.2")

        @self.agent.tool
        async def search_documents(ctx: RunContext, query: str) -> str:
            rows = ctx.deps.vector_store.search(query).to_list()
            return rows[0]["text"]

    def get_streaming_chat_handler(self):
        def chat_stream(question: str):
            return self.agent.run_stream_sync(question)
        return chat_stream

def _create_vector_store(documents_path: str):
    load_documents(documents_path)
    return Store()

def create_research_agent(documents_path: str):
{containment}
    _create_vector_store(documents_path)
    return ResearchAgent()
""",
        encoding="utf-8",
    )
    (package / "app.py").write_text(
        """
import os
import streamlit as st
from src.agent import create_research_agent

folder_path = st.text_input("Documents folder:", "Research")
valid_folder = folder_path and os.path.isdir(folder_path)

if valid_folder:
    st.session_state.agent = create_research_agent(
        documents_path=folder_path,
    )

if prompt := st.chat_input("Question"):
    stream = st.session_state.agent.get_streaming_chat_handler()(prompt)
""",
        encoding="utf-8",
    )


def test_pydantic_ai_streamlit_user_selected_rag_directory_is_attack_path(
    tmp_path: Path,
) -> None:
    _write_streamlit_rag_wrapper_fixture(tmp_path, contained=False)

    graph, findings = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "pydantic-ai"
    )
    tool = next(item for item in agent.tools if item.name == "search_documents")

    assert agent.name == "self.agent"
    assert tool.metadata["rag_retrieval"] is True
    assert tool.metadata["rag_returns_indexed_content"] is True
    assert tool.metadata["filesystem_path_constrained"] is False
    assert any(
        item.metadata.get("basis")
        == "source_proven_user_selected_rag_directory"
        and item.metadata.get("filesystem_path_constrained") is False
        for item in agent.inputs
    )
    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH013"
    )
    assert path.agent == "self.agent"
    assert path.metadata["basis"] == "source_proven_rag_directory_retrieval"
    assert path.metadata["path_containment"] == "not_detected"
    assert path.metadata["retrieval_tool"] == "search_documents"
    assert any(
        finding.rule_id == "PATH013" and finding.agent == "self.agent"
        for finding in findings
    )


def test_pydantic_ai_contained_rag_directory_does_not_create_attack_path(
    tmp_path: Path,
) -> None:
    _write_streamlit_rag_wrapper_fixture(tmp_path, contained=True)

    graph, findings = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "pydantic-ai"
    )
    tool = next(item for item in agent.tools if item.name == "search_documents")

    assert tool.metadata["filesystem_path_constrained"] is True
    assert any(
        item.metadata.get("basis")
        == "source_proven_user_selected_rag_directory"
        and item.metadata.get("filesystem_path_constrained") is True
        for item in agent.inputs
    )
    assert not any(item.path_id == "PATH013" for item in graph.attack_paths)
    assert not any(finding.rule_id == "PATH013" for finding in findings)


def test_pydantic_ai_command_registry_wrapper_is_not_host_process_execution(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")

@agent.tool
async def run_command(ctx, command: str) -> str:
    action = command.split()[0]
    if not _is_ai_action_allowed(action):
        return "blocked"
    cmd = get_command(action)
    allowed, error = check_command_permissions(cmd, ctx.deps.role)
    if not allowed:
        return error
    return await cmd(ctx.deps.socket, command)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(tool for tool in graph.agents[0].tools if tool.name == "run_command")

    assert "process.execute" not in tool.capabilities
    assert not any(
        finding.rule_id in {"AGT020", "AGT040"}
        and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_ai_configuration_derived_mcp_toolsets_preserve_bound_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

async def get_user_mcp_servers():
    return []

async def create_agent():
    user_mcp_servers = await get_user_mcp_servers()
    mcp_servers = user_mcp_servers or None
    agent = Agent("openai:gpt-5.2", toolsets=mcp_servers)
    return agent
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.transport == "unknown"
    assert server.metadata["dynamic_configured_mcp_catalogue"] is True
    assert server.metadata["configuration_dependent"] is True
    assert server.metadata["catalogue_source"] == "get_user_mcp_servers"
    assert agent.metadata["configuration_dependent_mcp_toolsets"] is True
    assert any(
        finding.rule_id == "AGT054" and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_ai_streamable_http_constructor_is_normalized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStreamableHTTP

server = MCPServerStreamableHTTP("https://mcp.example.test")
agent = Agent("openai:gpt-5.2", toolsets=[server])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    server = agent.mcp_servers[0]
    assert server.transport == "streamable-http"
    assert server.url == "https://mcp.example.test"


def test_pydantic_ai_search_result_url_fetch_is_indirect_medium_risk(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import requests
from pydantic_ai import Agent, RunContext

class DDGS:
    def text(self, query, max_results=5):
        return []

def search_web(query: str):
    return [
        {"url": result.get("href", "")}
        for result in DDGS().text(query, max_results=5)
    ]

def fetch_page_content(url: str):
    return requests.get(url, timeout=5).text

agent = Agent("openai:gpt-5.2")

@agent.tool
def deep_dive_search(ctx: RunContext, base_query: str, angle: str):
    search_query = f"{base_query} {angle}"
    results = search_web(search_query)
    detailed = []
    for result in results[:3]:
        detailed.append(fetch_page_content(result["url"]))
    return detailed

def run_research_agent(query: str):
    prompt = f"Research: {query}"
    return agent.run_sync(prompt)

def run_agent(prompt: str):
    return run_research_agent(prompt)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "deep_dive_search")
    assert tool.metadata["search_result_url_fetch"] is True
    assert tool.metadata["destination_provenance"] == "provider_search_result"
    assert any(
        destination.target == "<search-result-url>"
        and destination.metadata.get("network_scope")
        == "search_result_derived_destination"
        for destination in tool.destinations
    )
    net = next(item for item in findings if item.rule_id == "NET001")
    assert net.severity.label() == "medium"
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "pydantic_ai_public_wrapper_input_to_run"
    )
    assert ingress.metadata["runtime_invocation_proven"] is True
    path = next(item for item in graph.attack_paths if item.path_id == "PATH011")
    assert path.severity.label() == "medium"
    assert path.metadata["indirect_destination"] is True
    assert path.metadata["destination_provenance"] == "provider_search_result"


def test_pydantic_ai_native_tool_controls_constrain_shell_and_artifact_write(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import asyncio
from pydantic_ai import Agent

ALLOWED_COMMANDS = {"ls", "grep", "git"}
DANGEROUS_PATTERNS = [r"[|&;]"]

async def codebase_shell(command: str, args: list[str]):
    if command not in ALLOWED_COMMANDS:
        return "not allowed"
    for pattern in DANGEROUS_PATTERNS:
        if pattern in command:
            return "blocked"
    process = await asyncio.create_subprocess_exec(command, *args)
    return await process.wait()

def _validate_agent_scoped_path(filename: str):
    return ".shotgun/" + filename

def write_file(filename: str, content: str):
    path = _validate_agent_scoped_path(filename)
    with open(path, "w") as handle:
        handle.write(content)

agent = Agent(
    "openai:gpt-5.2",
    tools=[codebase_shell, write_file],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    shell = next(item for item in agent.tools if item.name == "codebase_shell")
    write = next(item for item in agent.tools if item.name == "write_file")
    assert shell.guardrails is True
    assert shell.metadata["process_execution_constrained"] is True
    assert write.guardrails is True
    assert write.metadata["filesystem_path_constrained"] is True
    assert write.metadata["agent_internal_artifact"] is True
    assert any(resource.selector == ".shotgun/**" for resource in write.resources)
    assert not any(
        finding.rule_id in {"AGT020", "AGT022", "AGT040"}
        and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_ai_imported_native_controls_propagate_from_source(
    tmp_path: Path,
) -> None:
    package = tmp_path / "native_tools"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "tools.py").write_text(
        """
import asyncio

ALLOWED_COMMANDS = {"ls", "grep", "git"}
DANGEROUS_PATTERNS = [r"[|&;]"]

async def codebase_shell(command: str, args: list[str]):
    if command not in ALLOWED_COMMANDS:
        return "not allowed"
    for pattern in DANGEROUS_PATTERNS:
        if pattern in command:
            return "blocked"
    process = await asyncio.create_subprocess_exec(command, *args)
    return await process.wait()

def _validate_agent_scoped_path(filename: str):
    return ".shotgun/" + filename

def write_file(filename: str, content: str):
    path = _validate_agent_scoped_path(filename)
    with open(path, "w") as handle:
        handle.write(content)

def append_file(filename: str, content: str):
    return write_file(filename, content)
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from native_tools.tools import append_file, codebase_shell, write_file

agent = Agent(
    "openai:gpt-5.2",
    tools=[codebase_shell, write_file, append_file],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    shell = next(item for item in agent.tools if item.name == "codebase_shell")
    write = next(item for item in agent.tools if item.name == "write_file")
    append = next(item for item in agent.tools if item.name == "append_file")

    assert shell.guardrails is True
    assert shell.metadata["process_execution_constrained"] is True
    for tool in (write, append):
        assert tool.guardrails is True
        assert tool.metadata["filesystem_path_constrained"] is True
        assert tool.metadata["agent_internal_artifact"] is True
        assert any(resource.selector == ".shotgun/**" for resource in tool.resources)

    assert not any(
        finding.rule_id in {"AGT020", "AGT021", "AGT022", "AGT040"}
        and finding.agent == "agent"
        for finding in findings
    )

def test_pydantic_ai_relative_reexported_native_controls_reach_bound_tools(
    tmp_path: Path,
) -> None:
    package = tmp_path / "app"
    tools = package / "tools"
    tools.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (tools / "__init__.py").write_text(
        """
from .codebase import codebase_shell
from .file_management import append_file, write_file
""",
        encoding="utf-8",
    )
    (tools / "codebase.py").write_text(
        """
import asyncio

ALLOWED_COMMANDS = {"ls", "grep", "git"}
DANGEROUS_PATTERNS = [r"[|&;]"]

async def codebase_shell(command: str, args: list[str]):
    if command not in ALLOWED_COMMANDS:
        return "not allowed"
    for pattern in DANGEROUS_PATTERNS:
        if pattern in command:
            return "blocked"
    process = await asyncio.create_subprocess_exec(command, *args)
    return await process.wait()
""",
        encoding="utf-8",
    )
    (tools / "file_management.py").write_text(
        """
def _validate_agent_scoped_path(filename: str):
    return ".shotgun/" + filename

def write_file(filename: str, content: str):
    path = _validate_agent_scoped_path(filename)
    with open(path, "w") as handle:
        handle.write(content)

def append_file(filename: str, content: str):
    return write_file(filename, content)
""",
        encoding="utf-8",
    )
    (package / "agent.py").write_text(
        """
from pydantic_ai import Agent
from .tools import append_file, codebase_shell, write_file

agent = Agent(
    "openai:gpt-5.2",
    tools=[codebase_shell, write_file, append_file],
)

def run_agent(prompt: str):
    return agent.run_sync(prompt)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.name == "agent" and any(tool.name == "codebase_shell" for tool in item.tools)
    )
    shell = next(item for item in agent.tools if item.name == "codebase_shell")
    write = next(item for item in agent.tools if item.name == "write_file")
    append = next(item for item in agent.tools if item.name == "append_file")

    assert shell.metadata["source_function"].endswith("codebase_shell")
    assert shell.metadata["process_execution_constrained"] is True
    assert shell.guardrails is True
    for tool in (write, append):
        assert tool.metadata["filesystem_path_constrained"] is True
        assert tool.metadata["agent_internal_artifact"] is True
        assert tool.guardrails is True
        assert any(resource.selector == ".shotgun/**" for resource in tool.resources)

    assert not any(
        finding.rule_id in {"AGT020", "AGT021", "AGT022", "AGT040", "CAP005"}
        and finding.agent == agent.name
        for finding in findings
    )
    assert not any(
        path.path_id in {"PATH001", "PATH002", "PATH006"}
        and path.agent == agent.name
        for path in graph.attack_paths
    )

def test_pydantic_ai_same_named_agents_keep_effective_authority_isolated(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    tests = tmp_path / "tests"
    runtime.mkdir()
    tests.mkdir()
    (runtime / "agent.py").write_text(
        """
from pydantic_ai import Agent

def read_record(record_id: str):
    return record_id

agent = Agent("openai:gpt-5.2", tools=[read_record])
""",
        encoding="utf-8",
    )
    (tests / "agent_fixture.py").write_text(
        """
from pydantic_ai import Agent

def update_record(record_id: str):
    return record_id

agent = Agent("openai:gpt-5.2", tools=[update_record])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agents = [item for item in graph.agents if item.name == "agent"]
    assert len(agents) == 2
    assert len({item.metadata.get("instance_key") for item in agents}) == 2
    assert not any(
        finding.rule_id == "CAP005" and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_ai_run_context_plan_state_is_not_external_write_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent, RunContext

class Deps:
    current_plan = None

async def create_plan(ctx: RunContext[Deps], goal: str):
    ctx.deps.current_plan = {"goal": goal, "steps": []}
    return "created"

async def remove_step(ctx: RunContext[Deps], step_id: str):
    plan = ctx.deps.current_plan
    if plan is not None:
        plan["steps"].clear()
    return step_id

agent = Agent("openai:gpt-5.2", tools=[create_plan, remove_step])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    create = next(item for item in agent.tools if item.name == "create_plan")
    remove = next(item for item in agent.tools if item.name == "remove_step")

    for tool in (create, remove):
        assert tool.metadata["agent_internal_state"] is True
        assert tool.metadata["mutation_semantics"] == "agent_internal_state"
        assert "data.write" not in tool.capabilities
        assert "destructive.write" not in tool.capabilities

    assert not any(
        finding.rule_id in {"AGT021", "AGT022", "AGT040", "CAP005"}
        and finding.agent == "agent"
        for finding in findings
    )

def test_pydantic_ai_src_layout_absolute_reexport_preserves_internal_state_semantics(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src" / "demo"
    tools = package / "tools"
    tools.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (tools / "__init__.py").write_text(
        "from demo.tools.plan_tools import create_plan, remove_step\n",
        encoding="utf-8",
    )
    (tools / "plan_tools.py").write_text(
        """
from pydantic_ai import RunContext

class Deps:
    current_plan = None

async def create_plan(ctx: RunContext[Deps], goal: str):
    ctx.deps.current_plan = {"goal": goal, "steps": []}
    return "created"

async def remove_step(ctx: RunContext[Deps], step_id: str):
    plan = ctx.deps.current_plan
    if plan is not None:
        plan["steps"].clear()
    return step_id
""",
        encoding="utf-8",
    )
    (package / "router.py").write_text(
        """
from pydantic_ai import Agent
from demo.tools import create_plan, remove_step

agent = Agent("openai:gpt-5.2")
agent.tool(create_plan)
agent.tool(remove_step)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.name == "agent" and any(tool.name == "create_plan" for tool in item.tools)
    )
    create = next(item for item in agent.tools if item.name == "create_plan")
    remove = next(item for item in agent.tools if item.name == "remove_step")

    for tool in (create, remove):
        assert tool.metadata["source_function_key"].endswith(
            f"plan_tools.{tool.name}"
        )
        assert tool.metadata["agent_internal_state"] is True
        assert "data.write" not in tool.capabilities
        assert "destructive.write" not in tool.capabilities

    assert not any(
        finding.rule_id in {"AGT021", "AGT022", "AGT040", "CAP005"}
        and finding.agent == "agent"
        for finding in findings
    )



def test_pydantic_ai_src_layout_absolute_reexport_preserves_internal_state(
    tmp_path: Path,
) -> None:
    src = tmp_path / "src"
    package = src / "demo"
    tools = package / "router" / "tools"
    tools.mkdir(parents=True)
    for init in [
        package / "__init__.py",
        package / "router" / "__init__.py",
    ]:
        init.write_text("", encoding="utf-8")
    (tools / "__init__.py").write_text(
        """
from demo.router.tools.plan_tools import create_plan, remove_step
""",
        encoding="utf-8",
    )
    (tools / "plan_tools.py").write_text(
        """
from pydantic_ai import RunContext

class Deps:
    current_plan = None

async def create_plan(ctx: RunContext[Deps], value: str):
    ctx.deps.current_plan = value
    return "ok"

async def remove_step(ctx: RunContext[Deps], value: str):
    plan = ctx.deps.current_plan
    if plan:
        plan.pop()
    return "ok"
""",
        encoding="utf-8",
    )
    (package / "router" / "router.py").write_text(
        """
from pydantic_ai import Agent
from demo.router.tools import create_plan, remove_step

agent = Agent("openai:gpt-5.2")
agent.tool(create_plan)
agent.tool(remove_step)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.name == "agent"
        and any(tool.name == "create_plan" for tool in item.tools)
    )
    create = next(tool for tool in agent.tools if tool.name == "create_plan")
    remove = next(tool for tool in agent.tools if tool.name == "remove_step")

    for tool in (create, remove):
        assert tool.metadata["source_function"].endswith(tool.name)
        assert tool.metadata["agent_internal_state"] is True
        assert not (tool.capabilities & {"data.write", "destructive.write"})

    assert not any(
        finding.rule_id in {"AGT021", "AGT022", "AGT040"}
        and finding.agent == agent.name
        for finding in findings
    )
