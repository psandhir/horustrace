from pathlib import Path

from horustrace.adapters.registry import detect_python_frameworks
from horustrace.effective_authority import effective_authority_relationships
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


def test_pydantic_ai_web_loader_model_selected_url_is_source_backed_path(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from langchain_community.document_loaders import WebBaseLoader
from pydantic_ai import Agent, Tool

def web_scraper(urls: list[str]) -> str:
    text = ""
    for url in urls:
        loader = WebBaseLoader(url)
        docs = loader.load()
        text += str(docs)
    return text

agent = Agent(
    "openai:gpt-5.2",
    tools=[Tool(web_scraper, takes_ctx=False)],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "web_scraper")

    assert tool.metadata["model_selected_url_fetch"] is True
    assert tool.metadata["model_selected_url_parameters"] == ["urls"]
    assert any(
        destination.target == "<dynamic-url>"
        and destination.metadata.get("network_abstraction") == "url_loader"
        for destination in tool.destinations
    )

    flow = next(
        item
        for item in graph.flow_paths
        if item.agent == "agent"
        and item.source_kind == "agent_tool_input"
        and item.sink_kind == "server_side_url_fetch"
    )
    assert flow.confidence.value == "supported"
    assert flow.source_label == "web_scraper.urls"
    assert flow.sink_label == "WebBaseLoader"

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH011"
        and item.agent == "agent"
        and item.metadata.get("basis") == "static_dataflow"
    )
    assert path.metadata["network_abstraction"] == "url_loader"
    assert path.metadata["destination_provenance"] == "model_selected_url_argument"
    assert any(
        finding.rule_id == "PATH011" and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_ai_model_selected_write_path_is_resource_scope(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent, Tool

def save_output(filename: str, content: bytes) -> str:
    with open(filename, "wb") as handle:
        handle.write(content)
    return filename

agent = Agent(
    "openai:gpt-5.2",
    tools=[Tool(save_output, takes_ctx=False)],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "save_output")

    assert tool.metadata["model_selected_filesystem_path"] is True
    assert tool.metadata["filesystem_path_constrained"] is False
    assert tool.metadata["model_selected_path_parameters"] == ["filename"]
    resource = next(
        item
        for item in tool.resources
        if item.selector == "<model-selected-path>"
    )
    assert resource.kind == "file"
    assert resource.access == {"data.write"}
    assert resource.metadata["model_selected_path"] is True
    assert resource.metadata["path_parameters"] == ["filename"]
    assert resource.metadata["path_containment"] == "not_detected"

    finding = next(
        item
        for item in findings
        if item.rule_id == "AGT022" and item.agent == "agent"
    )
    assert "resource_scope=<model-selected-path>" in finding.evidence
    assert "path_parameters=filename" in finding.evidence
    assert "path_containment=not_detected" in finding.evidence


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

def test_pydantic_ai_langchain_python_repl_preserves_execution_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.ext.langchain import tool_from_langchain
from langchain_experimental.tools.python.tool import PythonREPLTool

python_tool = tool_from_langchain(PythonREPLTool())

agent = Agent(
    "openai-responses:gpt-5.2",
    tools=[python_tool],
)

app = agent.to_web()
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    repl = next(
        item
        for item in agent.tools
        if item.metadata.get("wrapped_tool") == "PythonREPLTool"
    )

    assert repl.kind == "langchain_python_repl"
    assert "process.execute" in repl.capabilities
    assert repl.metadata["source"] == "tool_from_langchain"
    assert repl.metadata["wrapped_framework"] == "langchain"
    assert any(
        item.metadata.get("basis") == "pydantic_ai_to_web_input"
        and item.trust == "untrusted"
        for item in agent.inputs
    )
    assert any(
        finding.rule_id == "AGT020"
        and finding.agent == "agent"
        for finding in findings
    )
    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH001"
        and item.metadata.get("wrapped_tool") == "PythonREPLTool"
    )
    assert path.metadata["basis"] == "source_bound_ingress_authority"
    assert path.nodes[-1] == "wrapped code execution"




def test_pydantic_run_context_is_not_model_selected_path_parameter(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pathlib import Path
from pydantic_ai import Agent, RunContext

class Deps:
    output_dir: str = "/tmp"

agent = Agent("openai:gpt-5.2")

@agent.tool
def write_report(ctx: RunContext[Deps], filename: str, content: str) -> str:
    target = Path(filename)
    target.write_text(content)
    return str(target)

@agent.tool
def write_context_file(ctx: RunContext[Deps], content: str) -> str:
    target = Path(ctx.deps.output_dir) / "report.txt"
    target.write_text(content)
    return str(target)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    report = next(item for item in agent.tools if item.name == "write_report")
    context_write = next(
        item for item in agent.tools if item.name == "write_context_file"
    )

    assert report.metadata["model_selected_path_parameters"] == ["filename"]
    resource = next(
        item
        for item in report.resources
        if item.metadata.get("model_selected_path") is True
    )
    assert resource.metadata["path_parameters"] == ["filename"]
    assert "ctx" not in resource.metadata["path_parameters"]

    assert context_write.metadata.get("model_selected_filesystem_path") is not True
    assert not any(
        item.metadata.get("model_selected_path") is True
        for item in context_write.resources
    )


def test_pydantic_dynamic_agent_toolset_preserves_unresolved_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from pydantic_ai import Agent, FunctionToolset, RunContext

agent = Agent("openai:gpt-5.2")

def run_command(command: str) -> str:
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    ).stdout

@agent.toolset
def dynamic_tools(ctx: RunContext[dict]):
    return FunctionToolset(tools=[run_command])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")

    assert agent.metadata["dynamic_tools"] is True
    assert agent.metadata["dynamic_toolset_providers"] == ["dynamic_tools"]

    placeholder = next(
        item
        for item in agent.tools
        if item.kind == "pydantic_dynamic_toolset"
    )
    assert placeholder.name == "dynamic-toolset:dynamic_tools"
    assert placeholder.capabilities == set()
    assert placeholder.metadata["dynamic_authority"] is True
    assert placeholder.metadata["tool_catalogue_unresolved"] is True

    relationship = next(
        item
        for item in effective_authority_relationships(graph)
        if item.target_name == "dynamic-toolset:dynamic_tools"
    )
    assert relationship.resolution == "partially_resolved"
    assert "capabilities" in relationship.unresolved
    assert relationship.semantics["dynamic_authority"] is True
    assert relationship.semantics["tool_catalogue_unresolved"] is True

    assert any(
        diagnostic.code == "dynamic_configuration"
        and "@agent.toolset" in diagnostic.message
        for diagnostic in graph.coverage.diagnostics
    )
    assert not any(finding.rule_id == "AGT020" for finding in findings)


def test_pydantic_declarative_capability_projects_source_visible_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
import requests
from pathlib import Path

from pydantic_ai import Agent, FunctionToolset
from pydantic_ai.capabilities import Capability

def write_record(path: str, value: str) -> str:
    Path(path).write_text(value)
    return path

def run_command(command: str) -> str:
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    ).stdout

commands = FunctionToolset(tools=[run_command])
ops = Capability(
    id="ops",
    description="Operational tools",
    tools=[write_record],
    toolsets=[commands],
    defer_loading=True,
)

@ops.tool_plain
def lookup_order(order_id: str) -> str:
    return requests.get(
        f"https://orders.example.com/{order_id}",
        timeout=5,
    ).text

agent = Agent("openai:gpt-5.2", capabilities=[ops])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tools = {item.name: item for item in agent.tools}

    assert {"write_record", "run_command", "lookup_order"} <= set(tools)
    assert "data.write" in tools["write_record"].capabilities
    assert "process.execute" in tools["run_command"].capabilities
    assert "network.external" in tools["lookup_order"].capabilities

    for name in ("write_record", "run_command", "lookup_order"):
        assert tools[name].metadata["binding_origin"] == "pydantic_capability"
        assert tools[name].metadata["capability_bundle"] == "ops"

    assert "ops" not in set(agent.metadata.get("unmodeled_capabilities") or [])

    relationships = {
        item.target_name: item
        for item in effective_authority_relationships(graph)
    }
    assert {"write_record", "run_command", "lookup_order"} <= set(relationships)
    assert relationships["lookup_order"].semantics["capability_bundle"] == "ops"



def test_pydantic_current_workspace_constraints_are_projected(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.capabilities import LocalWorkspace
from pydantic_ai_harness import FileSystem

agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[
        LocalWorkspace("/srv/read-only", read_only=True),
        FileSystem(),
    ],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    fs = next(item for item in agent.tools if item.name == "FileSystem")

    assert agent.metadata["workspace_provider"] == "local"
    assert agent.metadata["workspace_read_only"] is True
    assert agent.metadata["workspace"]["root"] == "/srv/read-only"
    assert fs.capabilities == {"data.read"}
    assert any(
        resource.selector == "/srv/read-only"
        and resource.access == {"data.read"}
        for resource in fs.resources
    )
    assert not any(
        finding.rule_id == "AGT040" and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_bubblewrap_removes_network_but_preserves_ssh_target(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai_harness import BubblewrapSandbox, Coder, SSHWorkspace

agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[
        BubblewrapSandbox(SSHWorkspace("dev@build-box", working_dir="/srv/app")),
        Coder(),
    ],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    coder = next(item for item in agent.tools if item.name == "Coder")

    assert agent.metadata["sandbox"] == "bubblewrap"
    assert agent.metadata["workspace_network_allowed"] is False
    assert "network.external" not in coder.capabilities
    assert "process.execute" in coder.capabilities
    assert any(resource.selector == "/srv/app" for resource in coder.resources)
    assert any(destination.target == "ssh://dev@build-box" for destination in agent.network)
    assert coder.metadata["network_isolated"] is True


def test_pydantic_subagents_bind_named_children_without_subprocess_false_delegation(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from pydantic_ai import Agent
from pydantic_ai_harness import SubAgent, SubAgents

def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

def write_report(path: str, content: str) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path

worker = Agent("anthropic:claude-opus-5-5", name="worker", tools=[write_report])
parent = Agent(
    "anthropic:claude-opus-5-5",
    name="parent",
    tools=[run_command],
    capabilities=[
        SubAgents(
            agents=[SubAgent(worker)],
            include_self=True,
            max_depth=2,
        )
    ],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    parent = next(item for item in graph.agents if item.name == "parent")
    run_command = next(item for item in parent.tools if item.name == "run_command")
    delegated = next(item for item in parent.tools if item.name == "SubAgents")

    assert run_command.metadata.get("delegate_target") is None
    assert "agent.delegate" not in run_command.capabilities
    assert delegated.metadata["delegate_targets"] == ["worker", "self"]
    assert delegated.metadata["include_self"] is True
    assert delegated.metadata["max_depth"] == 2
    assert "data.write" in delegated.capabilities


def test_pydantic_memory_skills_and_capability_creation_are_authority_bearing(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pathlib import Path
from pydantic_ai import Agent
from pydantic_ai.capabilities import LocalWorkspace
from pydantic_ai_harness import CapabilityCreation, Memory, Skills
from pydantic_ai_harness.memory import FileStore

creation = CapabilityCreation(directory=Path(".authored"))
agent = Agent(
    "anthropic:claude-opus-5-5",
    capabilities=[
        LocalWorkspace("/workspace"),
        Memory(FileStore(".agent-memory")),
        Skills(".agents/skills"),
        creation,
    ],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tools = {item.name: item for item in agent.tools}

    assert {"Memory", "Skills", "CapabilityCreation"} <= set(tools)
    assert {"data.read", "data.write"} <= tools["Memory"].capabilities
    assert any(r.selector == ".agent-memory" for r in tools["Memory"].resources)
    assert tools["Skills"].capabilities == {"data.read"}
    assert tools["Skills"].metadata["deferred_capability_catalogue"] is True
    assert any(r.selector == ".agents/skills" for r in tools["Skills"].resources)
    assert {"process.execute", "data.write"} <= tools["CapabilityCreation"].capabilities
    assert tools["CapabilityCreation"].metadata["host_process_execution"] is True
    assert any(r.selector == ".authored" for r in tools["CapabilityCreation"].resources)
    assert agent.metadata["dynamic_tools"] is True


def test_pydantic_hosted_harness_mcp_capabilities_preserve_auth_and_readonly(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai_harness.github import GitHub
from pydantic_ai_harness.slack import Slack

github_agent = Agent(
    "openai:gpt-5.6-sol",
    capabilities=[GitHub(auth="gh-token")],
)
slack_agent = Agent(
    "openai:gpt-5.6-sol",
    capabilities=[Slack(auth="xoxp-token", read_only=True)],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    github = next(item for item in graph.agents if item.name == "github_agent")
    slack = next(item for item in graph.agents if item.name == "slack_agent")

    github_server = github.mcp_servers[0]
    assert github_server.url == "https://api.githubcopilot.com/mcp/"
    assert github_server.authenticated is True
    assert github_server.metadata["read_only"] is False

    slack_server = slack.mcp_servers[0]
    assert slack_server.url == "https://mcp.slack.com/mcp"
    assert slack_server.authenticated is True
    assert slack_server.metadata["read_only"] is True
    assert slack.metadata["read_only_integrations"] == ["slack"]

def test_pydantic_runcontext_dependency_methods_propagate_concrete_repository_effects(
    tmp_path: Path,
) -> None:
    (tmp_path / "storage.py").write_text(
        """
class CSVStore:
    def __init__(self, path: str):
        self.path = path

    def add_transaction(self, value: str) -> str:
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(value + "\\n")
        return value

    def update_budget_limits(self, value: str) -> str:
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(value)
        return value
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent, RunContext
from storage import CSVStore

class BudgetContext:
    csv_manager: CSVStore

agent = Agent(
    "openai:gpt-5.2",
    deps_type=BudgetContext,
)

@agent.tool
async def add_transaction(ctx: RunContext[BudgetContext], value: str) -> str:
    return ctx.deps.csv_manager.add_transaction(value)

@agent.tool
async def set_budget_limit(ctx: RunContext[BudgetContext], value: str) -> str:
    return ctx.deps.csv_manager.update_budget_limits(value)

@agent.tool_plain
def add_numbers(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tools = {item.name: item for item in agent.tools}

    assert "data.write" in tools["add_transaction"].capabilities
    assert "data.write" in tools["set_budget_limit"].capabilities
    assert tools["add_transaction"].metadata["repository_effect_enriched"] is True
    assert "file:write" in tools["add_transaction"].metadata[
        "repository_effect_evidence"
    ]
    assert "data.write" not in tools["add_numbers"].capabilities
    assert "destructive.write" not in tools["add_numbers"].capabilities

    assert any(
        finding.rule_id in {"AGT022", "AGT040"}
        and finding.agent == "agent"
        and "add_transaction" in finding.message
        for finding in findings
    )



def test_pydantic_ai_dynamic_sse_toolset_is_preserved(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerSSE

def build_agent(server_url: str):
    client = MCPServerSSE(
        url=server_url,
        headers={"X-User-ID": "session"},
    )
    return Agent("openai:gpt-5.2", toolsets=[client])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.metadata["framework"] == "pydantic-ai")
    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.transport == "sse"
    assert server.metadata["dynamic_mcp_endpoint"] is True
    assert server.metadata["dynamic_mcp_endpoint_basis"] == "operator_configuration"


def test_pydantic_local_mcp_console_script_projects_repository_catalogue(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "local-mcp-app"
version = "0.1.0"

[project.scripts]
localmcp = "localmcp:main"
""",
        encoding="utf-8",
    )
    package = tmp_path / "src" / "localmcp"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        """
from .server import mcp

def main():
    mcp.run(transport="stdio")
""",
        encoding="utf-8",
    )
    (package / "server.py").write_text(
        """
import subprocess
from fastmcp import FastMCP

mcp = FastMCP("trading")

@mcp.tool()
def order_send(order: str) -> str:
    return subprocess.run(
        ["trade-cli", order],
        capture_output=True,
        text=True,
    ).stdout
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

server = MCPServerStdio("uv", args=["run", "localmcp"])
agent = Agent("openai:gpt-5.2", toolsets=[server])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.metadata["framework"] == "pydantic-ai")
    server = agent.mcp_servers[0]
    assert server.metadata["binding_origin"] == "local_stdio_console_script"
    assert server.metadata["console_script_modules"] == ["localmcp"]
    assert server.metadata["repository_resolved"] is True
    assert any(
        tool["name"] == "order_send"
        for tool in server.metadata["discovered_tools"]
    )


def test_pydantic_model_object_preserves_provider_endpoint_provenance(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

provider = OpenAIProvider(base_url="https://llm-proxy.example/v1")
model = OpenAIChatModel("gpt-5-mini", provider=provider)
agent = Agent(model=model)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]

    assert agent.metadata["model"] == "gpt-5-mini"
    assert agent.metadata["model_provider"] == "openai"
    assert agent.metadata["model_hosting"] == "provider_hosted"
    assert agent.metadata["model_endpoint"] == "https://llm-proxy.example/v1"
    assert agent.metadata["model_constructor"] == "OpenAIChatModel"
    assert agent.metadata["model_source_reference"] == (
        "pydantic_ai.models.openai.OpenAIChatModel"
    )
    assert agent.metadata["model_provider_source_reference"] == (
        "pydantic_ai.providers.openai.OpenAIProvider"
    )
    assert agent.metadata["model_resolution"] == "resolved_identifier"


def test_pydantic_google_cloud_model_preserves_region(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google_cloud import GoogleCloudProvider

model = GoogleModel(
    "gemini-2.5-pro",
    provider=GoogleCloudProvider(
        project="payments-prod",
        location="europe-west1",
    ),
)
agent = Agent(model)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]

    assert agent.metadata["model"] == "gemini-2.5-pro"
    assert agent.metadata["model_provider"] == "google-cloud-vertex"
    assert agent.metadata["model_hosting"] == "provider_hosted"
    assert agent.metadata["model_region"] == "europe-west1"
    assert agent.metadata["model_constructor"] == "GoogleModel"


def test_pydantic_dynamic_model_reference_stays_unresolved(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

def build(model):
    return Agent(model)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]

    assert agent.metadata.get("model") is None
    assert agent.metadata["model_reference"] == "model"
    assert agent.metadata["model_resolution"] == "unresolved_reference"

def test_pydantic_factory_return_with_console_toolset_composes_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from dataclasses import dataclass
from pydantic_ai import Agent
from pydantic_ai_backends import LocalBackend, create_console_toolset

@dataclass
class AgentDeps:
    backend: LocalBackend

def create_cli_agent(enable_execute: bool = True):
    toolset = create_console_toolset(
        include_execute=enable_execute,
        require_write_approval=False,
        require_execute_approval=False,
    )
    base_agent = Agent("openai:gpt-4o-mini", deps_type=AgentDeps)
    return base_agent.with_toolset(toolset)

agent = create_cli_agent(enable_execute=runtime_flag)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("factory_function") == "create_cli_agent"
    )

    assert agent.metadata["factory_return_toolset"] is True
    tools = {tool.name: tool for tool in agent.tools}
    assert {"console:file-read", "console:file-write", "console:execute"} <= set(tools)
    assert tools["console:file-read"].capabilities == {"data.read"}
    assert tools["console:file-write"].capabilities == {"data.read", "data.write"}
    assert tools["console:file-write"].approval is False
    assert "process.execute" in tools["console:execute"].capabilities
    assert tools["console:execute"].approval is False
    assert tools["console:execute"].metadata["configuration_dependent"] is True

    resource = tools["console:execute"].resources[0]
    assert resource.selector == "<runtime-backend-filesystem>"
    assert resource.metadata["data_connection_type"] == "filesystem"
    assert resource.metadata["data_connection_resolution"] == "dynamic"
    assert resource.metadata["resource_provenance"] == "console_toolset_backend"


def test_pydantic_console_toolset_literal_execute_false_removes_process_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai_backends import create_console_toolset

def create_readwrite_agent():
    toolset = create_console_toolset(
        include_execute=False,
        require_write_approval=True,
    )
    base_agent = Agent("openai:gpt-4o-mini")
    return base_agent.with_toolset(toolset)

agent = create_readwrite_agent()
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("factory_function") == "create_readwrite_agent"
    )

    tools = {tool.name: tool for tool in agent.tools}
    assert "console:execute" not in tools
    assert tools["console:file-write"].approval is True
    assert "data.write" in agent.capabilities
    assert "process.execute" not in agent.capabilities

def test_pydantic_factory_instance_cli_input_reaches_console_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import asyncio
from pydantic_ai import Agent
from pydantic_ai_backends import create_console_toolset

def create_cli_agent():
    toolset = create_console_toolset(
        include_execute=True,
        require_write_approval=False,
        require_execute_approval=False,
    )
    base_agent = Agent("openai:gpt-4o-mini")
    return base_agent.with_toolset(toolset)

async def main():
    cli_agent = create_cli_agent()
    user_input = input("You: ")
    await cli_agent.run(user_input)

asyncio.run(main())
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("factory_function") == "create_cli_agent"
    )

    assert agent.metadata["factory_instance"] is True
    assert agent.metadata["factory_assignment_line"] > agent.location.line
    assert any(
        source.metadata.get("basis") == "pydantic_ai_cli_input_to_run"
        for source in agent.inputs
    )
    assert "process.execute" in agent.capabilities
    assert "data.read" in agent.capabilities
    assert "data.write" in agent.capabilities



def test_pydantic_agent_alias_inside_application_wrapper_is_detected(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent as PydanticAgent


class Agent:
    def __init__(self, model: str):
        self._model = model
        self._agent = None

    def _build_agent(self):
        if self._agent is None:
            self._agent = PydanticAgent(
                self._model,
                name="wrapped-agent",
            )
        return self._agent
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "self._agent")
    assert agent.metadata["framework"] == "pydantic-ai"


def test_user_defined_agent_constructor_is_not_misclassified_as_pydantic(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import RunContext


class Agent:
    def __init__(self, name: str):
        self.name = name


agent = Agent("local-wrapper")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    assert not any(
        item.metadata.get("framework") == "pydantic-ai"
        for item in graph.agents
    )


def test_repository_local_pydantic_agent_subclass_factory_is_detected(
    tmp_path: Path,
) -> None:
    (tmp_path / "mcpx_pydantic_ai.py").write_text(
        """
import pydantic_ai


class Agent(pydantic_ai.Agent):
    pass
""",
        encoding="utf-8",
    )
    (tmp_path / "example.py").write_text(
        """
from mcpx_pydantic_ai import Agent
from pydantic_ai import capture_run_messages


def new_agent(result_type, model="claude-3-5-sonnet-latest"):
    return Agent(model, result_type=result_type)


agent = new_agent(int)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")

    assert agent.metadata["framework"] == "pydantic-ai"
    assert agent.metadata["repository_subclass_provenance"] is True
    assert agent.metadata["framework_base"] == "pydantic_ai.Agent"
    assert agent.metadata["subclass_module"] == "mcpx_pydantic_ai"
    assert agent.metadata["subclass_name"] == "Agent"
    assert agent.metadata["factory_function"] == "new_agent"
    assert agent.metadata["model_reference"] == "model"
    assert agent.metadata["model_resolution"] == "unresolved_reference"


def test_repository_local_unrelated_agent_subclass_is_not_detected(
    tmp_path: Path,
) -> None:
    (tmp_path / "local_agent.py").write_text(
        """
class Base:
    pass


class Agent(Base):
    pass
""",
        encoding="utf-8",
    )
    (tmp_path / "example.py").write_text(
        """
from local_agent import Agent
from pydantic_ai import capture_run_messages

agent = Agent()
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    assert not any(
        item.metadata.get("repository_subclass_provenance") is True
        for item in graph.agents
    )
