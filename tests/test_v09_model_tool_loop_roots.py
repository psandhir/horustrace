from pathlib import Path

from horustrace.adapters.registry import detect_python_frameworks
from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def test_custom_mcp_model_tool_loop_is_discovered_as_agent_root(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from mcp import ClientSession

class Agent:
    def __init__(self, session: ClientSession, provider):
        self.session = session
        self.provider = provider

    async def connect(self):
        tools = (await self.session.list_tools()).tools
        self.provider.set_tools(tools)

    async def run_turn(self, prompt):
        response = self.provider.send_user_message(prompt)
        while response.tool_calls:
            for call in response.tool_calls:
                await self.session.call_tool(call.name, call.arguments)
            response = self.provider.send_tool_results([])
        return response
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "model-tool-loop" in detect_python_frameworks(source)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    )
    assert agent.name == "agent"
    assert agent.metadata["discovery_basis"] == "model_tools_selection_dispatch"
    assert set(agent.metadata["discovery_signals"]) == {
        "model_call",
        "model_selection",
        "tool_catalogue",
        "tool_dispatch",
    }
    assert agent.tools == []
    assert agent.mcp_servers == []
    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "agent" and item.name == "agent"
    )
    assert node.attributes["discovery_basis"] == "model_tools_selection_dispatch"
    assert node.attributes["semantic_entity_kind"] == "agent"
    assert node.attributes["semantic_entity_id"] == agent.metadata["semantic_entity_id"]
    assert effective_authority_report(graph)["relationships"] == []


def test_openai_compatible_custom_tool_loop_is_discovered(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from openai import OpenAI

class Agent:
    def __init__(self):
        self.llm = OpenAI()
        self.tools = []

    def call_tool(self, name, arguments):
        return {"name": name, "arguments": arguments}

    def run(self, messages):
        response = self.llm.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=self.tools,
        )
        for call in response.choices[0].message.tool_calls:
            self.call_tool(call.function.name, call.function.arguments)
        return response
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    roots = [
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    ]
    assert [item.name for item in roots] == ["agent"]


def test_agent_named_class_without_model_selected_dispatch_is_not_promoted(
    tmp_path: Path,
) -> None:
    source = tmp_path / "helper.py"
    source.write_text(
        """
class Agent:
    async def connect(self):
        return await self.session.list_tools()

    async def invoke(self, prompt):
        return await self.model.invoke(prompt)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "model-tool-loop" not in detect_python_frameworks(source)
    assert not any(
        item.metadata.get("framework") == "model-tool-loop"
        for item in graph.agents
    )


def test_livekit_tool_bound_agent_constructor_is_discovered(
    tmp_path: Path,
) -> None:
    source = tmp_path / "voice.py"
    source.write_text(
        """
from livekit.agents import Agent

realtime_agent = Agent(
    instructions="help",
    llm=realtime_model,
    tools=tools,
)

pipeline_agent = Agent(
    instructions="help",
    llm=standard_model,
    tools=tools,
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "model-tool-loop" in detect_python_frameworks(source)
    agents = [
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    ]
    assert [item.name for item in agents] == ["realtime_agent", "pipeline_agent"]
    assert len({item.metadata["instance_key"] for item in agents}) == 2
    assert graph.adg is not None
    adg_agents = [
        item
        for item in graph.adg.nodes
        if item.kind == "agent"
        and item.framework == "model-tool-loop"
        and item.name in {"realtime_agent", "pipeline_agent"}
    ]
    assert len(adg_agents) == 2
    assert all(
        item.metadata["discovery_basis"] == "explicit_tool_bound_agent_constructor"
        for item in agents
    )


def test_openai_agents_sdk_is_not_duplicated_by_generic_adapter(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, function_tool

@function_tool
def search(query: str) -> str:
    return query

agent = Agent(name="support", tools=[search])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "openai-agents" in detect_python_frameworks(source)
    assert "model-tool-loop" not in detect_python_frameworks(source)
    assert not any(
        item.metadata.get("framework") == "model-tool-loop"
        for item in graph.agents
    )


def test_unrelated_tools_keyword_does_not_prove_model_tool_exposure(
    tmp_path: Path,
) -> None:
    source = tmp_path / "helper.py"
    source.write_text(
        """
class Agent:
    def prepare(self):
        helper.configure(tools=self.registry)

    def run(self, prompt):
        response = self.model.invoke(prompt)
        for call in response.tool_calls:
            self.session.call_tool(call.name, call.arguments)
        return response
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "model-tool-loop" not in detect_python_frameworks(source)
    assert not any(
        item.metadata.get("framework") == "model-tool-loop"
        for item in graph.agents
    )


def test_same_named_explicit_agent_branches_remain_distinct_in_adg(
    tmp_path: Path,
) -> None:
    source = tmp_path / "voice.py"
    source.write_text(
        """
from livekit.agents import Agent

if realtime:
    agent = Agent(llm=realtime_model, tools=tools)
else:
    agent = Agent(llm=standard_model, tools=tools)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    roots = [
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
        and item.name == "agent"
    ]
    assert len(roots) == 2
    assert len({item.metadata["instance_key"] for item in roots}) == 2
    assert graph.adg is not None
    nodes = [
        item
        for item in graph.adg.nodes
        if item.kind == "agent"
        and item.framework == "model-tool-loop"
        and item.name == "agent"
    ]
    assert len(nodes) == 2
    assert len({item.node_id for item in nodes}) == 2
    assert {item.location["line"] for item in nodes} == {5, 7}


def test_gemini_mcp_client_loop_is_discovered_without_agent_class_name(
    tmp_path: Path,
) -> None:
    source = tmp_path / "client.py"
    source.write_text(
        """
from google import genai
from google.genai.types import GenerateContentConfig
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

class MCPClient:
    def __init__(self):
        self.session = None
        self._client = genai.Client()

    async def connect_to_server(self, server_script_path: str):
        params = StdioServerParameters(
            command="python",
            args=[server_script_path],
        )
        await stdio_client(params)

    async def process_query(self, query: str):
        response = await self.session.list_tools()
        available_tools = response.tools
        result = self._client.models.generate_content(
            model="gemini",
            contents=[query],
            config=GenerateContentConfig(tools=available_tools),
        )
        for part in result.candidates[0].content.parts:
            if part.function_call:
                await self.session.call_tool(
                    part.function_call.name,
                    part.function_call.args,
                )
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    roots = [
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    ]
    assert len(roots) == 1
    agent = roots[0]
    assert agent.metadata["source_class"] == "MCPClient"
    assert set(agent.metadata["discovery_signals"]) == {
        "model_call",
        "model_selection",
        "tool_catalogue",
        "tool_dispatch",
    }
    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.name == "<dynamic-stdio-mcp>"
    assert server.metadata["dynamic_server_selection"] is True
    assert server.metadata["binding_origin"] == (
        "source_proven_dynamic_stdio_selection"
    )
    assert server.metadata["tool_catalogue_dynamic"] is True


def test_non_agent_class_with_list_tools_but_no_model_selection_is_not_promoted(
    tmp_path: Path,
) -> None:
    source = tmp_path / "client.py"
    source.write_text(
        """
class MCPClient:
    async def inspect(self):
        return await self.session.list_tools()

    async def call(self, name):
        return await self.session.call_tool(name, {})
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert not any(
        item.metadata.get("framework") == "model-tool-loop"
        for item in graph.agents
    )


def test_dynamic_mcp_loop_does_not_bind_discovered_repository_servers(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.py").write_text(
        """
class MCPClient:
    async def connect(self, path):
        params = StdioServerParameters(command="python", args=[path])
        await stdio_client(params)

    async def run(self, prompt):
        tools = (await self.session.list_tools()).tools
        response = self.model.generate_content(prompt, tools=tools)
        if response.function_call:
            await self.session.call_tool(
                response.function_call.name,
                response.function_call.args,
            )
""",
        encoding="utf-8",
    )
    (tmp_path / "server_a.py").write_text(
        """
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("a")
@mcp.tool()
def dangerous_a():
    return "a"
""",
        encoding="utf-8",
    )
    (tmp_path / "server_b.py").write_text(
        """
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("b")
@mcp.tool()
def dangerous_b():
    return "b"
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    )

    assert [server.name for server in agent.mcp_servers] == [
        "<dynamic-stdio-mcp>"
    ]
    assert all(
        server.name != "a" and server.name != "b"
        for server in agent.mcp_servers
    )


def test_openai_responses_mcp_loop_binds_source_visible_default_stdio_server(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import AsyncOpenAI


def _repo_root():
    return Path(__file__).resolve().parent


def _load_config(config_path=None):
    path = Path(config_path or "mcp_config.json")
    if path.exists():
        return json.loads(path.read_text())
    return {
        "mcpServers": {
            "workspace": {
                "enabled": True,
                "command": sys.executable,
                "args": [str(_repo_root() / "mcp_server_example.py")],
            }
        }
    }


class OpenAIMCPAgent:
    def __init__(self):
        self.client = AsyncOpenAI()
        self.openai_tools = []
        self.tool_map = {}
        self.servers = {}

    async def connect(self):
        config = _load_config()
        for server_name, server_config in config["mcpServers"].items():
            params = StdioServerParameters(
                command=server_config["command"],
                args=server_config.get("args", []),
            )
            read_stream, write_stream = await stdio_client(params).__aenter__()
            session = ClientSession(read_stream, write_stream)
            await session.initialize()
            self.servers[server_name] = session
            tools_result = await session.list_tools()
            for tool in tools_result.tools:
                openai_name = f"{server_name}__{tool.name}"
                self.tool_map[openai_name] = (server_name, tool.name)
                self.openai_tools.append(
                    {
                        "type": "function",
                        "name": openai_name,
                        "parameters": tool.inputSchema,
                    }
                )

    async def call_tool(self, openai_tool_name, tool_input):
        server_name, real_tool_name = self.tool_map[openai_tool_name]
        return await self.servers[server_name].call_tool(real_tool_name, tool_input)

    async def run(self, prompt):
        response = await self.client.responses.create(
            model="gpt-test",
            input=prompt,
            tools=self.openai_tools,
        )
        for item in response.output:
            if item.type == "function_call":
                await self.call_tool(item.name, json.loads(item.arguments))
        return response
""",
        encoding="utf-8",
    )
    (tmp_path / "mcp_server_example.py").write_text(
        """
import subprocess
import sys

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("jarvis-workspace")


@mcp.tool()
def run_python(code: str) -> str:
    completed = subprocess.run(
        [sys.executable, "-c", code],
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.stdout


if __name__ == "__main__":
    mcp.run()
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    )
    assert agent.name == "open_ai_m_c_p_agent"
    assert [server.name for server in agent.mcp_servers] == ["workspace"]
    server = agent.mcp_servers[0]
    assert server.metadata["binding_origin"] == "local_stdio_script"
    assert server.metadata["repository_resolved"] is True
    assert server.metadata["implementation_name"] == "jarvis-workspace"
    assert server.metadata["discovered_tool_capabilities"] == ["process.execute"]
    assert any(
        item.rule_id == "AGT053"
        and item.agent == agent.name
        for item in findings
    )
    assert not any(
        item.rule_id == "AGT020"
        and "Unbound tool 'run_python'" in item.message
        for item in findings
    )
    assert not any(tool.name == "run_python" for tool in graph.unbound_tools)
    assert effective_authority_report(graph)["relationships"] == [
        {
            "relationship_id": effective_authority_report(graph)["relationships"][0][
                "relationship_id"
            ],
            "agent": agent.name,
            "target_kind": "mcp_server",
            "target_name": "workspace",
            "capabilities": ["mcp.local"],
            "resources": [],
            "destinations": [],
            "identity": None,
            "dimensions": {
                "binding": "resolved",
                "scope": "unknown",
                "identity": "unknown",
                "destination": "not_applicable",
                "approval": "unknown",
            },
            "scope": {
                "allowed_tools": [],
                "denied_tools": [],
                "resources": [],
            },
            "approval": {
                "required": None,
                "guardrails": [],
                "inherited_control": False,
            },
            "evidence": [
                {
                    "origin": "observed",
                    "fact": "agent_mcp_binding",
                    "subject": "workspace",
                    "location": {
                        "path": str((tmp_path / "agent.py").resolve()),
                        "line": 21,
                        "column": 20,
                    },
                }
            ],
        }
    ]
