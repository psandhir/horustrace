import ast
from pathlib import Path

from horustrace.analysis import build_attack_paths
from horustrace.models import Agent, Graph, InputSource, MCPServer, Tool
from horustrace.runtime_ingress import _authentication_posture
from horustrace.scanner import scan


def test_fastapi_websocket_ingress_reaches_bound_mcp_execution(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import sys
from pathlib import Path

from openai import AsyncOpenAI


def _repo_root():
    return Path(__file__).resolve().parent


def _load_config(config_path=None):
    return {
        "mcpServers": {
            "workspace": {
                "enabled": True,
                "command": sys.executable,
                "args": [str(_repo_root() / "workspace_server.py")],
            }
        }
    }


class OpenAIMCPAgent:
    def __init__(self):
        self.client = AsyncOpenAI()
        self.config_path = None
        self.openai_tools = []
        self.session = None

    async def connect(self):
        config = _load_config(self.config_path)
        tools_result = await self.session.list_tools()
        for tool in tools_result.tools:
            self.openai_tools.append(
                {
                    "type": "function",
                    "name": tool.name,
                    "parameters": tool.inputSchema,
                }
            )
        return config

    async def call_tool(self, name, arguments):
        return await self.session.call_tool(name, arguments)

    async def run(self, prompt):
        response = await self.client.responses.create(
            model="gpt-5",
            input=prompt,
            tools=self.openai_tools,
        )
        for item in response.output:
            if item.type == "function_call":
                await self.call_tool(item.name, {})
        return response
""",
        encoding="utf-8",
    )
    (tmp_path / "workspace_server.py").write_text(
        """
import subprocess
import sys
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("workspace")

@mcp.tool()
def run_python(code: str) -> str:
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
""",
        encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        """
from fastapi import FastAPI, WebSocket
from agent import OpenAIMCPAgent

app = FastAPI()

@app.websocket("/ws/agent")
async def agent_socket(websocket: WebSocket):
    await websocket.accept()
    payload = await websocket.receive_json()
    prompt = (payload.get("prompt") or "").strip()
    async with OpenAIMCPAgent() as agent:
        await agent.run(prompt)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("source_class") == "OpenAIMCPAgent"
    )
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.metadata["runtime_invocation_proven"] is True
    assert ingress.metadata["ingress_framework"] == "fastapi_websocket"

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH001"
        and item.metadata.get("target_kind") == "mcp_server"
    )
    assert path.agent == agent.name
    assert path.nodes[-2:] == ["workspace", "process.execute"]
    assert path.metadata["basis"] == "source_bound_ingress_authority"


def test_aiohttp_handler_ingress_reaches_runtime_bound_adk_wrapper(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from aiohttp import web
from google.adk.agents import Agent
from google.adk.runners import Runner


def store_memory(value: str):
    memory.write(value)


def build_agents():
    writer = Agent(
        name="writer",
        model="gemini",
        tools=[store_memory],
    )
    return writer


class MemoryAgent:
    def __init__(self):
        self.agent = build_agents()
        self.runner = Runner(agent=self.agent, app_name="memory")

    async def _execute(self, text: str):
        return await self.runner.run_async(new_message=text)

    async def ingest(self, text: str):
        return await self._execute(text)


def build_http(agent: MemoryAgent):
    app = web.Application()

    async def handle_ingest(request: web.Request):
        data = await request.json()
        text = str(data.get("text", "")).strip()
        return web.json_response({"result": await agent.ingest(text)})

    app.router.add_post("/ingest", handle_ingest)
    return app
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "google-adk"
        and item.name == "writer"
    )
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.metadata["ingress_framework"] == "aiohttp"

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH002"
        and item.metadata.get("target_kind") == "tool"
        and item.nodes[-2] == "store_memory"
    )
    assert path.metadata["basis"] == "source_bound_ingress_authority"


def test_agent_factory_holder_without_runtime_binding_is_not_ingress(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from aiohttp import web
from google.adk.agents import Agent


def store_memory(value: str):
    memory.write(value)


def build_agents():
    writer = Agent(name="writer", model="gemini", tools=[store_memory])
    return writer


class Holder:
    def __init__(self):
        self.agent = build_agents()

    async def query(self, text: str):
        return text


def build_http(holder: Holder):
    app = web.Application()

    async def handle_query(request: web.Request):
        data = await request.json()
        return web.json_response({"result": await holder.query(data.get("q", ""))})

    app.router.add_post("/query", handle_query)
    return app
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "google-adk"
        and item.name == "writer"
    )

    assert not any(
        item.metadata.get("basis") == "source_bound_runtime_ingress"
        for item in agent.inputs
    )


def test_runtime_bound_ingress_reaches_state_changing_mcp() -> None:
    server = MCPServer(
        name="workspace",
        transport="stdio",
        metadata={"discovered_tool_capabilities": ["data.write"]},
    )
    agent = Agent(
        name="agent",
        inputs=[
            InputSource(
                name="web.prompt",
                trust="untrusted",
                kind="web",
                metadata={
                    "basis": "source_bound_runtime_ingress",
                    "runtime_invocation_proven": True,
                },
            )
        ],
        mcp_servers=[server],
    )

    path = next(
        item
        for item in build_attack_paths(Graph(agents=[agent]))
        if item.path_id == "PATH002"
        and item.metadata.get("target_kind") == "mcp_server"
    )

    assert path.nodes == ["web.prompt", "agent", "workspace", "data.write"]
    assert path.metadata["basis"] == "source_bound_ingress_authority"


def test_flask_global_request_reaches_cached_wrapper_agent_write(
    tmp_path: Path,
) -> None:
    (tmp_path / "chat_engine.py").write_text(
        """
from agents import Agent, Runner, function_tool


@function_tool
def save_user_response(session_id: str, response: str):
    store.write(session_id, response)


class FormChatAgent:
    def __init__(self):
        self.agent = Agent(
            name="Barney",
            model="gpt-4o-mini",
            tools=[save_user_response],
        )

    def process_message(self, session_id: str, user_message: str):
        prompt = f"{session_id}: {user_message}"
        return Runner.run_sync(self.agent, prompt)


chat_agent = None


def get_chat_agent():
    global chat_agent
    if chat_agent is None:
        chat_agent = FormChatAgent()
    return chat_agent
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
from flask import Flask, request
from chat_engine import get_chat_agent

app = Flask(__name__)


@app.route("/api/chat/message", methods=["POST"])
def process_chat_message():
    data = request.get_json()
    session_id = data.get("session_id")
    message = data.get("message", "").strip()
    agent = get_chat_agent()
    return agent.process_message(session_id, message)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "Barney")
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.metadata["ingress_framework"] == "flask"
    assert ingress.metadata["runtime_invocation_proven"] is True

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH002"
        and item.agent == agent.name
        and item.metadata.get("target_kind") == "tool"
        and item.nodes[-2] == "save_user_response"
    )
    assert path.nodes[-1] in {"data.write", "destructive.write"}
    assert path.metadata["basis"] == "source_bound_ingress_authority"


def test_flask_global_request_does_not_bind_constant_wrapper_call(
    tmp_path: Path,
) -> None:
    (tmp_path / "chat_engine.py").write_text(
        """
from agents import Agent, Runner, function_tool


@function_tool
def save_user_response(response: str):
    store.write(response)


class FormChatAgent:
    def __init__(self):
        self.agent = Agent(
            name="Barney",
            model="gpt-4o-mini",
            tools=[save_user_response],
        )

    def process_message(self, user_message: str):
        return Runner.run_sync(self.agent, user_message)


chat_agent = None


def get_chat_agent():
    global chat_agent
    if chat_agent is None:
        chat_agent = FormChatAgent()
    return chat_agent
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
from flask import Flask, request
from chat_engine import get_chat_agent

app = Flask(__name__)


@app.route("/health", methods=["POST"])
def health():
    request.get_json()
    agent = get_chat_agent()
    return agent.process_message("constant-health-check")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Barney")

    assert not any(
        item.metadata.get("basis") == "source_bound_runtime_ingress"
        for item in agent.inputs
    )


def test_aiohttp_optional_public_auth_posture_is_preserved_on_paths() -> None:
    tree = ast.parse(
        """
import os
from aiohttp import web

def get_api_key_map():
    return os.getenv("MEMORY_API_KEYS", "")

@web.middleware
async def api_key_auth_middleware(request, handler):
    api_key_map = get_api_key_map()
    if not api_key_map:
        request["user_id"] = "public"
        return await handler(request)
    api_key = request.headers.get("X-API-Key", "")
    if not api_key:
        raise web.HTTPUnauthorized()
    return await handler(request)
"""
    )
    posture = _authentication_posture(tree, "aiohttp")
    assert posture["authentication_detected"] is True
    assert posture["authentication_mode"] == "optional_public_default"
    assert posture["public_default"] is True
    assert posture["authentication_environment_variables"] == ["MEMORY_API_KEYS"]

    graph = Graph(
        agents=[
            Agent(
                name="memory",
                inputs=[
                    InputSource(
                        name="handle_ingest:external-input",
                        trust="untrusted",
                        kind="web",
                        metadata={
                            "basis": "source_bound_runtime_ingress",
                            "runtime_invocation_proven": True,
                            **posture,
                        },
                    )
                ],
                tools=[
                    Tool(
                        name="store_memory",
                        kind="function",
                        capabilities={"data.write"},
                    )
                ],
            )
        ]
    )
    path = next(item for item in build_attack_paths(graph) if item.path_id == "PATH002")
    assert path.metadata["authentication_mode"] == "optional_public_default"
    assert path.metadata["public_default"] is True
    assert path.metadata["authentication_environment_variables"] == ["MEMORY_API_KEYS"]


def test_a2a_request_context_reaches_wrapped_strands_agent(
    tmp_path: Path,
) -> None:
    (tmp_path / "doc_agent.py").write_text(
        """
from strands import Agent
from strands_tools import shell


class DocAgent:
    def _load_agent(self, session_id: str):
        agent = Agent(
            name="docs",
            model="us.amazon.nova-pro-v1:0",
            tools=[shell],
        )
        return agent

    async def stream(self, query: str, session_id: str):
        agent = self._load_agent(session_id)
        async for event in agent.stream_async(query):
            yield event
""",
        encoding="utf-8",
    )
    (tmp_path / "agent_executor.py").write_text(
        """
from a2a.server.agent_execution import AgentExecutor, RequestContext


class StrandsAgentExecutor(AgentExecutor):
    def __init__(self, agent):
        self.agent = agent

    async def execute(self, context: RequestContext, event_queue):
        query = context.get_user_input()
        async for event in self.agent.stream(query, "session"):
            event_queue.enqueue_event(event)
""",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        """
from doc_agent import DocAgent
from agent_executor import StrandsAgentExecutor

executor = StrandsAgentExecutor(DocAgent())
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "docs")
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.metadata["ingress_framework"] == "a2a"
    assert ingress.metadata["runtime_invocation_proven"] is True
    assert ingress.metadata["wrapper_class"] == "DocAgent"

    path = next(
        item
        for item in graph.attack_paths
        if item.agent == "docs"
        and item.path_id == "PATH001"
        and item.metadata.get("basis") == "source_bound_ingress_authority"
        and item.nodes[-1] == "process.execute"
    )
    assert path.metadata["ingress_basis"] == "source_bound_runtime_ingress"
    assert path.metadata["target_kind"] == "tool"


def test_a2a_default_request_handler_reaches_nested_strands_wrapper(
    tmp_path: Path,
) -> None:
    (tmp_path / "doc_agent.py").write_text(
        """
import subprocess
from strands import Agent


def run_command(command: str):
    return subprocess.run(command, shell=True, capture_output=True, text=True)


class DocAgent:
    def _load_agent_from_memory(self, session_id: str):
        if session_id:
            agent = Agent(
                model="us.amazon.nova-pro-v1:0",
                tools=[shell],
            )
        else:
            agent = Agent(
                model="us.amazon.nova-pro-v1:0",
                tools=[shell],
            )
        return agent

    async def stream(self, query: str, session_id: str):
        agent = self._load_agent_from_memory(session_id=session_id)
        async for event in agent.stream_async(query):
            yield event
""",
        encoding="utf-8",
    )
    (tmp_path / "agent_executor.py").write_text(
        """
from a2a.server.agent_execution import AgentExecutor, RequestContext


class StrandsAgentExecutor(AgentExecutor):
    def __init__(self, agent):
        self.agent = agent

    async def execute(self, context: RequestContext, event_queue):
        query = context.get_user_input()
        task = context.current_task
        async for event in self.agent.stream(query, task.contextId):
            event_queue.enqueue_event(event)
""",
        encoding="utf-8",
    )
    (tmp_path / "__main1__.py").write_text(
        """
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from agent_executor import StrandsAgentExecutor
from doc_agent import DocAgent

request_handler = DefaultRequestHandler(
    agent_executor=StrandsAgentExecutor(DocAgent()),
    task_store=InMemoryTaskStore(),
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "strands-agents"
    )

    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.metadata["ingress_framework"] == "a2a"
    assert ingress.metadata["wrapper_class"] == "DocAgent"

    # This fixture isolates wrapper/helper ingress composition. Tool authority
    # is validated independently below against the holdout's direct CalcAgent
    # shell topology.
    assert ingress.metadata["runtime_invocation_proven"] is True


def test_a2a_request_handler_to_strands_shell_produces_attack_path(
    tmp_path: Path,
) -> None:
    (tmp_path / "utils_agent.py").write_text(
        """
from strands import Agent
from strands_tools import calculator, current_time, shell


class CalcAgent:
    SUPPORTED_CONTENT_TYPES = ["text", "text/plain"]

    def __init__(self):
        self.agent = Agent(
            tools=[calculator, current_time, shell],
        )

    async def stream(self, query: str, session_id: str):
        async for event in self.agent.stream_async(query):
            yield event
""",
        encoding="utf-8",
    )
    (tmp_path / "agent_executor.py").write_text(
        """
from a2a.server.agent_execution import AgentExecutor, RequestContext


class StrandsAgentExecutor(AgentExecutor):
    def __init__(self, agent):
        self.agent = agent

    async def execute(self, context: RequestContext, event_queue):
        query = context.get_user_input()
        async for event in self.agent.stream(query, "session"):
            event_queue.enqueue_event(event)
""",
        encoding="utf-8",
    )
    (tmp_path / "__main3__.py").write_text(
        """
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from agent_executor import StrandsAgentExecutor
from utils_agent import CalcAgent

request_handler = DefaultRequestHandler(
    agent_executor=StrandsAgentExecutor(CalcAgent()),
    task_store=InMemoryTaskStore(),
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "strands-agents"
        and item.metadata.get("source_class") == "CalcAgent"
    )

    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.metadata["ingress_framework"] == "a2a"

    path = next(
        item
        for item in graph.attack_paths
        if item.agent == agent.name
        and item.nodes[-1] == "process.execute"
    )
    assert path.path_id == "PATH001"
    assert path.metadata["basis"] == "source_bound_ingress_authority"
    assert path.metadata["target_kind"] == "tool"
