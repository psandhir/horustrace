from pathlib import Path

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


def test_chainlit_message_ingress_reaches_compiled_langgraph_write(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        """
import asyncio
import chainlit as cl
from concurrent.futures import ThreadPoolExecutor
from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode

executor = ThreadPoolExecutor()


def save_record(value: str):
    store.write(value)


tools = [save_record]
tool_node = ToolNode(tools)
workflow = StateGraph(dict)
workflow.add_node("agent", lambda state: state)
workflow.add_node("action", tool_node)
workflow.add_edge("agent", "action")
app = workflow.compile()


@cl.on_message
async def on_message(message: cl.Message):
    response = await asyncio.get_event_loop().run_in_executor(
        executor,
        app.invoke,
        {"messages": [HumanMessage(content=message.content)]},
    )
    return response
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "langgraph"
        and item.name == "workflow"
    )
    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis") == "source_bound_runtime_ingress"
    )
    assert ingress.metadata["ingress_framework"] == "chainlit"

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH002"
        and item.metadata.get("target_kind") == "tool"
        and item.nodes[-2] == "save_record"
    )
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
