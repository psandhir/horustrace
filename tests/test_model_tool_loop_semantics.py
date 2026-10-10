from pathlib import Path

from horustrace.scanner import scan


def test_custom_agent_loop_chat_collect_and_registry_execute_is_detected(
    tmp_path: Path,
) -> None:
    (tmp_path / "loop.py").write_text(
        """
class AgentLoop:
    def __init__(self, llm, tools):
        self.llm = llm
        self.tools = tools

    async def run(self, messages):
        available_tools = self.tools.get_tool_definitions()
        response = await self.llm.chat_collect(messages, tools=available_tools)
        if response.tool_calls:
            return self._run_tools_parallel(response.tool_calls)
        return response

    def _run_tools_parallel(self, tool_calls):
        return [self.tools.execute(call.name, call.arguments) for call in tool_calls]
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent_loop")
    assert agent.metadata["framework"] == "model-tool-loop"
    assert agent.metadata["discovery_basis"] == "model_tools_selection_dispatch"
    assert set(agent.metadata["discovery_signals"]) == {
        "model_call",
        "model_selection",
        "tool_catalogue",
        "tool_dispatch",
    }


def test_unrelated_agent_class_with_generic_execute_is_not_detected(
    tmp_path: Path,
) -> None:
    (tmp_path / "service.py").write_text(
        """
class AgentCache:
    def execute(self, value):
        return value

    def get_tools(self):
        return []
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    assert not any(item.name == "agent_cache" for item in graph.agents)


def test_custom_agent_loop_detects_model_method_passed_through_retry_wrapper(
    tmp_path: Path,
) -> None:
    (tmp_path / "loop.py").write_text(
        """
async def _llm_call_with_retry(fn, **kwargs):
    return await fn(**kwargs)

class AgentLoop:
    def __init__(self, llm, tools):
        self.llm = llm
        self.tools = tools

    async def run(self, messages):
        available_tools = self.tools.get_tool_definitions()
        response = await _llm_call_with_retry(
            self.llm.chat_collect,
            messages=messages,
            tools=available_tools,
        )
        if response.tool_calls:
            return self._run_tools_parallel(response.tool_calls)
        return response

    def _run_tools_parallel(self, tool_calls):
        return [self.tools.execute(call.name, call.arguments) for call in tool_calls]
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent_loop")
    assert set(agent.metadata["discovery_signals"]) == {
        "model_call",
        "model_selection",
        "tool_catalogue",
        "tool_dispatch",
    }


def test_custom_planner_skill_orchestrator_is_an_agent(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
class AgenticChatbot:
    def __init__(self, planner, joke_skill, recipe_skill):
        self.planner = planner
        self.joke_skill = joke_skill
        self.recipe_skill = recipe_skill

    def respond(self, history, user_message):
        plan = self.planner.plan(history=history, user_message=user_message)
        if plan.action == "joke":
            return self.joke_skill.run(plan, history, user_message)
        return self.recipe_skill.run(plan, history, user_message)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agentic_chatbot")
    assert agent.metadata["discovery_basis"] == "source_proven_delegated_orchestration"
    assert agent.metadata["discovery_signals"] == ["delegated_planner", "skill_dispatch"]


def test_custom_planner_to_mcp_loop_is_an_agent(tmp_path: Path) -> None:
    (tmp_path / "loop.py").write_text(
        """
from core.strategy import decide_next_action

class AgentLoop:
    def __init__(self, dispatcher):
        self.mcp = dispatcher
        self.tools = dispatcher.get_all_tools()

    async def run(self, context, perception):
        plan = await decide_next_action(
            context=context, perception=perception, all_tools=self.tools
        )
        response = await self.mcp.call_tool(plan.name, plan.arguments)
        return response
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent_loop")
    assert agent.metadata["discovery_basis"] == "source_proven_delegated_orchestration"
    assert agent.metadata["discovery_signals"] == ["delegated_planner", "mcp_dispatch"]


def test_named_planner_without_tool_dispatch_is_not_agent(tmp_path: Path) -> None:
    (tmp_path / "planner.py").write_text(
        """
class AgentPlannerCache:
    def __init__(self, planner):
        self.planner = planner
    def respond(self, value):
        return self.planner.plan(value)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert not any(agent.name == "agent_planner_cache" for agent in graph.agents)


def test_custom_openai_mcp_sse_loop_retains_dynamic_session_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.py").write_text(
        """
from mcp import ClientSession
from mcp.client.sse import sse_client

class MCPClient:
    async def connect(self, server_url):
        self.streams = sse_client(url=server_url)
        self.session_context = ClientSession(*streams)
        self.session = await self.session_context.__aenter__()

    async def process_query(self, query):
        response = await self.session.list_tools()
        available_tools = [
            {"type": "function", "function": {"name": tool.name}}
            for tool in response.tools
        ]
        completion = await self.openai.chat.completions.create(
            messages=[{"role": "user", "content": query}],
            tools=available_tools,
        )
        for tool_call in completion.choices[0].message.tool_calls:
            await self.session.call_tool(tool_call.function.name, {})
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "m_c_p_client")
    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.transport == "sse"
    assert server.url is None
    assert server.metadata["binding_origin"] == "source_proven_mcp_session_loop"
    assert server.metadata["session_receivers"] == ["self.session"]
    assert server.metadata["tool_catalogue_dynamic"] is True
    assert server.metadata["endpoint_selection_actor"] == "caller_or_operator"
    assert server.allowed_tools == []
    assert not agent.capabilities

    from horustrace.mcp_effective import effective_mcp_authority_report

    report = effective_mcp_authority_report(graph)
    assert report["summary"]["bound_relationships"] == 1
    assert report["authorities"][0]["tools"]["catalogue_known"] is False


def test_unrelated_mcp_session_cannot_inherit_custom_agent_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.py").write_text(
        """
from mcp import ClientSession
from mcp.client.sse import sse_client

class MCPClient:
    async def connect(self, server_url):
        self.transport = sse_client(url=server_url)
        self.session_context = ClientSession(*streams)

    async def process_query(self, query):
        response = await self.session.list_tools()
        completion = await self.openai.chat.completions.create(
            messages=[], tools=response.tools,
        )
        for tool_call in completion.choices[0].message.tool_calls:
            await self.other_session.call_tool(tool_call.function.name, {})
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "m_c_p_client")
    assert agent.mcp_servers == []


def test_source_literal_sse_endpoint_is_not_model_selected(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.py").write_text(
        """
from mcp import ClientSession
from mcp.client.sse import sse_client

class MCPClient:
    async def connect(self):
        self.transport = sse_client(url="https://trusted.example.test/sse")
        self.session_context = ClientSession(*streams)

    async def run(self):
        tools = await self.session.list_tools()
        answer = await self.llm.chat.completions.create(tools=tools.tools)
        for call in answer.tool_calls:
            await self.session.call_tool(call.name, call.args)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "m_c_p_client")
    server = agent.mcp_servers[0]
    assert server.url == "https://trusted.example.test/sse"
    assert server.metadata["dynamic_mcp_endpoint"] is False
    assert server.metadata["endpoint_selection_actor"] == "source"
