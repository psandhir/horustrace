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
