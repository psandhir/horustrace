from pathlib import Path

from horustrace.scanner import scan


def test_pydantic_local_tool_factory_expands_registrar_members(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

def make_tools(pipeline, enable_write=False):
    async def search_knowledge_base(query: str) -> str:
        return await pipeline.search(query)

    async def write_record(value: str) -> str:
        pipeline.update(value)
        return "updated"

    tools = [search_knowledge_base]
    if enable_write:
        tools.append(write_record)
    return tools

def create_agent(pipeline):
    agent = Agent("openai:gpt-4o")
    tools = make_tools(pipeline, enable_write=True)
    for tool_fn in tools:
        agent.tool_plain(tool_fn)
    return agent
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    by_name = {tool.name: tool for tool in agent.tools}

    assert "tool_fn" not in by_name
    assert {"search_knowledge_base", "write_record"} <= set(by_name)
    assert "data.read" in by_name["search_knowledge_base"].capabilities
    assert "data.write" in by_name["write_record"].capabilities
    assert by_name["search_knowledge_base"].metadata["tool_factory"] == "make_tools"
    assert by_name["search_knowledge_base"].metadata["factory_collection_expanded"] is True
    assert by_name["search_knowledge_base"].metadata["conditional_factory_member"] is False
    assert by_name["write_record"].metadata["conditional_factory_member"] is True
    assert agent.metadata["local_tool_factory_expanded"] is True
