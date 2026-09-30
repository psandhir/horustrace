from pathlib import Path

from horustrace.scanner import scan


def _write_fixture(tmp_path: Path, *, tool_owner_check: bool) -> None:
    (tmp_path / "models.py").write_text(
        """
class Chat:
    id: str
    owner_id: str
    title: str
""",
        encoding="utf-8",
    )

    owner_guard = (
        """
        if chat.owner_id != ctx.user_id:
            return "not authorized"
"""
        if tool_owner_check
        else ""
    )
    (tmp_path / "tools.py").write_text(
        f"""
from langchain_core.tools import BaseTool
from models import Chat

class UpdateChatTitleTool(BaseTool):
    name: str = "update_chat_title"

    def _run(self, chat_id: str, title: str, ctx=None):
        with Session() as session:
            chat = session.get(Chat, chat_id)
{owner_guard}
            chat.title = title
            session.add(chat)
            session.commit()
            return "updated"

update_chat_title_tool = UpdateChatTitleTool()
""",
        encoding="utf-8",
    )

    (tmp_path / "catalogue.py").write_text(
        """
from tools import update_chat_title_tool

def get_tools_by_credentials(connectors):
    tools = [update_chat_title_tool]
    return tools
""",
        encoding="utf-8",
    )

    (tmp_path / "agent.py").write_text(
        """
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph
from catalogue import get_tools_by_credentials

class LangGraphAgent:
    def __init__(self, connectors):
        tools = get_tools_by_credentials(connectors)
        self.llm = ChatOpenAI(model="gpt-test").bind_tools(tools)

    async def _chat(self, state):
        return {"messages": [await self.llm.ainvoke(state["messages"])]}

    async def create_graph(self):
        graph_builder = StateGraph(dict)
        graph_builder.add_node("chat", self._chat)
        graph_builder.set_entry_point("chat")
        return graph_builder.compile()

    async def get_response(self, messages, session_id, user_id):
        graph = await self.create_graph()
        return await graph.ainvoke({"messages": messages})
""",
        encoding="utf-8",
    )

    (tmp_path / "api.py").write_text(
        """
from models import Chat
from agent import LangGraphAgent

@router.post("/messages")
async def create_message(session, current_user, message_in):
    chat = session.get(Chat, message_in.chat_id)
    if chat.owner_id != current_user.id:
        raise PermissionError("not enough permissions")
    agent = LangGraphAgent([])
    return await agent.get_response(message_in.content, str(chat.id), str(current_user.id))
""",
        encoding="utf-8",
    )


def test_model_callable_owner_scoped_mutation_is_flagged(tmp_path: Path) -> None:
    _write_fixture(tmp_path, tool_owner_check=False)

    graph, findings = scan(tmp_path)

    agent = next(
        item for item in graph.agents if item.metadata.get("framework") == "langgraph"
    )
    tool = next(item for item in agent.tools if item.name == "update_chat_title")

    assert "data.write" in tool.capabilities
    assert tool.metadata["authority_binding_basis"] == "langchain_bind_tools_factory"
    assert tool.metadata["object_authorization_boundary_bypass"] is True
    assert tool.metadata["object_model"] == "Chat"
    assert tool.metadata["object_id_parameter"] == "chat_id"
    assert tool.metadata["ownership_field"] == "owner_id"
    assert any(
        item.metadata.get("basis") == "source_bound_object_authorization_route"
        and item.metadata.get("runtime_invocation_proven") is True
        for item in agent.inputs
    )

    assert any(
        finding.rule_id == "DATA004" and finding.agent == agent.name
        for finding in findings
    )
    path = next(item for item in graph.attack_paths if item.path_id == "PATH014")
    assert path.agent == agent.name
    assert path.metadata["object_model"] == "Chat"
    assert path.metadata["object_id_parameter"] == "chat_id"


def test_principal_bound_owner_check_suppresses_authorization_bypass(
    tmp_path: Path,
) -> None:
    _write_fixture(tmp_path, tool_owner_check=True)

    graph, findings = scan(tmp_path)

    agent = next(
        item for item in graph.agents if item.metadata.get("framework") == "langgraph"
    )
    tool = next(item for item in agent.tools if item.name == "update_chat_title")

    assert "data.write" in tool.capabilities
    assert tool.metadata.get("object_authorization_boundary_bypass") is not True
    assert not any(finding.rule_id == "DATA004" for finding in findings)
    assert not any(item.path_id == "PATH014" for item in graph.attack_paths)
