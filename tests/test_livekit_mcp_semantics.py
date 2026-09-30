from pathlib import Path

from horustrace.scanner import scan


def _write_livekit_fixture(\n    tmp_path: Path,\n    *,\n    authenticated_token: bool,\n    can_publish: bool = True,\n) -> None:
    (tmp_path / "db.py").write_text(
        """
def db_transfer_funds(from_account: str, to_account: str, amount: float):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE accounts SET balance = balance - ? WHERE account_number = ?",
        (amount, from_account),
    )
    cursor.execute(
        "UPDATE accounts SET balance = balance + ? WHERE account_number = ?",
        (amount, to_account),
    )
    conn.commit()
    return {"status": "SUCCESS"}
""",
        encoding="utf-8",
    )
    (tmp_path / "mcp_server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP
from db import db_transfer_funds

mcp = FastMCP("banking")

@mcp.tool()
def transfer_funds(from_account: str, to_account: str, amount: float):
    return db_transfer_funds(from_account, to_account, amount)
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from livekit.agents import Agent, AgentSession, function_tool

async def _call_mcp_tool(tool_name, arguments):
    return "ok"

@function_tool
async def transfer_funds(
    from_account: str,
    to_account: str,
    amount: float,
):
    return await _call_mcp_tool(
        "transfer_funds",
        {
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
        },
    )

async def entrypoint(ctx):
    tools = [transfer_funds]
    model = object()
    agent = Agent(llm=model, tools=tools)
    session = AgentSession()
    await session.start(agent=agent, room=ctx.room)
""",
        encoding="utf-8",
    )
    auth_parameter = (
        ", current_user=Depends(require_user)"
        if authenticated_token
        else ""
    )
    (tmp_path / "backend.py").write_text(
        f"""
from fastapi import FastAPI, Depends
from livekit.api import AccessToken, VideoGrants

app = FastAPI()

def get_settings():
    return object()

def require_user():
    return object()

@app.post("/session/credential")
async def create_token(request, settings=Depends(get_settings){auth_parameter}):
    return (
        AccessToken()
        .with_grants(
            VideoGrants(
                room_join=True,
                can_publish={can_publish!r},
                can_subscribe=True,
            )
        )
    )
""",
        encoding="utf-8",
    )


def test_public_livekit_audio_reaches_committed_mcp_mutation(tmp_path: Path) -> None:
    _write_livekit_fixture(tmp_path, authenticated_token=False)

    graph, findings = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    )
    tool = next(item for item in agent.tools if item.name == "transfer_funds")

    assert tool.metadata["livekit_model_tool"] is True
    assert tool.metadata["mcp_tool_name"] == "transfer_funds"
    assert tool.metadata["mcp_dispatch_proven"] is True
    assert tool.metadata["mcp_mutation_proven"] is True
    assert tool.metadata["state_scope"] == "repository_local_state"
    assert tool.metadata["state_backend"] == "local_sqlite"
    assert {"data.write", "destructive.write"} <= tool.capabilities
    assert any(
        item.metadata.get("basis") == "source_proven_public_livekit_audio"
        and item.metadata.get("authenticated") is False
        and item.metadata.get("can_publish") is True
        for item in agent.inputs
    )

    assert any(
        finding.rule_id == "AGT021" and finding.agent == agent.name
        for finding in findings
    )
    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH002" and item.agent == agent.name
    )
    assert "destructive action" in path.title.lower()


def test_authenticated_livekit_token_does_not_create_public_ingress_path(
    tmp_path: Path,
) -> None:
    _write_livekit_fixture(tmp_path, authenticated_token=True)

    graph, findings = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    )
    tool = next(item for item in agent.tools if item.name == "transfer_funds")

    assert {"data.write", "destructive.write"} <= tool.capabilities
    assert not any(
        item.metadata.get("basis") == "source_proven_public_livekit_audio"
        for item in agent.inputs
    )
    assert any(
        finding.rule_id == "AGT021" and finding.agent == agent.name
        for finding in findings
    )
    assert not any(
        item.path_id == "PATH002" and item.agent == agent.name
        for item in graph.attack_paths
    )


def test_non_publishing_livekit_token_does_not_create_public_ingress_path(
    tmp_path: Path,
) -> None:
    _write_livekit_fixture(
        tmp_path,
        authenticated_token=False,
        can_publish=False,
    )

    graph, _ = scan(tmp_path)

    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    )
    tool = next(item for item in agent.tools if item.name == "transfer_funds")

    # Tool authority is still source-proven, but a non-publishing credential
    # does not establish participant-to-model ingress.
    assert {"data.write", "destructive.write"} <= tool.capabilities
    assert not any(
        item.metadata.get("basis") == "source_proven_public_livekit_audio"
        for item in agent.inputs
    )
    assert not any(
        item.path_id == "PATH002" and item.agent == agent.name
        for item in graph.attack_paths
    )
