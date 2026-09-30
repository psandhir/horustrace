from pathlib import Path

from horustrace.scanner import scan


def _write_fixture(
    tmp_path: Path,
    *,
    authenticated: bool,
    can_publish: bool = True,
) -> None:
    auth_import = ", Depends" if authenticated else ""
    auth_dependency = (
        ", current_user=Depends(get_current_user)" if authenticated else ""
    )
    (tmp_path / "backend.py").write_text(
        f"""
from fastapi import FastAPI{auth_import}
from livekit.api import AccessToken, VideoGrants

app = FastAPI()

def get_current_user():
    return object()

@app.post("/api/token")
async def create_token(request{auth_dependency}):
    token = (
        AccessToken()
        .with_grants(
            VideoGrants(
                room_join=True,
                can_publish={can_publish!r},
                can_subscribe=True,
            )
        )
    )
    return token.to_jwt()
""",
        encoding="utf-8",
    )

    (tmp_path / "agent.py").write_text(
        """
from livekit.agents import Agent, AgentSession, function_tool

async def _call_mcp_tool(tool_name, arguments):
    return "ok"

@function_tool
async def get_account_balance(account_number: str):
    return await _call_mcp_tool(
        "get_account_balance",
        {"account_number": account_number},
    )

@function_tool
async def transfer_funds(from_account: str, to_account: str, amount: float):
    return await _call_mcp_tool(
        "transfer_funds",
        {
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
        },
    )

async def entrypoint(ctx):
    await ctx.connect()
    tools = [get_account_balance, transfer_funds]
    agent = Agent(llm=model, tools=tools)
    session = AgentSession()
    await session.start(agent=agent, room=ctx.room)
""",
        encoding="utf-8",
    )

    (tmp_path / "mcp_server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP
from db import db_get_account_balance, db_transfer_funds

mcp = FastMCP("Banking")

@mcp.tool()
def get_account_balance(account_number: str):
    return db_get_account_balance(account_number)

@mcp.tool()
def transfer_funds(from_account: str, to_account: str, amount: float):
    return db_transfer_funds(from_account, to_account, amount)
""",
        encoding="utf-8",
    )

    (tmp_path / "db.py").write_text(
        """
import sqlite3

DB_PATH = "bank.db"

def get_connection():
    return sqlite3.connect(DB_PATH)

def db_get_account_balance(account_number: str):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT balance FROM accounts WHERE account_number = ?",
            (account_number,),
        )
        return cursor.fetchone()

def db_transfer_funds(from_account: str, to_account: str, amount: float):
    with get_connection() as conn:
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


def test_public_publish_capability_reaches_mcp_backed_sqlite_mutation(
    tmp_path: Path,
) -> None:
    _write_fixture(tmp_path, authenticated=False)

    graph, findings = scan(tmp_path)

    agents = [
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    ]
    assert agents
    agent = next(
        item
        for item in agents
        if any(tool.name == "transfer_funds" for tool in item.tools)
    )
    by_name = {tool.name: tool for tool in agent.tools}

    assert {"get_account_balance", "transfer_funds"} <= set(by_name)
    assert "data.read" in by_name["get_account_balance"].capabilities
    transfer = by_name["transfer_funds"]
    assert "data.write" in transfer.capabilities
    assert "external.write" not in transfer.capabilities
    assert "network.external" not in transfer.capabilities
    assert transfer.metadata["mcp_backed"] is True
    assert transfer.metadata["mcp_tool_name"] == "transfer_funds"
    assert transfer.metadata["state_scope"] == "local_demo_sqlite"
    assert "local_sqlite" in transfer.metadata["state_backends"]

    ingress = next(
        item
        for item in agent.inputs
        if item.metadata.get("basis")
        == "source_proven_public_realtime_capability"
    )
    assert ingress.metadata["runtime_invocation_proven"] is True
    assert ingress.metadata["authentication_detected"] is False
    assert ingress.metadata["session_transport"] == "livekit"
    assert ingress.metadata["session_capability"] == "room_join+publish"

    idn = next(
        finding
        for finding in findings
        if finding.rule_id == "IDN005" and finding.agent == agent.name
    )
    assert any("state_backends=local_sqlite" in item for item in idn.evidence)
    assert any("repository-local SQLite" in item for item in idn.limitations)

    path = next(
        item
        for item in graph.attack_paths
        if item.path_id == "PATH015" and item.agent == agent.name
    )
    assert path.metadata["session_transport"] == "livekit"
    assert path.metadata["state_scope"] == "local_demo_sqlite"
    assert "local_sqlite" in path.metadata["state_backends"]


def test_authenticated_realtime_token_mint_suppresses_public_session_path(
    tmp_path: Path,
) -> None:
    _write_fixture(tmp_path, authenticated=True)

    graph, findings = scan(tmp_path)

    assert not any(finding.rule_id == "IDN005" for finding in findings)
    assert not any(item.path_id == "PATH015" for item in graph.attack_paths)


def test_non_publishing_realtime_token_is_not_model_ingress(
    tmp_path: Path,
) -> None:
    _write_fixture(tmp_path, authenticated=False, can_publish=False)

    graph, findings = scan(tmp_path)

    assert not any(finding.rule_id == "IDN005" for finding in findings)
    assert not any(item.path_id == "PATH015" for item in graph.attack_paths)
