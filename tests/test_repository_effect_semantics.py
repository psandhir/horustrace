from pathlib import Path

from horustrace.scanner import scan


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_pydantic_imported_tool_wrapper_inherits_repository_nats_effects(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "tools" / "motion_tool.py",
        """
from pydantic_ai import Tool
from nats.aio.client import Client as NATS

async def motion_tool_fn(params):
    client = NATS()
    await client.connect("nats://localhost:4222")
    return await client.request("motion.cmd", b"go", timeout=5)

motion_tool = Tool(motion_tool_fn, name="motion_tool")
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent
from tools.motion_tool import motion_tool

agent = Agent("openai:gpt-4o", tools=[motion_tool])
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "motion_tool")

    assert {"network.external", "external.write"} <= tool.capabilities
    assert tool.metadata["repository_effect_resolved"] is True
    assert tool.metadata["repository_effect_source"].endswith(
        "tools.motion_tool.motion_tool_fn"
    )
    assert any(
        evidence.startswith("nats-command:motion.cmd")
        for evidence in tool.metadata["repository_effect_evidence"]
    )


def test_pydantic_decorated_tool_inherits_imported_twilio_effect(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "tools" / "sms.py",
        """
from twilio.rest import Client

def send_sms_alert(message: str) -> None:
    client = Client("sid", "token")
    client.messages.create(body=message, from_="+100", to="+200")
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent, RunContext
from tools.sms import send_sms_alert

agent = Agent("openai:gpt-4o")

@agent.tool
def send_alert(ctx: RunContext[None], message: str) -> str:
    send_sms_alert(message)
    return "sent"
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "send_alert")

    assert {"network.external", "external.write"} <= tool.capabilities
    assert tool.metadata["repository_effect_resolved"] is True
    assert "twilio:client.messages.create" in tool.metadata[
        "repository_effect_evidence"
    ]


def test_pydantic_imported_tool_wrapper_inherits_database_write_effect(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "tools" / "database_ops.py",
        """
from pydantic_ai import Tool

class Session:
    def add(self, value):
        pass
    def commit(self):
        pass

def create_product(value):
    session = Session()
    session.add(value)
    session.commit()

create_product_tool = Tool(create_product, name="create_product")
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent
from tools.database_ops import create_product_tool

agent = Agent("openai:gpt-4o", tools=[create_product_tool])
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "create_product_tool")

    assert "data.write" in tool.capabilities
    assert tool.metadata["repository_effect_resolved"] is True
