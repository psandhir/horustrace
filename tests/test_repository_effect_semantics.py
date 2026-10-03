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



def test_adk_tool_inherits_effects_from_function_local_repository_import(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "helpers.py",
        """
import subprocess

def extract_facts(binary_path: str) -> str:
    subprocess.run(["bn-headless", binary_path], check=True)
    with open("facts/Call.facts", "w") as handle:
        handle.write(binary_path)
    return "ok"
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent

def tool_extract_facts_batch(binary_path: str) -> str:
    import sys
    sys.path.insert(0, ".")
    from helpers import extract_facts
    return extract_facts(binary_path)

root_agent = Agent(
    name="binary-agent",
    model="gemini-2.5-flash",
    tools=[tool_extract_facts_batch],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "binary-agent")
    tool = next(
        item for item in agent.tools if item.name == "tool_extract_facts_batch"
    )

    assert {"process.execute", "data.write"} <= tool.capabilities
    assert tool.metadata.get("repository_effect_resolved") is True
    assert "process:subprocess.run" in tool.metadata.get(
        "repository_effect_evidence", []
    )
    assert "file:write" in tool.metadata.get("repository_effect_evidence", [])


def test_function_local_module_alias_resolves_repository_helper_effect(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "helpers.py",
        """
import subprocess

def find_loops(binary_path: str) -> list[str]:
    subprocess.run(["bn-headless", "--loops", binary_path], check=True)
    return []
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

@agent.tool_plain
def find_loop_functions(binary_path: str) -> list[str]:
    import helpers as local_helpers
    return local_helpers.find_loops(binary_path)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "find_loop_functions")

    assert "process.execute" in tool.capabilities
    assert "process:subprocess.run" in tool.metadata.get(
        "repository_effect_evidence", []
    )



def test_function_local_import_recovers_pathlib_write_effect(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "resolve_calls.py",
        """
from pathlib import Path

def resolve_call_targets(facts_dir: str, mapping: dict[str, str]) -> None:
    facts_dir = Path(facts_dir)
    call_file = facts_dir / "Call.facts"
    call_file.write_text("resolved")
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent

def tool_resolve_calls(mapping: dict, facts_dir: str = "") -> dict:
    from resolve_calls import resolve_call_targets
    resolve_call_targets(facts_dir, mapping)
    return {"facts_dir": facts_dir}

root_agent = Agent(
    name="resolver",
    model="gemini-2.5-flash",
    tools=[tool_resolve_calls],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "resolver")
    tool = next(item for item in agent.tools if item.name == "tool_resolve_calls")

    assert "data.write" in tool.capabilities
    assert "pathlib-write:write_text" in tool.metadata.get(
        "repository_effect_evidence", []
    )
