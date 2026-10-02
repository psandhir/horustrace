from pathlib import Path

from horustrace.scanner import scan


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_openai_local_list_append_does_not_corroborate_persistent_write(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
from agents import Agent, function_tool

@function_tool
def create_escalation_summary(text: str) -> str:
    lines = [f"Issue: {text}"]
    lines.append("Escalate if needed")
    return "\\n".join(lines)

agent = Agent(name="support", tools=[create_escalation_summary])
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "support")
    tool = next(item for item in agent.tools if item.name == "create_escalation_summary")

    assert "data.write" not in tool.capabilities
    assert "external.write" not in tool.capabilities
    assert not any(
        finding.agent == "support" and finding.rule_id in {"AGT022", "AGT040"}
        for finding in findings
    )


def test_repository_nats_read_and_control_subjects_have_distinct_effects(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "tools.py",
        """
from pydantic_ai import Tool
from nats.aio.client import Client as NATS

async def motion_fn(value):
    client = NATS()
    await client.connect("nats://localhost:4222")
    return await client.request("motion.cmd", b"go")

async def status_fn():
    client = NATS()
    await client.connect("nats://localhost:4222")
    return await client.request("status.cmd", b"status")

motion_tool = Tool(motion_fn, name="motion_tool")
status_tool = Tool(status_fn, name="status_tool")
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent
from tools import motion_tool, status_tool

agent = Agent("openai:gpt-4o", tools=[motion_tool, status_tool])
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    by_name = {tool.name: tool for tool in agent.tools}

    assert {"network.external", "external.write"} <= by_name["motion_tool"].capabilities
    assert "network.external" in by_name["status_tool"].capabilities
    assert "external.write" not in by_name["status_tool"].capabilities
    for name in ("motion_tool", "status_tool"):
        assert any(
            destination.target == "nats://localhost:4222"
            and destination.restricted is True
            for destination in by_name[name].destinations
        )
    assert not any(
        finding.rule_id == "NET002" and finding.agent == "agent"
        for finding in findings
    )


def test_repository_provider_sinks_preserve_fixed_destinations(tmp_path: Path) -> None:
    _write(
        tmp_path / "sms.py",
        """
from twilio.rest import Client

def send_sms(message):
    client = Client("sid", "token")
    client.messages.create(body=message, from_="+1", to="+2")
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent, RunContext
from sms import send_sms

agent = Agent("openai:gpt-4o")

@agent.tool
def alert(ctx: RunContext[None], message: str):
    send_sms(message)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "alert")

    assert {"external.write", "network.external"} <= tool.capabilities
    assert any(
        destination.target == "<provider:twilio>"
        and destination.restricted is True
        for destination in tool.destinations
    )


def test_adk_local_alias_of_environment_endpoint_remains_operator_configured(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import os
import requests
from google.adk.agents import Agent

CHECK_ORDER_STATUS_ENDPOINT = os.environ["CHECK_ORDER_STATUS_ENDPOINT"]

def check_status():
    endpoint = CHECK_ORDER_STATUS_ENDPOINT
    return requests.get(endpoint).json()

root_agent = Agent(
    name="renovation",
    model="gemini-2.5-flash",
    tools=[check_status],
)
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "renovation")
    tool = next(item for item in agent.tools if item.name == "check_status")

    assert any(
        destination.target == "<operator-configured:CHECK_ORDER_STATUS_ENDPOINT>"
        and destination.restricted is True
        for destination in tool.destinations
    )
    assert not any(
        destination.target == "<dynamic-url>"
        for destination in tool.destinations
    )
    assert not any(
        finding.rule_id in {"NET001", "NET002"}
        and finding.agent == "renovation"
        for finding in findings
    )


def test_adk_gcs_upload_is_source_visible_write_to_fixed_provider(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent
from google.cloud import storage

def store_pdf(buffer):
    client = storage.Client()
    bucket = client.bucket("documents")
    blob = bucket.blob("proposal.pdf")
    blob.upload_from_file(buffer, content_type="application/pdf")
    return "ok"

root_agent = Agent(
    name="renovation",
    model="gemini-2.5-flash",
    tools=[store_pdf],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "renovation")
    tool = next(item for item in agent.tools if item.name == "store_pdf")

    assert {"data.write", "external.write", "network.external"} <= tool.capabilities
    assert any(
        destination.target == "<google-cloud-storage>"
        and destination.restricted is True
        for destination in tool.destinations
    )
