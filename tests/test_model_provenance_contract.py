from pathlib import Path

import pytest

from horustrace.inventory_semantics import model_inventory_attributes
from horustrace.scanner import scan
from horustrace.semantic_contract import validate_graph_semantics

PYTHON_FRAMEWORK_CASES = (
    (
        "google-adk",
        """
from google.adk import Agent

root_agent = Agent(
    name="research",
    model="gemini-2.5-pro",
)
""",
        {
            "model": "gemini-2.5-pro",
            "model_provider": "google",
            "model_hosting": "provider_hosted",
            "model_resolution": "resolved_identifier",
        },
    ),
    (
        "openai-agents",
        """
from agents import Agent

agent = Agent(
    name="research",
    model="gpt-5",
)
""",
        {
            "model": "gpt-5",
            "model_resolution": "resolved_identifier",
        },
    ),
    (
        "pydantic-ai",
        """
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

provider = OpenAIProvider(base_url="https://llm.example/v1")
model = OpenAIChatModel("gpt-5-mini", provider=provider)
agent = Agent(model=model)
""",
        {
            "model": "gpt-5-mini",
            "model_provider": "openai",
            "model_hosting": "provider_hosted",
            "model_endpoint": "https://llm.example/v1",
            "model_resolution": "resolved_identifier",
        },
    ),
    (
        "amazon",
        """
from strands import Agent
from strands.models import BedrockModel

agent = Agent(
    model=BedrockModel(model_id="anthropic.claude-sonnet-4"),
)
""",
        {
            "model": "anthropic.claude-sonnet-4",
            "model_provider": "amazon-bedrock",
            "model_hosting": "provider_hosted",
            "model_constructor": "BedrockModel",
            "model_resolution": "resolved_identifier",
        },
    ),
    (
        "anthropic",
        """
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(
    model="sonnet",
    tools=["Read"],
)

async def run():
    async for message in query(prompt="inspect", options=options):
        pass
""",
        {
            "model": "sonnet",
            "model_provider": "anthropic",
            "model_hosting": "provider_hosted",
            "model_resolution": "resolved_identifier",
        },
    ),
    (
        "microsoft",
        """
from agent_framework import Agent
from agent_framework.openai import OpenAIChatClient

agent = Agent(
    client=OpenAIChatClient(model_id="gpt-4.1"),
    name="research",
)
""",
        {
            "model": "gpt-4.1",
            "model_provider": "openai",
            "model_hosting": "provider_hosted",
            "model_constructor": "OpenAIChatClient",
            "model_resolution": "resolved_identifier",
        },
    ),
)


@pytest.mark.parametrize(("case_name", "source", "expected"), PYTHON_FRAMEWORK_CASES)
def test_primary_frameworks_emit_canonical_model_provenance(
    tmp_path: Path,
    case_name: str,
    source: str,
    expected: dict[str, str],
) -> None:
    (tmp_path / "agent.py").write_text(source, encoding="utf-8")

    graph, _ = scan(tmp_path)

    assert graph.agents, case_name
    assert validate_graph_semantics(graph) == [], case_name

    agent = graph.agents[0]
    for key, value in expected.items():
        assert agent.metadata.get(key) == value, (case_name, key)

    attributes = model_inventory_attributes(agent.metadata)
    assert attributes["model_identifier"] == expected["model"]
    assert attributes["model_resolution"] == "resolved_identifier"

    model_nodes = [
        node
        for node in graph.adg.nodes
        if node.kind == "model"
    ]
    assert len(model_nodes) == 1, case_name
    for key in (
        "model_identifier",
        "model_provider",
        "model_hosting",
        "model_resolution",
    ):
        assert model_nodes[0].attributes[key] == attributes[key], (case_name, key)


def test_openai_literal_model_does_not_invent_provider(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
agent = Agent(name="research", model="gpt-5")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]
    attributes = model_inventory_attributes(agent.metadata)

    assert agent.metadata.get("model_provider") is None
    assert attributes["model_provider"] == "unknown"
    assert attributes["model_hosting"] == "unknown"


def test_amazon_default_model_is_provider_only_not_invented_identifier(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from strands import Agent
agent = Agent()
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = graph.agents[0]
    attributes = model_inventory_attributes(agent.metadata)

    assert agent.metadata.get("model") is None
    assert agent.metadata["model_provider"] == "amazon-bedrock"
    assert agent.metadata["model_resolution"] == "provider_only"
    assert attributes["model_identifier"] == "unknown"
    assert attributes["model_provider"] == "amazon-bedrock"
    assert any(node.kind == "model" for node in graph.adg.nodes)
