"""A default parameter must never become an agent because of later source."""

from horustrace.adapters.csharp_source import assignments, mask_non_code
from horustrace.adapters.microsoft_agent_framework_dotnet import scan_dotnet_file


SOURCE = """
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

public static AIAgent Get(
    IChatClient chatClient,
    IEnumerable<AITool>? additionalTools = null)
{
    var child = new ChatClientAgent(chatClient, "child");
    return child;
}
"""


def test_csharp_assignments_skip_default_parameters_not_local_agents() -> None:
    items = assignments(SOURCE, mask_non_code(SOURCE))
    assert "additionalTools" not in items
    assert "child" in items


def test_dotnet_factory_return_does_not_invent_additional_tools_agent(tmp_path) -> None:
    source = tmp_path / "LearnAgentFactory.cs"
    source.write_text(SOURCE, encoding="utf-8")
    graph = scan_dotnet_file(source)
    assert "additionalTools" not in {agent.name for agent in graph.agents}
    assert any(agent.name == "child" for agent in graph.agents)


def test_default_parameter_does_not_suppress_true_assignment_in_body() -> None:
    source = """
using Microsoft.Agents.AI;

public static AIAgent Build(IChatClient client, AIAgent? fallback = null)
{
    AIAgent active = client.AsAIAgent(name: "RuntimeAgent");
    return active;
}
"""
    items = assignments(source, mask_non_code(source))
    assert "fallback" not in items
    assert "active" in items


def test_factory_result_is_labelled_as_template_not_runtime_instance(tmp_path) -> None:
    source = tmp_path / "Factory.cs"
    source.write_text(
        """
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
public static AIAgent Get(IChatClient chatClient) =>
    chatClient.AsAIAgent(name: "NamedFromFactory");
""",
        encoding="utf-8",
    )
    graph = scan_dotnet_file(source)
    generated = next(agent for agent in graph.agents if agent.name == "NamedFromFactory")
    assert generated.metadata["source_entity_classification"] == "factory_return_template"
    assert generated.metadata["factory_method"] == "Get"
    assert generated.metadata["runtime_instance_verified"] is False
