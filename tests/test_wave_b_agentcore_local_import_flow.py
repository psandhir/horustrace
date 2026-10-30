"""Regression for local HTTP imports in pinned Amazon AgentCore case #570."""

from pathlib import Path

from horustrace.scanner import scan


def test_strands_agentcore_query_to_local_imported_requests_post(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from strands import Agent, tool

@tool(context=True)
def order_management_tool(query: str, tool_context) -> str:
    import requests
    url = "https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/abc/invocations"
    requests.post(url, data={"query": query}, timeout=120)
    return "ok"

@tool(context=True)
def personalization_agent_tool(query: str, tool_context) -> str:
    import requests as http
    http.post("https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/abc/invocations",
              data={"query": query}, timeout=120)
    return "ok"

@tool(context=True)
def product_recommendation_tool(query: str, tool_context) -> str:
    from requests import post as send
    send("https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/abc/invocations",
         data={"query": query}, timeout=120)
    return "ok"

@tool(context=True)
def troubleshooting_tool(query: str, tool_context) -> str:
    try:
        import requests
        requests.post("https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/abc/invocations",
                      data={"query": query}, timeout=120)
    except Exception:
        return "failed"
    return "ok"

agent = Agent(tools=[order_management_tool, personalization_agent_tool,
                     product_recommendation_tool, troubleshooting_tool])
""",
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    flows = [
        flow for flow in graph.flow_paths
        if flow.source_kind == "agent_tool_input"
        and flow.sink_kind == "external_send"
        and flow.agent == "agent"
    ]
    assert {flow.source_label for flow in flows} == {
        "order_management_tool.query",
        "personalization_agent_tool.query",
        "product_recommendation_tool.query",
        "troubleshooting_tool.query",
    }
    assert all(flow.metadata["agent_binding"]["basis"] == "source_function_key"
               for flow in flows)
    # All four source flows are observed, including aliased HTTP imports.
    # The existing Amazon capability adapter recognizes requests.post directly;
    # alias-aware *capability projection* is distinct from this flow fix and
    # must not be assumed just because the sink has been proven here.
    tools = {tool.name: tool for tool in graph.agents[0].tools}
    assert "network.external" in tools["order_management_tool"].capabilities
    assert "network.external" in tools["troubleshooting_tool"].capabilities
    for name in (
        "order_management_tool", "personalization_agent_tool",
        "product_recommendation_tool", "troubleshooting_tool",
    ):
        assert "external.write" not in tools[name].capabilities
        assert "data.write" not in tools[name].capabilities
    assert not any(f.rule_id in {"AGT022", "AGT040"} for f in findings)


def test_local_requests_name_overwritten_does_not_prove_http_flow(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from strands import Agent, tool

class FakeClient:
    def post(self, *args, **kwargs):
        return "locally handled"

@tool
def publish(query: str):
    import requests
    requests = FakeClient()
    return requests.post("not-an-http-url", data={"query": query})

agent = Agent(tools=[publish])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert not [f for f in graph.flow_paths if f.sink_kind == "external_send"]


def test_parameter_shadowing_requests_name_remains_hard_negative(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from strands import Agent, tool

@tool
def publish(query: str, requests):
    return requests.post("fake", data={"query": query})

agent = Agent(tools=[publish])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert not [f for f in graph.flow_paths if f.sink_kind == "external_send"]
