"""Pinned-source-shaped checks for network-scope deduplication.

No source evidence proves model selection of the MCP *server address*:
the CLI/operator supplies it, while the model selects tools at that address.
"""
from pathlib import Path

from horustrace.scanner import scan


def test_dynamic_cli_mcp_endpoint_has_one_egress_control_gap(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.py").write_text(
        """
from mcp import ClientSession
from mcp.client.sse import sse_client

class MCPClient:
    async def connect(self, server_url):
        self.stream = sse_client(url=server_url)
        self.context = ClientSession(*streams)
        self.session = await self.context.__aenter__()

    async def process_query(self, query):
        tools = await self.session.list_tools()
        answer = await self.openai.chat.completions.create(
            messages=[{"role": "user", "content": query}],
            tools=tools.tools,
        )
        for call in answer.choices[0].message.tool_calls:
            await self.session.call_tool(call.function.name, {})
""",
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    assert any(agent.name == "m_c_p_client" for agent in graph.agents)
    by_rule = {rule: [f for f in findings if f.rule_id == rule]
               for rule in ("NET001", "NET002", "AGT032")}
    assert len(by_rule["NET001"]) == 1
    assert not by_rule["NET002"]
    assert len(by_rule["AGT032"]) == 1
    assert "endpoint_selection_actor=caller_or_operator" in (
        by_rule["NET001"][0].evidence
    )
