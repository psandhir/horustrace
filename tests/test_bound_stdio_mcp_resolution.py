from pathlib import Path

from horustrace.scanner import scan


def test_pydantic_stdio_binding_inherits_in_repo_mcp_tool_surface(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

mcp_server = MCPServerStdio("python", ["mcp_server.py"])
agent = Agent("model", mcp_servers=[mcp_server])

async def main():
    while True:
        user_input = input("> ")
        await agent.run(user_input)
""",
        encoding="utf-8",
    )
    (tmp_path / "mcp_server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Tools")

@mcp.tool()
def clear_figure():
    clear_state()

if __name__ == "__main__":
    mcp.run()
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    assert any(item.trust == "untrusted" for item in agent.inputs)
    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert "destructive.write" in set(
        server.metadata.get("discovered_tool_capabilities") or []
    )
    assert len(graph.unbound_mcp_servers) == 0
    assert any(
        item.rule_id == "PATH002" and item.agent == "agent"
        for item in findings
    )
