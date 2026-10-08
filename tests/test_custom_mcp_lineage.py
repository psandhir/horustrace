from pathlib import Path

from horustrace.scanner import scan
from horustrace.security_graph import build_agent_security_graph


def _write_agent_loop(root: Path) -> None:
    core = root / "core"
    core.mkdir(parents=True, exist_ok=True)
    (core / "loop.py").write_text(
        """
from core.strategy import decide_next_action

class AgentLoop:
    def __init__(self, dispatcher):
        self.mcp = dispatcher
        self.tools = dispatcher.get_all_tools()

    async def run(self, context):
        plan = await decide_next_action(context=context, all_tools=self.tools)
        return await self.mcp.call_tool(plan.name, plan.arguments)
""",
        encoding="utf-8",
    )


def _write_config(root: Path) -> None:
    config = root / "config"
    config.mkdir(parents=True, exist_ok=True)
    (config / "profiles.yaml").write_text(
        """mcp_servers:
  - id: math
    script: server.py
    cwd: C:/external/windows/location
    transport: stdio
  - id: telegram
    transport: sse
    url: http://localhost:8000/sse
""",
        encoding="utf-8",
    )
    (root / "server.py").write_text("def main(): pass", encoding="utf-8")


def test_custom_agent_binds_source_proven_mcp_profile_without_runtime_claim(
    tmp_path: Path,
) -> None:
    _write_agent_loop(tmp_path)
    _write_config(tmp_path)
    (tmp_path / "agent.py").write_text(
        """
import yaml
from core.loop import AgentLoop
from core.session import MultiMCP

def main():
    with open("config/profiles.yaml") as f:
        profile = yaml.safe_load(f)
        servers = profile.get("mcp_servers", [])
    dispatcher = MultiMCP(server_configs=servers)
    agent = AgentLoop(dispatcher=dispatcher)
    return agent
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "agent_loop")
    assert {server.name for server in agent.mcp_servers} == {"math", "telegram"}
    math = next(server for server in agent.mcp_servers if server.name == "math")
    assert math.metadata["binding_origin"] == "source_proven_dispatcher_profile"
    assert math.metadata["repository_resolved"] is True
    assert math.metadata["server_startup"] == "unverified"
    assert math.metadata["working_directory"] == "C:/external/windows/location"
    report = build_agent_security_graph(graph, tmp_path).as_dict()
    mcp = [
        rel for rel in report["effective_authority"]["relationships"]
        if rel["target"]["kind"] == "mcp_server" and rel["agent"] == "agent_loop"
    ]
    assert {rel["target"]["name"] for rel in mcp} == {"math", "telegram"}
    assert all(rel["runtime_effectiveness"] == "not_verified" for rel in mcp)


def test_custom_agent_does_not_bind_coexisting_mcp_config_without_injection(
    tmp_path: Path,
) -> None:
    _write_agent_loop(tmp_path)
    _write_config(tmp_path)
    (tmp_path / "agent.py").write_text(
        """
import yaml
from core.loop import AgentLoop
from core.session import MultiMCP

def main():
    with open("config/profiles.yaml") as f:
        profile = yaml.safe_load(f)
        servers = profile.get("mcp_servers", [])
    unused = MultiMCP(server_configs=servers)
    agent = AgentLoop(dispatcher=None)
    return agent
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "agent_loop")
    assert not agent.mcp_servers


def test_custom_agent_does_not_bind_dynamic_mcp_profile(tmp_path: Path) -> None:
    _write_agent_loop(tmp_path)
    _write_config(tmp_path)
    (tmp_path / "agent.py").write_text(
        """
import yaml
from core.loop import AgentLoop
from core.session import MultiMCP

def main(profile_path):
    with open(profile_path) as f:
        profile = yaml.safe_load(f)
        servers = profile.get("mcp_servers", [])
    dispatcher = MultiMCP(server_configs=servers)
    agent = AgentLoop(dispatcher=dispatcher)
    return agent
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(a for a in graph.agents if a.name == "agent_loop")
    assert not agent.mcp_servers
