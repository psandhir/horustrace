from pathlib import Path

from horustrace.scanner import scan


def test_configured_registry_agent_binds_tools_and_user_ingress(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        """
from agents import function_tool

@function_tool
def get_agent_memory(agent_name: str):
    return {}

@function_tool
def update_agent_memory(agent_name: str, value: dict):
    return memory_store.update_memory(agent_name, value)
""",
        encoding="utf-8",
    )
    (tmp_path / "registry.py").write_text(
        """
from agents import Agent

class AgentRegistry:
    def load_agent_definitions(self, path):
        pass

    def _resolve_tools(self, names):
        return names

    def instantiate_agents(self):
        for name, agent_def in self.agent_definitions.items():
            Agent(name=agent_def["name"], tools=self._resolve_tools(agent_def["tools"]))

    def get_agent(self, name):
        return self.agents[name]
""",
        encoding="utf-8",
    )
    (tmp_path / "orchestration.py").write_text(
        """
from agents import Runner

async def execute_workflow(user_query, registry):
    router_agent = registry.get_agent("WorkflowRouterAgent")
    return await Runner.run(router_agent, input=user_query)
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
from fastapi import APIRouter
from orchestration import execute_workflow

router = APIRouter()

@router.post("/query")
async def query(request):
    return await execute_workflow(request.query, registry)
""",
        encoding="utf-8",
    )
    (tmp_path / "agent_definitions_fixed.json").write_text(
        """
{
  "agents": [{
    "name": "WorkflowRouterAgent",
    "instructions": "route",
    "tools": ["get_agent_memory", "update_agent_memory"]
  }]
}
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "WorkflowRouterAgent")
    assert {tool.name for tool in agent.tools} == {
        "get_agent_memory",
        "update_agent_memory",
    }
    assert any(item.trust == "untrusted" for item in agent.inputs)
    rule_ids = {item.rule_id for item in findings if item.agent == agent.name}
    assert {"AGT022", "AGT040", "CAP005", "PATH007"} <= rule_ids
