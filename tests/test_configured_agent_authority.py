from pathlib import Path

from horustrace.scanner import scan


def test_active_config_registry_enriches_agents_and_memory_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "config").mkdir()
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "config").mkdir()

    (tmp_path / "tools" / "memory_tools.py").write_text(
        """
from agents import function_tool

@function_tool
def get_agent_memory(agent_name: str):
    return {}

@function_tool
def update_agent_memory(agent_name: str, value: dict):
    memory_store.update_memory(agent_name, value)
    return "ok"
""",
        encoding="utf-8",
    )

    (tmp_path / "tools" / "registry.py").write_text(
        """
import json

def initialize_tool_registry():
    with open("tools/config/tool_definitions.json") as f:
        config = json.load(f)
    return config.get("tools", [])
""",
        encoding="utf-8",
    )
    (tmp_path / "tools" / "config" / "tool_definitions.json").write_text(
        """{
  "tools": [
    {
      "name": "get_agent_memory",
      "module": "tools.memory_tools",
      "function": "get_agent_memory"
    },
    {
      "name": "update_agent_memory",
      "module": "tools.memory_tools",
      "function": "update_agent_memory"
    }
  ]
}""",
        encoding="utf-8",
    )

    (tmp_path / "agents" / "registry.py").write_text(
        """
import json
from agents import Agent

class AgentRegistry:
    def __init__(self):
        self.agent_definitions = {}

    def load_agent_definitions(self, path):
        with open(path) as f:
            config = json.load(f)
        for item in config.get("agents", []):
            self.agent_definitions[item["name"]] = item

    def instantiate_agents(self):
        for name, agent_def in self.agent_definitions.items():
            Agent(
                name=agent_def["name"],
                tools=agent_def.get("tools"),
                handoffs=agent_def.get("handoffs"),
            )

    def get_agent(self, name):
        return None

def initialize_agent_registry():
    config_path = "agents/config/agent_definitions.json"
    return AgentRegistry()
""",
        encoding="utf-8",
    )
    (tmp_path / "agents" / "config" / "agent_definitions.json").write_text(
        """{
  "agents": [
    {
      "name": "WorkflowRouterAgent",
      "instructions": "Route requests.",
      "tools": ["get_agent_memory", "update_agent_memory"],
      "handoffs": []
    }
  ]
}""",
        encoding="utf-8",
    )

    (tmp_path / "app.py").write_text(
        """
from flask import Flask, request
from agents import Runner
from agents.registry import initialize_agent_registry

app = Flask(__name__)
agent_registry = initialize_agent_registry()

class OrchestrationEngine:
    def __init__(self, agent_registry):
        self.agent_registry = agent_registry

    async def execute_workflow(self, user_query):
        router_agent = self.agent_registry.get_agent("WorkflowRouterAgent")
        router_input = {"user_query": user_query}
        return await Runner.run(router_agent, input=router_input)

async def execute_orchestrated_workflow(user_query):
    engine = OrchestrationEngine(agent_registry)
    return await engine.execute_workflow(user_query)

@app.route("/chat", methods=["POST"])
async def chat():
    user_message = request.form.get("message", "")
    return await execute_orchestrated_workflow(user_message)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    router = next(agent for agent in graph.agents if agent.name == "WorkflowRouterAgent")
    assert router.metadata["config_registry_active"] is True
    assert {tool.name for tool in router.tools} == {
        "get_agent_memory",
        "update_agent_memory",
    }
    assert any(source.trust == "untrusted" for source in router.inputs)

    rule_ids = {finding.rule_id for finding in findings if finding.agent == router.name}
    assert {"AGT022", "AGT040", "CAP005", "PATH007"} <= rule_ids
