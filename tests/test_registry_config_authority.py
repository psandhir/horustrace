from pathlib import Path

from horustrace.scanner import scan


def test_source_proven_registry_binds_config_agents_and_memory_tools(
    tmp_path: Path,
) -> None:
    (tmp_path / "agents" / "registry").mkdir(parents=True)
    (tmp_path / "agents" / "config").mkdir(parents=True)
    (tmp_path / "tools" / "registry").mkdir(parents=True)
    (tmp_path / "tools" / "config").mkdir(parents=True)
    (tmp_path / "tools" / "memory_tools").mkdir(parents=True)

    for package in (
        tmp_path / "agents",
        tmp_path / "agents" / "registry",
        tmp_path / "tools",
        tmp_path / "tools" / "registry",
        tmp_path / "tools" / "memory_tools",
    ):
        (package / "__init__.py").write_text("", encoding="utf-8")

    (tmp_path / "agents" / "registry" / "agent_registry.py").write_text(
        """
import json
from agents import Agent

class AgentRegistry:
    def __init__(self, tool_registry=None):
        self.tool_registry = tool_registry
        self.agent_definitions = {}
        self.agents = {}

    def load_agent_definitions(self, config_path):
        with open(config_path) as f:
            config = json.load(f)
        for item in config.get("agents", []):
            self.agent_definitions[item["name"]] = item

    def _resolve_tools(self, names):
        return [self.tool_registry.get_tool(name) for name in names]

    def instantiate_agents(self):
        for name, item in self.agent_definitions.items():
            tools = self._resolve_tools(item.get("tools", []))
            self.agents[name] = Agent(
                name=item["name"],
                instructions=item["instructions"],
                model=item.get("model"),
                tools=tools,
            )
""",
        encoding="utf-8",
    )
    (tmp_path / "tools" / "registry" / "tool_registry.py").write_text(
        """
import json

class ToolRegistry:
    def __init__(self):
        self.tools = {}
        self.tool_definitions = {}

    def load_tool_definitions(self, config_path):
        with open(config_path) as f:
            config = json.load(f)
        for item in config.get("tools", []):
            self.tool_definitions[item["name"]] = item

    def instantiate_tools(self):
        return None

    def get_tool(self, name):
        return self.tools.get(name)
""",
        encoding="utf-8",
    )
    # A legacy sibling registry can coexist with the active package loader.
    # Its preferred config must not override the source-proven package loader.
    (tmp_path / "agents" / "registry.py").write_text(
        """
def initialize_agent_registry():
    config_path = "agent_definitions_updated_final.json"
    return config_path
""",
        encoding="utf-8",
    )
    (tmp_path / "agents" / "config" / "agent_definitions_updated_final.json").write_text(
        '{"agents": [ invalid legacy config',
        encoding="utf-8",
    )

    (tmp_path / "agents" / "registry" / "registry_loader.py").write_text(
        """
from .agent_registry import AgentRegistry

def initialize_agent_registry():
    agent_config = "agent_definitions_fixed.json"
    tool_config = "tool_definitions_fixed.json"
    registry = AgentRegistry()
    registry.load_agent_definitions(agent_config)
    registry.instantiate_agents()
    return registry
""",
        encoding="utf-8",
    )
    (tmp_path / "tools" / "registry" / "registry_loader.py").write_text(
        """
from .tool_registry import ToolRegistry

def initialize_tool_registry():
    config_path = "tool_definitions_fixed.json"
    registry = ToolRegistry()
    registry.load_tool_definitions(config_path)
    registry.instantiate_tools()
    return registry
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
from agents.registry.registry_loader import initialize_agent_registry

agent_registry = initialize_agent_registry()
""",
        encoding="utf-8",
    )
    (tmp_path / "tools" / "memory_tools" / "memory_tools.py").write_text(
        """
from agents import function_tool

class Store:
    def get_memory(self, agent_name):
        return {}
    def update_memory(self, agent_name, memory_update):
        return None
    def add_to_memory_list(self, agent_name, list_key, item):
        return None

memory_store = Store()

@function_tool
def get_agent_memory(agent_name: str):
    return memory_store.get_memory(agent_name)

@function_tool
def update_agent_memory(agent_name: str, memory_update: dict):
    return memory_store.update_memory(agent_name, memory_update)

@function_tool
def add_to_agent_memory_list(agent_name: str, list_key: str, item):
    return memory_store.add_to_memory_list(agent_name, list_key, item)
""",
        encoding="utf-8",
    )

    (tmp_path / "agents" / "config" / "agent_definitions_fixed.json").write_text(
        """{
  "agents": [{
    "name": "WorkflowRouterAgent",
    "instructions": "Route requests",
    "model": "gpt-4o-mini",
    "tools": [
      "get_agent_memory",
      "update_agent_memory",
      "add_to_agent_memory_list"
    ]
  }]
}""",
        encoding="utf-8",
    )
    (tmp_path / "tools" / "config" / "tool_definitions_fixed.json").write_text(
        """{
  "tools": [
    {
      "name": "get_agent_memory",
      "module": "tools.memory_tools.memory_tools",
      "function": "get_agent_memory"
    },
    {
      "name": "update_agent_memory",
      "module": "tools.memory_tools.memory_tools",
      "function": "update_agent_memory"
    },
    {
      "name": "add_to_agent_memory_list",
      "module": "tools.memory_tools.memory_tools",
      "function": "add_to_agent_memory_list"
    }
  ]
}""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    router = next(agent for agent in graph.agents if agent.name == "WorkflowRouterAgent")
    assert router.metadata["discovery_basis"] == "source_proven_json_registry"
    assert {tool.name for tool in router.tools} == {
        "get_agent_memory",
        "update_agent_memory",
        "add_to_agent_memory_list",
    }
    assert all(tool.metadata["binding_origin"] == "config_registry" for tool in router.tools)
    assert all(tool.metadata["registry_resolved"] is True for tool in router.tools)

    rule_ids = {finding.rule_id for finding in findings if finding.agent == router.name}
    assert {"AGT022", "AGT040", "CAP005", "PATH007"} <= rule_ids


def test_registry_json_without_runtime_loader_is_not_authority(tmp_path: Path) -> None:
    (tmp_path / "agent_definitions_fixed.json").write_text(
        '{"agents":[{"name":"Ghost","instructions":"unused","tools":["delete_file"]}]}',
        encoding="utf-8",
    )
    (tmp_path / "tool_definitions_fixed.json").write_text(
        '{"tools":[{"name":"delete_file","module":"tools","function":"delete_file"}]}',
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert not any(agent.name == "Ghost" for agent in graph.agents)
