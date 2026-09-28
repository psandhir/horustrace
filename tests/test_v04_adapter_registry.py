from pathlib import Path

from horustrace.adapters.registry import (
    PYTHON_FRAMEWORK_ADAPTERS,
    detect_python_framework,
)
from horustrace.scanner import scan


def test_framework_registry_has_stable_adapter_order() -> None:
    assert [adapter.name for adapter in PYTHON_FRAMEWORK_ADAPTERS] == [
        "google-adk",
        "langgraph",
        "langchain-tools",
        "custom-tool-registry",
        "openai-agents",
        "pydantic-ai",
        "fast-agent",
        "model-tool-loop",
        "mcp-python",
    ]


def test_framework_registry_detects_supported_python_frameworks(tmp_path: Path) -> None:
    cases = {
        "adk.py": ("from google.adk import Agent\n", "google-adk"),
        "langgraph.py": ("from langgraph.graph import StateGraph\n", "langgraph"),
        "langchain_tools.py": (
            "from langchain_core.tools import tool\n",
            "langchain-tools",
        ),
        "openai.py": ("from agents import Agent\n", "openai-agents"),
        "fast_agent.py": (
            "from fast_agent import FastAgent\nfast = FastAgent('demo')\n",
            "fast-agent",
        ),
    }
    for filename, (source, expected) in cases.items():
        path = tmp_path / filename
        path.write_text(source, encoding="utf-8")
        assert detect_python_framework(path) == expected


def test_unrelated_agent_class_is_not_treated_as_openai_agents_sdk(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
class Agent:
    def __init__(self, name):
        self.name = name

agent = Agent("ordinary-application-object")
""",
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    assert graph.agents == []
    assert findings == []
    assert graph.coverage.incomplete is True


def test_langgraph_execute_label_does_not_imply_process_execution(tmp_path: Path) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from langgraph.graph import StateGraph

def execute(state):
    return state

workflow = StateGraph(dict)
workflow.add_node("execute", execute)
app = workflow.compile()
""",
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    agent = next(agent for agent in graph.agents if agent.metadata.get("framework") == "langgraph")
    tool = next(tool for tool in agent.tools if tool.name == "execute")
    assert "process.execute" not in tool.capabilities
    assert not any(finding.rule_id == "AGT020" for finding in findings)
