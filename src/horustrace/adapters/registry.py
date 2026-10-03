"""Framework adapter registry for Python agent source files."""
# ruff: noqa: I001
from __future__ import annotations

from pathlib import Path

from horustrace.adapters.contract import PythonFrameworkAdapter
from horustrace.adapters.custom_tool_registry import is_custom_tool_registry_file
from horustrace.adapters.custom_tool_registry import scan_python_file as scan_custom_tool_registry_python
from horustrace.adapters.fast_agent import is_fast_agent_file
from horustrace.adapters.fast_agent import scan_python_file as scan_fast_agent_python
from horustrace.adapters.google_adk import is_google_adk_file
from horustrace.adapters.google_adk import scan_python_file as scan_google_adk_python
from horustrace.adapters.langchain_tools import is_langchain_tool_file
from horustrace.adapters.langchain_tools import scan_python_file as scan_langchain_tools_python
from horustrace.adapters.mcp_python import is_mcp_python_file
from horustrace.adapters.mcp_python import scan_python_file as scan_mcp_python
from horustrace.adapters.model_tool_loop import is_model_tool_loop_file
from horustrace.adapters.model_tool_loop import scan_python_file as scan_model_tool_loop_python
from horustrace.adapters.microsoft_agent_framework import is_microsoft_agent_framework_file
from horustrace.adapters.microsoft_agent_framework import scan_python_file as scan_microsoft_agent_framework_python
from horustrace.adapters.openai_agents import is_openai_agents_file
from horustrace.adapters.openai_agents import scan_python_file as scan_openai_python
from horustrace.adapters.pydantic_ai import is_pydantic_ai_file
from horustrace.adapters.pydantic_ai import scan_python_file as scan_pydantic_ai_python
from horustrace.models import Graph


PYTHON_FRAMEWORK_ADAPTERS: tuple[PythonFrameworkAdapter, ...] = (
    PythonFrameworkAdapter("google-adk", is_google_adk_file, scan_google_adk_python),
    PythonFrameworkAdapter("langchain-tools", is_langchain_tool_file, scan_langchain_tools_python),
    PythonFrameworkAdapter(
        "custom-tool-registry",
        is_custom_tool_registry_file,
        scan_custom_tool_registry_python,
    ),
    PythonFrameworkAdapter("openai-agents", is_openai_agents_file, scan_openai_python),
    PythonFrameworkAdapter(
        "microsoft-agent-framework",
        is_microsoft_agent_framework_file,
        scan_microsoft_agent_framework_python,
    ),
    PythonFrameworkAdapter("pydantic-ai", is_pydantic_ai_file, scan_pydantic_ai_python),
    PythonFrameworkAdapter("fast-agent", is_fast_agent_file, scan_fast_agent_python),
    PythonFrameworkAdapter(
        "model-tool-loop",
        is_model_tool_loop_file,
        scan_model_tool_loop_python,
    ),
    PythonFrameworkAdapter("mcp-python", is_mcp_python_file, scan_mcp_python),
)


def adapter_catalogue() -> list[dict[str, object]]:
    """Return the stable built-in adapter contract catalogue."""
    result: list[dict[str, object]] = []
    for adapter in PYTHON_FRAMEWORK_ADAPTERS:
        adapter.validate()
        result.append(adapter.as_dict())
    return result


def detect_python_frameworks(path: Path) -> list[str]:
    """Return all supported frameworks detected for a Python source file."""
    return [adapter.name for adapter in PYTHON_FRAMEWORK_ADAPTERS if adapter.detector(path)]


def detect_python_framework(path: Path) -> str | None:
    """Return the first supported framework detected for compatibility callers."""
    frameworks = detect_python_frameworks(path)
    return frameworks[0] if frameworks else None


def _merge_graph(target: Graph, source: Graph) -> None:
    target.agents.extend(source.agents)
    target.unbound_tools.extend(source.unbound_tools)
    target.unbound_mcp_servers.extend(source.unbound_mcp_servers)
    target.identities.extend(source.identities)
    target.coverage.diagnostics.extend(source.coverage.diagnostics)


def scan_python_file(path: Path) -> Graph:
    """Normalize every supported framework present in a Python source file."""
    graph = Graph()
    for adapter in PYTHON_FRAMEWORK_ADAPTERS:
        if adapter.detector(path):
            _merge_graph(graph, adapter.scanner(path))
    return graph
