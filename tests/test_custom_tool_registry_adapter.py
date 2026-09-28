from pathlib import Path

from horustrace.adapters.custom_tool_registry import is_custom_tool_registry_file
from horustrace.scanner import scan


def test_schema_declared_custom_tool_is_discovered(tmp_path: Path) -> None:
    source = tmp_path / "custom_tools.py"
    source.write_text(
        """
import httpx

def tool(**kwargs):
    def decorate(fn):
        return fn
    return decorate

@tool(
    name="send_webhook",
    description="Send data to a webhook.",
    parameters={"url": {"type": "string"}, "body": {"type": "object"}},
)
async def send_webhook(url: str, body: dict):
    return await httpx.AsyncClient().post(url, json=body)
""",
        encoding="utf-8",
    )

    assert is_custom_tool_registry_file(source)

    graph, _ = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "send_webhook")

    assert tool.kind == "custom_registry_tool"
    assert tool.metadata["explicit_schema"] is True
    assert {"network.external", "external.write"} <= tool.capabilities


def test_bare_custom_tool_decorator_is_not_claimed_without_schema_contract(
    tmp_path: Path,
) -> None:
    source = tmp_path / "custom.py"
    source.write_text(
        """
def tool(fn):
    return fn

@tool
def ordinary_action(value):
    return value
""",
        encoding="utf-8",
    )

    assert not is_custom_tool_registry_file(source)

    graph, _ = scan(tmp_path)
    assert not any(tool.name == "ordinary_action" for tool in graph.unbound_tools)


def test_schema_tool_delete_operation_is_destructive(tmp_path: Path) -> None:
    source = tmp_path / "files.py"
    source.write_text(
        """
from pathlib import Path

def tool(**kwargs):
    def decorate(fn):
        return fn
    return decorate

@tool(
    name="delete_file",
    description="Delete a file.",
    parameters={"path": {"type": "string"}},
)
def delete_file(path: str):
    Path(path).unlink()
    return "ok"
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "delete_file")

    assert {"data.write", "destructive.write"} <= tool.capabilities
