import json

import pytest

from horustrace.adapters.contract import PythonFrameworkAdapter
from horustrace.adapters.registry import (
    PYTHON_FRAMEWORK_ADAPTERS,
    adapter_catalogue,
    detect_python_frameworks,
)
from horustrace.cli import main
from horustrace.models import Graph


def _never_detects(_path):
    return False


def _empty_scan(_path):
    return Graph()


def test_builtin_adapters_conform_to_contract_v1() -> None:
    catalogue = adapter_catalogue()

    assert [item["name"] for item in catalogue] == [
        adapter.name for adapter in PYTHON_FRAMEWORK_ADAPTERS
    ]
    assert all(item["contract_version"] == 1 for item in catalogue)
    assert all(item["output"] == "horustrace.models.Graph" for item in catalogue)
    assert all(item["target_code_execution"] is False for item in catalogue)


def test_adapter_contract_rejects_invalid_name_and_version() -> None:
    with pytest.raises(ValueError, match="kebab-case"):
        PythonFrameworkAdapter(
            "Bad Adapter",
            _never_detects,
            _empty_scan,
        ).validate()

    with pytest.raises(ValueError, match="unsupported adapter contract"):
        PythonFrameworkAdapter(
            "future-adapter",
            _never_detects,
            _empty_scan,
            contract_version=2,
        ).validate()


def test_adapters_cli_exposes_contract_catalogue(capsys) -> None:
    assert main(["adapters", "--format", "json"]) == 0

    document = json.loads(capsys.readouterr().out)
    assert document["schema_version"] == 1
    assert any(item["name"] == "google-adk" for item in document["adapters"])
    assert all(item["execution_model"] == "static" for item in document["adapters"])


def test_langgraph_is_out_of_scope(tmp_path) -> None:
    source = tmp_path / "workflow.py"
    source.write_text(
        """
from langgraph.graph import StateGraph

workflow = StateGraph(dict)
workflow.add_node("transform", lambda state: state)
""",
        encoding="utf-8",
    )

    assert "langgraph" not in detect_python_frameworks(source)
