"""Public framework-adapter contract for HorusTrace v0.5."""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from horustrace.models import Graph
from horustrace.semantic_contract import SEMANTIC_CONTRACT_VERSION, validate_graph_semantics

ADAPTER_CONTRACT_VERSION = 1
_ADAPTER_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


@dataclass(frozen=True, slots=True)
class PythonFrameworkAdapter:
    """Static Python adapter that normalizes framework constructs into Graph."""

    name: str
    detector: Callable[[Path], bool]
    scanner: Callable[[Path], Graph]
    contract_version: int = ADAPTER_CONTRACT_VERSION

    def validate(self) -> None:
        if self.contract_version != ADAPTER_CONTRACT_VERSION:
            raise ValueError(
                f"unsupported adapter contract version: {self.contract_version}"
            )
        if not _ADAPTER_NAME.fullmatch(self.name):
            raise ValueError(
                "adapter name must be a lowercase kebab-case identifier"
            )
        if not callable(self.detector) or not callable(self.scanner):
            raise TypeError("adapter detector and scanner must be callable")

    def validate_graph(self, graph: Graph) -> None:
        errors = validate_graph_semantics(graph)
        if errors:
            raise ValueError("adapter graph violates semantic contract: " + "; ".join(errors))

    def as_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "name": self.name,
            "contract_version": self.contract_version,
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
            "language": "python",
            "input": "source_file",
            "output": "horustrace.models.Graph",
            "execution_model": "static",
            "target_code_execution": False,
        }
