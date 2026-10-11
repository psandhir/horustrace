"""Data-only, seeded source-shape regressions for security graph claims.

Every emitted case is a plain source string; no fixture or generated target is run
or imported. The scanner consumes it through its normal static source API.
"""
from __future__ import annotations

from dataclasses import dataclass

FAMILIES = (
    "module_alias",
    "from_import_alias",
    "parameter_rename",
    "helper_extraction",
    "import_order",
    "harmless_comment",
    "inline_method",
    "assigned_method",
)


@dataclass(frozen=True, slots=True)
class MetamorphicVariant:
    family: str
    seed: int
    risky_source: str
    near_miss_source: str
    expected_positive: tuple[str, str, str] = (
        "ops", "agent_tool_input", "process_execute",
    )
    expected_negative: tuple[str, str, str] = ()


def _construct(family: str, parameter: str, *, unsafe: bool) -> str:
    if family not in FAMILIES:
        raise ValueError(f"unsupported transformation family {family}")
    imports = "from agents import Agent, function_tool\nimport subprocess"
    prefix = ""
    tail = ""
    expression = "subprocess.run"
    command = parameter if unsafe else "['echo', 'fixed']"
    kwargs = ", shell=True" if unsafe else f", input={parameter}"
    helper_arg = "value" if unsafe else "['echo', 'fixed']"
    if family == "module_alias":
        imports = "from agents import Agent, function_tool\nimport subprocess as sp"
        expression = "sp.run"
    elif family == "from_import_alias":
        imports = "from agents import Agent, function_tool\nfrom subprocess import run as launch"
        expression = "launch"
    elif family == "import_order":
        imports = "import subprocess\nfrom agents import Agent, function_tool"
    elif family == "harmless_comment":
        prefix = "\n# Harmless comment: no executable statements changed.\n"
    elif family == "helper_extraction":
        prefix = (
            f"\ndef delegated(value):\n    {expression}("
            f"{helper_arg}"
            f"{', shell=True' if unsafe else ', input=value'})\n"
        )
        tail = f"delegated({parameter})"
    elif family in {"inline_method", "assigned_method"}:
        prefix = (
            "\nclass Worker:\n"
            "    def execute(self, value):\n"
            f"        subprocess.run({helper_arg}"
            f"{', shell=True' if unsafe else ', input=value'})\n"
        )
        tail = (
            f"Worker().execute({parameter})"
            if family == "inline_method"
            else f"worker = Worker()\n    worker.execute({parameter})"
        )
    if not tail:
        tail = f"{expression}({command}{kwargs})"
    return (
        f"{imports}\n{prefix}\n@function_tool\n"
        f"def dangerous_tool({parameter}: str):\n    {tail}\n\n"
        'agent = Agent(name="ops", tools=[dangerous_tool])\n'
    )


def generate_variant(family: str, seed: int) -> MetamorphicVariant:
    """Three deterministic harmless perturbations per supported transformation family."""
    if family not in FAMILIES or type(seed) is not int or not 0 <= seed < 3:
        raise ValueError("expected a known family and seed 0, 1 or 2")
    parameter = "command" if seed == 0 else ("requested_cmd" if seed == 1 else "payload")
    risky = _construct(family, parameter, unsafe=True)
    safe = _construct(family, parameter, unsafe=False)
    if seed == 1:
        risky = "# review comment: no security assertions here\n" + risky
        safe = "# review comment: no security assertions here\n" + safe
    if seed == 2:
        risky = risky.replace("\n@function_tool", "\n# inert formatting change\n\n@function_tool")
        safe = safe.replace("\n@function_tool", "\n# inert formatting change\n\n@function_tool")
    return MetamorphicVariant(family, seed, risky, safe)


def security_claims(graph) -> set[tuple[str, str, str]]:
    """Compare semantic agent/source/sink claims, not line numbers or finding counts."""
    return {
        (flow.agent, flow.source_kind, flow.sink_kind)
        for flow in graph.flow_paths
        if flow.agent is not None and flow.basis == "static_dataflow"
    }
