from pathlib import Path

from horustrace.scanner import scan


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_pydantic_runtime_capability_gate_counts_as_guardrail(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-4o")

@agent.tool
def create_order(ctx: RunContext[object], symbol: str) -> dict:
    if not ctx.deps.allow_trading:
        return {"ok": False, "reason": "Trading disabled"}

    broker.create_order(symbol=symbol)
    return {"ok": True}
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "create_order")

    assert "data.write" in tool.capabilities
    assert tool.guardrails is True
    assert tool.metadata["runtime_capability_gate"] is True
    assert tool.metadata["guardrail_mechanism"] == "runtime_capability_gate"
    assert not any(
        finding.rule_id in {"AGT022", "AGT040"}
        and finding.agent == "agent"
        for finding in findings
    )


def test_local_safe_path_helper_proves_workspace_containment(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
from pathlib import Path
from agents import Agent, function_tool

WORKDIR = Path("/workspace").resolve()

def _safe_path(path: str) -> Path:
    target = (WORKDIR / path).resolve()
    if target != WORKDIR and WORKDIR not in target.parents:
        raise ValueError(f"path escapes workspace: {path}")
    return target

@function_tool
def read(path: str) -> str:
    return _safe_path(path).read_text(encoding="utf-8")

@function_tool
def write(path: str, content: str) -> str:
    target = _safe_path(path)
    target.write_text(content, encoding="utf-8")
    return "ok"

agent = Agent(name="repo-agent", tools=[read, write])
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "repo-agent")
    by_name = {tool.name: tool for tool in agent.tools}

    for name in ("read", "write"):
        assert by_name[name].metadata["filesystem_path_constrained"] is True
        assert by_name[name].metadata["model_selected_path_parameters"] == ["path"]
        assert not any(
            resource.metadata.get("model_selected_path") is True
            for resource in by_name[name].resources
        )

    assert not any(
        finding.rule_id == "PATH012"
        and finding.agent == "repo-agent"
        for finding in findings
    )
