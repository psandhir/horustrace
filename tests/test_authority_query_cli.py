import json
from pathlib import Path

from horustrace import cli
from horustrace.models import Agent, Graph, Tool


def _graph() -> Graph:
    return Graph(
        agents=[
            Agent(
                name="agent",
                tools=[
                    Tool(
                        name="run",
                        kind="function",
                        capabilities={"process.execute"},
                        approval=False,
                    )
                ],
            )
        ]
    )


def test_query_cli_json(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_graph(), []))

    result = cli.main(
        [
            "query",
            str(tmp_path),
            "--capability",
            "process.execute",
            "--format",
            "json",
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["matches"] == 1
    assert report["results"][0]["agent"] == "agent"



def test_query_cli_filters_core_resolution(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_graph(), []))

    result = cli.main(
        [
            "query",
            str(tmp_path),
            "--core-resolution",
            "fully_resolved",
            "--format",
            "json",
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["matches"] == 1
    assert (
        report["results"][0]["relationship"]["core_resolution"]
        == "fully_resolved"
    )

def test_query_cli_requires_filter(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_graph(), []))

    result = cli.main(["query", str(tmp_path)])

    assert result == 1
    assert "requires at least one" in capsys.readouterr().err
