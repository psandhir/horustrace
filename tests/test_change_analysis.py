from __future__ import annotations

import json
import subprocess
from pathlib import Path

from horustrace.adg import ADGEdge, ADGNode, AgentDependencyGraph
from horustrace.change_analysis import build_git_diff, compare_scans, render_markdown
from horustrace.cli import main
from horustrace.git_snapshot import materialize_git_ref
from horustrace.models import (
    Agent,
    AgentPolicy,
    AuthorityContract,
    Finding,
    Graph,
    Severity,
    SourceLocation,
)

_SECURE_MANIFEST = """version: 1
agents:
  - name: finance-agent
    data:
      - name: finance-reports
        classification: confidential
        selector: /finance/approved-reports/**
    policy:
      required: [data.read, external.write, network.external]
      allowed_resources: [/finance/approved-reports/**]
      allowed_destinations: [https://mail.example.internal/**]
      require_approval_for: [external.write]
      max_privileged_capabilities: 1
    tools:
      - name: send_email
        capabilities: [external.write, network.external]
        human_approval: true
        guardrails: true
        destinations: [https://mail.example.internal/send]
"""

_UNAPPROVED_MANIFEST = _SECURE_MANIFEST.replace(
    "human_approval: true",
    "human_approval: false",
)


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _init_repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "horustrace@example.test")
    _git(repo, "config", "user.name", "HorusTrace Tests")

    manifest = repo / "horustrace.manifest.yaml"
    manifest.write_text(_SECURE_MANIFEST, encoding="utf-8")
    _git(repo, "add", "horustrace.manifest.yaml")
    _git(repo, "commit", "-m", "secure baseline")
    base = _git(repo, "rev-parse", "HEAD")

    manifest.write_text(_UNAPPROVED_MANIFEST, encoding="utf-8")
    _git(repo, "add", "horustrace.manifest.yaml")
    _git(repo, "commit", "-m", "remove approval")
    head = _git(repo, "rev-parse", "HEAD")
    return repo, base, head


def test_finding_line_movement_is_unchanged(tmp_path: Path) -> None:
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    base_root.mkdir()
    head_root.mkdir()
    (base_root / "agent.py").write_text("# base\n", encoding="utf-8")
    (head_root / "agent.py").write_text("# head\n", encoding="utf-8")

    base_finding = Finding(
        rule_id="TEST001",
        severity=Severity.HIGH,
        title="Example",
        message="Example",
        recommendation="Fix it",
        location=SourceLocation(base_root / "agent.py", line=3),
        agent="agent",
        evidence=["same semantic evidence"],
    )
    head_finding = Finding(
        rule_id="TEST001",
        severity=Severity.HIGH,
        title="Example",
        message="Example",
        recommendation="Fix it",
        location=SourceLocation(head_root / "agent.py", line=30),
        agent="agent",
        evidence=["same semantic evidence"],
    )

    report = compare_scans(
        Graph(adg=AgentDependencyGraph()),
        [base_finding],
        base_root,
        Graph(adg=AgentDependencyGraph()),
        [head_finding],
        head_root,
        base_ref="base",
        head_ref="head",
    )

    assert report["summary"]["introduced_findings"] == 0
    assert report["summary"]["resolved_findings"] == 0
    assert report["summary"]["unchanged_findings"] == 1


def test_compare_scans_reports_added_capability_and_introduced_finding(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    base_root.mkdir()
    head_root.mkdir()

    node_id = "adg-v1:example"
    base_graph = Graph(
        adg=AgentDependencyGraph(
            nodes=[
                ADGNode(
                    node_id=node_id,
                    kind="tool",
                    name="agent:publisher",
                    attributes={"capabilities": ["data.read"]},
                )
            ]
        )
    )
    head_graph = Graph(
        adg=AgentDependencyGraph(
            nodes=[
                ADGNode(
                    node_id=node_id,
                    kind="tool",
                    name="agent:publisher",
                    attributes={
                        "capabilities": ["data.read", "external.write"],
                    },
                )
            ]
        )
    )
    finding = Finding(
        rule_id="TEST002",
        severity=Severity.HIGH,
        title="New authority",
        message="New authority",
        recommendation="Review it",
        agent="agent",
        evidence=["publisher gained external.write"],
    )

    report = compare_scans(
        base_graph,
        [],
        base_root,
        head_graph,
        [finding],
        head_root,
        base_ref="base",
        head_ref="head",
    )

    assert report["summary"]["introduced_findings"] == 1
    assert report["summary"]["introduced_high_or_critical"] == 1
    assert report["summary"]["changed_authority_nodes"] == 1
    changed = report["authority"]["changed_nodes"][0]
    assert changed["added_capabilities"] == ["external.write"]


def test_materialize_git_ref_uses_committed_content(tmp_path: Path) -> None:
    repo, base, head = _init_repo(tmp_path)

    with materialize_git_ref(repo, base) as snapshot:
        content = (snapshot.root / "horustrace.manifest.yaml").read_text(
            encoding="utf-8"
        )
        assert snapshot.commit == base
        assert "human_approval: true" in content
        assert "human_approval: false" not in content

    assert base != head


def test_build_git_diff_detects_removed_approval(tmp_path: Path) -> None:
    repo, base, head = _init_repo(tmp_path)

    report = build_git_diff(repo, base, head)

    assert report["base"]["commit"] == base
    assert report["head"]["commit"] == head
    assert report["summary"]["introduced_findings"] >= 1
    assert report["summary"]["introduced_high_or_critical"] >= 1
    assert report["summary"]["changed_authority_nodes"] >= 1
    assert any(
        item["name"] == "finance-agent:send_email"
        for item in report["authority"]["changed_nodes"]
    )


def test_diff_cli_fails_only_on_introduced_threshold(
    tmp_path: Path,
    capsys,
) -> None:
    repo, base, head = _init_repo(tmp_path)

    result = main(
        [
            "diff",
            f"{base}..{head}",
            "--repo",
            str(repo),
            "--format",
            "json",
            "--fail-on",
            "high",
        ]
    )

    assert result == 2
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["introduced_high_or_critical"] >= 1

    reverse = main(
        [
            "diff",
            f"{head}..{base}",
            "--repo",
            str(repo),
            "--format",
            "json",
            "--fail-on",
            "high",
        ]
    )
    assert reverse == 0


def test_diff_cli_rejects_three_dot_range(tmp_path: Path, capsys) -> None:
    repo, base, head = _init_repo(tmp_path)

    result = main(
        [
            "diff",
            f"{base}...{head}",
            "--repo",
            str(repo),
        ]
    )

    assert result == 1
    assert "revision range must use BASE..HEAD" in capsys.readouterr().err


def test_compare_scans_classifies_severity_escalation_as_worsened(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-severity"
    head_root = tmp_path / "head-severity"
    base_root.mkdir()
    head_root.mkdir()
    (base_root / "agent.py").write_text("# base\n", encoding="utf-8")
    (head_root / "agent.py").write_text("# head\n", encoding="utf-8")

    common = {
        "rule_id": "TEST003",
        "title": "Severity change",
        "message": "Severity change",
        "recommendation": "Review it",
        "agent": "agent",
        "evidence": ["same evidence"],
    }
    base_finding = Finding(
        **common,
        severity=Severity.MEDIUM,
        location=SourceLocation(base_root / "agent.py"),
    )
    head_finding = Finding(
        **common,
        severity=Severity.HIGH,
        location=SourceLocation(head_root / "agent.py"),
    )

    report = compare_scans(
        Graph(adg=AgentDependencyGraph()),
        [base_finding],
        base_root,
        Graph(adg=AgentDependencyGraph()),
        [head_finding],
        head_root,
        base_ref="base",
        head_ref="head",
    )

    assert report["summary"]["introduced_findings"] == 0
    assert report["summary"]["changed_findings"] == 1
    assert report["summary"]["worsened_findings"] == 1
    assert report["findings"]["worsened"][0]["before"]["severity"] == "medium"
    assert report["findings"]["worsened"][0]["after"]["severity"] == "high"


def test_diff_cli_fails_on_worsened_finding_threshold(
    tmp_path: Path,
    monkeypatch,
) -> None:
    report = {
        "base": {"analysis_incomplete": False},
        "head": {"analysis_incomplete": False},
        "findings": {
            "introduced": [],
            "worsened": [
                {
                    "before": {"severity": "medium"},
                    "after": {"severity": "high"},
                }
            ],
        },
    }
    monkeypatch.setattr("horustrace.cli.build_git_diff", lambda *_args: report)

    result = main(
        [
            "diff",
            "base..head",
            "--repo",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "high",
        ]
    )

    assert result == 2

def test_compare_scans_classifies_authority_source_contexts(tmp_path: Path) -> None:
    base_root = tmp_path / "base-context"
    head_root = tmp_path / "head-context"
    base_root.mkdir()
    head_root.mkdir()

    agent_id = "adg-v1:runtime-agent"
    tool_id = "adg-v1:test-tool"
    head_graph = Graph(
        adg=AgentDependencyGraph(
            nodes=[
                ADGNode(
                    node_id=agent_id,
                    kind="agent",
                    name="runtime-agent",
                    location={"path": "src/agent.py", "line": 10, "column": 1},
                ),
                ADGNode(
                    node_id=tool_id,
                    kind="tool",
                    name="runtime-agent:test-helper",
                    location={
                        "path": "tests/test_agent.py",
                        "line": 20,
                        "column": 1,
                    },
                ),
            ],
            edges=[
                ADGEdge(
                    edge_id="edge-v1:test",
                    kind="INVOKES",
                    source=agent_id,
                    target=tool_id,
                    location={
                        "path": "tests/test_agent.py",
                        "line": 20,
                        "column": 1,
                    },
                )
            ],
        )
    )

    report = compare_scans(
        Graph(adg=AgentDependencyGraph()),
        [],
        base_root,
        head_graph,
        [],
        head_root,
        base_ref="base",
        head_ref="head",
    )

    contexts = {
        item["name"]: item["source_context"]
        for item in report["authority"]["added_nodes"]
    }
    assert contexts == {
        "runtime-agent": "runtime",
        "runtime-agent:test-helper": "test",
    }
    assert report["authority"]["added_edges"][0]["source_context"] == "test"
    assert report["context_summary"]["added_authority_nodes"] == {
        "runtime": 1,
        "test": 1,
    }
    assert report["context_summary"]["added_authority_edges"] == {"test": 1}


def test_render_markdown_separates_runtime_and_non_runtime_changes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    runtime_path = root / "src" / "agent.py"
    test_path = root / "tests" / "test_agent.py"
    runtime_path.parent.mkdir()
    test_path.parent.mkdir()
    runtime_path.write_text("# runtime\n", encoding="utf-8")
    test_path.write_text("# test\n", encoding="utf-8")

    runtime_finding = Finding(
        rule_id="TEST100",
        severity=Severity.HIGH,
        title="Runtime regression",
        message="Runtime regression",
        recommendation="Fix it",
        location=SourceLocation(runtime_path),
        agent="runtime-agent",
        evidence=["runtime evidence"],
        source_context="runtime",
    )
    test_finding = Finding(
        rule_id="TEST101",
        severity=Severity.MEDIUM,
        title="Test-only regression",
        message="Test-only regression",
        recommendation="Fix it",
        location=SourceLocation(test_path),
        agent="test-agent",
        evidence=["test evidence"],
        source_context="test",
    )

    report = compare_scans(
        Graph(adg=AgentDependencyGraph()),
        [],
        root,
        Graph(adg=AgentDependencyGraph()),
        [runtime_finding, test_finding],
        root,
        base_ref="base",
        head_ref="head",
    )
    rendered = render_markdown(report)

    assert "# HorusTrace Security Delta" in rendered
    assert "### Application/runtime finding changes" in rendered
    assert "### Non-runtime finding changes" in rendered
    assert "**HIGH TEST100**" in rendered
    assert "**MEDIUM TEST101**" in rendered
    assert "context `runtime`" in rendered
    assert "context `test`" in rendered


def test_diff_cli_markdown_output(tmp_path: Path, capsys) -> None:
    repo, base, head = _init_repo(tmp_path)

    result = main(
        [
            "diff",
            f"{base}..{head}",
            "--repo",
            str(repo),
            "--format",
            "markdown",
            "--fail-on",
            "none",
        ]
    )

    assert result == 0
    output = capsys.readouterr().out
    assert "# HorusTrace Security Delta" in output
    assert "Introduced findings" in output
    assert "Application/runtime finding changes" in output




def test_diff_reports_new_agent_without_authority_contract(tmp_path: Path) -> None:
    base_root = tmp_path / "base-contract"
    head_root = tmp_path / "head-contract"
    base_root.mkdir()
    head_root.mkdir()

    base_graph = Graph(
        agents=[
            Agent(
                name="governed",
                policy=AgentPolicy(authority=AuthorityContract()),
                location=SourceLocation(base_root / "agent.py", line=3),
            )
        ],
        adg=AgentDependencyGraph(),
    )
    head_graph = Graph(
        agents=[
            Agent(
                name="governed",
                policy=AgentPolicy(authority=AuthorityContract()),
                location=SourceLocation(head_root / "agent.py", line=3),
            ),
            Agent(
                name="new-unmanaged",
                location=SourceLocation(head_root / "new_agent.py", line=5),
            ),
        ],
        adg=AgentDependencyGraph(),
    )

    report = compare_scans(
        base_graph,
        [],
        base_root,
        head_graph,
        [],
        head_root,
        base_ref="base",
        head_ref="head",
    )

    coverage = report["authority_contract_coverage"]
    assert coverage["base"]["contract_coverage_percent"] == 100.0
    assert coverage["head"]["contract_coverage_percent"] == 50.0
    assert report["summary"]["introduced_missing_contracts"] == 1
    assert report["summary"]["new_agents_without_contract"] == 1
    assert coverage["new_agents_without_contract"] == [
        {
            "agent": "new-unmanaged",
            "status": "not_declared",
            "reason": "authority_contract_missing",
            "location": {
                "path": "new_agent.py",
                "line": 5,
                "column": 1,
            },
            "source_context": "runtime",
        }
    ]


def test_diff_require_authority_contract_fails_on_head_missing_contract(
    tmp_path: Path,
    monkeypatch,
) -> None:
    report = {
        "base": {"analysis_incomplete": False},
        "head": {"analysis_incomplete": False},
        "authority_resolution": {"regressed": False},
        "authority_policy_delta": {
            "introduced_violations": [],
            "contract_weakenings": [],
        },
        "authority_contract_coverage": {
            "head": {"agents_without_contract": 1},
        },
        "findings": {"introduced": [], "worsened": []},
    }
    monkeypatch.setattr("horustrace.cli.build_git_diff", lambda *_args: report)
    monkeypatch.setattr("horustrace.cli.render_diff_console", lambda _report: "diff")

    result = main(
        [
            "diff",
            "base..head",
            "--repo",
            str(tmp_path),
            "--fail-on",
            "none",
            "--require-authority-contract",
        ]
    )

    assert result == 2

