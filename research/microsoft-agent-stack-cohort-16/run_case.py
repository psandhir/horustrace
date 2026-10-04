from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from horustrace.config import load_config
from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "cohort.json").read_text(encoding="utf-8"))

SOURCE_EXTENSIONS = {
    ".py", ".cs", ".csproj", ".json", ".yaml", ".yml", ".toml", ".md"
}
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "dist", "build", "bin", "obj",
    "vendor", "__pycache__"
}
TOKENS = (
    "agent", "tool", "mcp", "program", "main", "workflow", "skill", "host",
    "auth", "identity", "provider"
)


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 900,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[-6000:])
    return result


def clone_case(root: Path, case: dict[str, Any]) -> Path:
    target = root / "repo"
    run(["git", "init", "-q", str(target)])
    run([
        "git", "-C", str(target), "remote", "add", "origin",
        f"https://github.com/{case['repo']}.git",
    ])
    run([
        "git", "-C", str(target), "fetch", "--quiet", "--depth=1",
        "--filter=blob:none", "origin", case["sha"],
    ], timeout=600)
    run([
        "git", "-C", str(target), "checkout", "--quiet", "--detach",
        "FETCH_HEAD",
    ])
    actual = run(["git", "-C", str(target), "rev-parse", "HEAD"]).stdout.strip()
    if actual != case["sha"]:
        raise RuntimeError(
            f"target SHA mismatch for {case['repo']}: {actual} != {case['sha']}"
        )
    return target


def clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    if isinstance(value, set):
        return sorted(clean(v) for v in value)
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def loc(location: Any, repo_root: Path) -> dict[str, Any] | None:
    if location is None:
        return None
    path = Path(location.path)
    try:
        rendered = path.resolve().relative_to(repo_root.resolve()).as_posix()
    except (OSError, ValueError):
        rendered = str(path)
    return {
        "path": rendered,
        "line": int(getattr(location, "line", 1) or 1),
        "column": int(getattr(location, "column", 1) or 1),
    }


def serialize_resource(resource: Any, repo_root: Path) -> dict[str, Any]:
    return {
        "kind": resource.kind,
        "selector": resource.selector,
        "access": sorted(resource.access),
        "classification": resource.classification,
        "location": loc(resource.location, repo_root),
        "metadata": clean(resource.metadata),
    }


def serialize_destination(destination: Any, repo_root: Path) -> dict[str, Any]:
    return {
        "target": destination.target,
        "direction": destination.direction,
        "restricted": destination.restricted,
        "location": loc(destination.location, repo_root),
        "metadata": clean(destination.metadata),
    }


def serialize_tool(tool: Any, repo_root: Path) -> dict[str, Any]:
    return {
        "name": tool.name,
        "kind": tool.kind,
        "capabilities": sorted(tool.capabilities),
        "approval": tool.approval,
        "guardrails": tool.guardrails,
        "identity": tool.identity,
        "location": loc(tool.location, repo_root),
        "resources": [
            serialize_resource(item, repo_root) for item in tool.resources
        ],
        "destinations": [
            serialize_destination(item, repo_root) for item in tool.destinations
        ],
        "metadata": clean(tool.metadata),
    }


def serialize_mcp(server: Any, repo_root: Path) -> dict[str, Any]:
    return {
        "name": server.name,
        "transport": server.transport,
        "url": server.url,
        "command": server.command,
        "args": list(server.args),
        "authenticated": server.authenticated,
        "approval": server.approval,
        "guardrails": server.guardrails,
        "allowed_tools": list(server.allowed_tools),
        "denied_tools": list(server.denied_tools),
        "identity": server.identity,
        "location": loc(server.location, repo_root),
        "resources": [
            serialize_resource(item, repo_root) for item in server.resources
        ],
        "metadata": clean(server.metadata),
    }


def serialize_agent(agent: Any, repo_root: Path) -> dict[str, Any]:
    return {
        "name": agent.name,
        "framework": agent.metadata.get("framework"),
        "language": agent.metadata.get("language"),
        "provider": agent.metadata.get("provider"),
        "location": loc(agent.location, repo_root),
        "capabilities": sorted(agent.capabilities),
        "metadata": clean(agent.metadata),
        "tools": [serialize_tool(item, repo_root) for item in agent.tools],
        "mcp_servers": [serialize_mcp(item, repo_root) for item in agent.mcp_servers],
        "inputs": [
            {
                "name": item.name,
                "trust": item.trust,
                "kind": item.kind,
                "location": loc(item.location, repo_root),
                "metadata": clean(item.metadata),
            }
            for item in agent.inputs
        ],
        "identities": [
            {
                "name": item.name,
                "provider": item.provider,
                "roles": sorted(item.roles),
                "permissions": sorted(item.permissions),
                "oauth_scopes": sorted(item.oauth_scopes),
                "credential_source": item.credential_source,
                "location": loc(item.location, repo_root),
                "metadata": clean(item.metadata),
            }
            for item in agent.identities
        ],
        "effective_resources": [
            serialize_resource(item, repo_root) for item in agent.effective_resources
        ],
        "effective_destinations": [
            serialize_destination(item, repo_root)
            for item in agent.effective_destinations
        ],
    }


def source_pack(scan_target: Path) -> str:
    files: list[tuple[int, str, Path]] = []
    for path in scan_target.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        rel = path.relative_to(scan_target)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        score = 0
        lowered = path.name.lower()
        if any(token in lowered for token in TOKENS):
            score += 300
        if path.suffix.lower() in {".py", ".cs"}:
            score += 100
        if "test" in str(rel).lower():
            score -= 80
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size < 18000:
            score += 40
        files.append((-score, rel.as_posix(), path))

    chunks: list[str] = []
    total = 0
    for _, rel, path in sorted(files):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if len(text) > 18000:
            text = text[:18000] + "\n...[truncated]..."
        chunk = f"\n===== FILE: {rel} =====\n{text}\n"
        if total + len(chunk) > 100000:
            continue
        chunks.append(chunk)
        total += len(chunk)
    return "".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = parser.parse_args()

    case = next(
        item for item in CONFIG["cases"] if item["case_id"] == args.case_id
    )
    out = args.output_dir / case["case_id"]
    out.mkdir(parents=True, exist_ok=True)

    started = time.monotonic()
    result: dict[str, Any] = {
        "schema_version": 1,
        "case_id": case["case_id"],
        "repo": case["repo"],
        "sha": case["sha"],
        "scan_path": case["scan_path"],
        "stack": case["stack"],
        "scored_p0": case["scored_p0"],
        "expected_framework": case.get("expected_framework"),
        "expected_agent_min": case.get("expected_agent_min", 0),
        "evidence_path": case.get("evidence_path"),
        "selection_signal": case.get("selection_signal"),
    }

    try:
        with tempfile.TemporaryDirectory(
            prefix=f"horus-ms-stack-{case['case_id']}-"
        ) as temp:
            repo_root = clone_case(Path(temp), case)
            scan_target = (
                repo_root
                if case["scan_path"] in {"", "."}
                else repo_root / case["scan_path"]
            )
            if not scan_target.exists():
                raise RuntimeError(f"scan path does not exist: {scan_target}")

            pack = source_pack(scan_target)
            (out / "source-pack.txt").write_text(pack, encoding="utf-8")

            graph, findings = scan(
                scan_target,
                config=load_config(scan_target),
            )

            agents = [
                serialize_agent(agent, repo_root) for agent in graph.agents
            ]
            unbound = [
                serialize_mcp(server, repo_root)
                for server in graph.unbound_mcp_servers
            ]
            expected_framework = case.get("expected_framework")
            framework_agents = [
                agent for agent in agents
                if expected_framework
                and agent.get("framework") == expected_framework
            ]
            agent_min = int(case.get("expected_agent_min", 0))
            structural_pass = (
                len(framework_agents) >= agent_min
                if case["scored_p0"]
                else None
            )

            attack_paths = [
                {
                    "path_id": item.path_id,
                    "title": item.title,
                    "agent": item.agent,
                    "nodes": clean(item.nodes),
                    "severity": item.severity.label(),
                    "metadata": clean(item.metadata),
                }
                for item in graph.attack_paths
            ]
            diagnostic_rows = [
                item.as_dict() for item in graph.coverage.diagnostics
            ]

            result.update({
                "scan": "ok",
                "agents": agents,
                "unbound_mcp_servers": unbound,
                "findings": [item.as_dict() for item in findings],
                "attack_paths": attack_paths,
                "effective_authority": clean(
                    effective_authority_report(graph)
                ),
                "diagnostics": diagnostic_rows,
                "counts": {
                    "agents": len(agents),
                    "expected_framework_agents": len(framework_agents),
                    "tools": sum(len(agent["tools"]) for agent in agents),
                    "bound_mcp_servers": sum(
                        len(agent["mcp_servers"]) for agent in agents
                    ),
                    "unbound_mcp_servers": len(unbound),
                    "findings": len(findings),
                    "attack_paths": len(attack_paths),
                    "diagnostics": len(diagnostic_rows),
                },
                "structural_p0_detection_pass": structural_pass,
                "source_pack_chars": len(pack),
            })
    except Exception as exc:
        result.update({
            "scan": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "counts": {
                "agents": 0,
                "expected_framework_agents": 0,
                "tools": 0,
                "bound_mcp_servers": 0,
                "unbound_mcp_servers": 0,
                "findings": 0,
                "attack_paths": 0,
                "diagnostics": 0,
            },
            "structural_p0_detection_pass": False
            if case["scored_p0"]
            else None,
        })

    result["elapsed_seconds"] = round(time.monotonic() - started, 2)
    (out / "result.json").write_text(
        json.dumps(result, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "case_id": result["case_id"],
        "scan": result["scan"],
        "stack": result["stack"],
        "structural_p0_detection_pass": result[
            "structural_p0_detection_pass"
        ],
        **result["counts"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
