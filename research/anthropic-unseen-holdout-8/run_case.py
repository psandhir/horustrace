from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "cohort.json").read_text(encoding="utf-8"))
EXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml", ".md"}
SKIP = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor", "__pycache__"}


def run(cmd: list[str], *, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if proc.returncode:
        raise RuntimeError((proc.stderr or proc.stdout)[-12000:])
    return proc


def clone_case(root: Path, case: dict) -> Path:
    target = root / "target"
    run(["git", "init", "-q", str(target)])
    run(["git", "-C", str(target), "remote", "add", "origin", f"https://github.com/{case['repo']}.git"])
    run(["git", "-C", str(target), "fetch", "--quiet", "--depth=1", "--filter=blob:none", "origin", case["sha"]])
    run(["git", "-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
    got = run(["git", "-C", str(target), "rev-parse", "HEAD"]).stdout.strip()
    if got != case["sha"]:
        raise RuntimeError(f"target SHA mismatch: {got} != {case['sha']}")
    return target


def source_pack(application: Path) -> str:
    rows: list[tuple[str, Path]] = []
    for path in application.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in EXT:
            continue
        rel = path.relative_to(application)
        if any(part in SKIP for part in rel.parts):
            continue
        rows.append((str(rel), path))
    out: list[str] = []
    total = 0
    for rel, path in sorted(rows):
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            continue
        if len(content) > 24000:
            content = content[:24000] + "\n...[truncated]..."
        chunk = f"\n===== FILE: {rel} =====\n{content}\n"
        if total + len(chunk) > 180000:
            continue
        out.append(chunk)
        total += len(chunk)
    return "".join(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = parser.parse_args()

    case = next(item for item in CONFIG["cases"] if item["case_id"] == args.case_id)
    out = args.output_dir / case["case_id"]
    out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=f"horus-anth-{case['case_id']}-") as raw:
        target = clone_case(Path(raw), case)
        application = target / case["application_path"]
        evidence = application / case["evidence_path"]
        if not application.exists():
            raise RuntimeError(f"missing application path: {application}")
        if not evidence.exists():
            raise RuntimeError(f"missing evidence path: {evidence}")

        pack = source_pack(application)
        (out / "source-pack.txt").write_text(pack, encoding="utf-8")

        graph, findings = scan(application)
        authority = effective_authority_report(graph)
        relationships = authority.get("relationships") or []

        agents = [
            item
            for item in graph.agents
            if item.metadata.get("framework") in {
                "claude-agent-sdk",
                "claude-managed-agents",
            }
        ]
        result = {
            "schema_version": 1,
            "study": CONFIG["study"],
            "case_id": case["case_id"],
            "repo": case["repo"],
            "sha": case["sha"],
            "surface": case["surface"],
            "source_signal": case["source_signal"],
            "evidence_path": case["evidence_path"],
            "counts": {
                "framework_agents": len(agents),
                "tools": sum(len(agent.tools) for agent in agents),
                "mcp_servers": sum(len(agent.mcp_servers) for agent in agents),
                "authority_relationships": sum(
                    1 for rel in relationships
                    if rel.get("agent") in {agent.name for agent in agents}
                ),
                "findings": len(findings),
            },
            "agents": [
                {
                    "name": agent.name,
                    "framework": agent.metadata.get("framework"),
                    "language": agent.metadata.get("language"),
                    "capabilities": sorted(agent.capabilities),
                    "metadata": dict(agent.metadata),
                    "tools": [
                        {
                            "name": tool.name,
                            "kind": tool.kind,
                            "capabilities": sorted(tool.capabilities),
                            "approval": tool.approval,
                            "metadata": dict(tool.metadata),
                        }
                        for tool in agent.tools
                    ],
                    "mcp_servers": [
                        {
                            "name": server.name,
                            "transport": server.transport,
                            "url": server.url,
                            "approval": server.approval,
                            "authenticated": server.authenticated,
                            "metadata": dict(server.metadata),
                        }
                        for server in agent.mcp_servers
                    ],
                }
                for agent in agents
            ],
            "authority_relationships": relationships,
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "agent": finding.agent,
                    "title": finding.title,
                }
                for finding in findings
            ],
        }
        (out / "result.json").write_text(
            json.dumps(result, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({
            "case_id": case["case_id"],
            "surface": case["surface"],
            "agents": [agent.name for agent in agents],
            **result["counts"],
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
