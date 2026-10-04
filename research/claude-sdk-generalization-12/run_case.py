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
EXT = {".py", ".json", ".yaml", ".yml", ".toml", ".md"}
SKIP = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor", "__pycache__", ".next"}
TOKENS = ("agent", "tool", "mcp", "hook", "permission", "client", "main", "supervisor", "options")


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if proc.returncode:
        raise RuntimeError((proc.stderr or proc.stdout)[-12000:])
    return proc


def clone_case(root: Path, case: dict) -> Path:
    target = root / "target"
    run(["git", "init", "-q", str(target)])
    run(["git", "-C", str(target), "remote", "add", "origin", f"https://github.com/{case['repo']}.git"])
    run(
        ["git", "-C", str(target), "fetch", "--quiet", "--depth=1", "--filter=blob:none", "origin", case["sha"]],
        timeout=1200,
    )
    run(["git", "-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
    got = run(["git", "-C", str(target), "rev-parse", "HEAD"]).stdout.strip()
    if got != case["sha"]:
        raise RuntimeError(f"target SHA mismatch: {got} != {case['sha']}")
    return target


def application_root(target: Path, case: dict) -> Path:
    root = target / case["application_path"]
    if not root.exists():
        raise RuntimeError(f"application_path does not exist: {case['application_path']}")
    return root


def source_pack(application: Path) -> str:
    files: list[tuple[int, str, Path]] = []
    for path in application.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in EXT:
            continue
        rel = path.relative_to(application)
        if any(part in SKIP for part in rel.parts):
            continue
        score = 300 if any(token in path.name.lower() for token in TOKENS) else 0
        if "test" in str(rel).lower():
            score -= 120
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size < 20000:
            score += 50
        files.append((-score, str(rel), path))

    out: list[str] = []
    total = 0
    for _, rel, path in sorted(files):
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        if len(text) > 20000:
            text = text[:20000] + "\n...[truncated]..."
        chunk = f"\n===== FILE: {rel} =====\n{text}\n"
        if total + len(chunk) > 140000:
            continue
        out.append(chunk)
        total += len(chunk)
    return "".join(out)


def inventory(graph) -> list[dict]:
    rows = []
    for agent in graph.agents:
        metadata = getattr(agent, "metadata", {}) or {}
        rows.append(
            {
                "name": agent.name,
                "framework": metadata.get("framework"),
                "tools": [
                    {
                        "name": tool.name,
                        "kind": tool.kind,
                        "capabilities": sorted(getattr(tool, "capabilities", set()) or []),
                        "approval": getattr(tool, "approval", None),
                    }
                    for tool in getattr(agent, "tools", []) or []
                ],
                "mcp_servers": [
                    {
                        "name": server.name,
                        "transport": server.transport,
                        "url": server.url,
                        "command": server.command,
                        "authenticated": server.authenticated,
                    }
                    for server in getattr(agent, "mcp_servers", []) or []
                ],
                "metadata": metadata,
            }
        )
    return rows


def observe(rows: list[dict]) -> dict:
    claude = [row for row in rows if row.get("framework") == "claude-agent-sdk"]
    tool_count = sum(len(row.get("tools") or []) for row in claude)
    mcp_count = sum(len(row.get("mcp_servers") or []) for row in claude)
    modes = sorted(
        {
            str((row.get("metadata") or {}).get("permission_mode"))
            for row in claude
            if (row.get("metadata") or {}).get("permission_mode")
        }
    )
    has_delegation = any(
        (row.get("metadata") or {}).get("delegates_to")
        or any(tool.get("kind") == "delegated_agent" for tool in row.get("tools") or [])
        for row in claude
    )
    has_hooks = any(
        (row.get("metadata") or {}).get("hook_events")
        or (row.get("metadata") or {}).get("hooks_configured")
        or (row.get("metadata") or {}).get("hooks_expression")
        for row in claude
    )
    return {
        "root": bool(claude),
        "framework_agents": len(claude),
        "tool_count": tool_count,
        "mcp": mcp_count > 0,
        "mcp_count": mcp_count,
        "delegation": has_delegation,
        "hooks": has_hooks,
        "permission_modes": modes,
    }


def adjudicate(required: dict, obs: dict) -> list[str]:
    misses: list[str] = []
    for key in ("root", "mcp", "delegation", "hooks"):
        if required.get(key) is True and not obs.get(key):
            misses.append(key)
    min_tools = required.get("min_tools")
    if isinstance(min_tools, int) and int(obs.get("tool_count") or 0) < min_tools:
        misses.append(f"min_tools>={min_tools}")
    required_modes = required.get("permission_mode_any") or []
    if required_modes and not set(required_modes).intersection(obs.get("permission_modes") or []):
        misses.append("permission_mode_any:" + "|".join(required_modes))
    return misses


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = parser.parse_args()

    case = next(item for item in CONFIG["cases"] if item["case_id"] == args.case_id)
    out = args.output_dir / case["case_id"]
    out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=f"horus-claude-{case['case_id']}-") as temp_dir:
        target = clone_case(Path(temp_dir), case)
        application = application_root(target, case)
        pack = source_pack(application)
        (out / "source-pack.txt").write_text(pack, encoding="utf-8")

        scan_path = out / "scan.json"
        run(
            ["horustrace", "scan", str(application), "--format", "json", "--output", str(scan_path), "--fail-on", "none"],
            timeout=1200,
        )
        scan_doc = json.loads(scan_path.read_text(encoding="utf-8"))

        graph_proc = run(["horustrace", "security-graph", str(application)], timeout=1200)
        graph_doc = json.loads(graph_proc.stdout)
        (out / "security-graph.json").write_text(json.dumps(graph_doc, indent=2) + "\n", encoding="utf-8")

        graph, _ = scan(application)
        authority_doc = effective_authority_report(graph)
        (out / "effective-authority.json").write_text(json.dumps(authority_doc, indent=2) + "\n", encoding="utf-8")

        rows = inventory(graph)
        obs = observe(rows)
        misses = adjudicate(case.get("required") or {}, obs)

        findings = scan_doc.get("findings") if isinstance(scan_doc.get("findings"), list) else []
        attack_paths = graph_doc.get("attack_paths") if isinstance(graph_doc.get("attack_paths"), list) else []
        authority_summary = authority_doc.get("summary") if isinstance(authority_doc.get("summary"), dict) else {}

        result = {
            "schema_version": 1,
            "study": CONFIG["study"],
            "case_id": case["case_id"],
            "repo": case["repo"],
            "sha": case["sha"],
            "surface": case["surface"],
            "application_path": case["application_path"],
            "evidence_path": case["evidence_path"],
            "validation_role": case["validation_role"],
            "source_signal": case["source_signal"],
            "required": case.get("required") or {},
            "observed": obs,
            "misses": misses,
            "coarse_status": "pass" if not misses else "miss",
            "source_pack_chars": len(pack),
            "counts": {
                "agents": len(rows),
                "findings": len(findings),
                "attack_paths": len(attack_paths),
                "authority_relationships": int(authority_summary.get("relationships") or 0),
                "partially_resolved_authority": int(authority_summary.get("partially_resolved_relationships") or 0),
                "unknown_authority": int(authority_summary.get("unknown_relationships") or 0),
            },
            "agent_inventory": rows,
            "findings": findings,
            "attack_paths": attack_paths,
            "authority_relationships": authority_doc.get("relationships") or [],
        }
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "case_id": case["case_id"],
            "repo": case["repo"],
            "surface": case["surface"],
            "coarse_status": result["coarse_status"],
            "required": result["required"],
            "observed": obs,
            "misses": misses,
            "counts": result["counts"],
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
