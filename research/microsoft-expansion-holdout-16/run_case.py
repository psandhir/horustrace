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
EXT = {".py", ".cs", ".json", ".yaml", ".yml", ".toml", ".csproj"}
SKIP = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor", "__pycache__", "bin", "obj"}
TOKENS = ("agent", "tool", "mcp", "auth", "identity", "workflow", "copilot", "program", "main", "manifest")


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 900,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if proc.returncode:
        raise RuntimeError((proc.stderr or proc.stdout)[-8000:])
    return proc


def clone_case(root: Path, case: dict) -> Path:
    target = root / "target"
    run(["git", "init", "-q", str(target)])
    run(
        [
            "git",
            "-C",
            str(target),
            "remote",
            "add",
            "origin",
            f"https://github.com/{case['repo']}.git",
        ]
    )
    run(
        [
            "git",
            "-C",
            str(target),
            "fetch",
            "--quiet",
            "--depth=1",
            "--filter=blob:none",
            "origin",
            case["sha"],
        ],
        timeout=1200,
    )
    run(
        [
            "git",
            "-C",
            str(target),
            "checkout",
            "--quiet",
            "--detach",
            "FETCH_HEAD",
        ]
    )
    got = run(["git", "-C", str(target), "rev-parse", "HEAD"]).stdout.strip()
    if got != case["sha"]:
        raise RuntimeError(f"target SHA mismatch: {got} != {case['sha']}")
    return target


def application_root(target: Path, case: dict) -> Path:
    root = target / case["application_path"]
    if not root.exists():
        raise RuntimeError(
            f"application_path does not exist: {case['application_path']}"
        )
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
            score -= 100
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size < 18000:
            score += 50
        files.append((-score, str(rel), path))

    out: list[str] = []
    total = 0
    for _, rel, path in sorted(files):
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        if len(text) > 18000:
            text = text[:18000] + "\n...[truncated]..."
        chunk = f"\n===== FILE: {rel} =====\n{text}\n"
        if total + len(chunk) > 100000:
            continue
        out.append(chunk)
        total += len(chunk)
    return "".join(out)


def agent_inventory(graph) -> list[dict]:
    rows: list[dict] = []
    for agent in graph.agents:
        rows.append(
            {
                "name": agent.name,
                "framework": (getattr(agent, "metadata", {}) or {}).get("framework"),
                "capabilities": sorted(getattr(agent, "capabilities", set()) or []),
                "tools": [tool.name for tool in getattr(agent, "tools", []) or []],
                "mcp_servers": [
                    server.name for server in getattr(agent, "mcp_servers", []) or []
                ],
                "identities": [
                    identity.name for identity in getattr(agent, "identities", []) or []
                ],
            }
        )
    return rows


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

    with tempfile.TemporaryDirectory(
        prefix=f"horus-msx-{case['case_id']}-"
    ) as temp_dir:
        target = clone_case(Path(temp_dir), case)
        application = application_root(target, case)

        pack = source_pack(application)
        (out / "source-pack.txt").write_text(pack, encoding="utf-8")

        scan_path = out / "scan.json"
        run(
            [
                "horustrace",
                "scan",
                str(application),
                "--format",
                "json",
                "--output",
                str(scan_path),
                "--fail-on",
                "none",
            ],
            timeout=1200,
        )
        scan_doc = json.loads(scan_path.read_text(encoding="utf-8"))

        graph_proc = run(
            ["horustrace", "security-graph", str(application)],
            timeout=1200,
        )
        graph_doc = json.loads(graph_proc.stdout)
        (out / "security-graph.json").write_text(
            json.dumps(graph_doc, indent=2) + "\n",
            encoding="utf-8",
        )

        graph, _ = scan(application)
        authority_doc = effective_authority_report(graph)
        (out / "effective-authority.json").write_text(
            json.dumps(authority_doc, indent=2) + "\n",
            encoding="utf-8",
        )

        findings = (
            scan_doc.get("findings")
            if isinstance(scan_doc.get("findings"), list)
            else []
        )
        paths = (
            graph_doc.get("attack_paths")
            if isinstance(graph_doc.get("attack_paths"), list)
            else []
        )
        scan_summary = (
            scan_doc.get("summary")
            if isinstance(scan_doc.get("summary"), dict)
            else {}
        )
        authority_summary = (
            authority_doc.get("summary")
            if isinstance(authority_doc.get("summary"), dict)
            else {}
        )
        inventory = agent_inventory(graph)

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
            "source_pack_chars": len(pack),
            "counts": {
                "agents": int(scan_summary.get("agents") or len(inventory)),
                "findings": len(findings),
                "attack_paths": len(paths),
                "authority_relationships": int(
                    authority_summary.get("relationships") or 0
                ),
                "partially_resolved_authority": int(
                    authority_summary.get("partially_resolved_relationships") or 0
                ),
                "unknown_authority": int(
                    authority_summary.get("unknown_relationships") or 0
                ),
            },
            "agent_inventory": inventory,
            "findings": [
                {"index": index, **item}
                for index, item in enumerate(findings)
                if isinstance(item, dict)
            ],
            "attack_paths": [
                {"index": index, **item}
                for index, item in enumerate(paths)
                if isinstance(item, dict)
            ],
            "authority_relationships": authority_doc.get("relationships") or [],
        }
        (out / "result.json").write_text(
            json.dumps(result, indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    "case_id": case["case_id"],
                    "surface": case["surface"],
                    "agents": [item["name"] for item in inventory],
                    **result["counts"],
                },
                indent=2,
            )
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
