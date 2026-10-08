from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import traceback
from pathlib import Path

from horustrace.authority_contract import authority_contract_report
from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "cohort.json").read_text(encoding="utf-8"))

EXT = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".cs", ".json", ".yaml", ".yml",
    ".toml", ".tf", ".hcl", ".md", ".xml", ".csproj", ".props", ".targets",
}
SKIP = {
    ".git", "node_modules", ".venv", "venv", "dist", "build", "vendor",
    "__pycache__", "bin", "obj", ".terraform", ".next",
}
TOKENS = (
    "agent", "tool", "mcp", "callback", "plugin", "skill", "a2a", "auth",
    "identity", "resource", "main", "app", "config", "workflow", "guard",
    "policy", "permission",
)


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if proc.returncode:
        raise RuntimeError((proc.stderr or proc.stdout)[-16000:])
    return proc


def clone_case(root: Path, case: dict) -> Path:
    target = root / "target"
    run(["git", "init", "-q", str(target)])
    run(["git", "-C", str(target), "remote", "add", "origin", f"https://github.com/{case['repo']}.git"])
    run(
        [
            "git", "-C", str(target), "fetch", "--quiet", "--depth=1",
            "--filter=blob:none", "origin", case["sha"],
        ],
        timeout=1800,
    )
    run(["git", "-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
    got = run(["git", "-C", str(target), "rev-parse", "HEAD"]).stdout.strip()
    if got != case["sha"]:
        raise RuntimeError(f"target SHA mismatch: {got} != {case['sha']}")
    return target


def application_root(target: Path, case: dict) -> Path:
    raw = case.get("application_path") or "."
    root = (target / raw).resolve()
    try:
        root.relative_to(target.resolve())
    except ValueError as exc:
        raise RuntimeError(f"application_path escapes repository: {raw}") from exc
    if not root.exists():
        raise RuntimeError(f"application_path does not exist: {raw}")
    return root


def source_pack(application: Path, case: dict) -> str:
    files: list[tuple[int, str, Path]] = []
    base = application if application.is_dir() else application.parent
    evidence = case.get("evidence_path")

    for path in base.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in EXT:
            continue
        rel = path.relative_to(base)
        if any(part in SKIP for part in rel.parts):
            continue
        score = 0
        if evidence and str(rel).replace("\\", "/").endswith(str(evidence).replace("\\", "/")):
            score += 1000
        if any(token in path.name.lower() for token in TOKENS):
            score += 300
        if "test" in str(rel).lower():
            score -= 100
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size < 32000:
            score += 50
        files.append((-score, str(rel), path))

    out: list[str] = []
    total = 0
    for _, rel, path in sorted(files):
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        if len(text) > 32000:
            text = text[:32000] + "\n...[truncated]..."
        chunk = f"\n===== FILE: {rel} =====\n{text}\n"
        if total + len(chunk) > 240000:
            continue
        out.append(chunk)
        total += len(chunk)
    return "".join(out)


def location_dict(value) -> dict | None:
    if value is None:
        return None
    return {
        "path": str(getattr(value, "path", "")),
        "line": getattr(value, "line", None),
        "column": getattr(value, "column", None),
    }


def agent_inventory(graph) -> list[dict]:
    rows: list[dict] = []
    for agent in graph.agents:
        rows.append(
            {
                "name": agent.name,
                "framework": (getattr(agent, "metadata", {}) or {}).get("framework"),
                "location": location_dict(getattr(agent, "location", None)),
                "metadata": getattr(agent, "metadata", {}) or {},
                "capabilities": sorted(getattr(agent, "capabilities", set()) or []),
                "tools": [
                    {
                        "name": tool.name,
                        "kind": getattr(tool, "kind", None),
                        "capabilities": sorted(getattr(tool, "capabilities", set()) or []),
                        "approval": getattr(tool, "approval", None),
                        "destinations": [
                            getattr(item, "target", None)
                            for item in (getattr(tool, "destinations", []) or [])
                        ],
                        "metadata": getattr(tool, "metadata", {}) or {},
                    }
                    for tool in (getattr(agent, "tools", []) or [])
                ],
                "mcp_servers": [
                    {
                        "name": server.name,
                        "transport": getattr(server, "transport", None),
                        "url": getattr(server, "url", None),
                        "command": getattr(server, "command", None),
                        "authenticated": getattr(server, "authenticated", None),
                        "allowed_tools": list(getattr(server, "allowed_tools", []) or []),
                        "denied_tools": list(getattr(server, "denied_tools", []) or []),
                        "metadata": getattr(server, "metadata", {}) or {},
                    }
                    for server in (getattr(agent, "mcp_servers", []) or [])
                ],
                "skills": [
                    {
                        "name": skill.name,
                        "description": getattr(skill, "description", None),
                        "allowed_tools": sorted(getattr(skill, "allowed_tools", set()) or []),
                        "scripts": list(getattr(skill, "scripts", []) or []),
                        "capabilities": sorted(getattr(skill, "capabilities", set()) or []),
                        "destinations": [
                            getattr(item, "target", None)
                            for item in (getattr(skill, "destinations", []) or [])
                        ],
                        "metadata": getattr(skill, "metadata", {}) or {},
                    }
                    for skill in (getattr(agent, "skills", []) or [])
                ],
                "identities": [
                    {
                        "name": identity.name,
                        "provider": getattr(identity, "provider", None),
                        "credential_source": getattr(identity, "credential_source", None),
                        "metadata": getattr(identity, "metadata", {}) or {},
                    }
                    for identity in (getattr(agent, "identities", []) or [])
                ],
            }
        )
    return rows


def diagnostic_inventory(graph) -> list[dict]:
    rows = []
    for item in getattr(getattr(graph, "coverage", None), "diagnostics", []) or []:
        rows.append(
            {
                "kind": getattr(item, "kind", None),
                "message": getattr(item, "message", None),
                "incomplete": getattr(item, "incomplete", None),
                "location": location_dict(getattr(item, "location", None)),
                "details": getattr(item, "details", {}) or {},
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = parser.parse_args()

    case = next(item for item in CONFIG["cases"] if item["case_id"] == args.case_id)
    out = args.output_dir / case["case_id"]
    out.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory(prefix=f"horus-ff60-{case['case_id']}-") as temp_dir:
            target = clone_case(Path(temp_dir), case)
            application = application_root(target, case)

            pack = source_pack(application, case)
            (out / "source-pack.txt").write_text(pack, encoding="utf-8")

            scan_path = out / "scan.json"
            run(
                [
                    "horustrace", "scan", str(application), "--format", "json",
                    "--output", str(scan_path), "--fail-on", "none",
                ],
                timeout=1800,
            )
            scan_doc = json.loads(scan_path.read_text(encoding="utf-8"))

            graph_proc = run(["horustrace", "security-graph", str(application)], timeout=1800)
            graph_doc = json.loads(graph_proc.stdout)
            (out / "security-graph.json").write_text(
                json.dumps(graph_doc, indent=2, default=str) + "\n", encoding="utf-8"
            )

            graph, _ = scan(application)
            authority_doc = effective_authority_report(graph)
            (out / "effective-authority.json").write_text(
                json.dumps(authority_doc, indent=2, default=str) + "\n", encoding="utf-8"
            )

            contract_doc = authority_contract_report(graph)
            (out / "authority-contract.json").write_text(
                json.dumps(contract_doc, indent=2, default=str) + "\n", encoding="utf-8"
            )

            findings = scan_doc.get("findings") if isinstance(scan_doc.get("findings"), list) else []
            paths = graph_doc.get("attack_paths") if isinstance(graph_doc.get("attack_paths"), list) else []
            scan_summary = scan_doc.get("summary") if isinstance(scan_doc.get("summary"), dict) else {}
            authority_summary = authority_doc.get("summary") if isinstance(authority_doc.get("summary"), dict) else {}
            inventory = agent_inventory(graph)
            diagnostics = diagnostic_inventory(graph)

            result = {
                "schema_version": 1,
                "study": CONFIG["study"],
                "scanner_baseline": CONFIG.get("scanner_baseline"),
                "case_id": case["case_id"],
                "framework": case["framework"],
                "repo": case["repo"],
                "sha": case["sha"],
                "application_path": case.get("application_path"),
                "evidence_path": case.get("evidence_path"),
                "surface": case.get("surface"),
                "source_signal": case.get("source_signal"),
                "provenance_case_id": case.get("provenance_case_id"),
                "source_pack_chars": len(pack),
                "counts": {
                    "agents": int(scan_summary.get("agents") or len(inventory)),
                    "findings": len(findings),
                    "attack_paths": len(paths),
                    "authority_relationships": int(authority_summary.get("relationships") or len(authority_doc.get("relationships") or [])),
                    "partially_resolved_authority": int(authority_summary.get("partially_resolved_relationships") or 0),
                    "unknown_authority": int(authority_summary.get("unknown_relationships") or 0),
                    "diagnostics": len(diagnostics),
                    "unbound_skills": len(getattr(graph, "unbound_skills", []) or []),
                },
                "agent_inventory": inventory,
                "unbound_skills": [
                    {
                        "name": item.name,
                        "description": getattr(item, "description", None),
                        "allowed_tools": sorted(getattr(item, "allowed_tools", set()) or []),
                        "scripts": list(getattr(item, "scripts", []) or []),
                        "metadata": getattr(item, "metadata", {}) or {},
                    }
                    for item in (getattr(graph, "unbound_skills", []) or [])
                ],
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
                "authority_contract": contract_doc,
                "assurance": scan_doc.get("assurance"),
                "coverage_diagnostics": diagnostics,
            }
            (out / "result.json").write_text(
                json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
            )
            print(json.dumps({"status": "ok", "case_id": case["case_id"], "framework": case["framework"], **result["counts"]}, indent=2))
        return 0
    except Exception as exc:
        failure = {
            "schema_version": 1,
            "study": CONFIG["study"],
            "case_id": case["case_id"],
            "framework": case["framework"],
            "repo": case["repo"],
            "sha": case["sha"],
            "status": "error",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }
        (out / "error.json").write_text(json.dumps(failure, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(failure, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
