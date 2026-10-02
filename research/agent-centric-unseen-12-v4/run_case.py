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
EXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".yaml", ".yml", ".toml"}
SKIP = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor", "__pycache__"}
TOKENS = ("agent", "tool", "mcp", "server", "workflow", "router", "client", "main")


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout)[-5000:])
    return p


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


def source_pack(target: Path) -> str:
    files: list[tuple[int, str, Path]] = []
    for p in target.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in EXT:
            continue
        rel = p.relative_to(target)
        if any(part in SKIP for part in rel.parts):
            continue
        score = 300 if any(token in p.name.lower() for token in TOKENS) else 0
        if "test" in str(rel).lower():
            score -= 50
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size < 14000:
            score += 50
        files.append((-score, str(rel), p))
    out: list[str] = []
    total = 0
    for _, rel, p in sorted(files):
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            continue
        if len(text) > 14000:
            text = text[:14000] + "\n...[truncated]..."
        chunk = f"\n===== FILE: {rel} =====\n{text}\n"
        if total + len(chunk) > 65000:
            continue
        out.append(chunk)
        total += len(chunk)
    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = ap.parse_args()
    case = next(c for c in CONFIG["cases"] if c["case_id"] == args.case_id)
    out = args.output_dir / case["case_id"]
    out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=f"horus-agent-unseen4-{case['case_id']}-") as td:
        target = clone_case(Path(td), case)
        pack = source_pack(target)
        (out / "source-pack.txt").write_text(pack, encoding="utf-8")

        scan_path = out / "scan.json"
        run(["horustrace", "scan", str(target), "--format", "json", "--output", str(scan_path), "--fail-on", "none"])
        scan_doc = json.loads(scan_path.read_text(encoding="utf-8"))

        graph_cp = run(["horustrace", "security-graph", str(target)])
        graph_doc = json.loads(graph_cp.stdout)
        (out / "security-graph.json").write_text(json.dumps(graph_doc, indent=2) + "\n", encoding="utf-8")

        graph, _ = scan(target)
        authority_doc = effective_authority_report(graph)
        (out / "effective-authority.json").write_text(
            json.dumps(authority_doc, indent=2) + "\n", encoding="utf-8"
        )

        findings = scan_doc.get("findings") if isinstance(scan_doc.get("findings"), list) else []
        paths = graph_doc.get("attack_paths") if isinstance(graph_doc.get("attack_paths"), list) else []
        summary = scan_doc.get("summary") if isinstance(scan_doc.get("summary"), dict) else {}
        authority_summary = authority_doc.get("summary") if isinstance(authority_doc.get("summary"), dict) else {}
        result = {
            "schema_version": 1,
            "case_id": case["case_id"],
            "repo": case["repo"],
            "sha": case["sha"],
            "framework": case["framework"],
            "evidence_path": case.get("evidence_path"),
            "source_pack_chars": len(pack),
            "counts": {
                "agents": int(summary.get("agents") or 0),
                "findings": len(findings),
                "attack_paths": len(paths),
                "authority_relationships": int(authority_summary.get("relationships") or 0),
                "partially_resolved_authority": int(authority_summary.get("partially_resolved_relationships") or 0),
                "unknown_authority": int(authority_summary.get("unknown_relationships") or 0)
            },
            "findings": [{"index": i, **x} for i, x in enumerate(findings) if isinstance(x, dict)],
            "attack_paths": [{"index": i, **x} for i, x in enumerate(paths) if isinstance(x, dict)],
            "authority_relationships": authority_doc.get("relationships") or [],
        }
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"case_id": case["case_id"], **result["counts"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
