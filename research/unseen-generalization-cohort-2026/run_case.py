from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "cohort.json").read_text(encoding="utf-8"))
EXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".yaml", ".yml", ".toml"}
SKIP = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor", "__pycache__"}
TOK = ("agent", "tool", "mcp", "main", "server", "app", "workflow", "graph", "router", "client")


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 900, check: bool = True):
    p = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError((p.stderr or p.stdout)[-5000:])
    return p


def clone(root: Path, row: dict) -> Path:
    target = root / "target"
    run(["git", "init", "-q", str(target)])
    run(["git", "-C", str(target), "remote", "add", "origin", f"https://github.com/{row['repo']}.git"])
    run(["git", "-C", str(target), "fetch", "--quiet", "--depth=1", "--filter=blob:none", "origin", row["sha"]])
    run(["git", "-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
    got = run(["git", "-C", str(target), "rev-parse", "HEAD"]).stdout.strip()
    if got != row["sha"]:
        raise RuntimeError(f"target SHA mismatch: {got} != {row['sha']}")
    return target


def source_pack(target: Path) -> str:
    files = []
    for p in target.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in EXT:
            continue
        rel = p.relative_to(target)
        if any(part in SKIP for part in rel.parts):
            continue
        score = 300 if any(token in p.name.lower() for token in TOK) else 0
        if "test" in str(rel).lower():
            score -= 40
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size < 14000:
            score += 50
        files.append((-score, str(rel), p))
    out, total = [], 0
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


def parse_json(stdout: str, label: str) -> dict:
    s = stdout.strip()
    start = s.find("{")
    if start < 0:
        raise RuntimeError(f"{label}: no JSON output")
    value, _ = json.JSONDecoder().raw_decode(s[start:])
    if not isinstance(value, dict):
        raise RuntimeError(f"{label}: expected JSON object")
    return value


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = ap.parse_args()
    row = next(x for x in CONFIG["cases"] if x["case_id"] == args.case_id)
    out = args.output_dir / row["case_id"]
    out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=f"horus-unseen-{row['case_id']}-") as td:
        target = clone(Path(td), row)
        pack = source_pack(target)
        (out / "source-pack.txt").write_text(pack, encoding="utf-8")
        scan_path = out / "scan.json"
        scan_proc = run(
            ["horustrace", "scan", str(target), "--format", "json", "--output", str(scan_path), "--fail-on", "none"],
            check=False,
        )
        if not scan_path.exists():
            result = {
                **row,
                "scanner_sha": CONFIG["scanner_baseline_sha"],
                "source_pack_chars": len(pack),
                "scan_status": "error",
                "scan_error": (scan_proc.stderr or scan_proc.stdout)[-8000:],
                "finding_count": None,
                "path_count": None,
                "node_count": None,
                "findings": [],
                "attack_paths": [],
            }
            (out / "result.json").write_text(json.dumps(result, indent=2) + "\\n", encoding="utf-8")
            print(json.dumps({"case_id": row["case_id"], "repo": row["repo"], "family": row["family"], "scan_status": "error"}, indent=2))
            return 0
        scan = json.loads(scan_path.read_text(encoding="utf-8"))

        graph_proc = run(["horustrace", "security-graph", str(target)], check=False)
        if graph_proc.returncode:
            result = {
                **row,
                "scanner_sha": CONFIG["scanner_baseline_sha"],
                "source_pack_chars": len(pack),
                "scan_status": "graph_error",
                "scan_error": (graph_proc.stderr or graph_proc.stdout)[-8000:],
                "finding_count": len(scan.get("findings") or []),
                "path_count": None,
                "node_count": None,
                "findings": [{"index": i, **x} for i, x in enumerate(scan.get("findings") or []) if isinstance(x, dict)],
                "attack_paths": [],
            }
            (out / "result.json").write_text(json.dumps(result, indent=2) + "\\n", encoding="utf-8")
            print(json.dumps({"case_id": row["case_id"], "repo": row["repo"], "family": row["family"], "scan_status": "graph_error"}, indent=2))
            return 0
        graph = parse_json(graph_proc.stdout, "security-graph")
        topology = graph.get("topology") if isinstance(graph.get("topology"), dict) else {}
        nodes = topology.get("nodes") if isinstance(topology.get("nodes"), list) else []
        paths = graph.get("attack_paths") if isinstance(graph.get("attack_paths"), list) else []
        findings = scan.get("findings") if isinstance(scan.get("findings"), list) else []

        (out / "security-graph.json").write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
        result = {
            **row,
            "scanner_sha": CONFIG["scanner_baseline_sha"],
            "source_pack_chars": len(pack),
            "scan_status": "success",
            "scan_error": None,
            "finding_count": len(findings),
            "path_count": len(paths),
            "node_count": len(nodes),
            "findings": [{"index": i, **x} for i, x in enumerate(findings) if isinstance(x, dict)],
            "attack_paths": [{"index": i, **x} for i, x in enumerate(paths) if isinstance(x, dict)],
        }
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({k: result[k] for k in ("case_id", "repo", "family", "finding_count", "path_count", "node_count")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
