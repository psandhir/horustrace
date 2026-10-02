from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "cohort.json").read_text(encoding="utf-8"))
EXT = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".yaml", ".yml",
    ".toml", ".tf", ".md",
}
SKIP = {
    ".git", "node_modules", ".venv", "venv", "dist", "build", "vendor",
    "__pycache__", ".next", "site-packages",
}
TOKENS = (
    "agent", "tool", "mcp", "server", "workflow", "runner", "handoff",
    "guardrail", "approval", "policy", "security", "client", "main",
)


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if proc.returncode:
        raise RuntimeError((proc.stderr or proc.stdout)[-5000:])
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


def candidate_files(target: Path, evidence_path: str | None) -> list[tuple[int, str, Path, int]]:
    files: list[tuple[int, str, Path, int]] = []
    for path in target.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in EXT:
            continue
        rel = path.relative_to(target)
        if any(part in SKIP for part in rel.parts):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        rel_text = rel.as_posix()
        score = 0
        if evidence_path and rel_text == evidence_path:
            score += 2000
        name = path.name.lower()
        score += 250 * sum(token in name for token in TOKENS)
        lower = rel_text.lower()
        if any(token in lower for token in ("agent", "tool", "mcp", "security", "guardrail", "workflow")):
            score += 350
        if path.suffix.lower() == ".py":
            score += 150
        if "test" in lower or "example" in lower:
            score -= 40
        if size <= 18000:
            score += 50
        files.append((-score, rel_text, path, size))
    return sorted(files)


def source_pack(target: Path, evidence_path: str | None) -> tuple[str, list[dict[str, object]]]:
    ranked = candidate_files(target, evidence_path)
    manifest = [
        {"path": rel, "size": size, "priority": -score}
        for score, rel, _path, size in ranked
    ]
    chunks: list[str] = []
    total = 0
    budget = 120_000
    per_file = 20_000
    for _score, rel, path, _size in ranked:
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        if len(text) > per_file:
            text = text[:per_file] + "\n...[truncated]..."
        chunk = f"\n===== FILE: {rel} =====\n{text}\n"
        if total + len(chunk) > budget:
            continue
        chunks.append(chunk)
        total += len(chunk)
    return "".join(chunks), manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = parser.parse_args()

    case = next(item for item in CONFIG["cases"] if item["case_id"] == args.case_id)
    out = args.output_dir / case["case_id"]
    out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix=f"horus-source-{case['case_id']}-") as temp:
        target = clone_case(Path(temp), case)
        pack, files = source_pack(target, case.get("evidence_path"))
        (out / "source-pack.txt").write_text(pack, encoding="utf-8")
        manifest = {
            "schema_version": 1,
            "case_id": case["case_id"],
            "repo": case["repo"],
            "sha": case["sha"],
            "framework": case["framework"],
            "evidence_path": case.get("evidence_path"),
            "selection_basis": case.get("selection_basis") or [],
            "source_pack_chars": len(pack),
            "files": files,
            "horustrace_executed": False,
        }
        (out / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({
            "case_id": case["case_id"],
            "repo": case["repo"],
            "source_pack_chars": len(pack),
            "files": len(files),
            "horustrace_executed": False,
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
