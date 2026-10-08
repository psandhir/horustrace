"""Collect source-only review packets from the 180 historical, pinned Git SHAs.

No scanner output is read. No target application source is imported or executed.
LangGraph is deliberately omitted because framework support was deprecated.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from scripts.real_world_agent_security_execute import fetch_case

SKIP = {
    ".git", ".venv", "venv", "__pycache__", ".tox", "site-packages",
    "node_modules", ".next", "dist", "build", "vendor", "generated",
}
EXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cs", ".go", ".java",
       ".yaml", ".yml", ".toml", ".json", ".md", ".mdx", ".ipynb", ".sh", ".tf"}
MAX_CHARS = 320000
MAX_FILES = 180
MAX_SINGLE_FILE = 85000
ROOT = Path("research/real-world-agent-security-2026")


def _candidate_files(scope: Path, application: Path) -> list[Path]:
    if scope.is_file():
        return [scope]
    selected: list[Path] = []
    for root, folders, filenames in os.walk(scope, followlinks=False):
        folders[:] = [
            folder for folder in folders
            if folder not in SKIP and not folder.startswith(".")
            and not (Path(root) / folder).is_symlink()
        ]
        for name in filenames:
            path = Path(root) / name
            if (path.suffix.lower() in EXT and not name.startswith(".")
                    and not path.is_symlink()):
                selected.append(path)
    # The original frozen application entrypoint is always first. In large
    # codebases, path sorting must never consume the budget before that file.
    # No scanner signal informs file selection.
    return sorted(
        selected,
        key=lambda p: (p != application, p.suffix.lower() in {".md", ".mdx"}, str(p)),
    )[:MAX_FILES]


def source_case(case: dict, workspace: Path, out: Path, tier_c: bool) -> dict:
    case_id = case["case_id"]
    target_root = workspace / case_id
    scope, _authority, error = fetch_case(workspace, case, tier_c=tier_c)
    record = {
        "case_id": case_id, "repo": case["repo"], "sha": case["sha"],
        "framework": case["framework_stratum"],
        "application_path": case["application_path"], "source_output_seen": False,
        "source_scope": case["application_path"], "status": "failed" if error else "ok",
        "error": error, "source_coverage": "insufficient",
    }
    if error or scope is None:
        return record
    application = target_root / case["application_path"]
    files = _candidate_files(scope, application)
    sections = []
    file_info = []
    remaining = MAX_CHARS
    omitted = 0
    for path in files:
        if remaining <= 0:
            omitted += 1
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            omitted += 1
            continue
        relative = path.relative_to(target_root).as_posix()
        # A bounded source packet is always considered qualified, never
        # independently evidence-complete when not every relevant file is known.
        allowed = min(len(body), remaining, MAX_SINGLE_FILE)
        snippet = body[:allowed]
        sections.append(f"===== SOURCE FILE: {relative} =====\n" + "\n".join(
            f"{i:06d}: {line}" for i, line in enumerate(snippet.splitlines(), 1)))
        file_info.append({"path": relative, "original_chars": len(body),
                          "supplied_chars": allowed, "truncated": allowed < len(body),
                          "full_source_sha256": hashlib.sha256(body.encode()).hexdigest()})
        remaining -= allowed
        if allowed < len(body):
            omitted += 1
    if scope.is_dir() and len(files) == MAX_FILES:
        omitted += 1
    application_included = (
        any(item["path"] == case["application_path"] for item in file_info)
        if application.is_file() else (
            any(item["path"].startswith(case["application_path"].rstrip("/") + "/")
                for item in file_info)
        )
    )
    if not application_included:
        omitted += 1
    folder = out / case_id
    folder.mkdir(parents=True, exist_ok=True)
    text = "\n\n".join(sections)
    (folder / "source-only.txt").write_text(text, encoding="utf-8")
    record.update({
        "source_chars": len(text), "source_pack_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "file_count": len(file_info), "files": file_info, "omitted_or_truncated": omitted,
        "application_entrypoint_included": application_included,
        "source_coverage": "qualified" if text and application_included else "insufficient",
    })
    (folder / "source-manifest.json").write_text(json.dumps(record, indent=2) + "\n",
                                                  encoding="utf-8")
    return record


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--workers", type=int, default=6)
    args = p.parse_args()
    frozen = json.loads((ROOT / "cohort.json").read_text())
    if not (frozen.get("cohort_frozen") and frozen.get("ground_truth_locked")
            and len(frozen["cases"]) == 180):
        raise SystemExit("historical cohort is not the locked frozen 180")
    cases = [c for c in frozen["cases"] if c["framework_stratum"] != "langgraph"]
    if len(cases) != 145:
        raise SystemExit(f"unexpected active cohort count: {len(cases)}")
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="horusscan-source-only-"))
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(args.workers, 8))) as exe:
            futures = {exe.submit(source_case, c, work, out,
                                  c["case_id"] in frozen["tier_c_case_ids"]): c
                       for c in cases}
            records = []
            for future in concurrent.futures.as_completed(futures):
                try:
                    records.append(future.result())
                except Exception as exc:  # noqa: BLE001 - isolate per-repository fetch failures
                    c = futures[future]
                    records.append({"case_id": c["case_id"], "repo": c["repo"],
                                    "sha": c["sha"], "framework": c["framework_stratum"],
                                    "status": "failed", "error": str(exc),
                                    "source_coverage": "insufficient"})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    records.sort(key=lambda c: c["case_id"])
    manifest = {
        "schema_version": 1, "type": "scanner_blind_source_packet",
        "historical_cohort": frozen["study"],
        "deprecated_langgraph_excluded": 35,
        "active_cases": len(cases),
        "case_statuses": dict(Counter(r.get("status") for r in records)),
        "review_status": "not_started",
        "independent_judges": [],
        "model_prompt_hash": None,
        "source_pack_limit_chars": MAX_CHARS,
        "cases": records,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                        encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in
                      ("active_cases", "case_statuses", "review_status")}))
    return 0 if manifest["case_statuses"].get("ok") == len(cases) else 2


if __name__ == "__main__":
    raise SystemExit(main())
