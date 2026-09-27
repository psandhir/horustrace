"""Execute the frozen v0.11 deployment-identity cohort.

Targets are fetched at pinned SHAs. Target code is never installed, imported, or
executed. The study invokes HorusTrace repository deployment discovery only.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from horustrace.deployment_discovery import discover_repository_deployment_evidence

SCHEMA_VERSION = 1
CLONE_TIMEOUT = 120


class StudyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RepoPin:
    repo: str
    sha: str
    path: str


@dataclass(frozen=True, slots=True)
class ExpectedRelationship:
    provider: str
    workload_key: str
    identity_key: str
    identity_projection: str | None


@dataclass(frozen=True, slots=True)
class StudyCase:
    case_id: str
    provider: str
    infrastructure: RepoPin
    truth_path: Path


def _load(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise StudyError(f"{path}: cannot load study input") from exc
    if not isinstance(value, dict):
        raise StudyError(f"{path}: expected mapping")
    return value


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StudyError(f"{where}: expected non-empty string")
    return value.strip()


def _repo_pin(value: Any, where: str) -> RepoPin:
    if not isinstance(value, dict):
        raise StudyError(f"{where}: expected mapping")
    repo = _string(value.get("repo"), f"{where}.repo")
    sha = _string(value.get("sha"), f"{where}.sha").lower()
    path = _string(value.get("path", "."), f"{where}.path")
    if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
        raise StudyError(f"{where}.sha: expected full 40-char Git SHA")
    rel = Path(path)
    if rel.is_absolute() or ".." in rel.parts:
        raise StudyError(f"{where}.path: must stay within repository")
    return RepoPin(repo=repo, sha=sha, path=path)


def load_cohort(path: Path) -> list[StudyCase]:
    doc = _load(path)
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise StudyError(f"{path}: schema_version must be {SCHEMA_VERSION}")
    if doc.get("study") != "deployment-identity-v011":
        raise StudyError(f"{path}: unexpected study")
    if doc.get("frozen") is not True:
        raise StudyError(f"{path}: cohort must be frozen before execution")
    if doc.get("horustrace_results_used_for_selection") is not False:
        raise StudyError(f"{path}: selection must be independent of HorusTrace results")
    raw_cases = doc.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise StudyError(f"{path}: cases must be non-empty")

    root = path.parent
    result: list[StudyCase] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_cases):
        where = f"cases[{index}]"
        if not isinstance(raw, dict):
            raise StudyError(f"{where}: expected mapping")
        case_id = _string(raw.get("case_id"), f"{where}.case_id")
        if case_id in seen:
            raise StudyError(f"{where}.case_id: duplicate {case_id}")
        seen.add(case_id)
        provider = _string(raw.get("provider"), f"{where}.provider").lower()
        if provider not in {"gcp", "aws", "azure", "kubernetes"}:
            raise StudyError(f"{where}.provider: unsupported provider")
        infrastructure = _repo_pin(raw.get("infrastructure"), f"{where}.infrastructure")
        truth_rel = Path(_string(raw.get("truth"), f"{where}.truth"))
        if truth_rel.is_absolute() or ".." in truth_rel.parts:
            raise StudyError(f"{where}.truth: unsafe path")
        truth_path = root / truth_rel
        if not truth_path.is_file():
            raise StudyError(f"{where}.truth: missing {truth_rel}")
        result.append(StudyCase(case_id, provider, infrastructure, truth_path))
    return result


def load_truth(path: Path, case: StudyCase) -> list[ExpectedRelationship]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise StudyError(f"{path}: schema_version must be {SCHEMA_VERSION}")
    if doc.get("case_id") != case.case_id:
        raise StudyError(f"{path}: case_id mismatch")
    if doc.get("provider") != case.provider:
        raise StudyError(f"{path}: provider mismatch")
    if doc.get("reviewed") is not True:
        raise StudyError(f"{path}: reviewed must be true")
    if doc.get("horustrace_results_seen") is not False:
        raise StudyError(f"{path}: truth must be locked before HorusTrace output is seen")
    raw = doc.get("relationships")
    if not isinstance(raw, list) or not raw:
        raise StudyError(f"{path}: relationships must be non-empty")
    result: list[ExpectedRelationship] = []
    for index, item in enumerate(raw):
        where = f"{path}: relationships[{index}]"
        if not isinstance(item, dict):
            raise StudyError(f"{where}: expected mapping")
        result.append(
            ExpectedRelationship(
                provider=case.provider,
                workload_key=_string(item.get("workload_key"), f"{where}.workload_key"),
                identity_key=_string(item.get("identity_key"), f"{where}.identity_key"),
                identity_projection=(
                    _string(item.get("identity_projection"), f"{where}.identity_projection")
                    if item.get("identity_projection") is not None
                    else None
                ),
            )
        )
    return result


def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, env=env)


def fetch_pinned_repo(root: Path, pin: RepoPin) -> Path:
    target = root / "repo"
    target.mkdir(parents=True, exist_ok=True)
    commands = [
        ["git", "init", "-q", str(target)],
        ["git", "-C", str(target), "remote", "add", "origin", f"https://github.com/{pin.repo}.git"],
        ["git", "-C", str(target), "fetch", "--quiet", "--depth=1", "--filter=blob:none", "origin", pin.sha],
        ["git", "-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
    ]
    for command in commands:
        result = _run(command, CLONE_TIMEOUT)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-3000:]
            raise StudyError(f"{pin.repo}@{pin.sha}: fetch failed: {detail}")
    selected = target / pin.path
    if not selected.exists():
        raise StudyError(f"{pin.repo}@{pin.sha}: path missing: {pin.path}")
    return selected


def _observed_relationships(provider: str, source: Path) -> list[tuple[str, str]]:
    discovery = discover_repository_deployment_evidence(source)
    bundles = [bundle for bundle in discovery.bundles if bundle.provider == provider]
    if len(bundles) > 1:
        raise StudyError(f"{source}: duplicate provider bundles for {provider}")
    if not bundles:
        return []
    bundle = bundles[0]
    return sorted((item.workload_id, item.identity) for item in bundle.workloads)


def _expected_key(item: ExpectedRelationship) -> tuple[str, str]:
    return item.workload_key, item.identity_key


def score_case(case: StudyCase, truth: list[ExpectedRelationship], observed: list[tuple[str, str]]) -> dict[str, Any]:
    expected = Counter(_expected_key(item) for item in truth)
    predicted = Counter(observed)
    matched = expected & predicted
    missing = expected - predicted
    extra = predicted - expected

    def rows(counter: Counter[tuple[str, str]]) -> list[dict[str, str]]:
        return [
            {"workload_key": workload, "identity_key": identity}
            for (workload, identity), count in sorted(counter.items())
            for _ in range(count)
        ]

    return {
        "case_id": case.case_id,
        "provider": case.provider,
        "expected": sum(expected.values()),
        "predicted": sum(predicted.values()),
        "tp": sum(matched.values()),
        "fn": sum(missing.values()),
        "fp": sum(extra.values()),
        "matched": rows(matched),
        "missing": rows(missing),
        "extra": rows(extra),
    }


def aggregate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(item["tp"] for item in cases)
    fp = sum(item["fp"] for item in cases)
    fn = sum(item["fn"] for item in cases)

    def ratio(num: int, den: int) -> float | None:
        return round(num / den, 4) if den else None

    providers: dict[str, dict[str, Any]] = {}
    for provider in ("gcp", "aws", "azure", "kubernetes"):
        rows = [item for item in cases if item["provider"] == provider]
        p_tp = sum(item["tp"] for item in rows)
        p_fp = sum(item["fp"] for item in rows)
        p_fn = sum(item["fn"] for item in rows)
        if rows:
            providers[provider] = {
                "cases": len(rows),
                "tp": p_tp,
                "fp": p_fp,
                "fn": p_fn,
                "precision": ratio(p_tp, p_tp + p_fp),
                "recall": ratio(p_tp, p_tp + p_fn),
            }
    return {
        "schema_version": 1,
        "study": "deployment-identity-v011",
        "summary": {
            "cases": len(cases),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn),
            "acceptance_recall": 0.90,
            "recall_gate_passed": bool(tp + fn) and tp / (tp + fn) >= 0.90,
        },
        "providers": providers,
        "cases": cases,
        "runtime_effectiveness": "not_verified",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cohort", type=Path, default=Path("research/deployment-identity-v011/cohort.yaml"))
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    cases = load_cohort(args.cohort)
    truths = {case.case_id: load_truth(case.truth_path, case) for case in cases}
    if args.validate_only:
        print(json.dumps({"valid": True, "cases": len(cases)}, indent=2))
        return 0

    workspace = Path(tempfile.mkdtemp(prefix="horustrace-v011-deployment-identity-"))
    try:
        results = []
        for case in cases:
            source = fetch_pinned_repo(workspace / case.case_id, case.infrastructure)
            observed = _observed_relationships(case.provider, source)
            results.append(score_case(case, truths[case.case_id], observed))
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    report = aggregate(results)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
