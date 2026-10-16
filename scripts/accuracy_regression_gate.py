"""Fail-closed same-head Fresh-16/Full-60 gate for protected scanner changes.

Runs for every pull request. Pure validators are exercised by negative tests.
This action is not a substitute for repository-admin branch protection.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

FRESH_WORKFLOW = "fresh16-source-claim-regression.yml"
FULL_WORKFLOW = "full-framework-60-post-remediation-20261006.yml"
MAX_WAIT_SECONDS = 85 * 60
POLL_SECONDS = 45
RISK_PREFIXES = (
    "src/horustrace/",
    "research/fresh-unseen-generalization-20/",
    "research/source-claim-regression/",
    "research/full-framework-60-20261005/",
    "research/full-framework-60-post-remediation-20261006/",
)
RISK_FILES = {
    ".github/workflows/accuracy-regression-gate.yml",
    ".github/workflows/fresh16-source-claim-regression.yml",
    ".github/workflows/full-framework-60-post-remediation-20261006.yml",
    "scripts/accuracy_regression_gate.py",
    "scripts/pipeline_integrity_study.py",
    "scripts/source_claim_regression_gate.py",
    "tests/test_accuracy_ci_gate_contract.py",
    "tests/test_accuracy_regression_gate.py",
}
FROZEN_BLOBS = {
    "research/fresh-unseen-generalization-20/cohort.json":
        "8526378a3c54d6ae74bab9b3982e8303fb14bce7",
    "research/full-framework-60-20261005/cohort.json":
        "1ea88dbb611cb7c0a81d5b8717553ef539cbdd49",
    "research/source-claim-regression/postmerge-fresh16-claims.json":
        "0273281887b4d9130bc6f6eaceef7eabf134d8c5",
}


class GateError(ValueError):
    """A missing, mismatched or failed security gate."""


def needs_accuracy_cohorts(changed_files: list[str]) -> bool:
    if not changed_files:
        raise GateError("missing PR file list")
    if len(changed_files) != len(set(changed_files)):
        raise GateError("duplicate PR paths")
    return any(
        path in RISK_FILES or any(path.startswith(prefix) for prefix in RISK_PREFIXES)
        for path in changed_files
    )


def expected_cases(root: Path) -> dict[str, set[str]]:
    """Read exact checked-out frozen manifests, verifying immutable git blobs."""
    for name, blob in FROZEN_BLOBS.items():
        payload = (root / name).read_bytes()
        actual = hashlib.sha1(
            b"blob " + str(len(payload)).encode() + b"\0" + payload
        ).hexdigest()
        if actual != blob:
            raise GateError(f"frozen source manifest changed: {name}")
    fresh = json.loads(
        (root / "research/fresh-unseen-generalization-20/cohort.json").read_text()
    )
    full = json.loads(
        (root / "research/full-framework-60-20261005/cohort.json").read_text()
    )
    f = [c["case_id"] for c in fresh["cases"] if c["framework"] != "langgraph"]
    g = [c["case_id"] for c in full["cases"]]
    if len(f) != 16 or len(set(f)) != 16 or len(g) != 60 or len(set(g)) != 60:
        raise GateError("frozen 16/60 cohort missing/duplicate/modified")
    return {FRESH_WORKFLOW: set(f), FULL_WORKFLOW: set(g)}


def choose_current_head_run(
    runs: list[dict[str, Any]], *, head_sha: str, pr_number: int,
) -> dict[str, Any] | None:
    candidates = []
    for run in runs:
        if run.get("head_sha") != head_sha or run.get("event") != "pull_request":
            continue
        prs = run.get("pull_requests") or []
        if prs and not any(p.get("number") == pr_number for p in prs):
            continue
        candidates.append(run)
    if not candidates:
        return None
    return max(candidates, key=lambda x: (
        str(x.get("created_at") or ""), int(x.get("run_attempt") or 1),
        int(x.get("id") or 0),
    ))


def assess_run(run: dict[str, Any] | None, head_sha: str) -> str:
    if run is None:
        return "pending"
    if run.get("head_sha") != head_sha:
        raise GateError("stale workflow SHA")
    if run.get("status") != "completed":
        if run.get("status") in {
            "requested", "queued", "pending", "waiting", "in_progress",
        }:
            return "pending"
        raise GateError(f"unexpected workflow status {run.get('status')}")
    if run.get("conclusion") != "success":
        raise GateError(f"workflow did not succeed: {run.get('conclusion')}")
    return "success"


def verify_jobs(
    jobs: list[dict[str, Any]], cohort: str, case_ids: set[str],
) -> None:
    aggregate_name = ("Aggregate post-remediation cohort"
                      if cohort == FULL_WORKFLOW else "aggregate")
    expected = set(case_ids) | {aggregate_name}
    if cohort == FULL_WORKFLOW:
        expected.add("prepare")
    names = [job.get("name") for job in jobs]
    if len(names) != len(expected) or set(names) != expected:
        raise GateError(
            f"{cohort}: missing, duplicate or unexpected jobs "
            f"expected={len(expected)} observed={len(names)}"
        )
    if any(job.get("status") != "completed" or job.get("conclusion") != "success"
           for job in jobs):
        raise GateError(f"{cohort}: at least one case or aggregate is not green")
    for job in jobs:
        if job.get("name") == aggregate_name:
            required = (
                {"Enforce versioned pipeline and ADG integrity",
                 "Enforce frozen source-claim regression gate"}
                if cohort == FRESH_WORKFLOW else
                {"Fail closed on semantic pipeline and ADG integrity",
                 "Compare with exact baseline"}
            )
            steps = {s.get("name"): s.get("conclusion")
                     for s in job.get("steps") or []}
            if not all(steps.get(name) == "success" for name in required):
                raise GateError(f"{cohort}: aggregate source-integrity steps missing/red")


def verify_artifacts(
    artifacts: list[dict[str, Any]], cohort: str, case_ids: set[str],
) -> dict[str, Any]:
    prefix, summary = (
        ("fresh16-claim-gate-", "fresh16-source-claim-gate-summary")
        if cohort == FRESH_WORKFLOW else
        ("ff60-post-case-", "full-framework-60-post-remediation-summary")
    )
    expected = {prefix + case for case in case_ids} | {summary}
    names = [item.get("name") for item in artifacts]
    if len(names) != len(expected) or set(names) != expected:
        raise GateError(
            f"{cohort}: incomplete/duplicate artifact inventory "
            f"expected={len(expected)} observed={len(names)}"
        )
    if any(item.get("expired") or int(item.get("size_in_bytes") or 0) <= 0
           for item in artifacts):
        raise GateError(f"{cohort}: missing/expired/empty evidence artifact")
    return next(item for item in artifacts if item["name"] == summary)


def verify_summary_zip(archive: bytes, cohort: str, count: int) -> None:
    if len(archive) > 20_000_000:
        raise GateError("oversized aggregate evidence")
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        names = zipped.namelist()
        if len(names) > 80 or any(name.startswith("/") or ".." in Path(name).parts
                                  for name in names):
            raise GateError("unsafe aggregate artifact")
        def report(filename: str) -> dict[str, Any]:
            hits = [name for name in names if name == filename or name.endswith("/" + filename)]
            if len(hits) != 1:
                raise GateError(f"{cohort}: missing/duplicate {filename}")
            info = zipped.getinfo(hits[0])
            if info.file_size > 6_000_000:
                raise GateError(f"oversized summary: {filename}")
            document = json.loads(zipped.read(info))
            if not isinstance(document, dict):
                raise GateError(f"malformed summary: {filename}")
            return document
        integrity = report("pipeline-integrity.json")
        if (integrity.get("total") != count or integrity.get("valid") is not True
                or integrity.get("errors") != []
                or len(integrity.get("cases") or []) != count):
            raise GateError(f"{cohort}: invalid pipeline/ADG integrity")
        if cohort == FRESH_WORKFLOW:
            source = report("semantic-claims.json")
            sample = report("summary.json")
            if (source.get("passed") is not True
                    or sample.get("completed") != count
                    or sample.get("errors") != []):
                raise GateError("Fresh-16 source claim regression failed")
        else:
            comparison = report("comparison.json")
            gate = comparison.get("regression_gate") or {}
            if gate.get("passed") is not True or gate.get("failures") != []:
                raise GateError("Full-60 exact pinned regression baseline failed")


class GitHubAPI:
    def __init__(self, repository: str, token: str):
        if "/" not in repository or not token:
            raise GateError("missing GitHub repository/token")
        self.root = "https://api.github.com/repos/" + repository
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def get(self, uri: str, *, binary: bool = False) -> Any:
        if not uri.startswith("/") or uri.startswith("//"):
            raise GateError("unsafe API path")
        request = urllib.request.Request(self.root + uri, headers=self.headers)
        with urllib.request.urlopen(request, timeout=45) as result:
            payload = result.read(20_000_001)
        if len(payload) > 20_000_000:
            raise GateError("oversized API response")
        return payload if binary else json.loads(payload)

    def pages(self, path: str, collection: str | None = None) -> list[Any]:
        items: list[Any] = []
        for page in range(1, 31):
            sep = "&" if "?" in path else "?"
            data = self.get(f"{path}{sep}per_page=100&page={page}")
            part = data if collection is None else data.get(collection)
            if not isinstance(part, list):
                raise GateError("malformed GitHub API response")
            items.extend(part)
            if len(part) < 100:
                return items
        raise GateError("API pagination limit exceeded")


def evaluate(api: GitHubAPI, *, pr_number: int, head_sha: str,
             root: Path, deadline: float) -> dict[str, Any]:
    files = api.pages(f"/pulls/{pr_number}/files")
    changed = [entry.get("filename") for entry in files]
    if any(not isinstance(path, str) for path in changed):
        raise GateError("unparseable PR file inventory")
    if not needs_accuracy_cohorts(changed):
        return {
            "scope": "not_applicable", "pr": pr_number, "sha": head_sha,
            "reason": "No production scanner or frozen evaluation-contract changes",
            "cohorts": {},
        }
    expected = expected_cases(root)
    complete: dict[str, Any] = {}
    while time.monotonic() < deadline:
        # Fail closed when the pull request moves while a long cohort runs.
        pr = api.get(f"/pulls/{pr_number}")
        if pr.get("head", {}).get("sha") != head_sha:
            raise GateError("PR head changed during accuracy check")
        for workflow in (FRESH_WORKFLOW, FULL_WORKFLOW):
            if workflow in complete:
                continue
            runs = api.pages(
                f"/actions/workflows/{workflow}/runs?"
                + urllib.parse.urlencode({
                    "event": "pull_request", "head_sha": head_sha,
                }),
                "workflow_runs",
            )
            run = choose_current_head_run(
                runs, head_sha=head_sha, pr_number=pr_number,
            )
            state = assess_run(run, head_sha)
            if state == "pending":
                continue
            run_id = run["id"]
            jobs = api.pages(f"/actions/runs/{run_id}/jobs?filter=latest", "jobs")
            verify_jobs(jobs, workflow, expected[workflow])
            artifacts = api.pages(f"/actions/runs/{run_id}/artifacts", "artifacts")
            summary = verify_artifacts(artifacts, workflow, expected[workflow])
            archive = api.get(
                f"/actions/artifacts/{summary['id']}/zip", binary=True,
            )
            digest = summary.get("digest") or ""
            if digest.startswith("sha256:") and (
                hashlib.sha256(archive).hexdigest() != digest.split(":", 1)[1]
            ):
                raise GateError(f"{workflow}: downloaded artifact digest mismatch")
            verify_summary_zip(archive, workflow, len(expected[workflow]))
            complete[workflow] = {
                "run_id": run_id, "head_sha": head_sha,
                "cases": len(expected[workflow]), "artifact_count": len(artifacts),
                "url": run.get("html_url"),
                "source_integrity": "verified",
            }
        if len(complete) == 2:
            return {
                "scope": "scanner_or_evaluation", "pr": pr_number,
                "sha": head_sha, "cohorts": complete,
            }
        time.sleep(POLL_SECONDS)
    raise GateError(
        f"timed out waiting for current-head Fresh-16 and Full-60: "
        f"completed={sorted(complete)}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--head", required=True)
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        if len(args.head) != 40:
            raise GateError("invalid full head SHA")
        api = GitHubAPI(args.repo, os.environ.get("GITHUB_TOKEN", ""))
        result = evaluate(
            api, pr_number=args.pr, head_sha=args.head, root=args.root,
            deadline=time.monotonic() + MAX_WAIT_SECONDS,
        )
        print(json.dumps(result, indent=2))
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
                out.write("## Same-head accuracy regression gate\n\n")
                out.write("PR `#{}`, head `{}`: **PASS** (`{}`).\n\n".format(
                    args.pr, args.head, result["scope"],
                ))
                for cohort, item in result["cohorts"].items():
                    out.write(f"- {cohort}: {item['cases']} cases, "
                              f"{item['artifact_count']} artifacts, "
                              f"[completed run]({item['url']})\n")
        return 0
    except (GateError, OSError, ValueError, urllib.error.URLError,
            zipfile.BadZipFile) as exc:
        print(f"ACCURACY GATE NO-GO: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
