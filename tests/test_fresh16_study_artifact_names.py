"""Ensure the Fresh-16 release gate always collects its exact case artifacts."""
from fnmatch import fnmatch
from pathlib import Path

import yaml


def test_case_artifact_uploads_match_aggregate_download_pattern() -> None:
    root = Path(__file__).parents[1]
    workflow = yaml.safe_load(
        (root / ".github" / "workflows" / "fresh16-source-claim-regression.yml")
        .read_text(encoding="utf-8")
    )
    jobs = workflow["jobs"]
    scan = jobs["scan"]
    aggregate = jobs["aggregate"]
    upload = next(
        step for step in scan["steps"]
        if step.get("name") == "Upload complete per-case evidence"
    )
    download = next(
        step for step in aggregate["steps"]
        if step.get("name") == "Download exact-case artifacts"
    )
    template = upload["with"]["name"]
    pattern = download["with"]["pattern"]
    case_ids = scan["strategy"]["matrix"]["case_id"]
    assert len(case_ids) == 16
    assert all(case_id.startswith("gen-") for case_id in case_ids)
    assert "${{ matrix.case_id }}" in template

    names = [template.replace("${{ matrix.case_id }}", case_id)
             for case_id in case_ids]
    assert len(set(names)) == 16
    assert all(fnmatch(name, pattern) for name in names)
    assert not fnmatch("fresh16-source-claim-gate-summary", pattern)
