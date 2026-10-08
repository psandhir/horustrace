"""Execute independent source-only model reviews with a strict evidence contract.

This is an opt-in billed API adapter; it DOES NOT run on push and never reads
HorusScan scan results. Use --case-id for a bounded pilot. It cannot simulate
independent reviews using this conversation's retrospective ChatGPT context.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts.frozen180_llm_review import ROOT, ReviewError, validate_review
from scripts.run_llm_adjudication import JudgeConfig, _call_judge

STUDY = "frozen180-llm-source-review-20261008"


def api_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Keep OpenAI structured-output schema subset; local validation stays strict."""
    drop = {"$schema", "$id", "title", "minLength", "minimum", "pattern", "description"}
    def walk(value: Any) -> Any:
        if isinstance(value, list):
            return [walk(x) for x in value]
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items() if k not in drop}
        return value
    return walk(schema)


def make_input(manifest: dict[str, Any], source: str) -> str:
    """Only pinned source provenance and source text cross the model boundary."""
    public = {
        "study": STUDY,
        "case_id": manifest["case_id"],
        "repo": manifest["repo"],
        "sha": manifest["sha"],
        "framework": manifest["framework"],
        "review_scope": {
            "application_path": manifest["application_path"],
            "source_pack_sha256": manifest["source_pack_sha256"],
        },
        "source_coverage": "qualified",
        "omitted_or_truncated": manifest["omitted_or_truncated"],
        "source_text": source,
    }
    return json.dumps(public, ensure_ascii=False)


def review_case(source_root: Path, destination: Path, case_id: str,
                prompt: str, schema: dict[str, Any], judges: list[JudgeConfig]) -> list[dict]:
    folder = source_root / case_id
    manifest = json.loads((folder / "source-manifest.json").read_text())
    source_text = (folder / "source-only.txt").read_text()
    if manifest.get("application_entrypoint_included") is not True:
        raise ReviewError(f"{case_id}: application entrypoint missing from packet")
    if manifest["case_id"] != case_id:
        raise ReviewError(f"{case_id}: source manifest mismatch")
    user_text = make_input(manifest, source_text)
    prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    output = []
    for judge in judges:
        response, provider_request_id = _call_judge(
            judge, system_prompt=prompt, user_prompt=user_text,
            schema=api_schema(schema), max_retries=2)
        if not provider_request_id:
            raise ReviewError(
                f"{judge.reviewer_id}/{case_id}: provider did not return auditable request ID"
            )
        validation = validate_review(response, manifest, source_text, schema)
        run_time = datetime.datetime.now(datetime.UTC).isoformat()
        payload = json.dumps(response, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        evidence_sha = hashlib.sha256(payload.encode()).hexdigest()
        judge_folder = destination / judge.reviewer_id
        judge_folder.mkdir(parents=True, exist_ok=True)
        (judge_folder / f"{case_id}.json").write_text(payload)
        envelope = {
            "case_id": case_id,
            "reviewer_id": judge.reviewer_id,
            "provider": judge.provider,
            "model": judge.model,
            "provider_request_id": provider_request_id,
            "execution_id": provider_request_id,
            "prompt_version": "frozen180-source-review-v1",
            "prompt_sha256": prompt_sha,
            "source_pack_sha256": manifest["source_pack_sha256"],
            "source_revision": manifest["sha"],
            "review_sha256": evidence_sha,
            "scanner_output_seen": False,
            "independent_review": True,
            "independent_human": False,
            "locked": True,
            "locked_at": run_time,
            "validation": validation,
        }
        (judge_folder / f"{case_id}.reviewer.json").write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n")
        output.append(envelope)
    return output


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--case-id", action="append", required=True,
                   help="Repeat for a bounded pilot; supports only one frozen study.")
    p.add_argument("--judge-a-provider", choices=["openai", "google"], default="openai")
    p.add_argument("--judge-a-model", required=True)
    p.add_argument("--judge-b-provider", choices=["openai", "google"], default="google")
    p.add_argument("--judge-b-model", required=True)
    p.add_argument("--prompt", type=Path, default=ROOT / "SOURCE_REVIEW_PROMPT_V1.md")
    p.add_argument("--schema", type=Path, default=ROOT / "source-review.schema.json")
    p.add_argument("--confirm-large-run", action="store_true",
                   help="Allow more than three cases (two billed judge calls per case)")
    args = p.parse_args()
    case_ids = sorted(set(args.case_id))
    if len(case_ids) > 3 and not args.confirm_large_run:
        raise SystemExit("pilot is capped at 3 cases; explicitly confirm larger billed runs")
    if args.judge_a_provider == args.judge_b_provider:
        raise SystemExit("source review requires independent providers by default")
    manifest = json.loads((args.source_root / "manifest.json").read_text())
    if manifest.get("active_cases") != 145:
        raise SystemExit("expected source-only frozen 145 active repository cases")
    included = {item["case_id"] for item in manifest["cases"]
                if item["framework"] != "langgraph" and item["status"] == "ok"}
    if not set(case_ids) <= included:
        raise SystemExit("case IDs must be present in scanner-blind frozen source inventory")
    if any(not (args.source_root / case / "source-only.txt").is_file() for case in case_ids):
        raise SystemExit("missing source packet file")
    prompt = args.prompt.read_text()
    schema = json.loads(args.schema.read_text())
    judges = [
        JudgeConfig(reviewer_id="source-judge-a", provider=args.judge_a_provider,
                    model=args.judge_a_model),
        JudgeConfig(reviewer_id="source-judge-b", provider=args.judge_b_provider,
                    model=args.judge_b_model),
    ]
    records = []
    for case in case_ids:
        records.extend(review_case(args.source_root, args.output, case, prompt, schema, judges))
        print(f"Locked two independent source-only model reviews for {case}")
    summary = {
        "study": STUDY, "cases_requested": case_ids, "review_count": len(records),
        "dual_review_cases": len(records) // 2,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "scanner_output_seen": False, "reveal_allowed": False,
        "validation_not_ground_truth": True,
        "reviewers": records,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "phase-a-pilot-manifest.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
