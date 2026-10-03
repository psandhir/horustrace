"""Prepare a frozen blinded review packet for two independent LLM judges.

The source packet is not mutated. This adapter only replaces empty reviewer slots with
versioned LLM identities; it does not add HorusTrace findings, rule IDs, severities, or
other scanner metadata.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

STUDY = "attack-path-finding-validation-2026"


class LLMReviewPacketError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Judge:
    reviewer_id: str
    provider: str
    model: str


def _load(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise LLMReviewPacketError(f"{path}: cannot load review packet") from exc
    if not isinstance(value, dict):
        raise LLMReviewPacketError(f"{path}: expected mapping")
    return value


def _require_text(value: str, field: str) -> str:
    value = value.strip()
    if not value:
        raise LLMReviewPacketError(f"{field} is required")
    return value


def prepare_packet(
    packet: dict[str, Any],
    *,
    judge_a: Judge,
    judge_b: Judge,
    prompt_version: str,
) -> dict[str, Any]:
    if packet.get("study") != STUDY:
        raise LLMReviewPacketError("packet belongs to a different study")
    cases = packet.get("cases")
    if not isinstance(cases, list) or not cases:
        raise LLMReviewPacketError("packet cases must be a non-empty list")

    prompt_version = _require_text(prompt_version, "prompt_version")
    judges = (judge_a, judge_b)
    ids = [_require_text(judge.reviewer_id, "reviewer_id") for judge in judges]
    if ids[0] == ids[1]:
        raise LLMReviewPacketError("LLM judges must have different reviewer_id values")

    result = copy.deepcopy(packet)
    result["review_protocol"] = "dual_blind_llm_v1"
    result["llm_prompt_version"] = prompt_version
    result["llm_judges"] = [
        {
            "reviewer_id": ids[index],
            "provider": _require_text(judge.provider, "provider"),
            "model": _require_text(judge.model, "model"),
        }
        for index, judge in enumerate(judges)
    ]

    for case_index, case in enumerate(result["cases"]):
        if not isinstance(case, dict):
            raise LLMReviewPacketError(f"cases[{case_index}] must be a mapping")
        slots = case.get("reviewers")
        if not isinstance(slots, list) or len(slots) != 2:
            raise LLMReviewPacketError(
                f"cases[{case_index}]: exactly two reviewer slots are required"
            )
        for index, judge in enumerate(judges):
            slots[index] = {
                "reviewer_id": ids[index],
                "reviewer_kind": "llm",
                "independent_review": True,
                "independent_human": False,
                "horustrace_output_seen": False,
                "locked": False,
                "model": {
                    "provider": judge.provider.strip(),
                    "name": judge.model.strip(),
                    "prompt_version": prompt_version,
                },
                "verdict": "unresolved",
                "partial_reasons": [],
                "severity": "unresolved",
                "evidence": [],
                "rationale": "",
            }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--judge-a-id", required=True)
    parser.add_argument("--judge-a-provider", required=True)
    parser.add_argument("--judge-a-model", required=True)
    parser.add_argument("--judge-b-id", required=True)
    parser.add_argument("--judge-b-provider", required=True)
    parser.add_argument("--judge-b-model", required=True)
    parser.add_argument("--prompt-version", default="llm-review-v2")
    args = parser.parse_args()

    prepared = prepare_packet(
        _load(args.packet),
        judge_a=Judge(args.judge_a_id, args.judge_a_provider, args.judge_a_model),
        judge_b=Judge(args.judge_b_id, args.judge_b_provider, args.judge_b_model),
        prompt_version=args.prompt_version,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(prepared, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    print(
        f"prepared {len(prepared['cases'])} cases for "
        f"{args.judge_a_id} and {args.judge_b_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
