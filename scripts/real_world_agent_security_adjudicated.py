"""Rescore frozen-study effective authority with post-hoc adjudication patches.

The immutable locked truth is never modified. This tool reports the original locked
metrics beside a second, explicitly post-hoc view that applies source-reviewed
authority_truth_patch records from the study adjudications directory.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

STUDY = "real-world-agent-security-2026"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def pair_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        norm(item.get("agent")),
        norm(item.get("target_kind")),
        norm(item.get("target_name")),
    )


def pair_doc(key: tuple[str, str, str]) -> dict[str, str]:
    return {
        "agent": key[0],
        "target_kind": key[1],
        "target_name": key[2],
    }


def _counter(items: list[dict[str, Any]]) -> Counter[tuple[str, str, str]]:
    return Counter(pair_key(item) for item in items if isinstance(item, dict))


def _expanded(counter: Counter[tuple[str, str, str]]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for key in sorted(counter):
        result.extend(pair_doc(key) for _ in range(counter[key]))
    return result


def load_authority_patches(adjudications: Path) -> dict[str, dict[str, Any]]:
    patches: dict[str, dict[str, Any]] = {}
    if not adjudications.exists():
        return patches
    for path in sorted(adjudications.glob("*.json")):
        document = load_json(path)
        if document.get("study") != STUDY:
            continue
        patch = document.get("authority_truth_patch")
        case_id = document.get("case_id")
        if not isinstance(case_id, str) or not isinstance(patch, dict):
            continue
        if case_id in patches:
            raise ValueError(f"duplicate authority truth patch for {case_id}")
        patches[case_id] = {
            "path": str(path),
            "classification": document.get("classification"),
            "remove": patch.get("remove") if isinstance(patch.get("remove"), list) else [],
            "add": patch.get("add") if isinstance(patch.get("add"), list) else [],
            "unresolved": (
                patch.get("unresolved")
                if isinstance(patch.get("unresolved"), list)
                else []
            ),
        }
    return patches


def apply_patch(
    truth: Counter[tuple[str, str, str]],
    patch: dict[str, Any] | None,
) -> tuple[
    Counter[tuple[str, str, str]],
    Counter[tuple[str, str, str]],
]:
    corrected = truth.copy()
    unresolved: Counter[tuple[str, str, str]] = Counter()
    if patch is None:
        return corrected, unresolved

    for item in patch["remove"]:
        key = pair_key(item)
        if corrected[key] <= 0:
            raise ValueError(f"patch removes absent authority relationship: {key}")
        corrected[key] -= 1
        if corrected[key] == 0:
            del corrected[key]

    for item in patch["add"]:
        corrected[pair_key(item)] += 1

    for item in patch["unresolved"]:
        unresolved[pair_key(item)] += 1

    return corrected, unresolved


def score_case(
    case: dict[str, Any],
    patch: dict[str, Any] | None,
) -> dict[str, Any] | None:
    authority = (case.get("comparisons") or {}).get("effective_authority")
    if not isinstance(authority, dict):
        return None

    matched = authority.get("matched_pairs")
    missing = authority.get("missing_pairs")
    extra = authority.get("extra_pairs")
    if not all(isinstance(items, list) for items in (matched, missing, extra)):
        raise ValueError(
            f"{case.get('case_id')}: authority pair ledger is required; "
            "rerun with the v0.10 authority ledger harness"
        )

    locked_truth = _counter([*matched, *missing])
    predicted = _counter([*matched, *extra])
    corrected_truth, unresolved = apply_patch(locked_truth, patch)

    remaining = predicted.copy()
    tp = 0
    missing_corrected: Counter[tuple[str, str, str]] = Counter()
    for key, count in corrected_truth.items():
        hits = min(count, remaining[key])
        tp += hits
        if hits:
            remaining[key] -= hits
            if remaining[key] == 0:
                del remaining[key]
        if hits < count:
            missing_corrected[key] = count - hits

    fn = sum(missing_corrected.values())
    fp = sum(remaining.values())
    precision_eligible = bool(authority.get("precision_eligible"))

    return {
        "case_id": case.get("case_id"),
        "repo": case.get("repo"),
        "framework": case.get("framework"),
        "precision_eligible": precision_eligible,
        "patch_applied": patch is not None,
        "adjudication_classification": (
            patch.get("classification") if patch is not None else None
        ),
        "locked": {
            "truth": int(authority.get("truth", 0)),
            "predicted": int(authority.get("predicted", 0)),
            "tp": int(authority.get("tp", 0)),
            "fn": int(authority.get("fn", 0)),
            "fp_if_complete": int(authority.get("fp_if_complete", 0)),
        },
        "adjudicated": {
            "truth": sum(corrected_truth.values()),
            "predicted": sum(predicted.values()),
            "tp": tp,
            "fn": fn,
            "fp_if_complete": fp,
            "missing_pairs": _expanded(missing_corrected),
            "extra_pairs": _expanded(remaining),
        },
        "unresolved": _expanded(unresolved),
    }


def ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def rescore(
    candidate: dict[str, Any],
    patches: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if candidate.get("study") != STUDY:
        raise ValueError(f"candidate does not belong to {STUDY}")

    case_reports: list[dict[str, Any]] = []
    seen_cases: set[str] = set()
    for case in candidate.get("cases") or []:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("case_id") or "")
        report = score_case(case, patches.get(case_id))
        if report is None:
            continue
        case_reports.append(report)
        seen_cases.add(case_id)

    unused = sorted(set(patches) - seen_cases)
    if unused:
        raise ValueError(
            "authority adjudication patches reference cases without authority ledgers: "
            + ", ".join(unused)
        )

    truth = predicted = tp = fn = 0
    precision_cases = precision_tp = fp = 0
    unresolved = 0
    patched_cases = 0
    for case in case_reports:
        adjusted = case["adjudicated"]
        truth += adjusted["truth"]
        predicted += adjusted["predicted"]
        tp += adjusted["tp"]
        fn += adjusted["fn"]
        unresolved += len(case["unresolved"])
        if case["patch_applied"]:
            patched_cases += 1
        if case["precision_eligible"]:
            precision_cases += 1
            precision_tp += adjusted["tp"]
            fp += adjusted["fp_if_complete"]

    locked = ((candidate.get("metrics") or {}).get("effective_authority") or {})
    return {
        "schema_version": 1,
        "study": STUDY,
        "scanner_sha": candidate.get("scanner_sha"),
        "cohort_cases": candidate.get("cohort_cases"),
        "authority": {
            "locked": locked,
            "post_hoc_adjudicated": {
                "truth": truth,
                "predicted": predicted,
                "tp": tp,
                "fn": fn,
                "recall": ratio(tp, tp + fn),
                "precision_complete_cases": precision_cases,
                "precision_tp": precision_tp,
                "fp": fp,
                "precision": ratio(precision_tp, precision_tp + fp),
                "unresolved_corrections": unresolved,
                "patched_cases": patched_cases,
            },
        },
        "cases": case_reports,
        "methodology": {
            "locked_truth_modified": False,
            "post_hoc": True,
            "precision_scope": "original_precision_eligible_cases_only",
            "runtime_effectiveness": "not_verified",
        },
    }


def fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def render_markdown(report: dict[str, Any]) -> str:
    locked = report["authority"]["locked"]
    adjusted = report["authority"]["post_hoc_adjudicated"]
    lines = [
        "# HorusTrace v0.10 Authority Adjudication",
        "",
        f"- Candidate scanner: `{report['scanner_sha']}`",
        f"- Frozen cohort: {report['cohort_cases']} repositories",
        "- Locked truth remains unchanged.",
        "- Post-hoc metrics apply only separately recorded pinned-source adjudications.",
        "",
        "## Effective authority",
        "",
        "| View | Precision | Recall | TP | FN | FP* | Truth |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| Original locked reference | {fmt(locked.get('precision'))} | "
            f"{fmt(locked.get('recall'))} | {fmt(locked.get('tp'))} | "
            f"{fmt(locked.get('fn'))} | {fmt(locked.get('fp'))} | "
            f"{fmt(locked.get('truth'))} |"
        ),
        (
            f"| Post-hoc adjudicated | {fmt(adjusted.get('precision'))} | "
            f"{fmt(adjusted.get('recall'))} | {fmt(adjusted.get('tp'))} | "
            f"{fmt(adjusted.get('fn'))} | {fmt(adjusted.get('fp'))} | "
            f"{fmt(adjusted.get('truth'))} |"
        ),
        "",
        "\* Precision remains restricted to the original completeness-marked cases.",
        "",
        f"- Patched cases: {adjusted['patched_cases']}",
        f"- Relationships moved to unresolved by adjudication: {adjusted['unresolved_corrections']}",
        "",
        "## Patched cases",
        "",
        "| Case | Classification | Locked TP/FN/FP | Adjudicated TP/FN/FP | Unresolved |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    patched = [case for case in report["cases"] if case["patch_applied"]]
    for case in patched:
        before = case["locked"]
        after = case["adjudicated"]
        lines.append(
            f"| {case['case_id']} | {case['adjudication_classification']} | "
            f"{before['tp']}/{before['fn']}/{before['fp_if_complete']} | "
            f"{after['tp']}/{after['fn']}/{after['fp_if_complete']} | "
            f"{len(case['unresolved'])} |"
        )
    lines.extend(
        [
            "",
            "This report is a post-hoc disagreement view, not a replacement for the preregistered locked-reference result.",
            "",
        ]
    )
    return "\n".join(lines)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--adjudications", type=Path, required=True)
    p.add_argument("--output-json", type=Path, required=True)
    p.add_argument("--output-markdown", type=Path, required=True)
    return p


def main() -> int:
    args = parser().parse_args()
    report = rescore(
        load_json(args.candidate),
        load_authority_patches(args.adjudications),
    )
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.output_markdown.write_text(render_markdown(report) + "\n", encoding="utf-8")
    print(render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
