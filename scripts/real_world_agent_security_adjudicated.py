"""Apply post-hoc effective-authority adjudications without mutating locked truth."""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


def norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def pair(item: dict[str, Any]) -> tuple[str, str, str]:
    return (norm(item.get("agent")), norm(item.get("target_kind")), norm(item.get("target_name")))


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def apply_patch(truth: Counter[tuple[str, str, str]], patch: dict[str, Any]) -> Counter[tuple[str, str, str]]:
    corrected = truth.copy()
    for item in patch.get("remove") or []:
        key = pair(item)
        if corrected[key] <= 0:
            raise ValueError(f"adjudication removes missing relationship: {key}")
        corrected[key] -= 1
        if corrected[key] == 0:
            del corrected[key]
    for item in patch.get("add") or []:
        corrected[pair(item)] += 1
    # unresolved relationships are intentionally excluded from corrected precision/recall.
    return corrected


def score(result: dict[str, Any], adjudication_dir: Path) -> dict[str, Any]:
    patches: dict[str, dict[str, Any]] = {}
    for path in sorted(adjudication_dir.glob("*-effective-authority.json")):
        doc = load(path)
        if doc.get("original_locked_truth_preserved") is not True:
            raise ValueError(f"{path}: adjudication must preserve original locked truth")
        patch = doc.get("authority_truth_patch")
        if isinstance(patch, dict):
            patches[str(doc.get("case_id"))] = patch

    raw = Counter()
    corrected = Counter()
    corrected_cases: list[str] = []
    remaining_missing: dict[str, list[dict[str, str]]] = {}

    for case in result.get("cases") or []:
        auth = (case.get("comparisons") or {}).get("effective_authority")
        if not isinstance(auth, dict):
            continue
        matched = [pair(x) for x in auth.get("matched_pairs") or []]
        missing = [pair(x) for x in auth.get("missing_pairs") or []]
        extra = [pair(x) for x in auth.get("extra_pairs") or []]
        truth = Counter(matched + missing)
        predicted = Counter(matched + extra)

        raw["truth"] += sum(truth.values())
        raw["predicted"] += sum(predicted.values())
        raw["tp"] += sum((truth & predicted).values())
        raw["fn"] += sum((truth - predicted).values())
        if auth.get("precision_eligible"):
            raw["precision_tp"] += sum((truth & predicted).values())
            raw["fp"] += sum((predicted - truth).values())

        case_id = str(case.get("case_id"))
        corrected_truth = truth
        if case_id in patches:
            corrected_truth = apply_patch(truth, patches[case_id])
            corrected_cases.append(case_id)

        corrected["truth"] += sum(corrected_truth.values())
        corrected["predicted"] += sum(predicted.values())
        corrected["tp"] += sum((corrected_truth & predicted).values())
        corrected["fn"] += sum((corrected_truth - predicted).values())
        if auth.get("precision_eligible"):
            corrected["precision_tp"] += sum((corrected_truth & predicted).values())
            corrected["fp"] += sum((predicted - corrected_truth).values())

        unresolved_missing = corrected_truth - predicted
        if unresolved_missing:
            remaining_missing[case_id] = [
                {"agent": a, "target_kind": k, "target_name": n}
                for (a, k, n), count in sorted(unresolved_missing.items())
                for _ in range(count)
            ]

    def ratio(num: int, den: int) -> float | None:
        return round(num / den, 4) if den else None

    raw_precision_den = raw["precision_tp"] + raw["fp"]
    corrected_precision_den = corrected["precision_tp"] + corrected["fp"]
    return {
        "schema_version": 1,
        "study": result.get("study"),
        "scanner_sha": result.get("scanner_sha"),
        "method": "post-hoc pinned-source adjudication; immutable locked truth preserved",
        "corrected_cases": sorted(corrected_cases),
        "raw_locked_truth": {
            **dict(raw),
            "precision": ratio(raw["precision_tp"], raw_precision_den),
            "recall": ratio(raw["tp"], raw["truth"]),
        },
        "post_hoc_adjudicated": {
            **dict(corrected),
            "precision": ratio(corrected["precision_tp"], corrected_precision_den),
            "recall": ratio(corrected["tp"], corrected["truth"]),
        },
        "remaining_missing": remaining_missing,
        "warning": "Post-hoc adjudicated metrics are diagnostic only and do not replace preregistered raw locked-truth gates.",
    }


def render(report: dict[str, Any]) -> str:
    raw = report["raw_locked_truth"]
    adj = report["post_hoc_adjudicated"]
    lines = [
        "# v0.10 Effective-Authority Adjudicated Closeout",
        "",
        f"- Scanner SHA: `{report['scanner_sha']}`",
        f"- Corrected cases: {', '.join(report['corrected_cases']) or 'none'}",
        "",
        "| View | Precision | Recall | TP | FP | FN | Truth |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        f"| Immutable locked truth | {raw['precision']:.4f} | {raw['recall']:.4f} | {raw['tp']} | {raw['fp']} | {raw['fn']} | {raw['truth']} |",
        f"| Post-hoc source adjudication | {adj['precision']:.4f} | {adj['recall']:.4f} | {adj['tp']} | {adj['fp']} | {adj['fn']} | {adj['truth']} |",
        "",
        "## Remaining adjudicated misses",
        "",
    ]
    if report["remaining_missing"]:
        for case_id, items in sorted(report["remaining_missing"].items()):
            for item in items:
                lines.append(f"- {case_id}: `{item['agent']} -> {item['target_name']}`")
    else:
        lines.append("- none")
    lines += ["", f"> {report['warning']}", ""]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--result", type=Path, required=True)
    p.add_argument("--adjudications", type=Path, required=True)
    p.add_argument("--output-json", type=Path, required=True)
    p.add_argument("--output-markdown", type=Path, required=True)
    args = p.parse_args()
    report = score(load(args.result), args.adjudications)
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_markdown.write_text(render(report), encoding="utf-8")
    print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
