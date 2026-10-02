from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

FINDING_VALUES = ["true_positive", "partial", "false_positive", "unresolved"]
PATH_VALUES = FINDING_VALUES
RECALL_VALUES = ["full", "partial", "missed", "unresolved"]


def add(dst: dict[str, int], src: dict[str, int]) -> None:
    for k, v in src.items():
        dst[k] += v


def tally(items: list[dict], field: str, values: list[str]) -> dict[str, int]:
    out = {v: 0 for v in values}
    for item in items:
        value = item.get(field)
        if value in out:
            out[value] += 1
    return out


def ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--adjudication", type=Path, default=Path(__file__).with_name("adjudication-summary.json"))
    args = ap.parse_args()
    rows = []
    for path in sorted(args.input.rglob("result.json")):
        rows.append(json.loads(path.read_text(encoding="utf-8")))

    groups: dict[tuple[str, str], dict] = {}
    for row in rows:
        for state in row["states"]:
            key = (row["panel"], state["state"])
            if key not in groups:
                groups[key] = {
                    "panel": row["panel"],
                    "state": state["state"],
                    "repos": 0,
                    "finding_count": 0,
                    "path_count": 0,
                    "finding_verdicts": {v: 0 for v in FINDING_VALUES},
                    "path_verdicts": {v: 0 for v in PATH_VALUES},
                    "finding_recall": {v: 0 for v in RECALL_VALUES},
                    "path_recall": {v: 0 for v in RECALL_VALUES},
                    "archived_checks": 0,
                    "archived_matches": 0,
                }
            g = groups[key]
            g["repos"] += 1
            g["finding_count"] += state["finding_count"]
            g["path_count"] += state["path_count"]
            add(g["finding_verdicts"], tally(state["claim_review"].get("finding_verdicts", []), "verdict", FINDING_VALUES))
            add(g["path_verdicts"], tally(state["claim_review"].get("path_verdicts", []), "verdict", PATH_VALUES))
            add(g["finding_recall"], tally(state["recall_review"].get("blind_finding_matches", []), "status", RECALL_VALUES))
            add(g["path_recall"], tally(state["recall_review"].get("blind_path_matches", []), "status", RECALL_VALUES))
            check = state.get("archived_count_check")
            if check:
                g["archived_checks"] += 1
                g["archived_matches"] += int(bool(check.get("matches")))

    external = {}
    if args.adjudication.exists():
        doc = json.loads(args.adjudication.read_text(encoding="utf-8"))
        for item in doc.get("groups", []):
            external[(item["panel"], item["state"])] = item

    summary = []
    for key in sorted(groups):
        g = groups[key]
        if key in external:
            ext = external[key]
            counts = ext.get("finding_verdicts", {})
            total = sum(int(counts.get(v, 0)) for v in FINDING_VALUES)
            if total != g["finding_count"]:
                raise ValueError(f"external adjudication count mismatch for {key}: {total} != {g['finding_count']}")
            g["finding_verdicts"] = {v: int(counts.get(v, 0)) for v in FINDING_VALUES}
            g["finding_adjudication_source"] = "external"
        else:
            g["finding_adjudication_source"] = "embedded"
        fv = g["finding_verdicts"]
        pv = g["path_verdicts"]
        fr = g["finding_recall"]
        pr = g["path_recall"]
        fden = fv["true_positive"] + fv["partial"] + fv["false_positive"]
        pden = pv["true_positive"] + pv["partial"] + pv["false_positive"]
        frden = fr["full"] + fr["partial"] + fr["missed"]
        prden = pr["full"] + pr["partial"] + pr["missed"]
        g["finding_precision_strict"] = ratio(fv["true_positive"], fden)
        g["finding_precision_supported"] = ratio(fv["true_positive"] + fv["partial"], fden)
        g["finding_partial_rate_resolved"] = ratio(fv["partial"], fden)
        g["path_precision_supported"] = ratio(pv["true_positive"] + pv["partial"], pden)
        g["finding_recall_full"] = ratio(fr["full"], frden)
        g["finding_recall_full_or_partial"] = ratio(fr["full"] + fr["partial"], frden)
        g["path_recall_full_or_partial"] = ratio(pr["full"] + pr["partial"], prden)
        summary.append(g)

    output = {
        "schema_version": 1,
        "study": "retrospective-adjudicator-calibration-2026",
        "cases": len(rows),
        "groups": summary,
        "adjudication_file": str(args.adjudication) if args.adjudication.exists() else None,
        "results": rows,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Retrospective adjudicator calibration",
        "",
        "| Panel | Scanner state | Repos | Findings | TP/P/FP/U | Supported precision | Partial rate | Blind recall full+partial | Paths | Path TP/P/FP/U | Path recall full+partial |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for g in summary:
        fv = g["finding_verdicts"]
        pv = g["path_verdicts"]
        def fmt(x):
            return "n/a" if x is None else f"{x:.1%}"
        lines.append(
            f"| {g['panel']} | {g['state']} | {g['repos']} | {g['finding_count']} | "
            f"{fv['true_positive']}/{fv['partial']}/{fv['false_positive']}/{fv['unresolved']} | "
            f"{fmt(g['finding_precision_supported'])} | {fmt(g['finding_partial_rate_resolved'])} | "
            f"{fmt(g['finding_recall_full_or_partial'])} | {g['path_count']} | "
            f"{pv['true_positive']}/{pv['partial']}/{pv['false_positive']}/{pv['unresolved']} | "
            f"{fmt(g['path_recall_full_or_partial'])} |"
        )
    lines += ["", "## Historical rerun checks", ""]
    for g in summary:
        if g["archived_checks"]:
            lines.append(f"- {g['panel']} / {g['state']}: {g['archived_matches']}/{g['archived_checks']} archived finding/path counts reproduced.")
    (args.output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
