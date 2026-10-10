from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

COUNT_KEYS = (
    "agents",
    "findings",
    "attack_paths",
    "authority_relationships",
    "partially_resolved_authority",
    "unknown_authority",
    "diagnostics",
    "unbound_skills",
)


def load_baseline(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows[row["case_id"]] = {
                "framework": row["framework"],
                "counts": {key: int(row[key]) for key in COUNT_KEYS},
            }
    return rows


def load_post(path: Path) -> dict[str, dict]:
    rows = {}
    for result_path in sorted(path.rglob("result.json")):
        item = json.loads(result_path.read_text(encoding="utf-8"))
        rows[item["case_id"]] = item
    return rows


def aggregate_cases(rows: dict[str, dict]) -> dict[str, dict]:
    out = defaultdict(lambda: {key: 0 for key in COUNT_KEYS})
    out_zero = defaultdict(list)
    for case_id, item in rows.items():
        framework = item["framework"]
        counts = item["counts"]
        for key in COUNT_KEYS:
            out[framework][key] += int(counts.get(key) or 0)
        if int(counts.get("agents") or 0) == 0:
            out_zero[framework].append(case_id)
    result = {}
    for framework in sorted(out):
        result[framework] = {
            **out[framework],
            "zero_agent_cases": sorted(out_zero[framework]),
        }
    return result


def relationship_metrics(post: dict[str, dict]) -> dict:
    core = Counter()
    detail = Counter()
    source_context = Counter()
    findings_context = Counter()
    path_basis = Counter()
    restricted_destinations = 0
    total_destinations = 0

    for item in post.values():
        for relationship in item.get("authority_relationships") or []:
            core[str(relationship.get("core_resolution") or "unknown")] += 1
            detail[str(
                relationship.get("detail_resolution")
                or relationship.get("resolution")
                or "unknown"
            )] += 1
            source_context[str(relationship.get("source_context") or "unknown")] += 1
            for destination in relationship.get("destinations") or []:
                total_destinations += 1
                if destination.get("restricted") is True:
                    restricted_destinations += 1

        for finding in item.get("findings") or []:
            findings_context[str(finding.get("source_context") or "unknown")] += 1

        for path in item.get("attack_paths") or []:
            metadata = path.get("metadata") or {}
            basis = path.get("basis") or metadata.get("basis") or "unknown"
            path_basis[str(basis)] += 1

    total_relationships = sum(core.values())
    return {
        "core_resolution": dict(sorted(core.items())),
        "detail_resolution": dict(sorted(detail.items())),
        "core_fully_resolved_ratio": (
            round(core.get("fully_resolved", 0) / total_relationships, 6)
            if total_relationships
            else 1.0
        ),
        "relationships_by_source_context": dict(sorted(source_context.items())),
        "findings_by_source_context": dict(sorted(findings_context.items())),
        "attack_paths_by_basis": dict(sorted(path_basis.items())),
        "destinations": {
            "total": total_destinations,
            "restricted": restricted_destinations,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scanner-revision", required=True)
    parser.add_argument("--harness-revision", required=True)
    parser.add_argument("--gate-baseline", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    baseline = load_baseline(args.baseline)
    post = load_post(args.input)
    gate_doc = json.loads(args.gate_baseline.read_text(encoding="utf-8"))
    baseline_agg = aggregate_cases(baseline)
    post_agg = aggregate_cases(post)

    changed_cases = []
    for case_id in sorted(set(baseline) | set(post)):
        before = baseline.get(case_id)
        after = post.get(case_id)
        if before is None or after is None:
            changed_cases.append({
                "case_id": case_id,
                "framework": (after or before or {}).get("framework"),
                "status": "added" if before is None else "missing",
                "delta": {},
            })
            continue
        delta = {
            key: int(after["counts"].get(key) or 0) - int(before["counts"].get(key) or 0)
            for key in COUNT_KEYS
        }
        if any(delta.values()):
            changed_cases.append({
                "case_id": case_id,
                "framework": after["framework"],
                "status": "changed",
                "delta": delta,
                "baseline": before["counts"],
                "post": after["counts"],
            })

    framework_delta = {}
    for framework in sorted(set(baseline_agg) | set(post_agg)):
        before = baseline_agg.get(framework, {})
        after = post_agg.get(framework, {})
        framework_delta[framework] = {
            key: int(after.get(key) or 0) - int(before.get(key) or 0)
            for key in COUNT_KEYS
        }
        framework_delta[framework]["zero_agent_before"] = before.get(
            "zero_agent_cases", []
        )
        framework_delta[framework]["zero_agent_after"] = after.get(
            "zero_agent_cases", []
        )

    metrics = relationship_metrics(post)

    gate = gate_doc["gate"]
    post_totals = {
        key: sum(int((item.get("counts") or {}).get(key) or 0) for item in post.values())
        for key in COUNT_KEYS
    }
    zero_agent_cases = sorted(
        case_id
        for case_id, item in post.items()
        if int((item.get("counts") or {}).get("agents") or 0) == 0
    )
    core_unknown = int(metrics["core_resolution"].get("unknown", 0))
    gate_failures: list[str] = []

    expected_cases = int(gate["expected_cases"])
    missing_cases = sorted(set(baseline) - set(post))
    if len(post) != expected_cases:
        gate_failures.append(
            f"frozen cases present {len(post)}/{expected_cases}"
        )
    if len(missing_cases) > int(gate["max_missing_cases"]):
        gate_failures.append(
            f"missing cases {len(missing_cases)} > {gate['max_missing_cases']}: "
            + ", ".join(missing_cases)
        )
    if len(zero_agent_cases) > int(gate["max_zero_agent_cases"]):
        gate_failures.append(
            f"zero-agent cases {len(zero_agent_cases)} > "
            f"{gate['max_zero_agent_cases']}: "
            + ", ".join(zero_agent_cases)
        )
    if core_unknown > int(gate["max_core_unknown"]):
        gate_failures.append(
            f"core-unknown authority {core_unknown} > {gate['max_core_unknown']}"
        )
    if post_totals["agents"] < int(gate["min_total_agents"]):
        gate_failures.append(
            f"agents {post_totals['agents']} < {gate['min_total_agents']}"
        )
    if post_totals["authority_relationships"] < int(
        gate["min_total_authority_relationships"]
    ):
        gate_failures.append(
            "authority relationships "
            f"{post_totals['authority_relationships']} < "
            f"{gate['min_total_authority_relationships']}"
        )
    if metrics["core_fully_resolved_ratio"] < float(
        gate["min_core_fully_resolved_ratio"]
    ):
        gate_failures.append(
            "core fully-resolved ratio "
            f"{metrics['core_fully_resolved_ratio']:.3f} < "
            f"{float(gate['min_core_fully_resolved_ratio']):.3f}"
        )

    # Compare live posture against the adjudicated *post-remediation* 14-path
    # closure, not the pre-source-context 24-path baseline. The original CSV is
    # still retained for historical count deltas. Never allow arbitrary drops
    # from a case just because it once contained suppressed example paths.
    path_floor = gate.get("attack_path_floor_by_case")
    if not isinstance(path_floor, dict):
        gate_failures.append("missing post-remediation attack-path floor")
    else:
        unknown_path_cases = sorted(set(path_floor) - set(baseline))
        if unknown_path_cases:
            gate_failures.append(
                "attack-path floor includes unknown cases: "
                + ", ".join(unknown_path_cases)
            )
        floor_total = sum(int(value) for value in path_floor.values())
        if floor_total != int(gate.get("min_attack_path_floor_total", -1)):
            gate_failures.append(
                f"attack-path floor total {floor_total} differs from locked reference"
            )
        for case_id in sorted(baseline):
            after = post.get(case_id)
            if after is None:
                continue
            expected = int(path_floor.get(case_id, 0))
            actual = int((after.get("counts") or {}).get("attack_paths") or 0)
            if actual < expected:
                gate_failures.append(
                    f"{case_id} attack paths {actual} below post-remediation "
                    f"source-backed floor {expected}"
                )

    post_by_framework = aggregate_cases(post)
    for framework, minimums in gate["framework_minimums"].items():
        observed = post_by_framework.get(framework, {})
        for key in ("agents", "authority_relationships"):
            minimum = int(minimums[key])
            actual = int(observed.get(key) or 0)
            if actual < minimum:
                gate_failures.append(
                    f"{framework} {key} {actual} < {minimum}"
                )

    report = {
        "schema_version": 1,
        "study": "full-framework-60-post-remediation-20261006",
        "frozen_cohort": "full-framework-60-20261005",
        "baseline_scanner_revision": "bf02b7e831973ff733b6fab369094ce784e1a1bd",
        "post_scanner_revision": args.scanner_revision,
        "study_harness_revision": args.harness_revision,
        "baseline_cases": len(baseline),
        "post_cases": len(post),
        "missing_cases": sorted(set(baseline) - set(post)),
        "framework_baseline": baseline_agg,
        "framework_post": post_agg,
        "framework_delta": framework_delta,
        "changed_cases": changed_cases,
        "post_resolution_metrics": metrics,
        "regression_gate": {
            "baseline": gate_doc,
            "post_totals": post_totals,
            "zero_agent_cases": zero_agent_cases,
            "failures": gate_failures,
            "passed": not gate_failures,
        },
    }
    (args.output / "comparison.json").write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Full-framework 60 post-remediation comparison",
        "",
        f"- baseline scanner: `{report['baseline_scanner_revision']}`",
        f"- post scanner: `{args.scanner_revision}`",
        f"- study harness: `{args.harness_revision}`",
        f"- frozen cases present: **{len(post)}/{len(baseline)}**",
        f"- cases with count-level changes: **{len(changed_cases)}**",
        f"- core fully-resolved ratio: **{metrics['core_fully_resolved_ratio']:.1%}**",
        f"- regression gate: **{'PASS' if not gate_failures else 'FAIL'}**",
        "",
        "## Regression gate",
        "",
    ]
    if gate_failures:
        lines.extend(f"- FAIL: {failure}" for failure in gate_failures)
    else:
        lines.append("- all frozen-cohort guardrails passed")
    lines += [
        "",
        "## Framework deltas",
        "",
        "| Framework | Agents | Findings | Paths | Authority | Partial | Unknown | Diagnostics | Unbound Skills |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for framework, row in framework_delta.items():
        lines.append(
            f"| {framework} | {row['agents']:+d} | {row['findings']:+d} | "
            f"{row['attack_paths']:+d} | {row['authority_relationships']:+d} | "
            f"{row['partially_resolved_authority']:+d} | "
            f"{row['unknown_authority']:+d} | {row['diagnostics']:+d} | "
            f"{row['unbound_skills']:+d} |"
        )

    lines += [
        "",
        "## Post-remediation resolution signal",
        "",
        f"- core resolution: `{json.dumps(metrics['core_resolution'], sort_keys=True)}`",
        f"- detail resolution: `{json.dumps(metrics['detail_resolution'], sort_keys=True)}`",
        f"- relationship source context: `{json.dumps(metrics['relationships_by_source_context'], sort_keys=True)}`",
        f"- finding source context: `{json.dumps(metrics['findings_by_source_context'], sort_keys=True)}`",
        f"- attack-path basis: `{json.dumps(metrics['attack_paths_by_basis'], sort_keys=True)}`",
        f"- restricted destinations: **{metrics['destinations']['restricted']}/{metrics['destinations']['total']}**",
        "",
        "## Changed cases",
        "",
    ]
    if changed_cases:
        for item in changed_cases:
            if item["status"] != "changed":
                lines.append(f"- {item['case_id']}: **{item['status']}**")
                continue
            meaningful = ", ".join(
                f"{key} {value:+d}"
                for key, value in item["delta"].items()
                if value
            )
            lines.append(
                f"- **{item['case_id']}** ({item['framework']}): {meaningful}"
            )
    else:
        lines.append("- none")

    (args.output / "comparison.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    return 1 if gate_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
