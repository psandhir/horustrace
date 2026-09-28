"""Validate and score the post-hoc HorusTrace semantic parity benchmark.

This benchmark intentionally does not rewrite the preregistered frozen source
reference. It is a separate source-adjudicated layer for security-semantic
regressions discovered during LLM-parity review.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

EVIDENCE_STATES = {"observed", "inferred", "unresolved"}
ASSERTION_TYPES = {
    "finding_present",
    "finding_absent",
    "finding_max_count",
    "summary_min",
    "summary_max",
    "summary_exact",
}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RULE_RE = re.compile(r"^[A-Z]{3,4}[0-9]{3}$")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def _validate_evidence(value: Any, where: str, errors: list[str]) -> None:
    _require(value in EVIDENCE_STATES, f"{where}: invalid evidence_state {value!r}", errors)


def validate(benchmark: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    _require(benchmark.get("schema_version") == 1, "schema_version must be 1", errors)
    _require(
        benchmark.get("original_locked_truth_preserved") is True,
        "original_locked_truth_preserved must be true",
        errors,
    )
    cases = benchmark.get("cases")
    _require(isinstance(cases, list) and bool(cases), "cases must be a non-empty list", errors)
    if not isinstance(cases, list):
        return errors

    expected_count = benchmark.get("methodology", {}).get("case_count")
    if isinstance(expected_count, int):
        _require(len(cases) == expected_count, "methodology.case_count must match cases", errors)

    seen: set[str] = set()
    for index, case in enumerate(cases):
        where = f"cases[{index}]"
        _require(isinstance(case, dict), f"{where}: expected object", errors)
        if not isinstance(case, dict):
            continue
        case_id = case.get("case_id")
        _require(isinstance(case_id, str) and bool(case_id), f"{where}: missing case_id", errors)
        if isinstance(case_id, str):
            _require(case_id not in seen, f"{where}: duplicate case_id {case_id}", errors)
            seen.add(case_id)
            where = case_id

        source = case.get("source_reference")
        _require(isinstance(source, dict), f"{where}: source_reference must be object", errors)
        if isinstance(source, dict):
            _require(bool(source.get("repo")), f"{where}: source repo required", errors)
            sha = source.get("sha")
            _require(
                isinstance(sha, str) and bool(SHA_RE.fullmatch(sha)),
                f"{where}: invalid pinned SHA",
                errors,
            )
            paths = source.get("paths")
            _require(isinstance(paths, list) and bool(paths), f"{where}: source paths required", errors)

        semantic = case.get("semantic_model")
        _require(isinstance(semantic, dict), f"{where}: semantic_model must be object", errors)
        if isinstance(semantic, dict):
            facts = semantic.get("authority_facts", [])
            _require(isinstance(facts, list), f"{where}: authority_facts must be list", errors)
            if isinstance(facts, list):
                for fi, fact in enumerate(facts):
                    _require(
                        isinstance(fact, dict),
                        f"{where}: authority_facts[{fi}] must be object",
                        errors,
                    )
                    if isinstance(fact, dict):
                        _validate_evidence(
                            fact.get("evidence_state"),
                            f"{where}: authority_facts[{fi}]",
                            errors,
                        )
                        _require(
                            bool(fact.get("fact")),
                            f"{where}: authority_facts[{fi}] missing fact",
                            errors,
                        )

        policy = case.get("policy_expectations")
        _require(isinstance(policy, dict), f"{where}: policy_expectations must be object", errors)
        policy_pairs: list[tuple[str, str]] = []
        if isinstance(policy, dict):
            for bucket in ("required", "forbidden", "candidate"):
                values = policy.get(bucket)
                _require(isinstance(values, list), f"{where}: policy.{bucket} must be list", errors)
                if not isinstance(values, list):
                    continue
                for pi, item in enumerate(values):
                    iw = f"{where}: policy.{bucket}[{pi}]"
                    _require(isinstance(item, dict), f"{iw} must be object", errors)
                    if not isinstance(item, dict):
                        continue
                    rule = item.get("rule_id")
                    _require(
                        isinstance(rule, str) and bool(RULE_RE.fullmatch(rule)),
                        f"{iw}: invalid rule_id",
                        errors,
                    )
                    _validate_evidence(item.get("evidence_state"), iw, errors)
                    _require(bool(item.get("reason")), f"{iw}: reason required", errors)
                    if isinstance(rule, str) and bucket in {"required", "forbidden"}:
                        policy_pairs.append((bucket, rule))

        assertions = case.get("regression_assertions")
        _require(
            isinstance(assertions, list),
            f"{where}: regression_assertions must be list",
            errors,
        )
        assertion_pairs: set[tuple[str, str]] = set()
        if isinstance(assertions, list):
            for ai, assertion in enumerate(assertions):
                aw = f"{where}: regression_assertions[{ai}]"
                _require(isinstance(assertion, dict), f"{aw} must be object", errors)
                if not isinstance(assertion, dict):
                    continue
                atype = assertion.get("type")
                _require(atype in ASSERTION_TYPES, f"{aw}: unsupported type {atype!r}", errors)
                if atype and str(atype).startswith("finding_"):
                    rule = assertion.get("rule_id")
                    _require(
                        isinstance(rule, str) and bool(RULE_RE.fullmatch(rule)),
                        f"{aw}: invalid rule_id",
                        errors,
                    )
                    if isinstance(rule, str):
                        mapped = (
                            "required"
                            if atype == "finding_present"
                            else "forbidden"
                            if atype == "finding_absent"
                            else "count"
                        )
                        assertion_pairs.add((mapped, rule))
                    if atype == "finding_max_count":
                        _require(
                            isinstance(assertion.get("value"), int),
                            f"{aw}: integer value required",
                            errors,
                        )
                elif atype in {"summary_min", "summary_max", "summary_exact"}:
                    _require(bool(assertion.get("field")), f"{aw}: summary field required", errors)
                    _require(
                        isinstance(assertion.get("value"), int),
                        f"{aw}: integer value required",
                        errors,
                    )

        for bucket, rule in policy_pairs:
            mapped = "required" if bucket == "required" else "forbidden"
            _require(
                (mapped, rule) in assertion_pairs,
                f"{where}: policy {bucket} {rule} lacks matching regression assertion",
                errors,
            )

    return errors


def _finding_matches(finding: dict[str, Any], assertion: dict[str, Any]) -> bool:
    if finding.get("rule_id") != assertion.get("rule_id"):
        return False
    wanted_path = assertion.get("path_contains")
    if wanted_path:
        location = finding.get("location")
        path = location.get("path") if isinstance(location, dict) else None
        if not isinstance(path, str) or str(wanted_path) not in path:
            return False
    wanted_agent = assertion.get("agent")
    if wanted_agent and finding.get("agent") != wanted_agent:
        return False
    return True


def evaluate_assertion(
    case_result: dict[str, Any],
    assertion: dict[str, Any],
) -> tuple[bool, str]:
    atype = assertion["type"]
    findings = case_result.get("findings") or []
    if not isinstance(findings, list):
        findings = []

    if atype.startswith("finding_"):
        matches = [
            finding
            for finding in findings
            if isinstance(finding, dict) and _finding_matches(finding, assertion)
        ]
        if atype == "finding_present":
            return bool(matches), f"expected finding {assertion['rule_id']}; observed {len(matches)}"
        if atype == "finding_absent":
            return not matches, f"forbidden finding {assertion['rule_id']}; observed {len(matches)}"
        if atype == "finding_max_count":
            limit = assertion["value"]
            return len(matches) <= limit, (
                f"finding {assertion['rule_id']} count {len(matches)} <= {limit}"
            )

    observed = case_result.get("observed") or {}
    summary = observed.get("summary") if isinstance(observed, dict) else {}
    if not isinstance(summary, dict):
        summary = {}
    field = assertion["field"]
    actual = summary.get(field)
    expected = assertion["value"]
    if not isinstance(actual, int):
        return False, f"summary.{field} missing/non-integer"
    if atype == "summary_min":
        return actual >= expected, f"summary.{field}={actual} >= {expected}"
    if atype == "summary_max":
        return actual <= expected, f"summary.{field}={actual} <= {expected}"
    if atype == "summary_exact":
        return actual == expected, f"summary.{field}={actual} == {expected}"
    raise ValueError(f"unsupported assertion type: {atype}")


def score(result: dict[str, Any], benchmark: dict[str, Any]) -> dict[str, Any]:
    errors = validate(benchmark)
    if errors:
        raise ValueError("invalid benchmark: " + "; ".join(errors))

    result_cases = {
        case.get("case_id"): case
        for case in result.get("cases", [])
        if isinstance(case, dict) and isinstance(case.get("case_id"), str)
    }
    output_cases: list[dict[str, Any]] = []
    passed = failed = 0

    for benchmark_case in benchmark["cases"]:
        case_id = benchmark_case["case_id"]
        case_result = result_cases.get(case_id)
        rows: list[dict[str, Any]] = []
        if case_result is None:
            rows = [
                {
                    "assertion": assertion,
                    "passed": False,
                    "detail": "case missing from scanner result",
                }
                for assertion in benchmark_case["regression_assertions"]
            ]
        else:
            for assertion in benchmark_case["regression_assertions"]:
                ok, detail = evaluate_assertion(case_result, assertion)
                rows.append({"assertion": assertion, "passed": ok, "detail": detail})
        case_passed = sum(1 for row in rows if row["passed"])
        case_failed = len(rows) - case_passed
        passed += case_passed
        failed += case_failed
        output_cases.append(
            {
                "case_id": case_id,
                "repo": benchmark_case["source_reference"]["repo"],
                "passed": case_passed,
                "failed": case_failed,
                "assertions": rows,
            }
        )

    total = passed + failed
    return {
        "benchmark": benchmark["benchmark"],
        "scanner_sha": result.get("scanner_sha"),
        "assertions": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": (passed / total) if total else None,
        "cases": output_cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("benchmark", type=Path)
    parser.add_argument("--result", type=Path, help="Frozen/postfix study result JSON to score")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on validation/scoring failures",
    )
    args = parser.parse_args()

    benchmark = load_json(args.benchmark)
    errors = validate(benchmark)
    if errors:
        payload: dict[str, Any] = {"valid": False, "errors": errors}
        code = 2
    elif args.result:
        payload = score(load_json(args.result), benchmark)
        payload["valid"] = True
        code = 2 if args.strict and payload["failed"] else 0
    else:
        payload = {
            "valid": True,
            "benchmark": benchmark.get("benchmark"),
            "cases": len(benchmark["cases"]),
        }
        code = 0

    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
