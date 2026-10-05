"""Run the locked Agent Skill LLM semantic calibration study.

The study exercises the production skill-security-semantics prompt through
enrich_skill_llm_semantics. It scores semantic classification only; deterministic
Effective Authority correlation is already covered separately by unit tests.

Targets are synthetic SKILL.md documents from a frozen, hand-labelled corpus.
No target code is imported or executed.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from horustrace.llm_semantics import LLMSemanticConfig
from horustrace.models import Agent, Graph
from horustrace.skill_llm_semantics import (
    PROMPT_VERSION,
    SKILL_SECURITY_CONCEPTS,
    enrich_skill_llm_semantics,
)
from horustrace.skills import scan_skill_file

STUDY = "skill-llm-calibration-v1"
SCHEMA_VERSION = 1
DEFAULT_THRESHOLDS = (0.65, 0.75, 0.85)


class StudyError(ValueError):
    """Calibration input or execution is invalid."""


def load_cohort(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StudyError(f"{path}: cannot load cohort: {exc}") from exc
    if not isinstance(value, dict):
        raise StudyError(f"{path}: expected a JSON object")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise StudyError(
            f"{path}: schema_version must be {SCHEMA_VERSION}"
        )
    if value.get("study") != STUDY:
        raise StudyError(f"{path}: study must be {STUDY}")
    if value.get("prompt_version") != PROMPT_VERSION:
        raise StudyError(
            f"{path}: prompt_version must match production {PROMPT_VERSION}"
        )

    taxonomy = value.get("taxonomy")
    expected_taxonomy = list(SKILL_SECURITY_CONCEPTS)
    if taxonomy != expected_taxonomy:
        raise StudyError(
            f"{path}: taxonomy must exactly match production taxonomy"
        )

    thresholds = value.get("thresholds")
    if not isinstance(thresholds, list) or not thresholds:
        raise StudyError(f"{path}: thresholds must be a non-empty list")
    normalized_thresholds: list[float] = []
    for threshold in thresholds:
        if (
            not isinstance(threshold, (int, float))
            or not 0.0 <= float(threshold) <= 1.0
        ):
            raise StudyError(f"{path}: invalid threshold {threshold!r}")
        normalized_thresholds.append(float(threshold))
    if len(normalized_thresholds) != len(set(normalized_thresholds)):
        raise StudyError(f"{path}: thresholds must be unique")

    cases = value.get("cases")
    if not isinstance(cases, list) or not cases:
        raise StudyError(f"{path}: cases must be a non-empty list")
    seen: set[str] = set()
    allowed = set(expected_taxonomy)
    for index, case in enumerate(cases):
        where = f"{path}: cases[{index}]"
        if not isinstance(case, dict):
            raise StudyError(f"{where}: expected object")
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise StudyError(f"{where}.case_id: expected non-empty string")
        if case_id in seen:
            raise StudyError(f"{where}.case_id: duplicate {case_id}")
        seen.add(case_id)
        if case.get("difficulty") not in {
            "explicit",
            "inferred",
            "hard_negative",
            "multilabel",
        }:
            raise StudyError(f"{where}.difficulty: invalid stratum")
        instructions = case.get("instructions")
        if not isinstance(instructions, str) or not instructions.strip():
            raise StudyError(f"{where}.instructions: expected non-empty string")
        references = case.get("references")
        if not isinstance(references, dict) or any(
            not isinstance(name, str)
            or not name
            or not isinstance(text, str)
            for name, text in references.items()
        ):
            raise StudyError(f"{where}.references: expected string mapping")
        expected = case.get("expected_concepts")
        if not isinstance(expected, list) or any(
            not isinstance(item, str) or item not in allowed
            for item in expected
        ):
            raise StudyError(f"{where}.expected_concepts: invalid concept list")
        if len(expected) != len(set(expected)):
            raise StudyError(f"{where}.expected_concepts: duplicate concept")
        rationale = case.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise StudyError(f"{where}.rationale: expected non-empty string")

    value["thresholds"] = normalized_thresholds
    return value


def _materialize_case(root: Path, case: dict[str, Any]) -> tuple[Graph, Any]:
    case_root = root / str(case["case_id"])
    skill_dir = case_root / "skill"
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_path = skill_dir / "SKILL.md"
    skill_path.write_text(
        "---\n"
        f"name: {case['case_id']}\n"
        "description: Locked HorusTrace Skill semantic calibration case.\n"
        "---\n"
        + str(case["instructions"]).strip()
        + "\n",
        encoding="utf-8",
    )
    references = case.get("references") or {}
    for relative, text in references.items():
        target = skill_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(text), encoding="utf-8")

    skill = scan_skill_file(skill_path)
    if skill is None:
        raise StudyError(f"{case['case_id']}: synthetic Skill could not be parsed")
    skill.metadata["binding_state"] = "bound"
    skill.metadata["binding_origin"] = "calibration_fixture"
    skill.metadata["bound_agent"] = f"calibration-{case['case_id']}"

    agent = Agent(
        name=f"calibration-{case['case_id']}",
        skills=[skill],
        metadata={"framework": "skill-calibration"},
    )
    return Graph(agents=[agent]), skill


def _concept_map(semantics: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = semantics.get("concepts")
    if not isinstance(raw, list):
        raise StudyError("semantic output is missing concepts")
    result: dict[str, dict[str, Any]] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise StudyError("semantic output has non-object concept")
        concept = item.get("concept")
        if concept not in SKILL_SECURITY_CONCEPTS:
            raise StudyError(f"semantic output has unknown concept {concept!r}")
        result[str(concept)] = item
    if set(result) != set(SKILL_SECURITY_CONCEPTS):
        raise StudyError("semantic output does not cover full taxonomy")
    return result


def _division(numerator: int | float, denominator: int | float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _f1(precision: float, recall: float) -> float:
    return (
        2.0 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )


def score_results(
    case_results: list[dict[str, Any]],
    threshold: float,
) -> dict[str, Any]:
    matrix = {
        concept: {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for concept in SKILL_SECURITY_CONCEPTS
    }
    exact_cases = 0
    total_labels = 0
    correct_labels = 0
    difficulty = defaultdict(
        lambda: {
            "cases": 0,
            "exact_cases": 0,
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "tn": 0,
        }
    )
    errors: list[dict[str, Any]] = []

    for result in case_results:
        expected = set(result["expected_concepts"])
        concepts = _concept_map(result["semantics"])
        predicted = {
            concept
            for concept, item in concepts.items()
            if item.get("present") is True
            and isinstance(item.get("confidence"), (int, float))
            and float(item["confidence"]) >= threshold
        }
        if predicted == expected:
            exact_cases += 1

        stratum = difficulty[str(result["difficulty"])]
        stratum["cases"] += 1
        if predicted == expected:
            stratum["exact_cases"] += 1

        case_fp = sorted(predicted - expected)
        case_fn = sorted(expected - predicted)
        if case_fp or case_fn:
            errors.append(
                {
                    "case_id": result["case_id"],
                    "difficulty": result["difficulty"],
                    "false_positives": case_fp,
                    "false_negatives": case_fn,
                    "expected": sorted(expected),
                    "predicted": sorted(predicted),
                    "concept_details": {
                        concept: concepts[concept]
                        for concept in sorted(set(case_fp) | set(case_fn))
                    },
                }
            )

        for concept in SKILL_SECURITY_CONCEPTS:
            truth = concept in expected
            observed = concept in predicted
            total_labels += 1
            if truth == observed:
                correct_labels += 1
            if truth and observed:
                bucket = "tp"
            elif not truth and observed:
                bucket = "fp"
            elif truth and not observed:
                bucket = "fn"
            else:
                bucket = "tn"
            matrix[concept][bucket] += 1
            stratum[bucket] += 1

    per_concept: dict[str, Any] = {}
    for concept, counts in matrix.items():
        precision = _division(counts["tp"], counts["tp"] + counts["fp"])
        recall = _division(counts["tp"], counts["tp"] + counts["fn"])
        per_concept[concept] = {
            **counts,
            "support_positive": counts["tp"] + counts["fn"],
            "support_negative": counts["fp"] + counts["tn"],
            "precision": precision,
            "recall": recall,
            "f1": _f1(precision, recall),
            "accuracy": _division(
                counts["tp"] + counts["tn"],
                sum(counts.values()),
            ),
        }

    totals = {
        key: sum(counts[key] for counts in matrix.values())
        for key in ("tp", "fp", "fn", "tn")
    }
    micro_precision = _division(
        totals["tp"], totals["tp"] + totals["fp"]
    )
    micro_recall = _division(
        totals["tp"], totals["tp"] + totals["fn"]
    )
    macro_precision = sum(
        item["precision"] for item in per_concept.values()
    ) / len(per_concept)
    macro_recall = sum(
        item["recall"] for item in per_concept.values()
    ) / len(per_concept)
    macro_f1 = sum(
        item["f1"] for item in per_concept.values()
    ) / len(per_concept)

    difficulty_report: dict[str, Any] = {}
    for name, counts in sorted(difficulty.items()):
        precision = _division(counts["tp"], counts["tp"] + counts["fp"])
        recall = _division(counts["tp"], counts["tp"] + counts["fn"])
        difficulty_report[name] = {
            **counts,
            "exact_case_accuracy": _division(
                counts["exact_cases"], counts["cases"]
            ),
            "precision": precision,
            "recall": recall,
            "f1": _f1(precision, recall),
        }

    return {
        "threshold": threshold,
        "cases": len(case_results),
        "labels": total_labels,
        "exact_cases": exact_cases,
        "exact_case_accuracy": _division(exact_cases, len(case_results)),
        "label_accuracy": _division(correct_labels, total_labels),
        "micro": {
            **totals,
            "precision": micro_precision,
            "recall": micro_recall,
            "f1": _f1(micro_precision, micro_recall),
        },
        "macro": {
            "precision": macro_precision,
            "recall": macro_recall,
            "f1": macro_f1,
        },
        "per_concept": per_concept,
        "by_difficulty": difficulty_report,
        "errors": errors,
    }


def _recommended_threshold(scores: list[dict[str, Any]]) -> float:
    # Prefer macro F1. Tie-break toward higher precision, then the threshold
    # closest to the production default of 0.75.
    return float(
        max(
            scores,
            key=lambda item: (
                item["macro"]["f1"],
                item["micro"]["precision"],
                -abs(float(item["threshold"]) - 0.75),
            ),
        )["threshold"]
    )


def _confidence_bins(case_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges = ((0.0, 0.5), (0.5, 0.65), (0.65, 0.75), (0.75, 0.85), (0.85, 0.95), (0.95, 1.000001))
    bins: list[dict[str, Any]] = []
    for lower, upper in edges:
        total = 0
        correct = 0
        predicted_present = 0
        true_present = 0
        for result in case_results:
            expected = set(result["expected_concepts"])
            for concept, item in _concept_map(result["semantics"]).items():
                confidence = item.get("confidence")
                if not isinstance(confidence, (int, float)):
                    continue
                confidence = float(confidence)
                if not lower <= confidence < upper:
                    continue
                total += 1
                present = item.get("present") is True
                truth = concept in expected
                if present:
                    predicted_present += 1
                if truth:
                    true_present += 1
                if present == truth:
                    correct += 1
        bins.append(
            {
                "range": f"[{lower:.2f},{min(upper, 1.0):.2f}]",
                "labels": total,
                "accuracy": _division(correct, total),
                "predicted_present": predicted_present,
                "true_present": true_present,
            }
        )
    return bins


def run_case(
    case: dict[str, Any],
    workspace: Path,
    config: LLMSemanticConfig,
) -> dict[str, Any]:
    graph, skill = _materialize_case(workspace, case)
    stats = enrich_skill_llm_semantics(
        graph,
        workspace,
        config,
    )
    semantics = skill.metadata.get("llm_security_semantics")
    if not isinstance(semantics, dict):
        errors = stats.get("error_messages") if isinstance(stats, dict) else None
        raise StudyError(
            f"{case['case_id']}: no semantic output was applied; errors={errors!r}"
        )
    return {
        "case_id": case["case_id"],
        "difficulty": case["difficulty"],
        "expected_concepts": sorted(case["expected_concepts"]),
        "rationale": case["rationale"],
        "overall_confidence": semantics.get("overall_confidence"),
        "semantics": semantics,
        "stats": stats,
    }


def build_report(
    cohort: dict[str, Any],
    case_results: list[dict[str, Any]],
    *,
    provider: str,
    model: str,
) -> dict[str, Any]:
    thresholds = [
        float(value)
        for value in cohort.get("thresholds", DEFAULT_THRESHOLDS)
    ]
    scores = [
        score_results(case_results, threshold)
        for threshold in thresholds
    ]
    recommended = _recommended_threshold(scores)
    return {
        "schema_version": SCHEMA_VERSION,
        "study": STUDY,
        "prompt_version": PROMPT_VERSION,
        "provider": provider,
        "model": model,
        "scanner_sha": os.environ.get("GITHUB_SHA"),
        "design": cohort.get("design"),
        "summary": {
            "cases": len(case_results),
            "labels": len(case_results) * len(SKILL_SECURITY_CONCEPTS),
            "thresholds": thresholds,
            "recommended_threshold": recommended,
            "execution_errors": 0,
        },
        "threshold_scores": scores,
        "confidence_bins": _confidence_bins(case_results),
        "cases": case_results,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    recommended = summary["recommended_threshold"]
    chosen = next(
        item
        for item in report["threshold_scores"]
        if math.isclose(float(item["threshold"]), float(recommended))
    )
    lines = [
        "# Agent Skill LLM semantic calibration v1",
        "",
        (
            f"Model: `{report['provider']}:{report['model']}`; "
            f"prompt: `{report['prompt_version']}`."
        ),
        "",
        (
            "The corpus is hand-labelled and synthetic. The study measures semantic "
            "concept classification only; LLM output does not grant authority or emit "
            "findings."
        ),
        "",
        "## Summary",
        "",
        "| Metric | Result |",
        "| --- | ---: |",
        f"| Cases | {summary['cases']} |",
        f"| Binary concept labels | {summary['labels']} |",
        f"| Recommended confidence threshold | {recommended:.2f} |",
        f"| Exact case accuracy | {chosen['exact_case_accuracy']:.3f} |",
        f"| Label accuracy | {chosen['label_accuracy']:.3f} |",
        f"| Micro precision | {chosen['micro']['precision']:.3f} |",
        f"| Micro recall | {chosen['micro']['recall']:.3f} |",
        f"| Micro F1 | {chosen['micro']['f1']:.3f} |",
        f"| Macro F1 | {chosen['macro']['f1']:.3f} |",
        "",
        "## Threshold sweep",
        "",
        "| Threshold | Exact cases | Micro P | Micro R | Micro F1 | Macro F1 | FP | FN |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for score in report["threshold_scores"]:
        lines.append(
            f"| {score['threshold']:.2f} | "
            f"{score['exact_case_accuracy']:.3f} | "
            f"{score['micro']['precision']:.3f} | "
            f"{score['micro']['recall']:.3f} | "
            f"{score['micro']['f1']:.3f} | "
            f"{score['macro']['f1']:.3f} | "
            f"{score['micro']['fp']} | {score['micro']['fn']} |"
        )

    lines.extend(
        [
            "",
            f"## Per-concept metrics at {recommended:.2f}",
            "",
            "| Concept | Support + | Precision | Recall | F1 | FP | FN |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for concept in SKILL_SECURITY_CONCEPTS:
        item = chosen["per_concept"][concept]
        lines.append(
            f"| {concept} | {item['support_positive']} | "
            f"{item['precision']:.3f} | {item['recall']:.3f} | "
            f"{item['f1']:.3f} | {item['fp']} | {item['fn']} |"
        )

    lines.extend(
        [
            "",
            "## Difficulty breakdown",
            "",
            "| Stratum | Cases | Exact | Precision | Recall | F1 |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for name, item in chosen["by_difficulty"].items():
        lines.append(
            f"| {name} | {item['cases']} | "
            f"{item['exact_case_accuracy']:.3f} | "
            f"{item['precision']:.3f} | {item['recall']:.3f} | "
            f"{item['f1']:.3f} |"
        )

    lines.extend(["", "## Errors at recommended threshold", ""])
    if not chosen["errors"]:
        lines.append("No false-positive or false-negative concept labels.")
    else:
        for item in chosen["errors"]:
            lines.extend(
                [
                    f"### {item['case_id']} ({item['difficulty']})",
                    "",
                    "False positives: "
                    + (", ".join(item["false_positives"]) or "none"),
                    "",
                    "False negatives: "
                    + (", ".join(item["false_negatives"]) or "none"),
                    "",
                ]
            )
            for concept, detail in item["concept_details"].items():
                lines.append(
                    f"- `{concept}`: present={detail.get('present')}, "
                    f"confidence={detail.get('confidence')}, "
                    f"intent={detail.get('intent')}; "
                    f"evidence={detail.get('evidence')}"
                )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cohort",
        type=Path,
        default=Path("research/skill-llm-calibration-v1/cohort.json"),
    )
    parser.add_argument("--provider", default="openai")
    parser.add_argument("--model", default="gpt-6.1-sol")
    parser.add_argument(
        "--cache",
        type=Path,
        default=Path(".cache/skill-llm-calibration-v1.json"),
    )
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-markdown", type=Path)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        cohort = load_cohort(args.cohort)
        if args.validate_only:
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "study": STUDY,
                        "prompt_version": PROMPT_VERSION,
                        "cases": len(cohort["cases"]),
                        "valid": True,
                    },
                    indent=2,
                )
            )
            return 0

        config = LLMSemanticConfig(
            provider=args.provider,
            model=args.model,
            max_candidates=1,
            max_slice_chars=12_000,
            max_total_chars=12_000,
            min_confidence=0.0,
            cache_path=args.cache,
            fail_open=False,
        )
        config.validate()

        cleanup = args.workspace is None
        if args.workspace is None:
            workspace = Path(
                tempfile.mkdtemp(prefix="horustrace-skill-calibration-")
            )
        else:
            workspace = args.workspace
            workspace.mkdir(parents=True, exist_ok=True)

        try:
            results = [
                run_case(case, workspace, config)
                for case in cohort["cases"]
            ]
        finally:
            if cleanup:
                shutil.rmtree(workspace, ignore_errors=True)

        report = build_report(
            cohort,
            results,
            provider=args.provider,
            model=args.model,
        )
        output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        markdown = render_markdown(report)

        if args.output_json is not None:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(output, encoding="utf-8")
        if args.output_markdown is not None:
            args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
            args.output_markdown.write_text(markdown, encoding="utf-8")

        print(output, end="")
        return 0
    except StudyError as exc:
        print(f"skill calibration: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
