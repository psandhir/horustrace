from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _module():
    path = Path("scripts/real_world_agent_security_adjudicated.py")
    spec = importlib.util.spec_from_file_location(
        "real_world_agent_security_adjudicated",
        path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _candidate(*, precision_eligible: bool = True) -> dict:
    return {
        "study": "real-world-agent-security-2026",
        "scanner_sha": "a" * 40,
        "cohort_cases": 1,
        "metrics": {
            "effective_authority": {
                "truth": 2,
                "predicted": 2,
                "tp": 1,
                "fn": 1,
                "precision_complete_cases": 1,
                "precision_tp": 1,
                "fp": 1,
                "precision": 0.5,
                "recall": 0.5,
            }
        },
        "cases": [
            {
                "case_id": "rw-test",
                "repo": "example/repo",
                "framework": "test",
                "comparisons": {
                    "effective_authority": {
                        "truth": 2,
                        "predicted": 2,
                        "tp": 1,
                        "fn": 1,
                        "fp_if_complete": 1,
                        "precision_eligible": precision_eligible,
                        "matched_pairs": [
                            {
                                "agent": "agent",
                                "target_kind": "tool",
                                "target_name": "keep",
                            }
                        ],
                        "missing_pairs": [
                            {
                                "agent": "agent",
                                "target_kind": "tool",
                                "target_name": "old",
                            }
                        ],
                        "extra_pairs": [
                            {
                                "agent": "agent",
                                "target_kind": "tool",
                                "target_name": "new",
                            }
                        ],
                    }
                },
            }
        ],
    }


def test_replacement_patch_turns_fp_and_fn_into_tp() -> None:
    module = _module()
    report = module.rescore(
        _candidate(),
        {
            "rw-test": {
                "classification": "ground_truth_error",
                "remove": [
                    {"agent": "agent", "target_kind": "tool", "target_name": "old"}
                ],
                "add": [
                    {"agent": "agent", "target_kind": "tool", "target_name": "new"}
                ],
                "unresolved": [],
            }
        },
    )

    adjusted = report["authority"]["post_hoc_adjudicated"]
    assert adjusted["tp"] == 2
    assert adjusted["fn"] == 0
    assert adjusted["fp"] == 0
    assert adjusted["precision"] == 1.0
    assert adjusted["recall"] == 1.0


def test_add_patch_promotes_existing_extra_prediction() -> None:
    module = _module()
    candidate = _candidate()
    authority = candidate["cases"][0]["comparisons"]["effective_authority"]
    authority["missing_pairs"] = []
    authority["truth"] = 1
    authority["fn"] = 0

    report = module.rescore(
        candidate,
        {
            "rw-test": {
                "classification": "ground_truth_error",
                "remove": [],
                "add": [
                    {"agent": "agent", "target_kind": "tool", "target_name": "new"}
                ],
                "unresolved": [],
            }
        },
    )

    adjusted = report["authority"]["post_hoc_adjudicated"]
    assert adjusted["truth"] == 2
    assert adjusted["tp"] == 2
    assert adjusted["fp"] == 0


def test_unresolved_patch_is_reported_without_becoming_present_truth() -> None:
    module = _module()
    report = module.rescore(
        _candidate(),
        {
            "rw-test": {
                "classification": "ambiguous_evidence",
                "remove": [
                    {"agent": "agent", "target_kind": "tool", "target_name": "old"}
                ],
                "add": [],
                "unresolved": [
                    {
                        "agent": "agent",
                        "target_kind": "tool",
                        "target_name": "dynamic-binding",
                    }
                ],
            }
        },
    )

    adjusted = report["authority"]["post_hoc_adjudicated"]
    assert adjusted["truth"] == 1
    assert adjusted["tp"] == 1
    assert adjusted["fn"] == 0
    assert adjusted["unresolved_corrections"] == 1
    # The existing extra prediction remains a precision error; unresolved does
    # not silently bless it.
    assert adjusted["fp"] == 1


def test_duplicate_predictions_are_matched_one_to_one() -> None:
    module = _module()
    candidate = _candidate()
    authority = candidate["cases"][0]["comparisons"]["effective_authority"]
    authority["matched_pairs"] = []
    authority["missing_pairs"] = [
        {"agent": "agent", "target_kind": "tool", "target_name": "same"}
    ]
    authority["extra_pairs"] = [
        {"agent": "agent", "target_kind": "tool", "target_name": "same"},
        {"agent": "agent", "target_kind": "tool", "target_name": "same"},
    ]
    authority["truth"] = 1
    authority["predicted"] = 2
    authority["tp"] = 0
    authority["fn"] = 1
    authority["fp_if_complete"] = 2

    report = module.rescore(candidate, {})
    adjusted = report["authority"]["post_hoc_adjudicated"]

    assert adjusted["tp"] == 1
    assert adjusted["fn"] == 0
    assert adjusted["fp"] == 1


def test_precision_scope_stays_on_original_complete_cases() -> None:
    module = _module()
    report = module.rescore(
        _candidate(precision_eligible=False),
        {
            "rw-test": {
                "classification": "ground_truth_error",
                "remove": [
                    {"agent": "agent", "target_kind": "tool", "target_name": "old"}
                ],
                "add": [
                    {"agent": "agent", "target_kind": "tool", "target_name": "new"}
                ],
                "unresolved": [],
            }
        },
    )

    adjusted = report["authority"]["post_hoc_adjudicated"]
    assert adjusted["precision_complete_cases"] == 0
    assert adjusted["precision"] is None
    assert adjusted["recall"] == 1.0


def test_load_authority_patches_ignores_non_authority_adjudications(
    tmp_path: Path,
) -> None:
    module = _module()
    (tmp_path / "agent.json").write_text(
        json.dumps(
            {
                "study": "real-world-agent-security-2026",
                "case_id": "rw-agent",
                "dimension": "agent_entities",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "authority.json").write_text(
        json.dumps(
            {
                "study": "real-world-agent-security-2026",
                "case_id": "rw-test",
                "classification": "ground_truth_error",
                "authority_truth_patch": {
                    "remove": [],
                    "add": [
                        {
                            "agent": "Agent A",
                            "target_kind": "tool",
                            "target_name": "Tool A",
                        }
                    ],
                    "unresolved": [],
                },
            }
        ),
        encoding="utf-8",
    )

    patches = module.load_authority_patches(tmp_path)

    assert set(patches) == {"rw-test"}
    assert patches["rw-test"]["classification"] == "ground_truth_error"
