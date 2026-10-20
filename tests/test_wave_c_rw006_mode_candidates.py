"""C02l: source-pinned rw-006 conditional ADK factory, not a deployed graph."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "research/wave-c-c02l-rw006/rw-006-delegation-mode-candidates.json"
POPULATION = ROOT / "research/wave-c-c02f-active145/expected-agent-review-scopes.json"

_BLOBS = {
    "adk_deepagents/types.py": "7476bbad8eaf9b72e847614c902d59328b97a546",
    "adk_deepagents/graph.py": "6016c01a60b4df00cf91a1df6ad73aabdf9fb0ee",
    "adk_deepagents/tools/task.py": "03d9a3f35a3f3b2362f5276ada6ba066000407b1",
    "adk_deepagents/tools/task_dynamic_execution.py":
        "d0b6a5f333886f0e697aecbc6b93546a32e18ae2",
    "adk_deepagents/tools/task_dynamic.py":
        "32e1e8080336d2dfd58c6cebe969d02863e23b12",
}
_SHA = re.compile(r"[0-9a-f]{40}\Z")


def _load() -> dict:
    return json.loads(SEED.read_text(encoding="utf-8"))


def test_rw006_source_case_is_exact_active145_excluding_langgraph() -> None:
    data = _load()
    cohort = json.loads(POPULATION.read_text(encoding="utf-8"))
    row = next(x for x in cohort["expected_scopes"] if x["case_id"] == "rw-006")
    assert data["schema_version"] == 1
    assert data["case_id"] == row["case_id"]
    assert data["repository"] == row["repository"] == "manojlds/adk-deepagents"
    assert data["cohort_scope_id"] == row["scope_id"]
    assert data["pinned_commit_sha"] == row["commit_sha"]
    assert data["framework"] == row["framework"] == "google-adk"
    assert data["source_role"] == row["source_role"] == "unknown"
    assert _SHA.fullmatch(data["pinned_commit_sha"])


def test_rw006_source_anchors_have_unique_ids_and_real_blob_pins() -> None:
    sites = _load()["observations"]
    assert len(sites) == 30
    assert len({s["id"] for s in sites}) == len(sites)
    assert {s["path"] for s in sites} == set(_BLOBS)
    for s in sites:
        assert s["id"].startswith("rw006-")
        assert s["blob_sha"] == _BLOBS[s["path"]]
        assert _SHA.fullmatch(s["blob_sha"])
        assert s["line_start"] > 0
        assert s["line_start"] == s["line_end"]
        assert s["source_expression"]
        assert s["review_question"]
        assert "truth" not in s and "expected_label" not in s


def test_rw006_mode_matrix_conditions_match_source_branches() -> None:
    data = _load()
    modes = {m["delegation_mode"]: m for m in data["mode_candidates"]}
    assert set(modes) == {"static", "dynamic", "both"}
    for name in ("static", "dynamic", "both"):
        m = modes[name]
        assert m["conditional_static_subagent_tool_path"] == (
            name in {"static", "both"}
        )
        assert m["conditional_dynamic_registration_tool_path"] == (
            name in {"dynamic", "both"}
        )
        assert m["conditional_dynamic_task_tool_path"] == (
            name in {"dynamic", "both"}
        )
        assert m["general_purpose_prompt_description_path"] is True
        assert m["runtime_tool_catalogue_verified"] is False
        assert m["source_only"] is True
    assert next(s["source_expression"] for s in data["observations"]
                if s["id"] == "rw006-types-default-static") == (
                    'delegation_mode: Literal["static", "dynamic", "both"] = "static"'
                )


def test_rw006_do_not_turn_prompt_description_into_static_instance() -> None:
    data = _load()
    modes = {m["delegation_mode"]: m for m in data["mode_candidates"]}
    assert modes["dynamic"]["conditional_static_subagent_tool_path"] is False
    assert modes["dynamic"]["general_purpose_prompt_description_path"] is True
    by_id = {s["id"]: s for s in data["observations"]}
    assert 'in {"static", "both"}' in (
        by_id["rw006-static-branch"]["source_expression"]
    )
    assert 'in {"dynamic", "both"}' in (
        by_id["rw006-dynamic-branch"]["source_expression"]
    )
    assert "subagent_descriptions" not in (
        by_id["rw006-static-branch"]["source_expression"]
    )


def test_rw006_static_builder_wraps_prebuilt_without_new_constructor() -> None:
    sites = _load()["observations"]
    observed = {x["id"]: x for x in sites}
    assert observed["rw006-task-prebuilt-agent"]["source_expression"] == (
        "tools.append(AgentTool(agent=agent))"
    )
    assert observed["rw006-task-spec-constructor"]["source_expression"] == (
        "sub_agent = LlmAgent("
    )
    assert observed["rw006-task-wrapper-spec"]["source_expression"] == (
        "tools.append(AgentTool(agent=sub_agent))"
    )
    assert "include_general_purpose=True" in (
        observed["rw006-static-include-general"]["source_expression"]
    )
    assert observed["rw006-task-dedupe-general"]["source_expression"] == (
        'if "general_purpose" not in all_names:'
    )
    assert observed["rw006-task-general-purpose-spec"]["kind"] == (
        "general_purpose_spec_definition_syntax"
    )


def test_rw006_dynamic_tool_factories_are_not_runtime_subagents() -> None:
    observed = {x["id"]: x for x in _load()["observations"]}
    assert observed["rw006-dynamic-register-tool"]["source_expression"] == (
        "create_register_subagent_tool("
    )
    assert observed["rw006-dynamic-task-tool"]["source_expression"] == (
        "create_dynamic_task_tool("
    )
    assert observed["rw006-dynamic-subagent-constructor"]["source_expression"] == (
        "return LlmAgent("
    )
    assert observed["rw006-dynamic-builder"]["kind"] == (
        "dynamic_agent_factory_definition_syntax"
    )
    kinds = Counter(x["kind"] for x in observed.values())
    assert kinds["parent_agent_constructor_syntax"] == 1
    assert kinds["dynamic_agent_constructor_in_factory_syntax"] == 1
    assert kinds["subagent_constructor_in_factory_syntax"] == 1
    assert "runtime_agent_instance_observed" not in kinds


def test_rw006_source_review_is_never_independent_release_certification() -> None:
    data = _load()
    assert data["record_type"] == (
        "source_first_mode_sensitive_syntax_candidates_not_oracle_truth"
    )
    for key in (
        "scanner_predictions_consulted_in_this_review",
        "source_reviewer_independence_externally_verified",
        "source_blindness_externally_verified",
        "positive_universe_complete",
        "negative_universe_complete",
        "runtime_imports_verified",
        "runtime_agent_callable_verified",
        "release_accuracy_assessable",
    ):
        assert data[key] is False
    assert not any(
        s["kind"] == "verified_runtime_agent_instance"
        for s in data["observations"]
    )
