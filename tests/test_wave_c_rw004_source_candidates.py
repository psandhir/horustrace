"""Source-visible rw-004 review seed: never a closed independent V2 oracle."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "research/wave-c-c02g-real-source/rw-004-source-candidates.json"
POPULATION = ROOT / "research/wave-c-c02f-active145/expected-agent-review-scopes.json"
SHA = re.compile(r"[0-9a-f]{40}\Z")


def test_rw004_source_candidates_pin_exact_active145_case() -> None:
    data = json.loads(SEED.read_text(encoding="utf-8"))
    population = json.loads(POPULATION.read_text(encoding="utf-8"))
    original = next(x for x in population["expected_scopes"]
                    if x["case_id"] == "rw-004")
    assert data["repository"] == original["repository"]
    assert data["pinned_commit_sha"] == original["commit_sha"]
    assert data["cohort_scope_id"] == original["scope_id"]
    assert data["framework"] == original["framework"]
    assert data["source_role"] == "unknown"
    assert SHA.fullmatch(data["pinned_commit_sha"])


def test_rw004_separates_constructor_sites_from_alias_and_tool_list() -> None:
    data = json.loads(SEED.read_text(encoding="utf-8"))
    sites = data["observations"]
    assert len(sites) >= 6
    assert len({x["id"] for x in sites}) == len(sites)
    constructors = [x for x in sites if x["kind"] == "agent_constructor_syntax"]
    aliases = [x for x in sites if x["kind"] == "same_file_agent_alias_syntax"]
    tools = [x for x in sites if x["kind"] == "tool_argument_list_syntax"]
    assert len(constructors) == 2
    assert {x["path"] for x in constructors} == {
        "agent.py", "agentGemini/agent.py",
    }
    assert len(aliases) == 1
    assert aliases[0]["source_expression"] == "root_agent = funnel_agent"
    assert len(tools) == 2
    assert all(x["source_expression"] == "tools=[" for x in tools)
    assert all(SHA.fullmatch(x["blob_sha"]) for x in sites)
    assert all(x["line_start"] > 0 and x["line_end"] >= x["line_start"]
               for x in sites)
    assert all(x["review_question"].strip() for x in sites)


def test_rw004_never_certifies_semantics_or_human_blinding() -> None:
    data = json.loads(SEED.read_text(encoding="utf-8"))
    assert data["record_type"] == "source_first_syntax_candidate_not_oracle_truth"
    for field in (
        "source_reviewer_independence_externally_verified",
        "source_blindness_externally_verified",
        "positive_universe_complete",
        "negative_universe_complete",
        "runtime_imports_verified",
        "runtime_agent_callable_verified",
        "release_accuracy_assessable",
    ):
        assert data[field] is False
    assert data["scanner_predictions_consulted_in_this_review"] is False
    assert not any("truth" in x or "expected_label" in x
                   for x in data["observations"])
