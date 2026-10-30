"""C02k pinned rw-005 source-first ADK evidence is NOT release truth."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "research/wave-c-c02g-real-source/rw-005-source-candidates.json"
POPULATION = ROOT / "research/wave-c-c02f-active145/expected-agent-review-scopes.json"

_BLOBS = {
    "agent.py": "89ce05579a18e8e09822d4157cace7121a5d7c99",
    "__init__.py": "4caf51810fb5cf8babe6391d31d2116d6f9be05d",
    "api.py": "bfed9d84fd977eb20a4e7f8453aebff675ac9faf",
    "requirements.txt": "4742c50311e93ede85fcfff2cfc44702aef56ec6",
    "tools/metrics_tools.py": "f1641c3f53ec5eb66516fdac15847d8067f8581d",
    "tools/schema_tools.py": "bdab09514401e679b08e101feb2fcb4023e18284",
}
_SHA = re.compile(r"[0-9a-f]{40}\Z")


def _load() -> dict:
    return json.loads(LEDGER.read_text(encoding="utf-8"))


def test_rw005_case_matches_immutable_active_non_langgraph_population() -> None:
    record = _load()
    population = json.loads(POPULATION.read_text(encoding="utf-8"))
    expected = next(x for x in population["expected_scopes"]
                    if x["case_id"] == "rw-005")
    assert record["schema_version"] == 1
    assert record["case_id"] == "rw-005"
    assert record["repository"] == expected["repository"] == "Ojas-Patil26/VeriQ"
    assert record["pinned_commit_sha"] == expected["commit_sha"]
    assert record["cohort_scope_id"] == expected["scope_id"]
    assert record["framework"] == expected["framework"] == "google-adk"
    assert record["source_role"] == expected["source_role"] == "unknown"
    assert _SHA.fullmatch(record["pinned_commit_sha"])


def test_rw005_sources_have_pinned_witnesses_and_unique_syntax_ids() -> None:
    sites = _load()["observations"]
    assert len(sites) == 34
    assert len({s["id"] for s in sites}) == len(sites)
    assert {s["path"] for s in sites} == set(_BLOBS)
    for site in sites:
        assert site["id"].startswith("rw005-")
        assert site["blob_sha"] == _BLOBS[site["path"]]
        assert _SHA.fullmatch(site["blob_sha"])
        assert 1 <= site["line_start"] <= site["line_end"]
        assert site["line_start"] == site["line_end"]
        assert site["source_expression"].strip()
        assert site["review_question"].strip()
        assert all("truth" not in k and "expected_label" not in k
                   for k in site)


def test_rw005_five_agent_constructors_not_aliases_or_paths() -> None:
    sites = _load()["observations"]
    constructors = [s for s in sites if s["kind"] == "agent_constructor_syntax"]
    assert len(constructors) == 5
    assert {s["line_start"] for s in constructors} == {17, 44, 70, 106, 134}
    assert all(s["path"] == "agent.py" for s in constructors)
    expected_names = {
        "ingestion_agent", "anomaly_agent", "root_cause_agent",
        "report_agent", "root_agent",
    }
    assert {s["source_expression"].split("=")[0].strip()
            for s in constructors} == expected_names
    assert all("LlmAgent(" in s["source_expression"] for s in constructors)
    # Import/export/Runner statements are never additional constructors.
    assert len([s for s in sites if s["kind"] == "runtime_wrapper_agent_alias_syntax"]) == 1
    assert len([s for s in sites if s["kind"] == "adk_runner_constructor_syntax"]) == 1


def test_rw005_declared_delegations_are_not_tool_bindings() -> None:
    sites = _load()["observations"]
    members = [s for s in sites
               if s["kind"] == "declared_subagent_membership_syntax"]
    assert {s["line_start"] for s in members} == {159, 160, 161, 162}
    assert {s["source_expression"] for s in members} == {
        "ingestion_agent,", "anomaly_agent,", "root_cause_agent,", "report_agent,",
    }
    assert all(s["path"] == "agent.py" for s in members)
    assert all(s["kind"] != "declared_tool_binding_syntax" for s in members)


def test_rw005_tool_bindings_preserve_distinct_owners_and_shared_symbols() -> None:
    sites = _load()["observations"]
    bindings = [s for s in sites if s["kind"] == "declared_tool_binding_syntax"]
    assert len(bindings) == 8
    assert {s["line_start"] for s in bindings} == {
        36, 37, 38, 63, 64, 98, 99, 100,
    }
    observed = Counter(s["source_expression"] for s in bindings)
    assert observed["get_metric_timeseries,"] == 2
    assert observed["get_metric_lineage,"] == 2
    assert sum(observed.values()) == 8
    assert len(observed) == 6
    assert len([s for s in sites
                if s["kind"] == "explicit_empty_direct_tool_list_syntax"]) == 1
    empty = next(s for s in sites
                 if s["kind"] == "explicit_empty_direct_tool_list_syntax")
    assert (empty["line_start"], empty["source_expression"]) == (129, "tools=[],")


def test_rw005_api_route_is_not_source_proof_of_agent_can_call() -> None:
    sites = _load()["observations"]
    wrapper = next(s for s in sites
                   if s["kind"] == "runtime_wrapper_agent_alias_syntax")
    runner = next(s for s in sites
                  if s["kind"] == "adk_runner_agent_argument_syntax")
    rest = next(s for s in sites
                if s["kind"] == "fastapi_direct_tool_call_syntax")
    assert wrapper["path"] == runner["path"] == rest["path"] == "api.py"
    assert wrapper["source_expression"] == "_root_agent = _agent_mod.root_agent"
    assert runner["source_expression"] == "agent=_root_agent,"
    assert rest["source_expression"] == "return list_metrics()"
    assert rest["line_start"] == 124
    assert not any(s["kind"] == "verified_agent_can_call"
                   for s in sites)


def test_rw005_never_promotes_unreviewed_syntax_to_independent_truth() -> None:
    record = _load()
    assert record["record_type"] == "source_first_syntax_candidate_not_oracle_truth"
    for field in (
        "scanner_predictions_consulted_in_this_review",
        "source_reviewer_independence_externally_verified",
        "source_blindness_externally_verified",
        "positive_universe_complete",
        "negative_universe_complete",
        "runtime_imports_verified",
        "runtime_agent_callable_verified",
        "release_accuracy_assessable",
    ):
        assert record[field] is False
    assert not any(
        s.get("kind") in {"independent_source_positive", "verified_runtime_authority"}
        for s in record["observations"]
    )


def test_rw005_declared_sdk_version_not_runtime_tool_attestation() -> None:
    record = _load()
    sdk = next(s for s in record["observations"]
               if s["kind"] == "declared_sdk_dependency_syntax")
    assert sdk["path"] == "requirements.txt"
    assert sdk["source_expression"] == "google-adk==1.19.0"
    assert record["runtime_imports_verified"] is False



def test_rw005_candidate_edges_have_pinned_source_endpoints_and_witnesses() -> None:
    data = _load()
    all_ids = {row["id"] for row in data["observations"]}
    edges = data["candidate_edges"]
    assert len(edges) == 14
    assert len({row["id"] for row in edges}) == len(edges)
    kinds = Counter(row["edge_kind"] for row in edges)
    assert kinds == {
        "DECLARED_SUBAGENT_MEMBERSHIP": 4,
        "DECLARED_AGENT_TOOL_LISTING": 8,
        "DECLARED_RUNNER_AGENT_REFERENCE": 1,
        "DIRECT_APPLICATION_FUNCTION_CALL": 1,
    }
    for edge in edges:
        assert edge["from_source_ref"] in all_ids
        assert edge["to_source_ref"] in all_ids
        assert edge["relationship_witness_ref"] in all_ids
        assert edge["status"] == "declared_source_candidate_only"
        assert edge["runtime_verified"] is False
        assert edge["source_semantics_independently_adjudicated"] is False
        assert edge["effective_authority_established"] is False


def test_rw005_child_agent_bindings_preserve_eight_owners() -> None:
    edges = _load()["candidate_edges"]
    bindings = [row for row in edges
                if row["edge_kind"] == "DECLARED_AGENT_TOOL_LISTING"]
    by_owner = Counter(row["from_source_ref"] for row in bindings)
    assert by_owner == {
        "rw005-ingestion-constructor": 3,
        "rw005-anomaly-constructor": 2,
        "rw005-cause-constructor": 3,
    }
    assert not any(row["from_source_ref"] == "rw005-coordinator-constructor"
                   for row in bindings)
    shared = Counter(row["to_source_ref"] for row in bindings)
    assert shared["rw005-function-timeseries"] == 2
    assert shared["rw005-function-lineage"] == 2
    assert len(shared) == 6


def test_rw005_never_conflates_http_call_with_agent_tool_binding() -> None:
    edges = _load()["candidate_edges"]
    rest = next(row for row in edges
                if row["edge_kind"] == "DIRECT_APPLICATION_FUNCTION_CALL")
    assert rest["from_source_ref"] == "rw005-api-nonagent-route"
    assert rest["to_source_ref"] == "rw005-function-list-metrics"
    assert all(not row["edge_kind"].startswith("AGENT_CAN_CALL")
               for row in edges)
    runner = next(row for row in edges
                  if row["edge_kind"] == "DECLARED_RUNNER_AGENT_REFERENCE")
    assert runner["to_source_ref"] == "rw005-coordinator-constructor"
    assert runner["from_source_ref"] == "rw005-api-runner-constructor"
