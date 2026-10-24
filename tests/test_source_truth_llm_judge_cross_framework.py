"""C02p: source-only model reviewer works across ADK, MCP and Pydantic ledgers."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from horustrace.source_truth_llm_judge import (
    adjudicate_pinned_ledger_opinions,
    prepare_judge_packet,
    triage_model_scanner_disagreements,
)
from horustrace.source_truth_oracle import score_reference

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "research/wave-c-c02i-rw080/mcp-source-candidates.json"
PYDANTIC = ROOT / "research/wave-c-c02j-rw149/conditional-tool-source-candidates.json"
OPINIONS = ROOT / "research/wave-c-c02p-mcp-judge/rw-080-model-opinions.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_c02p_rw080_mcp_packet_normalizes_47_exact_source_witnesses() -> None:
    data = _load(MCP)
    packet = prepare_judge_packet(data)
    assert packet["case_id"] == "rw-080"
    assert packet["repository"] == "Amlan66/SSEEnabledMCPAgent"
    assert packet["commit_sha"] == data["pinned_commit_sha"]
    assert packet["framework"] == "mcp-custom"
    assert packet["source_role"] == "unknown"
    assert packet["witness_verification"] == "pinned_ledger_not_local_git_replayed"
    assert len(packet["candidates"]) == 47
    for candidate, source in zip(packet["candidates"], data["observations"]):
        assert candidate["id"] == source["id"]
        assert candidate["path"] == source["path"]
        assert candidate["blob_sha"] == source["blob_sha"]
        assert candidate["line_start"] == candidate["line_end"] == source["line"]
        assert candidate["source_expression"] == source["source_expression"]
        assert candidate["kind"] == "unclassified_source_syntax_candidate"
        assert "source_only_candidate" not in candidate


def test_c02p_rw149_pydantic_packet_normalizes_37_source_witnesses() -> None:
    data = _load(PYDANTIC)
    packet = prepare_judge_packet(data)
    assert packet["case_id"] == "rw-149"
    assert packet["repository"] == "LeonieFreisinger/pydanticai-base-agent"
    assert packet["commit_sha"] == data["pinned_commit_sha"]
    assert packet["framework"] == "pydantic-ai"
    assert len(packet["candidates"]) == 37
    assert all(item["kind"] == "unclassified_source_syntax_candidate"
               for item in packet["candidates"])
    for packet_item, original in zip(packet["candidates"], data["observations"]):
        assert packet_item["source_expression"] == original["expression"]
        assert packet_item["line_start"] == original["line"]
        assert packet_item["line_end"] == original["line"]
        assert packet_item["blob_sha"] == original["blob_sha"]
    assert prepare_judge_packet(deepcopy(data)) == packet


def test_c02p_rw080_actual_model_judgments_are_git_blob_replayable() -> None:
    review = _load(OPINIONS)
    assert review["ledger_blob_sha"] == (
        "f950abc4d38fffdf5537861459c0ff9b0fccc2c1"
    )
    result = adjudicate_pinned_ledger_opinions(MCP.read_bytes(), review)
    assert result["counts"] == {"negative": 8, "positive": 16, "unknown": 4}
    assert len(result["reference"]["labels"]) == 28
    assert result["source_oracle_status"]["aggregate"] is None
    assert result["source_oracle_status"]["all_scopes_assessable"] is False
    assert result["release_accuracy_assessable"] is False
    assert {s["construct"] for s in result["reference"]["scopes"]} == {
        "agent", "mcp_client", "mcp_server", "typed_edge", "effective_authority",
    }
    for scope in result["reference"]["scopes"]:
        assert scope["review_method"] == "model_reviewed"
        assert scope["scanner_blind"] is False
        assert scope["positive_complete"] is False
        assert scope["negative_complete"] is False


def test_c02p_rw080_hard_negatives_respect_exposes_vs_can_call() -> None:
    result = adjudicate_pinned_ledger_opinions(MCP.read_bytes(), _load(OPINIONS))
    labelled = {row["claim_id"]: row for row in result["reference"]["labels"]}
    assert labelled["source_edge:decorator_guarantees_AGENT_CAN_CALL"][
        "truth"
    ] == "negative"
    assert labelled["source_edge:static_enumerated_complete_remote_tool_catalogue"][
        "truth"
    ] == "negative"
    assert labelled["source_mcp_server:shared_Calculator_name_merges_distinct_files"][
        "truth"
    ] == "negative"
    assert labelled["source_mcp_server:server1_FastMCP_declaration"]["truth"] == "positive"
    assert labelled["source_mcp_server:server2_FastMCP_declaration"]["truth"] == "positive"
    assert labelled["source_edge:AgentLoop_dispatches_through_MultiMCP"][
        "truth"
    ] == "positive"
    assert all(
        row["truth"] == "unknown"
        for row in result["reference"]["labels"]
        if row["scope_id"] == "rw-080:effective_authority:unknown"
    )


def test_c02p_rw080_scanner_predicted_permission_still_not_measured_fp() -> None:
    result = adjudicate_pinned_ledger_opinions(MCP.read_bytes(), _load(OPINIONS))
    reference_digest = score_reference(result["reference"], [])["reference_sha256"]
    snapshot = {
        "schema_version": 1,
        "ontology_version": "v2_source_claims",
        "reference_sha256": reference_digest,
        "scanner_commit_sha": "c" * 40,
        "predictions": [
            {
                "scope_id": "rw-080:typed_edge:unknown",
                "claim_id": "source_edge:decorator_guarantees_AGENT_CAN_CALL",
            },
            {
                "scope_id": "rw-080:effective_authority:unknown",
                "claim_id": "runtime_authority:actual_remote_list_tools_results",
            },
        ],
    }
    triage = triage_model_scanner_disagreements(result, snapshot)
    labels = {item["claim_id"]: item for item in triage["claims"]}
    assert labels["source_edge:decorator_guarantees_AGENT_CAN_CALL"][
        "triage_category"
    ] == "candidate_source_negative_detected_by_scanner"
    assert labels["runtime_authority:actual_remote_list_tools_results"][
        "triage_category"
    ] == "runtime_unknown_requires_independent_evidence"
    assert triage["certified_fp"] is None and triage["certified_fn"] is None
    assert triage["production_cutover_authorized"] is False


@pytest.mark.parametrize("change", [
    lambda data: data.update({"scanner_predictions_consulted": True}),
    lambda data: data["observations"][0].update({"source_only_candidate": False}),
    lambda data: data["observations"][0].update({"line": True}),
    lambda data: data["observations"][0].update({"line_start": 2}),
    lambda data: data["observations"][0].update({"blob_sha": "wrong"}),
    lambda data: data["observations"][0].update({"source_expression": ""}),
])
def test_c02p_mcp_invalid_or_exposed_observation_fails_closed(
    change: object,
) -> None:
    data = _load(MCP)
    change(data)
    with pytest.raises((TypeError, ValueError)):
        prepare_judge_packet(data)


@pytest.mark.parametrize("change", [
    lambda data: data["observations"][0].update({"source_syntax_only": False}),
    lambda data: data["observations"][0].update({"expression": ""}),
    lambda data: data.update({"scanner_predictions_consulted": True}),
    lambda data: data["observations"][0].update({
        "source_expression": "different from expression",
    }),
])
def test_c02p_pydantic_missing_source_only_or_conflicting_anchor_fails(
    change: object,
) -> None:
    data = _load(PYDANTIC)
    change(data)
    with pytest.raises((TypeError, ValueError)):
        prepare_judge_packet(data)


def test_c02p_rw080_stale_or_fabricated_model_source_ledger_rejected() -> None:
    review = _load(OPINIONS)
    with pytest.raises(ValueError, match="Git blob SHA mismatch"):
        adjudicate_pinned_ledger_opinions(MCP.read_bytes() + b"x", review)
    review = _load(OPINIONS)
    review["decisions"][0]["candidate_id"] = "no-such-pinned-source"
    with pytest.raises(ValueError, match="source not in pinned packet"):
        adjudicate_pinned_ledger_opinions(MCP.read_bytes(), review)
