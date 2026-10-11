from horustrace.analysis import _path_metadata
from horustrace.attack_path_proof import proof_for_path_basis


def test_static_flow_is_the_only_proven_source_to_sink_class() -> None:
    for basis in ("static_dataflow", "source_proven_tool_dataflow"):
        proof = proof_for_path_basis(basis)
        assert proof["category"] == "static_dataflow"
        assert proof["static_source_to_sink_established"] is True
        assert proof["runtime_exploitability"] == "not_verified"


def test_delegation_proves_authority_path_but_not_value_flow() -> None:
    proof = proof_for_path_basis("source_bound_delegated_authority")
    assert proof["authority_reachability_established"] is True
    assert proof["static_source_to_sink_established"] is False


def test_source_patterns_are_not_automatically_flow_proofs() -> None:
    for basis in (
        "source_proven_indirect_tool_content",
        "source_proven_rag_directory_retrieval",
        "source_proven_object_authorization_bypass",
    ):
        proof = proof_for_path_basis(basis)
        assert proof["category"] == "source_backed_pattern"
        assert proof["static_source_to_sink_established"] is False


def test_capability_cooccurrence_remains_potential() -> None:
    metadata = _path_metadata(basis="capability_cooccurrence")
    assert metadata["proof"]["category"] == "capability_combination"
    assert metadata["proof"]["static_source_to_sink_established"] is False
    assert metadata["exploitability"] == "not_verified"
