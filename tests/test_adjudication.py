from __future__ import annotations

import pytest

from horustrace.adjudication import (
    FINDING_VERDICTS,
    PARTIAL_REASONS,
    materially_supported,
    validate_partial_reasons,
)


def test_partial_is_first_class_finding_verdict() -> None:
    assert "partial" in FINDING_VERDICTS
    assert materially_supported("supported") is True
    assert materially_supported("partial") is True
    assert materially_supported("unsupported") is False


def test_partial_requires_structured_reason() -> None:
    with pytest.raises(ValueError, match="requires at least one"):
        validate_partial_reasons("partial", [])

    assert validate_partial_reasons(
        "partial",
        ["destination_provenance", "control_semantics"],
    ) == ["destination_provenance", "control_semantics"]


def test_non_partial_cannot_carry_partial_reason() -> None:
    with pytest.raises(ValueError, match="only valid"):
        validate_partial_reasons("supported", ["resource_scope"])


def test_partial_reason_taxonomy_is_bounded() -> None:
    assert {
        "authority_binding",
        "principal",
        "reachability",
        "effect_semantics",
        "resource_scope",
        "destination_provenance",
        "control_semantics",
        "delegation_semantics",
        "runtime_qualification",
    } == set(PARTIAL_REASONS)

    with pytest.raises(ValueError, match="unknown partial_reasons"):
        validate_partial_reasons("partial", ["made_up_reason"])
