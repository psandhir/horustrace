from __future__ import annotations

from collections.abc import Iterable

ATTACK_VERDICTS = frozenset({"valid", "invalid", "unresolved"})
FINDING_VERDICTS = frozenset(
    {"supported", "partial", "unsupported", "unresolved"}
)
PARTIAL_REASONS = frozenset(
    {
        "authority_binding",
        "principal",
        "reachability",
        "effect_semantics",
        "resource_scope",
        "destination_provenance",
        "control_semantics",
        "delegation_semantics",
        "runtime_qualification",
    }
)


def validate_partial_reasons(
    verdict: str,
    reasons: object,
) -> list[str]:
    """Validate the machine-readable qualification taxonomy for a verdict.

    Historical supported/unsupported/unresolved packets remain valid when the
    field is absent. A partial verdict must state at least one material reason,
    and non-partial verdicts must not carry partial reasons.
    """
    if reasons is None:
        normalized: list[str] = []
    elif isinstance(reasons, list) and all(
        isinstance(reason, str) and reason.strip()
        for reason in reasons
    ):
        normalized = list(dict.fromkeys(reason.strip() for reason in reasons))
    else:
        raise ValueError("partial_reasons must be a list of non-empty strings")

    unknown = sorted(set(normalized) - PARTIAL_REASONS)
    if unknown:
        raise ValueError(f"unknown partial_reasons: {unknown}")

    if verdict == "partial" and not normalized:
        raise ValueError("partial verdict requires at least one partial_reason")
    if verdict != "partial" and normalized:
        raise ValueError("partial_reasons are only valid for a partial verdict")
    return normalized


def materially_supported(verdict: str) -> bool:
    return verdict in {"supported", "partial"}


def normalize_reason_counts(
    reasons: Iterable[str],
) -> dict[str, int]:
    counts = {reason: 0 for reason in sorted(PARTIAL_REASONS)}
    for reason in reasons:
        if reason in counts:
            counts[reason] += 1
    return {reason: count for reason, count in counts.items() if count}
