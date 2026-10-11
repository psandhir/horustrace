"""Reference integrity and protocol boundaries for evaluation evidence.

This module never imports or executes a target repository.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any, Protocol

from horustrace.evaluation.contracts import (
    Assertion,
    Attempt,
    EvaluationCase,
    EvaluationContractError,
    Observation,
)


def _canonical_digest(document: dict[str, Any]) -> str:
    """Use the AgentSecurityGraph canonical digest, excluding the emitted digest field."""
    payload = dict(document)
    payload.pop("digest", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def validate_case_bindings(
    case: EvaluationCase,
    asg: dict[str, Any],
    *,
    authority_contract_digest: str | None = None,
) -> None:
    """Reject stale ASG pins and dangling references before scoring or importing results."""
    if not isinstance(asg, dict) or asg.get("schema_version") != 1:
        raise EvaluationContractError("expected Agent Security Graph v1")
    actual = _canonical_digest(asg)
    if asg.get("digest", actual) != actual:
        raise EvaluationContractError("Agent Security Graph contains an invalid digest")
    if case.asg_digest != actual:
        raise EvaluationContractError("evaluation case is stale: ASG digest differs")
    if case.contract_digest is not None and case.contract_digest != authority_contract_digest:
        raise EvaluationContractError("evaluation case is stale: Authority Contract digest differs")

    topology = asg.get("topology")
    if not isinstance(topology, dict):
        raise EvaluationContractError("ASG lacks topology")
    candidates = [
        *(topology.get("nodes") or []),
        *(topology.get("edges") or []),
        *(asg.get("attack_paths") or []),
        *(asg.get("flows") or []),
        *((asg.get("effective_authority") or {}).get("relationships") or []),
    ]
    known: set[str] = set()
    for item in candidates:
        if not isinstance(item, dict):
            raise EvaluationContractError("ASG contains malformed references")
        for key in ("id", "path_id", "flow_id", "relationship_id"):
            if isinstance(item.get(key), str):
                known.add(item[key])
    missing = set(case.asset_ids) - known
    if missing:
        raise EvaluationContractError(
            f"evaluation references unknown ASG assets: {sorted(missing)}"
        )


class CaseGenerator(Protocol):
    def generate(self, asg: dict[str, Any]) -> Iterable[EvaluationCase]: ...


class CaseTransformer(Protocol):
    def transform(self, case: EvaluationCase) -> EvaluationCase: ...


class EvaluationTarget(Protocol):
    def execute(self, case: EvaluationCase) -> Attempt: ...


class AssertionScorer(Protocol):
    def score(
        self, case: EvaluationCase, observations: tuple[Observation, ...],
    ) -> tuple[Assertion, ...]: ...


class EvidenceStore(Protocol):
    def append(self, attempt: Attempt) -> None: ...


class FakeEvaluationTarget:
    """Deterministic instrumented fake target, limited to predeclared observation data.

    Its execution never invokes a repository, network endpoint, model or subprocess.
    """

    def __init__(self, observations: tuple[Observation, ...], *, mode: str = "completed"):
        if mode not in {"completed", "timed_out", "error", "skipped"}:
            raise EvaluationContractError(f"unsupported fake execution mode {mode}")
        self.observations = observations
        self.mode = mode

    def execute(self, case: EvaluationCase) -> Attempt:
        if case.scope != "external_agent":
            raise EvaluationContractError("fake target accepts external_agent cases only")
        state = self.mode
        error = ["synthetic execution failure"] if state in {"error", "timed_out"} else []
        return Attempt.from_dict({
            "attempt_id": f"{case.case_id}.attempt",
            "case_id": case.case_id,
            "execution_state": state,
            "outcome": "unresolved" if state == "completed" else "not_executed",
            "observations": (
                [obs.as_dict() for obs in self.observations] if state == "completed" else []
            ),
            "assertions": [],
            "errors": error,
        })
