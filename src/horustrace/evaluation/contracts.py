"""Versioned, data-only security evaluation records.

These records describe static assertions and optional externally executed tests.
They never execute scanned code or infer runtime safety from missing evidence.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = 1
SCOPES = frozenset({"static_scanner", "semantic_compiler", "external_agent"})
PARTITIONS = frozenset({"regression", "calibration", "holdout", "exploratory"})
EXECUTION_STATES = frozenset({
    "not_executed", "started", "completed", "error", "timed_out", "skipped", "unknown",
})
OUTCOMES = frozenset({
    "not_executed", "policy_violation", "control_enforced",
    "no_violation_observed", "unresolved",
})
VERDICTS = frozenset({"supported", "refuted", "unresolved"})
OBSERVATION_EFFECTS = frozenset({
    "attempted", "denied", "completed", "informational",
})
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class EvaluationContractError(ValueError):
    """Invalid or unsupported evaluation evidence."""


def _object(value: Any, where: str, required: set[str], optional: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvaluationContractError(f"{where}: expected object")
    absent = required - value.keys()
    unknown = value.keys() - required - optional
    if absent or unknown:
        raise EvaluationContractError(
            f"{where}: missing {sorted(absent)}; unknown {sorted(unknown)}"
        )
    return value


def _string(value: Any, where: str, *, allow_none: bool = False) -> str | None:
    if allow_none and value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise EvaluationContractError(f"{where}: expected nonempty bounded string")
    return value


def _identifier(value: Any, where: str) -> str:
    value = _string(value, where)
    if not _ID.fullmatch(value):
        raise EvaluationContractError(f"{where}: invalid identifier")
    return value


def _choice(value: Any, choices: frozenset[str], where: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise EvaluationContractError(f"{where}: unsupported value {value!r}")
    return value


def _sha(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise EvaluationContractError(f"{where}: expected full 40-hex commit SHA")
    return value


def _digest(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise EvaluationContractError(f"{where}: expected sha256:<64 hex> digest")
    return value


def _records(value: Any, where: str, record_type: type) -> tuple:
    if not isinstance(value, list) or len(value) > 10000:
        raise EvaluationContractError(f"{where}: expected bounded array")
    return tuple(record_type.from_dict(item) for item in value)


def _ids(values: Any, where: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, list) or (nonempty and not values) or len(values) > 10000:
        raise EvaluationContractError(f"{where}: expected bounded identifier array")
    result = tuple(_identifier(value, where) for value in values)
    if len(set(result)) != len(result):
        raise EvaluationContractError(f"{where}: duplicate identifiers")
    return result


def _unique(records: tuple, attr: str, where: str) -> None:
    values = [getattr(item, attr) for item in records]
    if len(set(values)) != len(values):
        raise EvaluationContractError(f"{where}: duplicate {attr}")


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    case_id: str
    family: str
    scope: str
    objective: str
    source_sha: str
    scanner_sha: str
    asg_digest: str
    assertion_ids: tuple[str, ...]
    target_ref: str | None = None
    framework: str | None = None
    language: str | None = None
    injection_surface: str | None = None
    contract_digest: str | None = None
    asset_ids: tuple[str, ...] = ()
    parent_case_id: str | None = None
    transformation_ids: tuple[str, ...] = ()
    partition: str = "regression"
    schema_version: int = SCHEMA_VERSION

    @classmethod
    def from_dict(cls, data: Any) -> EvaluationCase:
        required = {
            "schema_version", "case_id", "family", "scope", "objective",
            "source_sha", "scanner_sha", "asg_digest", "assertion_ids",
        }
        optional = {
            "target_ref", "framework", "language", "injection_surface", "contract_digest",
            "asset_ids", "parent_case_id", "transformation_ids", "partition",
        }
        item = _object(data, "case", required, optional)
        if type(item["schema_version"]) is not int or item["schema_version"] != SCHEMA_VERSION:
            raise EvaluationContractError("case: unsupported schema version")
        values = {
            "case_id": _identifier(item["case_id"], "case_id"),
            "family": _identifier(item["family"], "family"),
            "scope": _choice(item["scope"], SCOPES, "scope"),
            "objective": _string(item["objective"], "objective"),
            "source_sha": _sha(item["source_sha"], "source_sha"),
            "scanner_sha": _sha(item["scanner_sha"], "scanner_sha"),
            "asg_digest": _digest(item["asg_digest"], "asg_digest"),
            "assertion_ids": _ids(item["assertion_ids"], "assertion_ids", nonempty=True),
            "asset_ids": _ids(item.get("asset_ids", []), "asset_ids"),
            "transformation_ids": _ids(item.get("transformation_ids", []), "transformation_ids"),
            "partition": _choice(item.get("partition", "regression"), PARTITIONS, "partition"),
        }
        for key in ("target_ref", "framework", "language", "injection_surface"):
            values[key] = _string(item.get(key), key, allow_none=True)
        values["contract_digest"] = (
            _digest(item["contract_digest"], "contract_digest")
            if item.get("contract_digest") is not None else None
        )
        values["parent_case_id"] = (
            _identifier(item["parent_case_id"], "parent_case_id")
            if item.get("parent_case_id") is not None else None
        )
        if values["scope"] == "external_agent" and not values["target_ref"]:
            raise EvaluationContractError("external_agent case requires explicit target_ref")
        if values["parent_case_id"] == values["case_id"]:
            raise EvaluationContractError("case cannot be its own parent")
        return cls(**values)

    def as_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(asdict(self)))


@dataclass(frozen=True, slots=True)
class Observation:
    observation_id: str
    turn: int
    kind: str
    effect: str
    subject_id: str | None = None
    artifact_digest: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> Observation:
        item = _object(
            data, "observation", {"observation_id", "turn", "kind", "effect"},
            {"subject_id", "artifact_digest", "attributes"},
        )
        attributes = item.get("attributes", {})
        allowed = {"tool_id", "principal_id", "resource", "destination", "action", "approval_id", "call_id"}
        if (
            not isinstance(attributes, dict)
            or set(attributes) - allowed
            or any(not isinstance(v, str) or not v.strip() or len(v) > 512
                   for v in attributes.values())
        ):
            raise EvaluationContractError("observation.attributes: invalid structured evidence")
        turn = item["turn"]
        if type(turn) is not int or not 0 <= turn <= 100000:
            raise EvaluationContractError("observation.turn: expected bounded integer")
        return cls(
            observation_id=_identifier(item["observation_id"], "observation_id"),
            turn=turn,
            kind=_identifier(item["kind"], "kind"),
            effect=_choice(item["effect"], OBSERVATION_EFFECTS, "effect"),
            subject_id=(
                _identifier(item["subject_id"], "subject_id")
                if item.get("subject_id") is not None else None
            ),
            artifact_digest=(
                _digest(item["artifact_digest"], "artifact_digest")
                if item.get("artifact_digest") is not None else None
            ),
            attributes=dict(sorted(attributes.items())),
        )

    def as_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(asdict(self)))


@dataclass(frozen=True, slots=True)
class Assertion:
    assertion_id: str
    verdict: str
    scorer_id: str
    scorer_version: str
    evidence_ids: tuple[str, ...] = ()
    rationale: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> Assertion:
        item = _object(
            data, "assertion",
            {"assertion_id", "verdict", "scorer_id", "scorer_version", "evidence_ids"},
            {"rationale"},
        )
        rationale = item.get("rationale", "")
        if not isinstance(rationale, str) or len(rationale) > 4096:
            raise EvaluationContractError("rationale must be bounded text")
        value = cls(
            assertion_id=_identifier(item["assertion_id"], "assertion_id"),
            verdict=_choice(item["verdict"], VERDICTS, "verdict"),
            scorer_id=_identifier(item["scorer_id"], "scorer_id"),
            scorer_version=_identifier(item["scorer_version"], "scorer_version"),
            evidence_ids=_ids(item["evidence_ids"], "evidence_ids"),
            rationale=rationale,
        )
        if value.verdict in {"supported", "refuted"} and not value.evidence_ids:
            raise EvaluationContractError("decisive assertion requires evidence references")
        return value

    def as_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(asdict(self)))


@dataclass(frozen=True, slots=True)
class Attempt:
    attempt_id: str
    case_id: str
    execution_state: str
    outcome: str
    observations: tuple[Observation, ...] = ()
    assertions: tuple[Assertion, ...] = ()
    errors: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Any) -> Attempt:
        item = _object(
            data, "attempt",
            {"attempt_id", "case_id", "execution_state", "outcome", "observations", "assertions"},
            {"errors"},
        )
        observations = _records(item["observations"], "observations", Observation)
        assertions = _records(item["assertions"], "assertions", Assertion)
        _unique(observations, "observation_id", "observations")
        _unique(assertions, "assertion_id", "assertions")
        errors = item.get("errors", [])
        if not isinstance(errors, list) or len(errors) > 100:
            raise EvaluationContractError("errors: expected bounded array")
        errors_tuple = tuple(_string(e, "errors item") for e in errors)
        value = cls(
            attempt_id=_identifier(item["attempt_id"], "attempt_id"),
            case_id=_identifier(item["case_id"], "case_id"),
            execution_state=_choice(item["execution_state"], EXECUTION_STATES, "execution_state"),
            outcome=_choice(item["outcome"], OUTCOMES, "outcome"),
            observations=observations,
            assertions=assertions,
            errors=errors_tuple,
        )
        known = {obs.observation_id for obs in observations}
        for assertion in assertions:
            if set(assertion.evidence_ids) - known:
                raise EvaluationContractError("assertion references unknown observation")
        if value.execution_state != "completed" and value.outcome not in {
            "unresolved", "not_executed",
        }:
            raise EvaluationContractError("incomplete or errored attempt cannot claim safety")
        if value.execution_state in {"error", "timed_out"} and not value.errors:
            raise EvaluationContractError("failed attempt requires error explanation")
        if value.outcome in {"policy_violation", "control_enforced", "no_violation_observed"} and (
            not any(a.verdict == "supported" for a in assertions)
        ):
            raise EvaluationContractError("runtime outcome requires supported assertion")
        if value.outcome == "control_enforced" and not any(
            obs.effect == "denied" for obs in observations
        ):
            raise EvaluationContractError("control_enforced requires an observed denial")
        if value.outcome == "policy_violation" and not any(
            obs.effect == "completed" for obs in observations
        ):
            raise EvaluationContractError("policy_violation requires an observed completed effect")
        return value

    def as_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(asdict(self)))


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    run_id: str
    case: EvaluationCase
    attempts: tuple[Attempt, ...] = field(default_factory=tuple)
    schema_version: int = SCHEMA_VERSION

    @classmethod
    def from_dict(cls, data: Any) -> EvaluationResult:
        item = _object(
            data, "evaluation", {"schema_version", "run_id", "case", "attempts"}, set(),
        )
        if type(item["schema_version"]) is not int or item["schema_version"] != SCHEMA_VERSION:
            raise EvaluationContractError("evaluation: unsupported schema version")
        case = EvaluationCase.from_dict(item["case"])
        attempts = _records(item["attempts"], "attempts", Attempt)
        _unique(attempts, "attempt_id", "attempts")
        for attempt in attempts:
            if attempt.case_id != case.case_id:
                raise EvaluationContractError("attempt case_id does not match evaluation case")
            if {a.assertion_id for a in attempt.assertions} - set(case.assertion_ids):
                raise EvaluationContractError("attempt contains undeclared assertion")
            if case.scope != "external_agent" and attempt.outcome not in {
                "not_executed", "unresolved",
            }:
                raise EvaluationContractError("static evaluations cannot claim runtime outcome")
        return cls(run_id=_identifier(item["run_id"], "run_id"), case=case, attempts=attempts)

    def as_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(asdict(self)))

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, text: str) -> EvaluationResult:
        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise EvaluationContractError(f"duplicate JSON key: {key}")
                result[key] = value
            return result

        try:
            return cls.from_dict(json.loads(text, object_pairs_hook=no_duplicates))
        except (ValueError, TypeError) as exc:
            raise EvaluationContractError(f"invalid evaluation JSON: {exc}") from exc
