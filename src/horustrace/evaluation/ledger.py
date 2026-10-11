"""Append-only, offline adversarial evaluation ledger (#513).

Neither storing nor replaying events can contact targets, execute plugins or
reconstruct missing credentials. Journaling preserves uncertain side effects.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from horustrace.evaluation.contracts import (
    Attempt,
    EvaluationCase,
    EvaluationContractError,
    Observation,
)

LEDGER_VERSION = 1
MAX_RECORD = 1_048_576
MAX_ATTACHMENT = 2_097_152
PHASES = frozenset({"planned", "started", "observed", "finished", "rescored", "reconciled"})
_ALLOWED_PINS = frozenset({
    "harness_version", "generator_model", "target_model", "judge_model",
    "prompt_digest", "config_digest", "seed", "dependency_digest",
    "scorer_version", "budget_tokens", "budget_requests", "budget_seconds",
})
_SENSITIVE = re.compile(
    r"(?i)(authorization\s*[:=]\s*bearer\s+|(?:api[_-]?key|password|token|secret)"
    r"\s*[:=]\s*)([A-Za-z0-9_./+=-]{5,})"
)
_SECRET_MARKERS = re.compile(r"(?i)(?:SECRET|TOKEN|PASSWORD|APIKEY)-[A-Za-z0-9_-]{6,}")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _redact(value: str) -> str:
    value = _SENSITIVE.sub(lambda m: m.group(1) + "[REDACTED]", value)
    return _SECRET_MARKERS.sub("[REDACTED]", value)


def _safe_root(root: Path) -> Path:
    root = Path(root).absolute()
    if root.is_symlink():
        raise EvaluationContractError("ledger root cannot be a symlink")
    return root


def _write_exclusive(path: Path, data: bytes) -> None:
    with path.open("xb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())


def _read_json(path: Path, maximum: int = MAX_RECORD) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise EvaluationContractError(f"unsafe, missing or oversized ledger file: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise EvaluationContractError(f"invalid ledger JSON: {path.name}") from exc


class EvaluationLedger:
    """Append-only local journal; immutable run manifest, chain and attachment index."""

    def __init__(self, root: Path):
        self.root = _safe_root(root)
        self.manifest = _read_json(self.root / "manifest.json")
        if self.manifest.get("ledger_version") != LEDGER_VERSION:
            raise EvaluationContractError("unsupported ledger format")
        self.case = EvaluationCase.from_dict(self.manifest["case"])
        self.run_id = self.manifest["run_id"]
        if not isinstance(self.run_id, str) or not self.run_id:
            raise EvaluationContractError("invalid run identity")

    @classmethod
    def create(
        cls, root: Path, case: EvaluationCase, run_id: str,
        *, pins: dict[str, Any],
    ) -> EvaluationLedger:
        root = _safe_root(root)
        if root.exists():
            raise EvaluationContractError("ledger directory already exists")
        if not isinstance(pins, dict) or set(pins) - _ALLOWED_PINS:
            raise EvaluationContractError("unsupported run pins or possible credentials")
        if not run_id or not isinstance(run_id, str):
            raise EvaluationContractError("run_id required")
        if any(isinstance(v, (dict, list)) or v is None or len(str(v)) > 256
               for v in pins.values()):
            raise EvaluationContractError("pins must be bounded scalar metadata")
        if any(_redact(str(v)) != str(v) for v in pins.values()):
            raise EvaluationContractError("credentials are not allowed in run pins")
        root.mkdir(parents=True)
        manifest = {
            "ledger_version": LEDGER_VERSION,
            "run_id": run_id,
            "case": case.as_dict(),
            "pins": dict(sorted(pins.items())),
            "created_utc": datetime.now(UTC).isoformat(),
            "redaction_policy": "public_redacted_v1",
            "transformation_ids": list(case.transformation_ids),
            "partition": case.partition,
        }
        _write_exclusive(root / "manifest.json", canonical(manifest) + b"\n")
        _write_exclusive(root / "events.jsonl", b"")
        (root / "attachments").mkdir()
        return cls(root)

    def _events(self) -> list[dict[str, Any]]:
        path = self.root / "events.jsonl"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 20_000_000:
            raise EvaluationContractError("invalid journal file")
        raw = path.read_bytes()
        if raw and not raw.endswith(b"\n"):
            raise EvaluationContractError("truncated journal: do not resume external effects")
        records: list[dict[str, Any]] = []
        previous = "sha256:" + "0" * 64
        for index, row in enumerate(raw.splitlines()):
            if len(row) > MAX_RECORD:
                raise EvaluationContractError("oversized journal record")
            try:
                item = json.loads(row)
            except (ValueError, UnicodeError) as exc:
                raise EvaluationContractError("invalid journal record") from exc
            if not isinstance(item, dict) or set(item) != {
                "seq", "phase", "attempt_id", "payload", "prev", "hash",
            }:
                raise EvaluationContractError("invalid event envelope")
            hashed = {key: value for key, value in item.items() if key != "hash"}
            if item["seq"] != index or item["prev"] != previous or (
                item["hash"] != digest(canonical(hashed))
            ):
                raise EvaluationContractError("journal integrity chain mismatch")
            if item["phase"] not in PHASES:
                raise EvaluationContractError("unknown journal event phase")
            records.append(item)
            previous = item["hash"]
        return records

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        lock = self.root / ".write.lock"
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise EvaluationContractError("ledger writer locked; reconcile before retry") from exc
        try:
            os.close(fd)
            yield
        finally:
            lock.unlink(missing_ok=True)

    def append(self, phase: str, attempt_id: str, payload: dict[str, Any]) -> bool:
        if phase not in PHASES or not isinstance(payload, dict):
            raise EvaluationContractError("invalid append operation")
        with self._exclusive():
            if (self.root / "integrity.json").exists():
                raise EvaluationContractError("sealed evaluation bundle is immutable")
            records = self._events()
            related = [e for e in records if e["attempt_id"] == attempt_id]
            if phase in {"finished", "rescored"}:
                record = Attempt.from_dict(payload.get("attempt"))
                if record.attempt_id != attempt_id or record.case_id != self.case.case_id:
                    raise EvaluationContractError("attempt belongs to another case")
            if phase == "observed":
                Observation.from_dict(payload.get("observation"))
            if phase == "reconciled" and payload.get("disposition") not in {
                "confirmed_not_executed", "external_effect_confirmed", "unknown",
            }:
                raise EvaluationContractError("explicit reconciliation disposition required")
            if phase == "started" and not any(e["phase"] == "planned" for e in related):
                raise EvaluationContractError("attempt must be planned before start")
            if phase == "finished" and not any(e["phase"] == "started" for e in related):
                raise EvaluationContractError("attempt must be started before completion")
            if phase == "rescored" and not any(e["phase"] == "finished" for e in related):
                raise EvaluationContractError("cannot rescore absent original observations")
            # Duplicate imports and append retries are content-idempotent.
            if any(e["phase"] == phase and e["payload"] == payload for e in related):
                return False
            if phase == "finished" and any(e["phase"] == "finished" for e in related):
                raise EvaluationContractError("conflicting finished attempt cannot be rewritten")
            if phase == "started" and any(e["phase"] == "started" for e in related):
                raise EvaluationContractError("uncertain effect: started attempt requires reconciliation")
            if phase in {"planned", "started", "observed", "reconciled"} and any(
                e["phase"] == "finished" for e in related
            ):
                raise EvaluationContractError("finished attempt is immutable")
            encoded = canonical(payload)
            if len(encoded) > MAX_RECORD:
                raise EvaluationContractError("oversized event payload")
            if _redact(encoded.decode("utf-8")) != encoded.decode("utf-8"):
                raise EvaluationContractError("event payload contains credential-looking text")
            envelope = {
                "seq": len(records), "phase": phase, "attempt_id": attempt_id,
                "payload": payload,
                "prev": records[-1]["hash"] if records else "sha256:" + "0" * 64,
            }
            envelope["hash"] = digest(canonical(envelope))
            with (self.root / "events.jsonl").open("ab") as stream:
                stream.write(canonical(envelope) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            return True

    def state(self, attempt_id: str) -> str:
        events = [e for e in self._events() if e["attempt_id"] == attempt_id]
        if not events:
            return "absent"
        if any(e["phase"] == "finished" for e in events):
            return "completed"
        if events[-1]["phase"] == "reconciled":
            return events[-1]["payload"]["disposition"]
        if any(e["phase"] == "started" for e in events):
            return "unknown"  # never resend an uncertain side effect
        return "planned"

    def get_attempt(self, attempt_id: str) -> Attempt:
        events = [e for e in self._events()
                  if e["attempt_id"] == attempt_id and e["phase"] == "finished"]
        if len(events) != 1:
            raise EvaluationContractError("no unambiguous original finished attempt")
        return Attempt.from_dict(events[0]["payload"]["attempt"])

    def attach_text(self, text: str, *, sensitive: bool = True) -> dict[str, Any]:
        """Default public mode stores redacted bytes; secrets are never emitted."""
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_ATTACHMENT:
            raise EvaluationContractError("attachment must be bounded UTF-8 text")
        original = digest(text.encode("utf-8"))
        cleaned = _redact(text) if sensitive else text
        if _redact(cleaned) != cleaned:
            raise EvaluationContractError("unredacted credential-like attachment")
        data = cleaned.encode("utf-8")
        sha = digest(data)
        name = sha.partition(":")[2]
        path = self.root / "attachments" / name
        if (self.root / "integrity.json").exists():
            raise EvaluationContractError("sealed evaluation bundle is immutable")
        if path.is_symlink():
            raise EvaluationContractError("attachment path symlink not permitted")
        if not path.exists():
            _write_exclusive(path, data)
        return {
            "digest": sha,
            "original_digest": original,
            "redacted": cleaned != text,
            "exact_replay_available": cleaned == text,
        }

    def rescore(self, attempt_id: str, specifications: tuple, *,
                asg: dict[str, Any] | None = None,
                authority_contract_digest: str | None = None) -> Attempt:
        """Pure rescore of frozen observations; does not execute target or read secrets."""
        from horustrace.evaluation.scorers import score_attempt

        original = self.get_attempt(attempt_id)
        updated = score_attempt(self.case, original, specifications, asg=asg,
                                authority_contract_digest=authority_contract_digest)
        self.append("rescored", attempt_id, {"attempt": updated.as_dict()})
        return updated

    def validate(self) -> dict[str, Any]:
        events = self._events()
        index = self.root / "integrity.json"
        attachments = sorted(
            p.name for p in (self.root / "attachments").iterdir()
            if p.is_file() and not p.is_symlink()
        )
        for name in attachments:
            path = self.root / "attachments" / name
            if not re.fullmatch(r"[0-9a-f]{64}", name) or (
                digest(path.read_bytes()).partition(":")[2] != name
            ):
                raise EvaluationContractError("attachment integrity mismatch")
        result = {
            "ledger_version": LEDGER_VERSION, "run_id": self.run_id,
            "manifest_digest": digest((self.root / "manifest.json").read_bytes()),
            "events": len(events),
            "chain_head": events[-1]["hash"] if events else "sha256:" + "0" * 64,
            "attachments": attachments,
            "incomplete_attempts": sorted({
                e["attempt_id"] for e in events
                if self.state(e["attempt_id"]) in {"planned", "unknown"}
            }),
        }
        if index.exists() and _read_json(index) != result:
            raise EvaluationContractError("sealed bundle integrity mismatch")
        return result

    def seal(self) -> dict[str, Any]:
        with self._exclusive():
            if (self.root / "integrity.json").exists():
                return self.validate()
            result = self.validate()
            _write_exclusive(self.root / "integrity.json", canonical(result) + b"\n")
            return result


def promote_regression_pair(
    ledger: EvaluationLedger, attempt_id: str, *,
    positive_source: str, negative_source: str,
    adjudication: dict[str, str],
) -> dict[str, Any]:
    """Write an *explicitly reviewed synthetic* pair, never silently update held-out truth."""
    if ledger.case.partition == "holdout":
        raise EvaluationContractError("holdout cases cannot be promoted")
    if set(adjudication) != {
        "source_review_status", "reviewer", "review_packet_digest", "source_anchor",
    } or adjudication["source_review_status"] != "independently_source_adjudicated":
        raise EvaluationContractError("promotion requires explicit independent source adjudication")
    if not adjudication["source_anchor"] or not adjudication["reviewer"]:
        raise EvaluationContractError("source reviewer and anchor required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", adjudication["review_packet_digest"]):
        raise EvaluationContractError("review packet digest required")
    attempt = ledger.get_attempt(attempt_id)
    if attempt.execution_state != "completed":
        raise EvaluationContractError("uncompleted attempts cannot be promoted")
    if positive_source == negative_source or not positive_source or not negative_source:
        raise EvaluationContractError("paired positive/negative source required")
    if any(_redact(s) != s for s in (positive_source, negative_source)):
        raise EvaluationContractError("synthetic fixture contains sensitive text")
    manifest = {
        "schema_version": 1, "case_id": ledger.case.case_id,
        "run_id": ledger.run_id, "attempt_id": attempt_id,
        "review": dict(adjudication),
        "positive_source_digest": digest(positive_source.encode("utf-8")),
        "negative_source_digest": digest(negative_source.encode("utf-8")),
        "source_sha": ledger.case.source_sha,
        "asg_digest": ledger.case.asg_digest,
        "historical_truth_modified": False,
    }
    # Proposals live outside the sealed/immutable evidence bundle and never
    # modify historical truth, journal hashes or retained holdout artifacts.
    dest = (ledger.root.parent / f"{ledger.root.name}.regression_proposals"
            / ledger.case.case_id)
    if dest.exists():
        raise EvaluationContractError("reviewed regression proposal already exists")
    dest.mkdir(parents=True)
    _write_exclusive(dest / "positive.py", positive_source.encode("utf-8"))
    _write_exclusive(dest / "near_miss.py", negative_source.encode("utf-8"))
    _write_exclusive(dest / "manifest.json", canonical(manifest) + b"\n")
    return manifest
