"""Validate, inspect or rescore a locally pinned evaluation ledger offline.

No command launches scanned code, a model provider, MCP tool or network target.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from horustrace.evaluation.ledger import EvaluationLedger
from horustrace.evaluation.scorers import AssertionSpec


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--mode", choices=("validate", "replay", "rescore"), default="validate")
    parser.add_argument("--attempt", help="Exact attempt ID required for replay/rescore")
    parser.add_argument("--specifications", type=Path,
                        help="Locally reviewed JSON array of deterministic assertion specs")
    parser.add_argument("--authority-contract-digest",
                        help="Externally verified sha256 digest of the approved Authority Contract")
    args = parser.parse_args(argv)
    ledger = EvaluationLedger(args.bundle)
    integrity = ledger.validate()
    if args.mode == "validate":
        report = integrity
    else:
        if not args.attempt:
            parser.error("--attempt is required for replay/rescore")
        original = ledger.get_attempt(args.attempt)
        if args.mode == "replay":
            # Freeze/inspect the recorded event sequence. This is an offline
            # observation replay, not stochastic model regeneration.
            report = {
                "mode": "offline_observation_replay", "attempt": original.as_dict(),
                "run_id": ledger.run_id, "case_id": ledger.case.case_id,
                "exact_external_model_reproduction": False,
                "target_requests": 0,
            }
        else:
            if args.specifications is None:
                parser.error("--specifications is required for rescore")
            doc = json.loads(args.specifications.read_text(encoding="utf-8"))
            if not isinstance(doc, list):
                parser.error("specifications must be a JSON array")
            specs = tuple(AssertionSpec(**record) for record in doc)
            outcome = ledger.rescore(
                args.attempt, specs,
                authority_contract_digest=args.authority_contract_digest,
            )
            report = {
                "mode": "offline_rescore", "attempt": outcome.as_dict(),
                "run_id": ledger.run_id, "target_requests": 0,
            }
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
