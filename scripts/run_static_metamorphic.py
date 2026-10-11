"""Offline claim-preservation matrix for the #511 source metamorphic corpus.

No fixture import, process execution, MCP launch or network calls are performed.
"""
from __future__ import annotations

import json
import tempfile
from collections import Counter
from pathlib import Path

from horustrace.evaluation.metamorphic import generate_variant, security_claims
from horustrace.scanner import scan

EXPECTED = ("ops", "agent_tool_input", "process_execute")
MANIFEST = Path(__file__).resolve().parents[1] / "tests/fixtures/adversarial_static/manifest.json"


def main() -> int:
    cases = json.loads(MANIFEST.read_text(encoding="utf-8"))["cases"]
    families: dict[str, Counter] = {}
    with tempfile.TemporaryDirectory(prefix="horustrace-source-met") as directory:
        root = Path(directory)
        source = root / "agent.py"
        for record in cases:
            stats = families.setdefault(record["family"], Counter())
            variant = generate_variant(record["family"], record["seed"])
            source.write_text(variant.risky_source, encoding="utf-8")
            positive, _ = scan(root)
            if EXPECTED in security_claims(positive):
                stats["supported"] += 1
            else:
                stats["lost"] += 1
            source.write_text(variant.near_miss_source, encoding="utf-8")
            negative, _ = scan(root)
            if EXPECTED in security_claims(negative):
                stats["false_supported"] += 1
            else:
                stats["near_miss_rejected"] += 1
    report = {
        "schema_version": 1,
        "method": "source_only_metamorphic",
        "families": {key: dict(sorted(value.items())) for key, value in sorted(families.items())},
        "cases": len(cases),
        "paired_assertions": len(cases) * 2,
        "status": "pass" if all(
            s["supported"] == 3 and s["near_miss_rejected"] == 3
            for s in families.values()
        ) and len(families) == 8 else "fail",
        "scope": "pinned fixture assertions, not independent product-wide precision/recall",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
