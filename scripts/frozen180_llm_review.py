"""Validate scanner-blind frozen180 LLM responses against HorusScan-aligned facts.

No HorusScan report is read in this module. A successful validation is evidence
integrity, not source-security accuracy or reviewer independence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

STUDY = "frozen180-llm-source-review-20261008"
ROOT = Path("research/frozen180-llm-differential-20261008")
RULE_IDS = re.compile(r"\b(?:AGT|ADK|CAP|NET|DATA|IDN|PATH|SKL)\d{3}\b")
SOURCE_FILE = re.compile(r"^===== SOURCE FILE: (.+) =====$")
NUMBERED_LINE = re.compile(r"^(\d{6}): (.*)$")


class ReviewError(ValueError):
    pass


def _schema_validate(value: Any, spec: dict[str, Any], schema: dict, label: str) -> None:
    """Apply only the JSON-Schema keywords explicitly used by our frozen schema."""
    if "$ref" in spec:
        ref = spec["$ref"]
        if not ref.startswith("#/$defs/"):
            raise ReviewError(f"{label}: unsupported JSON schema reference")
        _schema_validate(value, schema["$defs"][ref.rsplit("/", 1)[-1]], schema, label)
        return
    if "anyOf" in spec:
        for variant in spec["anyOf"]:
            try:
                _schema_validate(value, variant, schema, label)
                return
            except ReviewError:
                continue
        raise ReviewError(f"{label}: matches none of the allowed types")
    kind = spec.get("type")
    if kind:
        kinds = kind if isinstance(kind, list) else [kind]
        allowed = {
            "object": lambda x: isinstance(x, dict),
            "array": lambda x: isinstance(x, list),
            "string": lambda x: isinstance(x, str),
            "integer": lambda x: isinstance(x, int) and not isinstance(x, bool),
            "null": lambda x: x is None,
        }
        if not any(allowed[k](value) for k in kinds):
            raise ReviewError(f"{label}: expected {kinds}")
    if "const" in spec and value != spec["const"]:
        raise ReviewError(f"{label}: wrong constant")
    if "enum" in spec and value not in spec["enum"]:
        raise ReviewError(f"{label}: invalid value {value!r}")
    if isinstance(value, str):
        if len(value) < spec.get("minLength", 0):
            raise ReviewError(f"{label}: empty/short string")
        if "pattern" in spec and not re.fullmatch(spec["pattern"], value):
            raise ReviewError(f"{label}: invalid pattern")
    if isinstance(value, int) and not isinstance(value, bool) and value < spec.get("minimum", 0):
        raise ReviewError(f"{label}: below minimum")
    if isinstance(value, dict):
        required = spec.get("required", [])
        missing = [k for k in required if k not in value]
        if missing:
            raise ReviewError(f"{label}: missing {missing}")
        props = spec.get("properties", {})
        if spec.get("additionalProperties") is False:
            extra = sorted(set(value) - set(props))
            if extra:
                raise ReviewError(f"{label}: forbidden/unexpected fields {extra}")
        for k, v in value.items():
            if k in props:
                _schema_validate(v, props[k], schema, f"{label}.{k}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            _schema_validate(child, spec["items"], schema, f"{label}[{i}]")


def source_lines(packet_text: str) -> dict[str, dict[int, str]]:
    paths: dict[str, dict[int, str]] = {}
    current = None
    for raw in packet_text.splitlines():
        start = SOURCE_FILE.fullmatch(raw)
        if start:
            current = start.group(1)
            if current in paths:
                raise ReviewError(f"duplicate source file header: {current}")
            paths[current] = {}
            continue
        entry = NUMBERED_LINE.fullmatch(raw)
        if entry and current is not None:
            number = int(entry.group(1))
            paths[current][number] = entry.group(2)
    return paths


def _evidence_objects(review: dict) -> list[dict]:
    evidence = []
    for key in ("entities", "relationships", "authority_contracts", "findings", "attack_paths"):
        for item in review[key]:
            evidence.extend(item["evidence"])
            if key == "attack_paths":
                for step in item["steps"]:
                    evidence.extend(step["evidence"])
    return evidence


def validate_review(review: dict, manifest: dict, source_text: str,
                    schema: dict) -> dict[str, Any]:
    _schema_validate(review, schema, schema, "review")
    if manifest.get("source_output_seen") is not False or manifest.get("status") != "ok":
        raise ReviewError("source packet is not a clean scanner-blind successful bundle")
    if manifest.get("application_entrypoint_included") is not True:
        raise ReviewError("source packet omitted its declared application entrypoint")
    for field, packet_field in (
        ("case_id", "case_id"), ("repo", "repo"), ("sha", "sha"),
        ("framework", "framework"),
    ):
        if review[field] != manifest[packet_field]:
            raise ReviewError(f"case provenance mismatch: {field}")
    if review["study"] != STUDY:
        raise ReviewError("wrong study")
    if review["review_scope"]["application_path"] != manifest["application_path"]:
        raise ReviewError("application path changed")
    digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    if digest != manifest["source_pack_sha256"]:
        raise ReviewError("source text/manifest digest mismatch")
    if review["review_scope"]["source_pack_sha256"] != digest:
        raise ReviewError("review did not bind exact source pack hash")
    if review["coverage"]["omitted_or_truncated"] != manifest["omitted_or_truncated"]:
        raise ReviewError("review concealed packet omissions")
    if review["coverage"]["source_coverage"] != "qualified":
        raise ReviewError("bounded packets cannot establish exhaustive source completeness")
    if review["coverage"]["review_result"] == "reviewed_no_candidate":
        raise ReviewError("negative completeness cannot be claimed from bounded packets")
    if not review["coverage"]["reviewed_files"]:
        raise ReviewError("no source files claimed reviewed")
    lines = source_lines(source_text)
    if not lines:
        raise ReviewError("source packet has no readable numbered files")
    if not set(review["coverage"]["reviewed_files"]) <= set(lines):
        raise ReviewError("review cites unavailable files as reviewed")
    names = set()
    kinds: dict[str, str] = {}
    for part in ("entities", "relationships", "authority_contracts", "findings", "attack_paths"):
        for item in review[part]:
            rid = item["id"]
            if rid in names:
                raise ReviewError(f"duplicate review ID {rid}")
            names.add(rid)
            if part == "entities":
                kinds[rid] = item["kind"]
            if not item["evidence"]:
                raise ReviewError(f"{rid}: source evidence required")
    for entity in review["entities"]:
        if entity["kind"] == "agent" and entity["binding_status"] == "declared_only":
            # Declared-only agent objects can be listed as such, never as
            # statically proven agent-reachable sinks.
            continue
    for rel in review["relationships"]:
        if kinds.get(rel["agent_id"]) != "agent":
            raise ReviewError(f"{rel['id']}: agent_id is not an inventoried agent")
        if rel["target_id"] is not None and rel["target_id"] not in kinds:
            raise ReviewError(f"{rel['id']}: unknown target_id")
    for item in review["authority_contracts"]:
        if kinds.get(item["agent_id"]) != "agent":
            raise ReviewError(f"{item['id']}: contract references unknown agent")
    for item in review["findings"]:
        if item["agent_id"] is not None and kinds.get(item["agent_id"]) != "agent":
            raise ReviewError(f"{item['id']}: finding agent is unbound")
        for rid in item["authority_relationship_ids"]:
            if rid not in names:
                raise ReviewError(f"{item['id']}: unknown authority relationship {rid}")
    for path in review["attack_paths"]:
        if kinds.get(path["agent_id"]) != "agent":
            raise ReviewError(f"{path['id']}: attack path needs an inventoried agent")
        if len(path["steps"]) < 3:
            raise ReviewError(f"{path['id']}: path has fewer than 3 grounded steps")
        orders = [x["order"] for x in path["steps"]]
        if orders != list(range(1, len(orders) + 1)):
            raise ReviewError(f"{path['id']}: out-of-order or duplicate path steps")
        for step in path["steps"]:
            if step["entity_id"] is not None and step["entity_id"] not in kinds:
                raise ReviewError(f"{path['id']}: path step references unknown entity")
            if not step["evidence"]:
                raise ReviewError(f"{path['id']}: every path step needs source evidence")
    for ev in _evidence_objects(review):
        path = ev["path"]
        if path not in lines:
            raise ReviewError(f"unknown source file: {path}")
        start, end = ev["line_start"], ev["line_end"]
        if end < start or end - start > 100:
            raise ReviewError(f"{path}: invalid/overly broad evidence range {start}-{end}")
        if not all(n in lines[path] for n in range(start, end + 1)):
            raise ReviewError(f"{path}:{start}-{end} not supplied in source packet")
        quote = ev["quote"]
        if quote is not None and quote.strip():
            body = "\n".join(lines[path][i] for i in range(start, end + 1))
            if quote.strip() not in body:
                raise ReviewError(f"{path}:{start}-{end}: evidence quote not in source")
    # Block copied scanner-specific rule IDs and scanner output contamination.
    if RULE_IDS.search(json.dumps(review)):
        raise ReviewError("independent source review contains scanner rule identifier")
    return {
        "valid": True,
        "study": STUDY,
        "case_id": review["case_id"],
        "source_pack_sha256": digest,
        "source_evidence_anchors": len(_evidence_objects(review)),
        "counts": {
            "entities": len(review["entities"]),
            "authority_relationships": len(review["relationships"]),
            "authority_contracts": len(review["authority_contracts"]),
            "findings": len(review["findings"]),
            "attack_paths": len(review["attack_paths"]),
        },
        "reveal_allowed": False,
        "accuracy_validated": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--review", type=Path, required=True)
    p.add_argument("--source-manifest", type=Path, required=True)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--schema", type=Path, default=ROOT / "source-review.schema.json")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    try:
        review = json.loads(args.review.read_text(encoding="utf-8"))
        manifest = json.loads(args.source_manifest.read_text(encoding="utf-8"))
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
        result = validate_review(review, manifest, args.source.read_text(encoding="utf-8"),
                                 schema)
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid independent source review: {exc}") from exc
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
