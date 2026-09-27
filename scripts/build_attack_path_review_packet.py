"""Build a blinded human-review packet from locked source truth only.

The generator never reads HorusTrace scan results, findings, or attack-path output.
Selection is deterministic over the immutable 2026 ground-truth directory.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

STUDY = "attack-path-finding-validation-2026"
SOURCE_STUDY = "real-world-agent-security-2026"


class PacketError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Candidate:
    case_id: str
    repo: str
    sha: str
    application_path: str
    category: str
    question: dict[str, Any]
    source_scope: tuple[str, ...]
    evidence_hint: tuple[dict[str, Any], ...]


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PacketError(f"{path}: expected JSON object")
    return value


def _review_slots() -> list[dict[str, Any]]:
    return [
        {
            "reviewer_id": "",
            "independent_human": True,
            "horustrace_output_seen": False,
            "locked": False,
            "verdict": "unresolved",
            "severity": "unresolved",
            "evidence": [],
            "rationale": "",
        },
        {
            "reviewer_id": "",
            "independent_human": True,
            "horustrace_output_seen": False,
            "locked": False,
            "verdict": "unresolved",
            "severity": "unresolved",
            "evidence": [],
            "rationale": "",
        },
    ]


def _source(doc: dict[str, Any]) -> tuple[str, str, str]:
    ref = doc.get("source_reference")
    if not isinstance(ref, dict):
        raise PacketError("ground truth missing source_reference")
    repo = str(ref.get("repo") or "").strip()
    sha = str(ref.get("sha") or "").strip()
    app = str(ref.get("application_path") or "").strip()
    if not repo or len(sha) != 40 or not app:
        raise PacketError(f"{doc.get('case_id')}: incomplete source reference")
    return repo, sha, app


def _evidence_paths(items: list[dict[str, Any]]) -> tuple[str, ...]:
    paths: list[str] = []
    for item in items:
        evidence = item.get("evidence")
        if not isinstance(evidence, list):
            continue
        for row in evidence:
            if isinstance(row, dict) and isinstance(row.get("path"), str):
                paths.append(row["path"])
    return tuple(sorted(set(paths)))


def _authority_candidates(doc: dict[str, Any]) -> list[Candidate]:
    tier_b = doc.get("tier_b") if isinstance(doc.get("tier_b"), dict) else {}
    relationships = tier_b.get("authority_relationships")
    if not isinstance(relationships, list):
        return []
    repo, sha, app = _source(doc)
    result: list[Candidate] = []
    for index, rel in enumerate(relationships):
        if not isinstance(rel, dict):
            continue
        agent = rel.get("agent")
        target_name = rel.get("target_name")
        target_kind = rel.get("target_kind")
        path = rel.get("path") or app
        if not all(isinstance(x, str) and x.strip() for x in (agent, target_name, target_kind, path)):
            continue
        result.append(
            Candidate(
                case_id=f"{doc['case_id']}-authority-{index+1:02d}",
                repo=repo,
                sha=sha,
                application_path=app,
                category="proven_authority",
                question={
                    "type": "attack_path",
                    "claim": {
                        "source": agent,
                        "relation": "can_invoke",
                        "target_kind": target_kind,
                        "target": target_name,
                    },
                    "prompt": (
                        "Does the pinned source statically prove that this agent can "
                        "directly invoke this target?"
                    ),
                },
                source_scope=tuple(sorted({app, path})),
                evidence_hint=(
                    {
                        "path": path,
                        "line": rel.get("line"),
                        "purpose": "review the source-level binding only",
                    },
                ),
            )
        )
    return result


def _near_miss_candidates(doc: dict[str, Any]) -> list[Candidate]:
    tier_a = doc.get("tier_a") if isinstance(doc.get("tier_a"), dict) else {}
    tier_b = doc.get("tier_b") if isinstance(doc.get("tier_b"), dict) else {}
    completeness = tier_a.get("reference_completeness")
    if not isinstance(completeness, dict) or completeness.get("tools") is not True:
        return []
    relationships = tier_b.get("authority_relationships")
    tools = tier_a.get("tools")
    agents = tier_a.get("agent_roots")
    if not isinstance(relationships, list) or not isinstance(tools, list) or not isinstance(agents, list):
        return []

    repo, sha, app = _source(doc)
    bound: dict[str, set[str]] = {}
    relation_paths: dict[str, set[str]] = {}
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        agent = rel.get("agent")
        target = rel.get("target_name")
        if isinstance(agent, str) and isinstance(target, str):
            bound.setdefault(agent, set()).add(target)
            path = rel.get("path")
            if isinstance(path, str):
                relation_paths.setdefault(agent, set()).add(path)

    tool_rows = [
        item
        for item in tools
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and isinstance(item.get("path"), str)
    ]
    result: list[Candidate] = []
    for agent_row in agents:
        if not isinstance(agent_row, dict):
            continue
        agent = agent_row.get("name")
        if not isinstance(agent, str) or agent not in bound:
            continue
        candidates = [tool for tool in tool_rows if tool["name"] not in bound[agent]]
        if not candidates:
            continue
        tool = sorted(candidates, key=lambda x: (str(x["path"]), str(x["name"])))[0]
        source_paths = {
            app,
            str(agent_row.get("path") or app),
            str(tool["path"]),
            *relation_paths.get(agent, set()),
        }
        result.append(
            Candidate(
                case_id=f"{doc['case_id']}-near-miss-{len(result)+1:02d}",
                repo=repo,
                sha=sha,
                application_path=app,
                category="invalid_near_miss",
                question={
                    "type": "attack_path",
                    "claim": {
                        "source": agent,
                        "relation": "can_invoke",
                        "target_kind": "tool",
                        "target": tool["name"],
                    },
                    "prompt": (
                        "Does the pinned source statically prove that this agent can "
                        "directly invoke this in-scope tool? Treat mere repository "
                        "co-presence as insufficient."
                    ),
                },
                source_scope=tuple(sorted(source_paths)),
                evidence_hint=(
                    {
                        "path": str(agent_row.get("path") or app),
                        "line": agent_row.get("line"),
                        "purpose": "review agent construction and actual bindings",
                    },
                    {
                        "path": str(tool["path"]),
                        "line": tool.get("line"),
                        "purpose": "review the near-miss tool independently",
                    },
                ),
            )
        )
    return result


def _delegation_candidates(doc: dict[str, Any]) -> list[Candidate]:
    tier_a = doc.get("tier_a") if isinstance(doc.get("tier_a"), dict) else {}
    edges = tier_a.get("delegation_edges")
    if not isinstance(edges, list):
        return []
    repo, sha, app = _source(doc)
    result: list[Candidate] = []
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            continue
        source = edge.get("source") or edge.get("from") or edge.get("agent")
        target = edge.get("target") or edge.get("to") or edge.get("delegate")
        path = edge.get("path") or app
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        result.append(
            Candidate(
                case_id=f"{doc['case_id']}-delegation-{index+1:02d}",
                repo=repo,
                sha=sha,
                application_path=app,
                category="delegation",
                question={
                    "type": "attack_path",
                    "claim": {
                        "source": source,
                        "relation": "delegates_to",
                        "target": target,
                    },
                    "prompt": (
                        "Does the pinned source statically prove this delegation/handoff "
                        "relationship?"
                    ),
                },
                source_scope=tuple(sorted({app, str(path)})),
                evidence_hint=(
                    {
                        "path": str(path),
                        "line": edge.get("line"),
                        "purpose": "review delegation construction",
                    },
                ),
            )
        )
    return result


def _signal_candidate(doc: dict[str, Any], signal: str, category: str) -> Candidate | None:
    tier_b = doc.get("tier_b") if isinstance(doc.get("tier_b"), dict) else {}
    signals = tier_b.get("security_relevant_signals")
    if not isinstance(signals, list) or signal not in signals:
        return None
    repo, sha, app = _source(doc)
    assertions = doc.get("assertions") if isinstance(doc.get("assertions"), list) else []
    paths = _evidence_paths([x for x in assertions if isinstance(x, dict)])
    scope = tuple(sorted(set(paths) | {app}))
    wording = {
        "approval_controls": (
            "Does the pinned source contain an approval/human-intervention control "
            "that can gate a security-relevant action?"
        ),
        "mcp_usage": (
            "Does the pinned source establish an MCP-mediated capability boundary "
            "relevant to agent reachability?"
        ),
        "external_write_or_transaction_semantics": (
            "Does the pinned source contain a capability that can perform an external "
            "write or transaction, rather than read-only behavior?"
        ),
        "external_write_or_network": (
            "Does the pinned source contain a capability that can cause an external "
            "write or network side effect?"
        ),
        "process_execution": (
            "Does the pinned source expose process/code execution as an agent-reachable "
            "capability or explicit tool?"
        ),
        "sensitive_resource_access": (
            "Does the pinned source expose access to a security-sensitive resource or "
            "credential-bearing context?"
        ),
        "multiple_trust_boundaries": (
            "Does the pinned source cross an explicit trust boundary through delegation, "
            "remote capability use, or external service access?"
        ),
    }
    return Candidate(
        case_id=f"{doc['case_id']}-{category}",
        repo=repo,
        sha=sha,
        application_path=app,
        category=category,
        question={
            "type": "attack_path",
            "claim": {"signal": signal},
            "prompt": wording[signal],
        },
        source_scope=scope,
        evidence_hint=tuple(
            {"path": path, "line": None, "purpose": "source-only security-signal review"}
            for path in scope
        ),
    )


def _unresolved_candidate(doc: dict[str, Any]) -> Candidate | None:
    tier_a = doc.get("tier_a") if isinstance(doc.get("tier_a"), dict) else {}
    unresolved = tier_a.get("unresolved")
    if not isinstance(unresolved, list) or not unresolved:
        return None
    repo, sha, app = _source(doc)
    return Candidate(
        case_id=f"{doc['case_id']}-unresolved",
        repo=repo,
        sha=sha,
        application_path=app,
        category="dynamic_unresolved",
        question={
            "type": "attack_path",
            "claim": {"constructs": sorted(str(x) for x in unresolved)},
            "prompt": (
                "Can the relevant security reachability be resolved statically from "
                "the pinned source without runtime assumptions?"
            ),
        },
        source_scope=(app,),
        evidence_hint=(
            {
                "path": app,
                "line": None,
                "purpose": "determine whether dynamic/static uncertainty is resolvable",
            },
        ),
    )


def _finding_candidates(doc: dict[str, Any]) -> list[Candidate]:
    assertions = doc.get("assertions")
    if not isinstance(assertions, list):
        return []
    repo, sha, app = _source(doc)
    result: list[Candidate] = []
    for assertion in assertions:
        if not isinstance(assertion, dict):
            continue
        predicate = assertion.get("predicate")
        state = assertion.get("expected_state")
        evidence = assertion.get("evidence")
        if predicate not in {"can_invoke", "explicit_tool_reference", "explicit_agent_entity"}:
            continue
        if state not in {"present", "absent", "unresolved"} or not isinstance(evidence, list):
            continue
        ev = tuple(
            {
                "path": row.get("path"),
                "line": row.get("line"),
                "purpose": "review source support for the proposed assertion",
            }
            for row in evidence
            if isinstance(row, dict) and isinstance(row.get("path"), str)
        )
        if not ev:
            continue
        result.append(
            Candidate(
                case_id=f"{doc['case_id']}-finding-{assertion.get('assertion_id')}",
                repo=repo,
                sha=sha,
                application_path=app,
                category=f"finding_{predicate}",
                question={
                    "type": "finding",
                    "claim": {
                        "subject": assertion.get("subject"),
                        "predicate": predicate,
                        "object": assertion.get("object"),
                    },
                    "prompt": (
                        "Is this source-level security/structure assertion factually "
                        "supported by the pinned source? Independently assign severity "
                        "based on security consequence, not HorusTrace output."
                    ),
                },
                source_scope=tuple(sorted({row["path"] for row in ev})),
                evidence_hint=ev,
            )
        )
    return result


def _stable_take(candidates: list[Candidate], count: int, used_repos: Counter[str] | None = None) -> list[Candidate]:
    from collections import Counter

    repo_counts = used_repos if used_repos is not None else Counter()
    selected: list[Candidate] = []
    for item in sorted(candidates, key=lambda x: (repo_counts[x.repo], x.sha, x.case_id)):
        if len(selected) >= count:
            break
        if repo_counts[item.repo] >= 3:
            continue
        selected.append(item)
        repo_counts[item.repo] += 1
    return selected


def build_packet(ground_truth_dir: Path) -> dict[str, Any]:
    from collections import Counter

    docs = [_load_json(path) for path in sorted(ground_truth_dir.glob("rw-*.json"))]
    docs = [
        doc
        for doc in docs
        if doc.get("study") == SOURCE_STUDY
        and isinstance(doc.get("truth_lock"), dict)
        and doc["truth_lock"].get("horustrace_output_seen") is False
    ]
    if len(docs) < 100:
        raise PacketError("ground-truth corpus unexpectedly small")

    authority: list[Candidate] = []
    delegation: list[Candidate] = []
    near_miss: list[Candidate] = []
    approval: list[Candidate] = []
    mcp: list[Candidate] = []
    write: list[Candidate] = []
    execution: list[Candidate] = []
    sensitive: list[Candidate] = []
    trust: list[Candidate] = []
    unresolved: list[Candidate] = []
    findings: list[Candidate] = []

    for doc in docs:
        authority.extend(_authority_candidates(doc))
        delegation.extend(_delegation_candidates(doc))
        near_miss.extend(_near_miss_candidates(doc))
        findings.extend(_finding_candidates(doc))
        for signal, target, category in [
            ("approval_controls", approval, "approval_gate"),
            ("mcp_usage", mcp, "mcp_boundary"),
            ("external_write_or_transaction_semantics", write, "external_write"),
            ("external_write_or_network", write, "external_write"),
            ("process_execution", execution, "process_execution"),
            ("sensitive_resource_access", sensitive, "sensitive_resource"),
            ("multiple_trust_boundaries", trust, "trust_boundary"),
        ]:
            candidate = _signal_candidate(doc, signal, category)
            if candidate is not None:
                target.append(candidate)
        candidate = _unresolved_candidate(doc)
        if candidate is not None:
            unresolved.append(candidate)

    repo_counts: Counter[str] = Counter()
    attack_cases: list[Candidate] = []
    quotas = [
        (authority, 5),
        (near_miss, 4),
        (delegation, 3),
        (approval, 3),
        (mcp, 3),
        (write, 3),
        (unresolved, 3),
        (execution + sensitive + trust, 3),
    ]
    for pool, count in quotas:
        selected = _stable_take(
            [x for x in pool if x.case_id not in {y.case_id for y in attack_cases}],
            count,
            repo_counts,
        )
        attack_cases.extend(selected)

    if len(attack_cases) < 20:
        fallback = authority + near_miss + delegation + approval + mcp + write + execution + sensitive + trust + unresolved
        attack_cases.extend(
            _stable_take(
                [x for x in fallback if x.case_id not in {y.case_id for y in attack_cases}],
                24 - len(attack_cases),
                repo_counts,
            )
        )
    attack_cases = attack_cases[:24]

    finding_repo_counts: Counter[str] = Counter()
    finding_cases: list[Candidate] = []
    by_category: dict[str, list[Candidate]] = {}
    for item in findings:
        by_category.setdefault(item.category, []).append(item)
    for category in sorted(by_category):
        finding_cases.extend(_stable_take(by_category[category], 6, finding_repo_counts))
    finding_cases = sorted(
        {item.case_id: item for item in finding_cases}.values(),
        key=lambda x: (finding_repo_counts[x.repo], x.sha, x.case_id),
    )[:24]

    if len(attack_cases) < 20:
        raise PacketError(f"only {len(attack_cases)} attack-path cases available")
    if len(finding_cases) < 12:
        raise PacketError(f"only {len(finding_cases)} finding cases available")

    def row(item: Candidate, case_type: str) -> dict[str, Any]:
        return {
            "case_id": item.case_id,
            "case_type": case_type,
            "category": item.category,
            "repository": {"repo": item.repo, "sha": item.sha},
            "application_path": item.application_path,
            "source_scope": list(item.source_scope),
            "question": item.question,
            "source_review_hints": list(item.evidence_hint),
            "reviewers": _review_slots(),
        }

    rows = [
        *(row(item, "attack_path") for item in attack_cases),
        *(row(item, "finding") for item in finding_cases),
    ]
    return {
        "schema_version": 1,
        "study": STUDY,
        "packet_version": 1,
        "selection_source": (
            "locked real-world-agent-security-2026 source truth only; "
            "no HorusTrace findings or attack-path output"
        ),
        "horustrace_output_used_for_selection": False,
        "scanner_reveal_allowed": False,
        "attack_path_target": "20-30",
        "finding_sampling": "stratified by source assertion predicate with repository caps",
        "case_counts": {
            "attack_path": len(attack_cases),
            "finding": len(finding_cases),
            "total": len(rows),
        },
        "cases": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ground-truth-dir",
        type=Path,
        default=Path("research/real-world-agent-security-2026/ground-truth"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    packet = build_packet(args.ground_truth_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(packet, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    print(json.dumps(packet["case_counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
