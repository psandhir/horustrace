"""rw-002 bounded positive/hard-negative FastAgent ontology witness.

This is post-hoc source inspection of a *closed list of two files*, not
exhaustive rw-002 truth, deployed inventory, or independent V2 precision.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from horustrace.adapters.fast_agent import scan_python_file

REPO = "omnigentx/jarvis"
SOURCE_SHA = "90d1eb1620912e752be2e6fe8156923a0394216d"
APP_FILE = "backend/agent.py"
COMPACTION_FILE = "backend/services/context_compaction.py"
BLOBS = {
    APP_FILE: "97f5e0fd49193dc66fa3f080ff5759ed8f2ddf1a",
    COMPACTION_FILE: "27b57b5bd590093fac04e7b6d10f938ce360bbb1",
}
# Independent source AST literals, rather than names taken from scanner output.
DECORATED_AGENTS = {
    ("PersonalAgent", "agent", 102),
    ("IoTAgent", "agent", 112),
    ("MusicAgent", "custom", 123),
    ("AudioReaderAgent", "custom", 134),
    ("ResearchAgent", "agent", 149),
    ("FinanceAgent", "agent", 172),
    ("CrawlStoriesAgent", "agent", 190),
    ("Jarvis", "agent", 302),
}


def _blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + bytes([0]) + raw).hexdigest()


def _dotted(value: ast.AST) -> str:
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        prefix = _dotted(value.value)
        return prefix + "." + value.attr if prefix else value.attr
    return ""


def _decorated_constructs(source: bytes) -> set[tuple[str, str, int]]:
    tree = ast.parse(source.decode("utf-8"))
    result: set[tuple[str, str, int]] = set()
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decoration in func.decorator_list:
            if not isinstance(decoration, ast.Call):
                continue
            d = _dotted(decoration.func)
            if d not in {"fast.agent", "fast.custom"}:
                continue
            name = next((ast.literal_eval(kw.value)
                         for kw in decoration.keywords
                         if kw.arg == "name" and isinstance(kw.value, ast.Constant)
                         and isinstance(kw.value.value, str)), None)
            if not isinstance(name, str):
                raise ValueError("nonliteral agent declaration name is source-unresolved")
            result.add((name, d.split(".")[-1], decoration.lineno))
    return result


def adjudicate(sources: dict[str, bytes], root: Path) -> dict[str, Any]:
    if set(sources) != set(BLOBS):
        raise ValueError("exact pinned application source witnesses required")
    for path, raw in sources.items():
        if _blob(raw) != BLOBS[path]:
            raise ValueError(f"pinned application Git blob changed: {path}")
    main_ast = ast.parse(sources[APP_FILE].decode("utf-8"))
    labels = _decorated_constructs(sources[APP_FILE])
    if labels != DECORATED_AGENTS:
        raise ValueError("source agent/custom decorator census changed")

    factories: list[tuple[str, int]] = []
    subclass_sites: list[int] = []
    for node in ast.walk(main_ast):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if _dotted(node.value.func) == "FastAgent":
                factories.extend((target.id, node.lineno) for target in node.targets
                                 if isinstance(target, ast.Name))
        if isinstance(node, ast.ClassDef) and node.name == "TagRelayAgent":
            if any(_dotted(base) == "McpAgent" for base in node.bases):
                subclass_sites.append(node.lineno)
    if factories != [("fast", 71)] or subclass_sites != [63]:
        raise ValueError("app factory/custom subclass source negatives changed")

    secondary = ast.parse(sources[COMPACTION_FILE].decode("utf-8"))
    compactor_sites = [
        n.lineno for n in ast.walk(secondary)
        if isinstance(n, ast.Call) and _dotted(n.func) == "LlmAgent"
    ]
    if compactor_sites != [536]:
        raise ValueError("conditional compaction LlmAgent source declaration changed")

    graph = scan_python_file(root / APP_FILE)
    got = {(a.name, a.metadata.get("agent_type"), a.location.line)
           for a in graph.agents if a.location is not None}
    if got != DECORATED_AGENTS or len(graph.agents) != len(got):
        raise ValueError(f"scanner agent declaration mismatch: {sorted(got)}")
    if graph.workflow_nodes:
        raise ValueError("scanner invented workflow for scoped eight agents")
    if any(a.name in {"fast", "TagRelayAgent", "shell"} for a in graph.agents):
        raise ValueError("factory/subclass/indirect compactor promoted as FastAgent agent")
    if any(a.metadata.get("framework") != "fast-agent" for a in graph.agents):
        raise ValueError("source decoration classified as unrelated agent framework")

    return {
        "schema_version": 1,
        "case_id": "rw-002",
        "repository": REPO,
        "source_sha": SOURCE_SHA,
        "scope": "two_exact_source_files_not_complete_repository",
        "blob_witnesses": dict(BLOBS),
        "source_positive_agent_declarations": [
            {"name": name, "decorator": kind, "path": APP_FILE, "line": line,
             "label": "source_declared_conditional_runtime_unverified"}
            for name, kind, line in sorted(labels, key=lambda x: x[2])
        ],
        "source_positive_agent_count": len(labels),
        "custom_agent_declarations": sum(kind == "custom" for _, kind, _ in labels),
        "source_hard_negative_not_agent": [
            {"symbol": name, "path": APP_FILE, "line": line,
             "reason": "FastAgent_app_factory_not_individual_agent"}
            for name, line in factories
        ] + [
            {"symbol": "TagRelayAgent", "path": APP_FILE, "line": subclass_sites[0],
             "reason": "custom_agent_class_definition_not_instantiated_agent"}
        ],
        "secondary_source_conditional_agents": [
            {"symbol": "context-compactor", "path": COMPACTION_FILE,
             "line": compactor_sites[0], "status": "LlmAgent_construct_inside_function"}
        ],
        "source_mcp_servers_runtime_verified": False,
        "source_skill_grants_runtime_verified": False,
        "original_frozen_reference_rewritten": False,
        "original_reference_complete": False,
        "source_truth_method": "posthoc_bounded_ast_crosscheck_not_independent_blind",
        "independent_exhaustive_negative_labels": False,
        "agent_precision": None,
        "agent_recall": None,
        "wave_b_go": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()
    if any(not (root / path).resolve().is_relative_to(root) for path in BLOBS):
        raise ValueError("source file escaped exact checkout")
    sources = {path: (root / path).read_bytes() for path in BLOBS}
    report = adjudicate(sources, root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({"case_id": report["case_id"],
                      "agents": report["source_positive_agent_count"],
                      "hard_negative": len(report["source_hard_negative_not_agent"]),
                      "go": report["wave_b_go"]}))


if __name__ == "__main__":
    main()
