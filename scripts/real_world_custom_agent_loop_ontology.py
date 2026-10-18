"""Shadow, source-only custom agent-construct ontology (not runtime authority).

Classification requires an explicit repeatable model-directed tool loop: the
model sees tools, returns selected tool calls, selected calls are dispatched,
and their results are fed into another model invocation. Neither a class name
nor a standalone MCP connection is sufficient. The syntactic witness is not
proof of execution or of specific per-agent effective tool binding.

This module is a research diagnostic. Do NOT silently substitute the output
for a production precision gate or original frozen source reference.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any


def dotted(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + ("." if base else "") + node.attr
    return ""


def loop_evidence(source: str, class_name: str) -> dict[str, Any]:
    tree = ast.parse(source)
    classes = [
        n for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == class_name
    ]
    if len(classes) != 1:
        raise ValueError(f"Expected one exact top-level class {class_name}")
    cls = classes[0]
    methods = [
        n for n in cls.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    # Syntax sites must be inside the same loop, not unrelated methods.
    all_loops = [
        (method, node)
        for method in methods
        for node in ast.walk(method)
        if isinstance(node, ast.While)
    ]
    for method, loop in all_loops:
        calls = [node for node in ast.walk(loop) if isinstance(node, ast.Call)]
        model_calls = [
            node for node in calls
            if dotted(node.func).endswith("chat.completions.create")
            and any(kw.arg == "tools" for kw in node.keywords)
        ]
        dispatches = [
            node for node in calls
            if dotted(node.func).endswith(".call_tool")
        ]
        if not model_calls or not dispatches:
            continue
        tool_selection = [
            node for node in ast.walk(loop)
            if isinstance(node, ast.Attribute) and node.attr == "tool_calls"
        ]
        results = [
            node for node in calls
            if dotted(node.func).endswith(".append")
            and any(
                isinstance(part, ast.Constant) and part.value == "tool"
                for arg in node.args for part in ast.walk(arg)
            )
        ]
        if not tool_selection or not results:
            continue
        return {
            "classification": "source_supported_agent_construct",
            "method": method.name,
            "loop_line": loop.lineno,
            "model_call_lines": sorted({n.lineno for n in model_calls}),
            "dispatch_lines": sorted({n.lineno for n in dispatches}),
            "tool_choice_lines": sorted({n.lineno for n in tool_selection}),
            "result_feedback_lines": sorted({n.lineno for n in results}),
            "runtime_deployment": "unresolved",
            "per_tool_effective_authority": "unresolved",
            "review_method": "posthoc_static_source_not_blinded",
        }
    return {
        "classification": "not_proven_by_iterative_model_tool_loop_rule",
        "runtime_deployment": "unresolved",
        "per_tool_effective_authority": "unresolved",
        "review_method": "posthoc_static_source_not_blinded",
    }


def source_only_review(
    path: Path, *, class_name: str, source_sha: str, repository: str,
) -> dict[str, Any]:
    if len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha):
        raise ValueError("exact lowercase source SHA required")
    if repository.count("/") != 1:
        raise ValueError("owner/repo provenance required")
    result = loop_evidence(path.read_text(encoding="utf-8"), class_name)
    return {
        "schema_version": 1,
        "source_sha": source_sha,
        "repository": repository,
        "source_path": str(path),
        "class_name": class_name,
        **result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--class-name", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    print(json.dumps(source_only_review(
        args.source, class_name=args.class_name,
        source_sha=args.source_sha, repository=args.repository,
    ), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
