"""Independent source-only AST witness inventory for bounded Google ADK syntax.

Do not import HorusTrace scanner, graph, LLM judge, or target SDK modules.
Module-level literal LlmAgent construction is not deployed/runtime authority.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Mapping
from typing import Any


def _id(kind: str, path: str, line: int, name: str) -> str:
    value = json.dumps([kind, path, line, name], separators=(",", ":"))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _kw(call: ast.Call, key: str) -> ast.AST | None:
    matches = [keyword.value for keyword in call.keywords if keyword.arg == key]
    if len(matches) != 1:
        return None
    return matches[0]


def _imported_agent_names(tree: ast.Module) -> set[str]:
    return {
        alias.asname or alias.name
        for item in tree.body
        if isinstance(item, ast.ImportFrom) and item.module == "google.adk.agents"
        for alias in item.names if alias.name == "LlmAgent"
    }


def _static_names(node: ast.AST) -> list[ast.Name] | None:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    if not all(isinstance(x, ast.Name) for x in node.elts):
        return None
    return list(node.elts)


def inspect_adk_python(path: str, source: str) -> dict[str, Any]:
    """Enumerate literal module-level ADK agents and explicit direct bindings.

    Dynamic constructors, arbitrary expressions, imported aliases, runtime
    dispatch and conditional branches are not treated as negative evidence.
    """
    if not isinstance(path, str) or not path.endswith(".py"):
        raise ValueError("source path must be a Python file")
    if path.startswith(("/", "./")) or "\\" in path or ".." in path.split("/"):
        raise ValueError("unsafe source path")
    if not isinstance(source, str):
        raise TypeError("source must be text")
    tree = ast.parse(source, filename=path)
    agent_classes = _imported_agent_names(tree)
    agents: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    delegations: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    sites: dict[str, dict[str, Any]] = {}
    for item in tree.body:
        if not isinstance(item, ast.Assign) or len(item.targets) != 1:
            continue
        target = item.targets[0]
        value = item.value
        if not (isinstance(target, ast.Name) and isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id in agent_classes):
            continue
        name_value = _kw(value, "name")
        if not (isinstance(name_value, ast.Constant)
                and isinstance(name_value.value, str)
                and name_value.value.strip()):
            unresolved.append({"path": path, "line": item.lineno,
                               "reason": "dynamic_or_missing_agent_display_name"})
            continue
        symbol = target.id
        if symbol in sites:
            unresolved.append({"path": path, "line": item.lineno,
                               "reason": "reassigned_agent_source_symbol"})
            continue
        entry = {
            "id": _id("agent", path, item.lineno, symbol),
            "path": path, "line": item.lineno,
            "symbol": symbol, "name": name_value.value,
            "source_only": True,
        }
        sites[symbol] = entry
        agents.append(entry)
        for field, relationship, target_rows in (
            ("tools", "DIRECT_TOOL_LIST_ENTRY", bindings),
            ("sub_agents", "SUB_AGENT_LIST_ENTRY", delegations),
        ):
            arg = _kw(value, field)
            if arg is None:
                continue  # missing list is NOT equivalent to a verified empty list
            names = _static_names(arg)
            if names is None:
                unresolved.append({"path": path, "line": arg.lineno,
                                   "reason": "dynamic_" + field,
                                   "agent": symbol})
                continue
            for element in names:
                target_rows.append({
                    "id": _id(relationship, path, element.lineno,
                              symbol + ":" + element.id),
                    "kind": relationship, "source_agent_id": entry["id"],
                    "source_agent": symbol, "target_symbol": element.id,
                    "path": path, "line": element.lineno,
                    "source_only": True,
                    "runtime_callability_verified": False,
                })
    # Directly re-assigning a recognized agent source variable after its
    # constructor creates ambiguity. Never certify a stale constructor site.
    for item in tree.body:
        if isinstance(item, ast.Assign):
            assigned = {
                node.id for target in item.targets for node in ast.walk(target)
                if isinstance(node, ast.Name)
            }
            for symbol in assigned & set(sites):
                if item.lineno != sites[symbol]["line"]:
                    unresolved.append({"path": path, "line": item.lineno,
                                       "reason": "agent_symbol_rebound",
                                       "symbol": symbol})
    for item in ast.walk(tree):
        if (isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
                and item.func.id in agent_classes
                and not any(node["line"] == item.lineno
                            for node in agents)):
            unresolved.append({
                "path": path, "line": item.lineno,
                "reason": "non_literal_or_nested_agent_constructor",
            })
    declared = {x["symbol"] for x in agents}
    for edge in delegations:
        if edge["target_symbol"] not in declared:
            unresolved.append({
                "path": edge["path"], "line": edge["line"],
                "reason": "sub_agent_target_not_declared_in_source_file",
                "symbol": edge["target_symbol"],
            })
    return {
        "path": path,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "agents": sorted(agents, key=lambda x: (x["path"], x["line"])),
        "direct_tool_entries": sorted(bindings, key=lambda x: x["line"]),
        "sub_agent_entries": sorted(delegations, key=lambda x: x["line"]),
        "unresolved": sorted(unresolved,
                             key=lambda x: (x["path"], x["line"], x["reason"])),
    }


def inspect_adk_scope(files: Mapping[str, str]) -> dict[str, Any]:
    if not files:
        raise ValueError("empty ADK source scope")
    sources = [inspect_adk_python(p, s) for p, s in sorted(files.items())]
    return {
        "schema_version": 1,
        "mode": "bounded_adk_module_level_ast_source_oracle_not_release_truth",
        "scope_files": [x["path"] for x in sources],
        "source_digests": {x["path"]: x["source_sha256"] for x in sources},
        "agents": [x for s in sources for x in s["agents"]],
        "direct_tool_entries": [x for s in sources
                                for x in s["direct_tool_entries"]],
        "sub_agent_entries": [x for s in sources
                              for x in s["sub_agent_entries"]],
        "unresolved": [x for s in sources for x in s["unresolved"]],
        "complete_scope_kind": "module_level_literal_LlmAgent_lists_only",
        "independent_human_review_verified": False,
        "runtime_callability_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
