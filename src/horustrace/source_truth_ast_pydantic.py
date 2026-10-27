"""Independent bounded AST check of Pydantic demo-level tool selection.

Inspects literal branch-return syntax only; never imports or executes target,
SDK or HorusTrace scanner. "else" is not restricted to levels 3 and 4.
"""

from __future__ import annotations

import ast
import hashlib
from typing import Any


def _level_condition(node: ast.AST, param: str) -> int | None:
    if not (isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name) and node.left.id == param
            and len(node.ops) == len(node.comparators) == 1
            and isinstance(node.ops[0], ast.Eq)):
        return None
    rhs = node.comparators[0]
    if not (isinstance(rhs, ast.Constant) and type(rhs.value) is int):
        return None
    return rhs.value


def _return_names(branch: list[ast.stmt]) -> list[str] | None:
    body = [x for x in branch if not (isinstance(x, ast.Expr)
            and isinstance(x.value, ast.Constant)
            and isinstance(x.value.value, str))]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return None
    value = body[0].value
    if not isinstance(value, (ast.List, ast.Tuple)):
        return None
    if not all(isinstance(x, ast.Name) for x in value.elts):
        return None
    return [x.id for x in value.elts]


def inspect_pydantic_level_returns(path: str, source: str) -> dict[str, Any]:
    if (not isinstance(path, str) or not path.endswith(".py")
            or path.startswith(("/", "./")) or "\\" in path
            or ".." in path.split("/")):
        raise ValueError("unsafe or non-Python source path")
    if not isinstance(source, str):
        raise TypeError("source must be text")
    tree = ast.parse(source, filename=path)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name == "get_tools_for_level"]
    if len(functions) != 1 or len(functions[0].args.args) != 1:
        raise ValueError("unique one-argument tool-selection function missing")
    fn = functions[0]
    param = fn.args.args[0].arg
    body = [x for x in fn.body if not (isinstance(x, ast.Expr)
            and isinstance(x.value, ast.Constant)
            and isinstance(x.value.value, str))]
    if len(body) != 1 or not isinstance(body[0], ast.If):
        raise ValueError("tool selection is not a supported literal branch")
    first = body[0]
    second = first.orelse
    if len(second) != 1 or not isinstance(second[0], ast.If):
        raise ValueError("expected explicit second level condition")
    mid = second[0]
    first_level = _level_condition(first.test, param)
    second_level = _level_condition(mid.test, param)
    if (first_level, second_level) != (1, 2):
        raise ValueError("unexpected level conditions; manual review required")
    level1 = _return_names(first.body)
    level2 = _return_names(mid.body)
    fallback = _return_names(mid.orelse)
    if any(v is None for v in (level1, level2, fallback)):
        raise ValueError("dynamic or nonliteral tool selection branch")
    if any(len(x) != len(set(x)) for x in (level1, level2, fallback)):
        raise ValueError("duplicate tool identifiers in selection branch")
    return {
        "mode": "bounded_pydantic_tool_return_ast_source_only",
        "path": path,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "function_line": fn.lineno,
        "selection_parameter": param,
        "level_1": level1,
        "level_2": level2,
        "else_branch_other_values": fallback,
        "level_3_uses_else": True,
        "level_4_uses_else": True,
        "runtime_level_value_known": False,
        "runtime_tools_registered": None,
        "effective_agent_can_call": None,
        "independent_human_review_verified": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }


def _method(tree: ast.Module, cls: str, method: str) -> ast.FunctionDef:
    matches = [
        item for item in tree.body
        if isinstance(item, ast.ClassDef) and item.name == cls
    ]
    if len(matches) != 1:
        raise ValueError("expected exactly one class " + cls)
    methods = [item for item in matches[0].body
               if isinstance(item, ast.FunctionDef) and item.name == method]
    if len(methods) != 1:
        raise ValueError("expected exactly one method " + cls + "." + method)
    return methods[0]


def inspect_pydantic_tool_plumbing(agent_source: str, base_source: str) -> dict:
    """Check source-visible selection-to-wrapper-to-registration links.

    This verifies AST expression shapes, never that the SDK installed or a
    deployment actually called/registered any tool.
    """
    outer = _method(ast.parse(agent_source), "SQLQueryAgent", "__init__")
    inner = _method(ast.parse(base_source), "BaseAgent", "__init__")
    selectors = [
        node for node in ast.walk(outer)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "tools"
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "get_tools_for_level"
        and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Attribute)
        and isinstance(node.value.args[0].value, ast.Name)
        and node.value.args[0].value.id == "self"
        and node.value.args[0].attr == "demo_level"
    ]
    pass_through = [
        node for node in ast.walk(outer)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "BaseAgent"
        and any(kw.arg == "tools" and isinstance(kw.value, ast.Name)
                and kw.value.id == "tools" for kw in node.keywords)
    ]
    self_tool_assignments = [
        node for node in inner.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Attribute)
        and isinstance(node.targets[0].value, ast.Name)
        and node.targets[0].value.id == "self"
        and node.targets[0].attr == "tools"
    ]
    if len(self_tool_assignments) != 1:
        raise ValueError("selected tools not uniquely bound to wrapper state")
    assignment = self_tool_assignments[0]
    value = assignment.value
    if not (isinstance(value, ast.BoolOp)
            and isinstance(value.op, ast.Or)
            and len(value.values) == 2
            and isinstance(value.values[0], ast.Name)
            and value.values[0].id == "tools"
            and isinstance(value.values[1], ast.List)
            and not value.values[1].elts):
        raise ValueError("wrapper tools state no longer derives from argument")
    registrations = [
        node for node in ast.walk(inner)
        if isinstance(node, ast.For) and isinstance(node.target, ast.Name)
        and node.target.id == "tool"
        and isinstance(node.iter, ast.Attribute)
        and isinstance(node.iter.value, ast.Name)
        and node.iter.value.id == "self"
        and node.iter.attr == "tools"
        and any(isinstance(x, ast.Call)
                and isinstance(x.func, ast.Attribute)
                and x.func.attr == "tool"
                and isinstance(x.func.value, ast.Attribute)
                and isinstance(x.func.value.value, ast.Name)
                and x.func.value.value.id == "self"
                and x.func.value.attr == "_agent"
                and len(x.args) == 1
                and isinstance(x.args[0], ast.Name)
                and x.args[0].id == "tool"
                for statement in node.body for x in ast.walk(statement))
    ]
    if (len(selectors) != 1 or len(pass_through) != 1
            or len(registrations) != 1
            or assignment.lineno >= registrations[0].lineno):
        raise ValueError("conditional tool-source plumbing changed")
    return {
        "source_selection_call_line": selectors[0].lineno,
        "source_pass_through_line": pass_through[0].lineno,
        "source_wrapper_tools_binding_line": assignment.lineno,
        "source_registration_loop_line": registrations[0].lineno,
        "selected_tool_registration_source_chain": True,
        "installed_sdk_verification": None,
        "runtime_tool_registration_verified": False,
        "effective_agent_can_call": None,
    }
