"""Bounded source-only constructor lifecycle evidence for Pydantic AI.

This is not a runtime symbolic executor. A conditional assignment is a source
witness, not evidence that a new instance or its tools are ever active.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class ConstructorPhase:
    binding: str
    scope: str
    enclosing_function: str | None
    call: ast.Call
    conditions: tuple[str, ...]

    @property
    def line(self) -> int:
        return self.call.lineno

    def as_source_witness(self, *, initial: bool) -> dict[str, object]:
        return {
            "phase": "initial_source_constructor" if initial else "source_reconstruction",
            "scope": self.scope,
            "enclosing_function": self.enclosing_function,
            "line": self.call.lineno,
            "column": self.call.col_offset + 1,
            "conditional": bool(self.conditions),
            "conditions": list(self.conditions),
            "runtime_effectiveness": "not_verified",
        }


def collect_pydantic_constructor_phases(
    tree: ast.AST,
    *,
    is_constructor: Callable[[ast.Call], bool],
    assignment_targets: Callable[[ast.AST], list[str]],
) -> dict[str, list[ConstructorPhase]]:
    """Collect all Pydantic constructor assignments without last-write loss.

    `self.agent` in methods of the same class is one logical source binding.
    Function-local and separate-class bindings have different lexical scopes.
    Consumers must not combine multiple scopes on the strength of a name alone.
    """

    found: dict[str, list[ConstructorPhase]] = {}

    def visit_block(
        statements: list[ast.stmt],
        classes: tuple[str, ...],
        functions: tuple[str, ...],
        conditions: tuple[str, ...],
    ) -> None:
        for statement in statements:
            if isinstance(statement, ast.ClassDef):
                visit_block(statement.body, (*classes, statement.name), (), conditions)
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit_block(statement.body, classes, (*functions, statement.name), conditions)
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                if isinstance(value, ast.Call) and is_constructor(value):
                    for binding in assignment_targets(statement):
                        # Instance attributes remain one binding across methods
                        # of the same enclosing class. Local variables do not.
                        scoped = classes if binding.startswith("self.") and classes else (
                            *classes, *functions
                        )
                        scope = ".".join(scoped) if scoped else "<module>"
                        phase = ConstructorPhase(
                            binding=binding,
                            scope=scope,
                            enclosing_function=".".join(functions) if functions else None,
                            call=value,
                            conditions=conditions,
                        )
                        found.setdefault(binding, []).append(phase)
                continue
            if isinstance(statement, ast.If):
                expression = ast.unparse(statement.test)
                visit_block(
                    statement.body, classes, functions,
                    (*conditions, f"if ({expression})"),
                )
                visit_block(
                    statement.orelse, classes, functions,
                    (*conditions, f"else of ({expression})"),
                )
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                visit_block(
                    statement.body, classes, functions,
                    (*conditions, f"{type(statement).__name__} iteration"),
                )
                visit_block(
                    statement.orelse, classes, functions,
                    (*conditions, f"{type(statement).__name__} else"),
                )
                continue
            if isinstance(statement, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                visit_block(
                    statement.body, classes, functions,
                    (*conditions, "try body"),
                )
                for handler in statement.handlers:
                    visit_block(
                        handler.body, classes, functions,
                        (*conditions, "exception handler"),
                    )
                visit_block(
                    statement.orelse, classes, functions,
                    (*conditions, "try else"),
                )
                visit_block(
                    statement.finalbody, classes, functions,
                    (*conditions, "finally"),
                )
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                visit_block(statement.body, classes, functions, conditions)
                continue
            if isinstance(statement, ast.Match):
                for case in statement.cases:
                    visit_block(
                        case.body, classes, functions,
                        (*conditions, "match case"),
                    )

    if isinstance(tree, ast.Module):
        visit_block(tree.body, (), (), ())

    for phases in found.values():
        phases.sort(key=lambda item: (item.line, item.call.col_offset, item.scope))
    return found
