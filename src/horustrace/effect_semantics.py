from __future__ import annotations

import ast

_COLLECTION_MUTATION_METHODS = {
    "append",
    "extend",
    "insert",
    "remove",
    "pop",
    "clear",
    "update",
    "add",
    "discard",
}
_PERSISTENCE_RECEIVER_MARKERS = {
    "db",
    "database",
    "session",
    "cursor",
    "connection",
    "conn",
    "engine",
    "repository",
    "store",
    "storage",
    "table",
    "collection",
}


def dotted_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def call_leaf(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def is_local_collection_mutation(call: ast.Call) -> bool:
    """Return True for source-local/in-memory collection mutation.

    This deliberately suppresses list/set/dict-style mutation only when the
    receiver does not look like a persistence abstraction.  It also treats
    sys.path mutation as process-local configuration rather than persistent data
    authority.
    """
    leaf = (call_leaf(call.func) or "").lower()
    if leaf not in _COLLECTION_MUTATION_METHODS:
        return False
    if not isinstance(call.func, ast.Attribute):
        return False

    receiver = call.func.value
    receiver_name = (dotted_name(receiver) or "").lower()
    if receiver_name == "sys.path":
        return True

    tokens = {
        token
        for token in receiver_name.replace("-", "_").replace(".", "_").split("_")
        if token
    }
    if tokens & _PERSISTENCE_RECEIVER_MARKERS:
        return False

    return isinstance(receiver, (ast.Name, ast.Attribute, ast.Subscript))


def sql_call_capabilities(call: ast.Call) -> set[str]:
    """Infer SQL read/write semantics from a literal execute statement."""
    leaf = (call_leaf(call.func) or "").lower()
    if leaf not in {"execute", "executemany", "executescript"} or not call.args:
        return set()

    statement = call.args[0]
    text: str | None = None
    if isinstance(statement, ast.Constant) and isinstance(statement.value, str):
        text = statement.value
    elif isinstance(statement, ast.JoinedStr):
        prefix = "".join(
            value.value
            for value in statement.values
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        )
        text = prefix or None

    if not text:
        return set()
    first = text.lstrip().split(None, 1)[0].upper() if text.lstrip() else ""
    if first in {"INSERT", "UPDATE", "REPLACE", "MERGE", "CREATE", "ALTER"}:
        return {"data.write"}
    if first in {"DELETE", "DROP", "TRUNCATE"}:
        return {"data.write", "destructive.write"}
    if first in {"SELECT", "WITH", "PRAGMA", "SHOW", "DESCRIBE", "EXPLAIN"}:
        return {"data.read"}
    return set()


def http_mutation_capabilities(call: ast.Call, *, function_name: str = "") -> set[str]:
    """Infer outbound mutation only for concrete HTTP verb calls.

    POST is suppressed for functions whose names are explicitly retrieval-like,
    because many search/query APIs use POST as a read transport.
    """
    leaf = (call_leaf(call.func) or "").lower()
    if leaf == "delete":
        return {"data.write", "external.write", "destructive.write"}
    if leaf in {"put", "patch"}:
        return {"data.write", "external.write"}
    if leaf != "post":
        return set()

    read_tokens = {
        "get",
        "list",
        "search",
        "read",
        "fetch",
        "query",
        "lookup",
        "retrieve",
        "inspect",
    }
    tokens = {
        token
        for token in function_name.lower().replace("-", "_").split("_")
        if token
    }
    return set() if tokens & read_tokens else {"data.write", "external.write"}


def executor_wrapped_callable(call: ast.Call) -> ast.AST | None:
    """Return the callable submitted through common async executor wrappers."""
    called = (dotted_name(call.func) or call_leaf(call.func) or "").lower()
    if called in {"asyncio.to_thread", "to_thread"} and call.args:
        return call.args[0]
    if (called.endswith(".run_in_executor") or called == "run_in_executor") and len(call.args) >= 2:
        return call.args[1]
    return None
