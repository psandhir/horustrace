from __future__ import annotations

import ast
import re
from urllib.parse import urlparse

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

    return isinstance(receiver, ast.Name)


def _sql_statement_capabilities(statement: str) -> set[str]:
    """Classify one literal SQL statement by material data effect."""
    normalized = " ".join(statement.strip().split())
    if not normalized:
        return set()
    upper = normalized.upper()
    first = upper.split(None, 1)[0]

    # Idempotent schema bootstrap is persistent initialization, but it does not
    # grant the agent authority to mutate application data. Treating every
    # CREATE TABLE IF NOT EXISTS as data.write caused read-only SQLite helpers
    # to inherit write authority merely because their connection initializer
    # ensured the schema existed.
    if first == "CREATE" and " IF NOT EXISTS " in f" {upper} ":
        return set()

    if first in {"INSERT", "UPDATE", "REPLACE", "MERGE", "CREATE", "ALTER"}:
        return {"data.write"}
    if first in {"DELETE", "DROP", "TRUNCATE"}:
        return {"data.write", "destructive.write"}
    if first in {"SELECT", "WITH", "PRAGMA", "SHOW", "DESCRIBE", "EXPLAIN"}:
        return {"data.read"}
    return set()


def sql_call_capabilities(call: ast.Call) -> set[str]:
    """Infer SQL read/write semantics from literal execute statements."""
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

    capabilities: set[str] = set()
    statements = text.split(";") if leaf == "executescript" else [text]
    for sql in statements:
        capabilities.update(_sql_statement_capabilities(sql))
    return capabilities


def _literal_payload_tokens(call: ast.Call) -> set[str]:
    """Extract operation-like literal strings from an inline HTTP payload."""
    payloads = [
        keyword.value
        for keyword in call.keywords
        if keyword.arg in {"json", "data"}
    ]
    tokens: set[str] = set()
    for payload in payloads:
        for node in ast.walk(payload):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            normalized = (
                node.value.lower()
                .replace("-", "_")
                .replace("/", "_")
                .replace(".", "_")
            )
            tokens.update(part for part in normalized.split("_") if part)
    return tokens


def _literal_http_target_tokens(call: ast.Call) -> set[str]:
    """Extract effect-bearing tokens from a source-visible HTTP target path."""
    leaf = (call_leaf(call.func) or "").lower()
    target = (
        call.args[1]
        if leaf == "request" and len(call.args) > 1
        else call.args[0]
        if call.args
        else next(
            (
                keyword.value
                for keyword in call.keywords
                if keyword.arg in {"url", "uri", "endpoint"}
            ),
            None,
        )
    )
    text: str | None = None
    if isinstance(target, ast.Constant) and isinstance(target.value, str):
        text = target.value
    elif isinstance(target, ast.JoinedStr):
        text = "".join(
            value.value
            for value in target.values
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        )
    if not text or not text.startswith(("http://", "https://")):
        return set()
    path = urlparse(text).path.lower()
    return {token for token in re.split(r"[^a-z0-9]+", path) if token}


def http_mutation_capabilities(call: ast.Call, *, function_name: str = "") -> set[str]:
    """Infer semantic outbound mutation independently from HTTP transport.

    DELETE/PUT/PATCH remain strong mutation signals. POST is only considered a
    write when the source-visible request body or endpoint carries an explicit
    mutation verb. The containing Python function name is deliberately ignored:
    business/action names are discovery hints, not proof of an external effect.
    """
    del function_name  # Backward-compatible parameter; names are not effect evidence.
    leaf = (call_leaf(call.func) or "").lower()
    if leaf == "delete":
        return {"data.write", "external.write", "destructive.write"}
    if leaf in {"put", "patch"}:
        return {"data.write", "external.write"}
    if leaf != "post":
        return set()

    write_tokens = {
        "add",
        "append",
        "create",
        "delete",
        "enqueue",
        "insert",
        "mutate",
        "notify",
        "post",
        "publish",
        "remove",
        "send",
        "submit",
        "trigger",
        "update",
        "upload",
        "write",
    }
    payload_tokens = _literal_payload_tokens(call)
    target_tokens = _literal_http_target_tokens(call)
    if payload_tokens & write_tokens or target_tokens & write_tokens:
        return {"data.write", "external.write"}
    return set()


def executor_wrapped_callable(call: ast.Call) -> ast.AST | None:
    """Return the callable submitted through common async executor wrappers."""
    called = (dotted_name(call.func) or call_leaf(call.func) or "").lower()
    if called in {"asyncio.to_thread", "to_thread"} and call.args:
        return call.args[0]
    if (called.endswith(".run_in_executor") or called == "run_in_executor") and len(call.args) >= 2:
        return call.args[1]
    return None
