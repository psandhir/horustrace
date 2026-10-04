from __future__ import annotations

import ast
import copy
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from horustrace.adapters.google_adk import (
    AGENT_TYPES,
    BUILTIN_TOOL_CAPABILITIES,
    BUILTIN_TOOL_REQUIRED_ROLES,
    RETRIEVAL_TOOLS,
    _mcp_from_toolset,
    _tool_from_call,
)
from horustrace.models import (
    Agent,
    Graph,
    Identity,
    InputSource,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    SourceLocation,
    Tool,
)

OAUTH_PREFIXES = (
    "https://www.googleapis.com/auth/",
    "https://www.googleapis.com/auth/cloud-platform",
)
SENSITIVE_NAME_PARTS = (
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "private_key",
    "credential",
)
GOOGLE_API_DESTINATIONS = {
    "drive": "https://www.googleapis.com/",
    "youtube": "https://www.googleapis.com/",
    "sheets": "https://sheets.googleapis.com/",
    "docs": "https://docs.googleapis.com/",
    "gmail": "https://gmail.googleapis.com/",
    "calendar": "https://www.googleapis.com/",
    "bigquery": "https://bigquery.googleapis.com/",
}


def _name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dotted(node: ast.AST | None) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _literal(node: ast.AST | None):
    try:
        return ast.literal_eval(node) if node is not None else None
    except (ValueError, TypeError):
        return None


def _string(node: ast.AST | None) -> str | None:
    value = _literal(node)
    return value if isinstance(value, str) else None


def _kw(call: ast.Call, key: str) -> ast.AST | None:
    return next((kw.value for kw in call.keywords if kw.arg == key), None)


def _loc(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path,
        getattr(node, "lineno", 1),
        getattr(node, "col_offset", 0) + 1,
    )


def _sensitive_name(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.lower().replace("-", "_")
    return any(part in normalized for part in SENSITIVE_NAME_PARTS)


def _destination(
    path: Path,
    node: ast.AST,
    target: str,
    *,
    restricted: bool,
    source: str,
    managed: bool = False,
) -> NetworkDestination:
    return NetworkDestination(
        target=target,
        restricted=restricted,
        location=_loc(path, node),
        metadata={
            "source": source,
            "repository_resolved": True,
            "network_scope": (
                "fixed_managed_service" if managed else
                "fixed_literal_destination" if source == "literal_url" else
                "explicit_destination" if restricted else
                "dynamic_destination"
            ),
        },
    )


def _function_imports(
    info: ModuleInfo,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    imports = {
        f"{module}.{remote}".strip(".").lower()
        for module, remote in info.imports.values()
    }
    for node in ast.walk(func):
        if isinstance(node, ast.Import):
            imports.update(alias.name.lower() for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").lower()
            imports.update(
                f"{module}.{alias.name}".strip(".")
                for alias in node.names
                if alias.name != "*"
            )
    return imports



def _required_role_function_ref(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    node: ast.AST,
) -> tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    if isinstance(node, ast.Name):
        if node.id in info.functions:
            return info, info.functions[node.id]
        imported = _imported_symbol(modules, info, node.id)
        if imported and imported[1] in imported[0].functions:
            target, symbol = imported
            return target, target.functions[symbol]
    if isinstance(node, ast.Attribute):
        return _attribute_function(modules, info, node)
    return None


def _required_role_agent_ref(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    node: ast.AST,
) -> tuple[ModuleInfo, str, ast.Call] | None:
    if isinstance(node, ast.Name):
        local = info.calls.get(node.id)
        if local is not None and (_name(local.func) or "") in AGENT_TYPES:
            return info, node.id, local
        imported = _imported_symbol(modules, info, node.id)
        if imported:
            target, symbol = imported
            call = target.calls.get(symbol)
            if call is not None and (_name(call.func) or "") in AGENT_TYPES:
                return target, symbol, call
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        imported = _imported_symbol(modules, info, node.value.id)
        if imported:
            target, remote = imported
            nested = (
                _find_module(modules, f"{target.module}.{remote}")
                if remote
                else target
            )
            candidate = nested or target
            call = candidate.calls.get(node.attr)
            if call is not None and (_name(call.func) or "") in AGENT_TYPES:
                return candidate, node.attr, call
    return None


def _required_role_tool_exprs(node: ast.AST | None) -> list[ast.AST]:
    if node is None:
        return []
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        result: list[ast.AST] = []
        for item in node.elts:
            result.extend(_required_role_tool_exprs(item))
        return result
    if isinstance(node, ast.IfExp):
        return [
            *_required_role_tool_exprs(node.body),
            *_required_role_tool_exprs(node.orelse),
        ]
    return [node]


def _analyze_required_gcp_roles_for_agent(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    alias: str,
    call: ast.Call,
    visited: set[tuple[str, str]],
) -> tuple[set[str], list[dict[str, object]]]:
    key = (info.module, f"@agent:{alias}")
    if key in visited:
        return set(), []
    visited.add(key)

    roles: set[str] = set()
    evidence: list[dict[str, object]] = []

    def merge(
        nested: tuple[set[str], list[dict[str, object]]] | None,
    ) -> None:
        if not nested:
            return
        nested_roles, nested_evidence = nested
        roles.update(nested_roles)
        for item in nested_evidence:
            if item not in evidence:
                evidence.append(item)

    for item in _required_role_tool_exprs(_kw(call, "tools")):
        resolved = _required_role_function_ref(modules, info, item)
        if resolved:
            target, func = resolved
            merge(
                _analyze_required_gcp_roles(
                    modules,
                    target,
                    func,
                    visited,
                )
            )

    # Agent callbacks execute as part of the agent invocation lifecycle and can
    # carry provider operations that are required even when not exposed as tools.
    for callback_name in (
        "before_agent_callback",
        "after_agent_callback",
        "before_model_callback",
        "after_model_callback",
        "before_tool_callback",
        "after_tool_callback",
    ):
        callback = _kw(call, callback_name)
        if callback is None:
            continue
        resolved = _required_role_function_ref(modules, info, callback)
        if resolved:
            target, func = resolved
            merge(
                _analyze_required_gcp_roles(
                    modules,
                    target,
                    func,
                    visited,
                )
            )

    return roles, evidence

def _analyze_required_gcp_roles(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    visited: set[tuple[str, str]] | None = None,
) -> tuple[set[str], list[dict[str, object]]]:
    """Return positive, source-backed GCP role requirements.

    These are minimum role hints, not a complete least-privilege baseline.
    Reconciliation may use them to prove missing authority, but not excess
    authority unless another source marks the required-role set complete.
    """
    visited = set() if visited is None else set(visited)
    key = (info.module, func.name)
    if key in visited:
        return set(), []
    visited.add(key)

    roles: set[str] = set()
    evidence: list[dict[str, object]] = []
    imports = _function_imports(info, func)
    calls = [node for node in ast.walk(func) if isinstance(node, ast.Call)]
    called_names = [
        (_dotted(node.func) or _name(node.func) or "").lower()
        for node in calls
    ]

    has_bigquery = any("google.cloud.bigquery" in value for value in imports)
    has_discovery = any(
        "google.cloud.discoveryengine" in value for value in imports
    )
    has_secretmanager = any(
        "google.cloud.secretmanager" in value for value in imports
    )
    has_cloudtasks = any("google.cloud.tasks" in value for value in imports)
    has_firestore = any("google.cloud.firestore" in value for value in imports)
    has_datastore = any("google.cloud.datastore" in value for value in imports)

    bigquery_client = has_bigquery and any(
        value.endswith("bigquery.client") for value in called_names
    )
    secret_client = has_secretmanager and any(
        value.endswith("secretmanagerserviceclient") for value in called_names
    )
    tasks_client = has_cloudtasks and any(
        value.endswith("cloudtasksclient") for value in called_names
    )
    firestore_client = has_firestore and any(
        value.endswith("firestore.client") for value in called_names
    )
    datastore_client = has_datastore and any(
        value.endswith("datastore.client") for value in called_names
    )

    def add(role: str, operation: str, node: ast.AST) -> None:
        roles.add(role)
        item: dict[str, object] = {
            "provider": "gcp",
            "role": role,
            "operation": operation,
            "source_module": info.module,
            "source_function": func.name,
            "line": getattr(node, "lineno", 1),
        }
        if item not in evidence:
            evidence.append(item)

    for node, called in zip(calls, called_names):
        leaf = (_name(node.func) or "").lower()

        bigquery_receiver = (
            called.rsplit(".", 1)[0]
            if "." in called
            else ""
        )
        bigquery_operation = bigquery_client or (
            has_bigquery
            and any(
                marker in bigquery_receiver
                for marker in ("bq", "bigquery")
            )
        )
        if bigquery_operation:
            if leaf == "query":
                add("roles/bigquery.jobUser", "bigquery.query", node)
                add("roles/bigquery.dataViewer", "bigquery.query", node)
            elif leaf in {
                "insert_rows",
                "insert_rows_json",
                "insert_rows_from_dataframe",
            }:
                add("roles/bigquery.dataEditor", f"bigquery.{leaf}", node)
            elif leaf in {
                "load_table_from_file",
                "load_table_from_json",
                "load_table_from_dataframe",
            }:
                add("roles/bigquery.jobUser", f"bigquery.{leaf}", node)
                add("roles/bigquery.dataEditor", f"bigquery.{leaf}", node)

        # The operation itself is high-signal when the function imports the
        # Discovery Engine SDK. The client may be lazy-constructed by a helper.
        if has_discovery and leaf in {"search", "rank", "recommend", "answer"}:
            add(
                "roles/discoveryengine.viewer",
                f"discoveryengine.{leaf}",
                node,
            )

        if secret_client and leaf == "access_secret_version":
            add(
                "roles/secretmanager.secretAccessor",
                "secretmanager.access_secret_version",
                node,
            )

        if tasks_client and leaf == "create_task":
            add("roles/cloudtasks.enqueuer", "cloudtasks.create_task", node)

        if (firestore_client or datastore_client) and leaf in {
            "get",
            "stream",
            "set",
            "update",
            "delete",
            "add",
            "create",
            "put",
            "put_multi",
            "get_multi",
        }:
            add("roles/datastore.user", f"datastore.{leaf}", node)

        local_name = _name(node.func)
        nested: tuple[set[str], list[dict[str, object]]] | None = None

        # Explicit bounded higher-order execution. This does not assume that an
        # arbitrary callable argument executes; it only follows well-known APIs
        # whose contract is to invoke the supplied function.
        callback_index: int | None = None
        if called in {"asyncio.to_thread", "to_thread"}:
            callback_index = 0
        elif called.endswith(".run_in_executor"):
            callback_index = 1
        if callback_index is not None and len(node.args) > callback_index:
            resolved_callback = _required_role_function_ref(
                modules,
                info,
                node.args[callback_index],
            )
            if resolved_callback:
                target, callback_func = resolved_callback
                nested_roles, nested_evidence = _analyze_required_gcp_roles(
                    modules,
                    target,
                    callback_func,
                    visited,
                )
                roles.update(nested_roles)
                for item in nested_evidence:
                    if item not in evidence:
                        evidence.append(item)

        # An AgentTool explicitly transfers execution to the named agent. Follow
        # that static target and collect only positive provider-role evidence
        # from its tools/callbacks.
        if leaf == "agenttool":
            agent_node = _kw(node, "agent")
            if agent_node is not None:
                resolved_agent = _required_role_agent_ref(
                    modules,
                    info,
                    agent_node,
                )
                if resolved_agent:
                    target_info, target_alias, target_call = resolved_agent
                    nested_roles, nested_evidence = (
                        _analyze_required_gcp_roles_for_agent(
                            modules,
                            target_info,
                            target_alias,
                            target_call,
                            visited,
                        )
                    )
                    roles.update(nested_roles)
                    for item in nested_evidence:
                        if item not in evidence:
                            evidence.append(item)
        if local_name in info.functions and local_name != func.name:
            nested = _analyze_required_gcp_roles(
                modules,
                info,
                info.functions[local_name],
                visited,
            )
        elif isinstance(node.func, ast.Name):
            imported = _imported_symbol(modules, info, node.func.id)
            if imported and imported[1] in imported[0].functions:
                target, symbol = imported
                nested = _analyze_required_gcp_roles(
                    modules,
                    target,
                    target.functions[symbol],
                    visited,
                )
        elif isinstance(node.func, ast.Attribute):
            imported_attr = _attribute_function(modules, info, node.func)
            if imported_attr:
                target, imported_func = imported_attr
                nested = _analyze_required_gcp_roles(
                    modules,
                    target,
                    imported_func,
                    visited,
                )

        if nested:
            nested_roles, nested_evidence = nested
            roles.update(nested_roles)
            for item in nested_evidence:
                if item not in evidence:
                    evidence.append(item)

    return roles, evidence


@dataclass
class ModuleInfo:
    path: Path
    module: str
    tree: ast.Module
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=dict)
    calls: dict[str, ast.Call] = field(default_factory=dict)
    sequences: dict[str, list[ast.AST]] = field(default_factory=dict)
    assignments: dict[str, ast.AST] = field(default_factory=dict)
    constants: dict[str, object] = field(default_factory=dict)
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)


def _module_name(root: Path, path: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _relative(
    current: str,
    level: int,
    module: str | None,
    *,
    current_is_package: bool = False,
) -> str:
    if level == 0:
        return module or ""

    parts = (
        current.split(".")
        if current_is_package
        else current.split(".")[:-1]
    )
    if level > 1:
        parts = parts[: -(level - 1)]
    if module:
        parts.extend(module.split("."))
    return ".".join(parts)


def _module_statements(statements: list[ast.stmt]):
    for node in statements:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        nested: list[list[ast.stmt]] = []
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            nested.extend([node.body, node.orelse])
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            nested.append(node.body)
        elif isinstance(node, ast.Try):
            nested.extend([node.body, node.orelse, node.finalbody])
            nested.extend(handler.body for handler in node.handlers)
        elif isinstance(node, ast.Match):
            nested.extend(case.body for case in node.cases)
        for body in nested:
            yield from _module_statements(body)


def _add_sequence_values(target: list[ast.AST], values: list[ast.AST]) -> None:
    seen = {ast.dump(item, include_attributes=False) for item in target}
    for value in values:
        key = ast.dump(value, include_attributes=False)
        if key not in seen:
            target.append(value)
            seen.add(key)


def _build(root: Path, path: Path) -> ModuleInfo | None:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return None

    info = ModuleInfo(path, _module_name(root, path), tree)
    statements = list(_module_statements(tree.body))
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            info.functions[node.name] = node
        elif isinstance(node, ast.ImportFrom):
            module = _relative(
                info.module,
                node.level,
                node.module,
                current_is_package=path.name == "__init__.py",
            )
            for alias in node.names:
                if alias.name != "*":
                    info.imports[alias.asname or alias.name] = (module, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                info.imports[alias.asname or alias.name.split(".")[0]] = (
                    alias.name,
                    "",
                )
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if not isinstance(target, ast.Name) or value is None:
                    continue
                info.assignments[target.id] = value
                literal = _literal(value)
                if literal is not None:
                    info.constants[target.id] = literal
                if isinstance(value, ast.Call):
                    info.calls[target.id] = value
                elif isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                    seq = info.sequences.setdefault(target.id, [])
                    _add_sequence_values(seq, list(value.elts))

    for node in statements:
        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name):
            continue
        sequence = info.sequences.get(call.func.value.id)
        if sequence is None:
            continue
        if call.func.attr == "append" and len(call.args) == 1:
            _add_sequence_values(sequence, [call.args[0]])
        elif call.func.attr == "extend" and len(call.args) == 1:
            arg = call.args[0]
            if isinstance(arg, (ast.List, ast.Tuple, ast.Set)):
                _add_sequence_values(sequence, list(arg.elts))
            elif isinstance(arg, ast.Name) and arg.id in info.sequences:
                _add_sequence_values(sequence, info.sequences[arg.id])
    return info


def _find_module(modules: dict[str, ModuleInfo], module_name: str) -> ModuleInfo | None:
    if module_name in modules:
        return modules[module_name]
    matches = [
        module
        for name, module in modules.items()
        if name.endswith(f".{module_name}") or module_name.endswith(f".{name}")
    ]
    return matches[0] if len(matches) == 1 else None


def _imported_symbol(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    symbol: str,
    visited: set[tuple[str, str]] | None = None,
) -> tuple[ModuleInfo, str] | None:
    visited = set() if visited is None else set(visited)
    key = (info.module, symbol)
    if key in visited:
        return None
    visited.add(key)
    ref = info.imports.get(symbol)
    if not ref:
        return None
    module_name, remote = ref
    direct = _find_module(modules, module_name)
    if direct is None:
        combined = f"{module_name}.{remote}" if remote else module_name
        direct = _find_module(modules, combined)
    if direct is None:
        return None
    if remote in direct.imports:
        chained = _imported_symbol(modules, direct, remote, visited)
        if chained:
            return chained
    return direct, remote


def _attribute_function(
    modules: dict[str, ModuleInfo], info: ModuleInfo, node: ast.Attribute
) -> tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    if not isinstance(node.value, ast.Name):
        return None
    imported = _imported_symbol(modules, info, node.value.id)
    if not imported:
        return None
    target, remote = imported
    # `from pkg import module` commonly resolves to pkg.module.
    nested = _find_module(modules, f"{target.module}.{remote}") if remote else target
    if nested and node.attr in nested.functions:
        return nested, nested.functions[node.attr]
    if node.attr in target.functions:
        return target, target.functions[node.attr]
    return None


def _oauth_scopes(tree: ast.AST) -> set[str]:
    scopes: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith(OAUTH_PREFIXES)
        ):
            scopes.add(node.value)
    return scopes


def _resolved_string(info: ModuleInfo, node: ast.AST | None) -> str | None:
    value = _string(node)
    if value is not None:
        return value
    if isinstance(node, ast.Name):
        constant = info.constants.get(node.id)
        return constant if isinstance(constant, str) else None
    return None


def _fixed_url_origin(
    info: ModuleInfo,
    node: ast.AST | None,
    assignments: dict[str, ast.AST] | None = None,
    visited: set[str] | None = None,
) -> str | None:
    """Resolve a fixed scheme/host while allowing dynamic path/query values."""
    if node is None:
        return None

    assignments = assignments or {}
    visited = set() if visited is None else set(visited)

    if isinstance(node, ast.Name):
        if node.id in visited:
            return None
        visited.add(node.id)
        assigned = assignments.get(node.id) or info.assignments.get(node.id)
        if assigned is not None:
            return _fixed_url_origin(info, assigned, assignments, visited)
        constant = info.constants.get(node.id)
        if isinstance(constant, str):
            node = ast.Constant(value=constant)
        else:
            return None

    if isinstance(node, ast.Call):
        called = (_dotted(node.func) or _name(node.func) or "").lower()
        if called in {"urllib.request.request", "request"}:
            target = node.args[0] if node.args else _kw(node, "url")
            return _fixed_url_origin(info, target, assignments, visited)
        return None

    prefix = ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        prefix = node.value
    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                prefix += value.value
            else:
                break
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _fixed_url_origin(info, node.left, assignments, visited)

    if not prefix.startswith(("http://", "https://")):
        return None
    parsed = urlparse(prefix)
    if not parsed.scheme or not parsed.hostname:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def _network_call_destination(
    info: ModuleInfo,
    call: ast.Call,
    called: str,
    assignments: dict[str, ast.AST] | None = None,
) -> NetworkDestination | None:
    # urllib.parse/string helpers are not network sinks. Only urlopen performs
    # I/O; Request(...) is a local request-object constructor whose wrapped URL
    # is resolved when it reaches urlopen().
    network_call = (
        any(
            marker in called
            for marker in (
                "requests.",
                "httpx.",
                "aiohttp",
                "session.get",
                "session.post",
                "session.put",
                "session.patch",
                "session.delete",
            )
        )
        or called.endswith("urllib.request.urlopen")
        or called == "urlopen"
    )
    if not network_call:
        return None

    target_node = call.args[0] if call.args else _kw(call, "url")
    target = _resolved_string(info, target_node)
    if target and target.startswith(("http://", "https://")):
        return _destination(
            info.path,
            call,
            target,
            restricted=False,
            source="literal_url",
        )

    fixed_origin = _fixed_url_origin(info, target_node, assignments)
    if fixed_origin:
        return _destination(
            info.path,
            call,
            fixed_origin,
            restricted=True,
            source="fixed_url_origin",
        )

    return _destination(
        info.path,
        call,
        "<dynamic-url>",
        restricted=False,
        source="dynamic_network_call",
    )


def _managed_destination(
    info: ModuleInfo,
    node: ast.AST,
    target: str,
    source: str,
) -> NetworkDestination:
    return _destination(
        info.path,
        node,
        target,
        restricted=True,
        source=source,
        managed=True,
    )


def _expr_uses_names(node: ast.AST | None, names: set[str]) -> bool:
    if node is None or not names:
        return False
    return any(
        isinstance(child, ast.Name) and child.id in names
        for child in ast.walk(node)
    )


def _assignment_targets(node: ast.AST) -> set[str]:
    targets: list[ast.AST]
    if isinstance(node, ast.Assign):
        targets = list(node.targets)
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
    else:
        return set()

    def names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            return {
                name
                for item in target.elts
                for name in names(item)
            }
        return set()

    return {
        name
        for target in targets
        for name in names(target)
    }


def _function_file_transfer_semantics(
    info: ModuleInfo,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[list[ResourceScope], dict[str, object]]:
    """Prove model-selected local file access and read-derived external transfer.

    Function parameters of model-callable ADK tools are caller/model selected.
    This analysis stays deliberately intraprocedural: it propagates path/data
    aliases through assignments, recognizes explicit containment checks, and only
    marks external transfer when data derived from a model-selected file read
    reaches a known external call argument.
    """
    params = {
        arg.arg
        for arg in [
            *func.args.posonlyargs,
            *func.args.args,
            *func.args.kwonlyargs,
        ]
    }
    if not params:
        return [], {}

    assignments = [
        node
        for node in ast.walk(func)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and node.value is not None
    ]

    path_taint = set(params)
    changed = True
    while changed:
        changed = False
        for assignment in assignments:
            if not _expr_uses_names(assignment.value, path_taint):
                continue
            for name in _assignment_targets(assignment):
                if name not in path_taint:
                    path_taint.add(name)
                    changed = True

    containment = False
    for call in (node for node in ast.walk(func) if isinstance(node, ast.Call)):
        leaf = (_name(call.func) or "").lower()
        called = (_dotted(call.func) or _name(call.func) or "").lower()
        if leaf in {"relative_to", "is_relative_to"}:
            receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
            if _expr_uses_names(receiver, path_taint):
                containment = True
        if called in {"os.path.commonpath", "commonpath"} and _expr_uses_names(
            call, path_taint
        ):
            containment = True

    file_handles: set[str] = set()
    read_locations: list[SourceLocation] = []

    def read_mode(call: ast.Call) -> bool:
        mode = (
            _string(call.args[1])
            if len(call.args) > 1
            else _string(_kw(call, "mode"))
        ) or "r"
        return not any(ch in mode for ch in "wax+")

    for node in ast.walk(func):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                call = item.context_expr
                if not isinstance(call, ast.Call):
                    continue
                called = (_dotted(call.func) or _name(call.func) or "").lower()
                if not (called == "open" or called.endswith(".open")):
                    continue
                path_expr = call.args[0] if call.args else _kw(call, "file")
                if not read_mode(call) or not _expr_uses_names(path_expr, path_taint):
                    continue
                read_locations.append(_loc(info.path, call))
                if isinstance(item.optional_vars, ast.Name):
                    file_handles.add(item.optional_vars.id)

        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
            node.value, ast.Call
        ):
            call = node.value
            called = (_dotted(call.func) or _name(call.func) or "").lower()
            if called == "open" or called.endswith(".open"):
                path_expr = call.args[0] if call.args else _kw(call, "file")
                if read_mode(call) and _expr_uses_names(path_expr, path_taint):
                    read_locations.append(_loc(info.path, call))
                    file_handles.update(_assignment_targets(node))

    file_data: set[str] = set()
    for assignment in assignments:
        value = assignment.value
        if not isinstance(value, ast.Call):
            continue
        leaf = (_name(value.func) or "").lower()
        if leaf not in {"read", "read_bytes", "read_text"}:
            continue
        receiver = value.func.value if isinstance(value.func, ast.Attribute) else None
        receiver_from_handle = (
            isinstance(receiver, ast.Name) and receiver.id in file_handles
        )
        receiver_from_path = _expr_uses_names(receiver, path_taint)
        if receiver_from_handle or receiver_from_path:
            file_data.update(_assignment_targets(assignment))

    changed = True
    while changed:
        changed = False
        for assignment in assignments:
            if not _expr_uses_names(assignment.value, file_data):
                continue
            for name in _assignment_targets(assignment):
                if name not in file_data:
                    file_data.add(name)
                    changed = True

    imports = _function_imports(info, func)
    document_ai = any(
        value.startswith("google.cloud.documentai")
        for value in imports
    )
    external_sinks: list[str] = []
    for call in (node for node in ast.walk(func) if isinstance(node, ast.Call)):
        called = (_dotted(call.func) or _name(call.func) or "").lower()
        leaf = (_name(call.func) or "").lower()
        network = _network_call_destination(info, call, called) is not None
        managed_document_ai = document_ai and leaf in {
            "process_document",
            "batch_process_documents",
        }
        if not (network or managed_document_ai):
            continue
        values = [*call.args, *(keyword.value for keyword in call.keywords)]
        if any(_expr_uses_names(value, file_data) for value in values):
            external_sinks.append(called or leaf or "external_call")

    if not read_locations:
        return [], {}

    parameters = sorted(params & path_taint)
    metadata: dict[str, object] = {
        "model_selected_file_read": True,
        "model_selected_path_parameters": parameters,
        "filesystem_path_constrained": containment,
    }
    if external_sinks:
        metadata["file_read_external_transfer"] = True
        metadata["file_read_external_sinks"] = sorted(set(external_sinks))

    resources = [
        ResourceScope(
            kind="file",
            selector="<model-selected-file>",
            access={"data.read"},
            location=read_locations[0],
            metadata={
                "source": "model_selected_function_parameter",
                "path_parameters": parameters,
                "path_containment": "explicit" if containment else "not_detected",
            },
        )
    ]
    return resources, metadata


def _analyze_function(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    visited: set[tuple[str, str]] | None = None,
) -> tuple[set[str], list[NetworkDestination], set[str]]:
    visited = set() if visited is None else set(visited)
    key = (info.module, func.name)
    if key in visited:
        return set(), [], set()
    visited.add(key)

    caps: set[str] = set()
    destinations: list[NetworkDestination] = []
    scopes: set[str] = set()
    local_assignments: dict[str, ast.AST] = {}
    for assignment in ast.walk(func):
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
            continue
        value = assignment.value
        if value is None:
            continue
        for name in _assignment_targets(assignment):
            local_assignments[name] = value

    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            called = (_dotted(node.func) or _name(node.func) or "").lower()
            leaf = (_name(node.func) or "").lower()

            if (
                called in {
                    "exec",
                    "eval",
                    "compile",
                    "builtins.exec",
                    "builtins.eval",
                    "builtins.compile",
                }
                or called == "os.system"
                or called.startswith("subprocess.")
                or "create_subprocess_" in called
                or called.endswith(".popen")
            ):
                caps.add("process.execute")

            if leaf == "open" or called.endswith(".open"):
                mode = _string(node.args[1]) if len(node.args) > 1 else _string(_kw(node, "mode"))
                mode = mode or "r"
                caps.add("data.write" if any(ch in mode for ch in "wax+") else "data.read")

            # Repository-local business methods commonly qualify the action
            # verb (for example db.update_account() or db.create_transaction()).
            # Preserve the same source semantics as exact update()/create() calls
            # without treating arbitrary verb occurrences later in a name as proof.
            action = leaf.split("_", 1)[0]
            if leaf in {"get_media"} or action in {
                "get",
                "list",
                "search",
                "fetch",
                "download",
                "export",
            }:
                caps.add("data.read")
            if leaf in {"set", "save_artifact"} or action in {
                "create",
                "update",
                "insert",
                "upload",
                "write",
            }:
                caps.add("data.write")
            if action in {"delete", "remove", "destroy", "purge"}:
                caps.update({"data.write", "destructive.write"})

            network_destination = _network_call_destination(
                info,
                node,
                called,
                local_assignments,
            )
            if network_destination is not None:
                caps.add("network.external")
                if leaf in {"post", "put", "patch", "delete"}:
                    caps.add("external.write")
                destinations.append(network_destination)

            if leaf == "build" and node.args:
                service = _string(node.args[0])
                if service:
                    caps.update({"data.read", "network.external"})
                    target = GOOGLE_API_DESTINATIONS.get(service.lower(), "https://www.googleapis.com/")
                    destinations.append(_managed_destination(info, node, target, f"google_api:{service}"))

            if called.startswith("storage.") or ".storage." in called:
                caps.add("network.external")
                destinations.append(_managed_destination(info, node, "https://storage.googleapis.com/", "google_cloud_storage"))
            if called.startswith("firestore.") or ".firestore." in called:
                caps.add("network.external")
                destinations.append(_managed_destination(info, node, "https://firestore.googleapis.com/", "google_cloud_firestore"))
            if called.startswith("bigquery.") or ".bigquery." in called:
                caps.add("network.external")
                destinations.append(_managed_destination(info, node, "https://bigquery.googleapis.com/", "google_cloud_bigquery"))
            if called.startswith("vertexai.") or ".vertexai." in called or "generativemodel" in called:
                caps.add("network.external")
                destinations.append(_managed_destination(info, node, "https://aiplatform.googleapis.com/", "google_vertex_ai"))
            if any(
                value.startswith("google.cloud.documentai")
                for value in _function_imports(info, func)
            ) and leaf in {"process_document", "batch_process_documents"}:
                caps.add("network.external")
                destinations.append(
                    _managed_destination(
                        info,
                        node,
                        "https://documentai.googleapis.com/",
                        "google_document_ai",
                    )
                )
            if "secretmanager" in called or leaf == "access_secret_version":
                caps.update({"network.external", "secrets.read"})
                destinations.append(_managed_destination(info, node, "https://secretmanager.googleapis.com/", "google_secret_manager"))

            if called in {"os.getenv", "os.environ.get"}:
                env_name = _string(node.args[0]) if node.args else None
                if _sensitive_name(env_name):
                    caps.add("secrets.read")
            if leaf == "get" and node.args:
                key_name = _string(node.args[0])
                if _sensitive_name(key_name):
                    caps.add("secrets.read")

            local_name = _name(node.func)
            if local_name in info.functions and local_name != func.name:
                nested_caps, nested_destinations, nested_scopes = _analyze_function(
                    modules, info, info.functions[local_name], visited
                )
                caps.update(nested_caps)
                destinations.extend(nested_destinations)
                scopes.update(nested_scopes)
            elif isinstance(node.func, ast.Name):
                imported = _imported_symbol(modules, info, node.func.id)
                if imported and imported[1] in imported[0].functions:
                    target, symbol = imported
                    nested_caps, nested_destinations, nested_scopes = _analyze_function(
                        modules, target, target.functions[symbol], visited
                    )
                    caps.update(nested_caps)
                    destinations.extend(nested_destinations)
                    scopes.update(nested_scopes)
            elif isinstance(node.func, ast.Attribute):
                imported_attr = _attribute_function(modules, info, node.func)
                if imported_attr:
                    target, imported_func = imported_attr
                    nested_caps, nested_destinations, nested_scopes = _analyze_function(
                        modules, target, imported_func, visited
                    )
                    caps.update(nested_caps)
                    destinations.extend(nested_destinations)
                    scopes.update(nested_scopes)

        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(
                isinstance(target, ast.Subscript)
                and "state" in (_dotted(target.value) or "").lower()
                for target in targets
            ):
                caps.add("data.write")

        if isinstance(node, ast.Attribute):
            dotted = (_dotted(node) or "").lower()
            if _sensitive_name(node.attr) and dotted.startswith(("config.", "settings.", "secrets.", "credentials.")):
                caps.add("secrets.read")
            if isinstance(node.value, ast.Name):
                imported = _imported_symbol(modules, info, node.value.id)
                if imported:
                    scopes.update(_oauth_scopes(imported[0].tree))

    unique_destinations: list[NetworkDestination] = []
    seen: set[tuple[str, bool, str]] = set()
    for destination in destinations:
        key = (
            destination.target,
            destination.restricted,
            str(destination.metadata.get("source") or ""),
        )
        if key not in seen:
            seen.add(key)
            unique_destinations.append(destination)
    return caps, unique_destinations, scopes


def _function_tool(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[Tool, Identity | None]:
    caps, destinations, scopes = _analyze_function(modules, info, func)
    resources, file_metadata = _function_file_transfer_semantics(info, func)
    required_roles, required_role_evidence = _analyze_required_gcp_roles(
        modules,
        info,
        func,
    )
    identity = None
    identity_name = None
    if scopes:
        identity_name = f"{func.name}:oauth"
        identity = Identity(
            name=identity_name,
            provider="gcp",
            oauth_scopes=scopes,
            credential_source="oauth",
            location=_loc(info.path, func),
            metadata={"repository_resolved": True, "source_function": func.name},
        )
    network_scope = None
    if "network.external" in caps:
        if any(not item.restricted for item in destinations):
            network_scope = "dynamic_destination"
        elif destinations and all(item.metadata.get("network_scope") == "fixed_managed_service" for item in destinations):
            network_scope = "fixed_managed_service"
        elif destinations:
            network_scope = "explicit_destination"
        else:
            network_scope = "unknown"
    metadata = {
        "framework": "google-adk",
        "repository_resolved": True,
        **file_metadata,
    }
    if network_scope:
        metadata["network_scope"] = network_scope
    if required_roles:
        metadata["required_authority_provider"] = "gcp"
        metadata["required_roles"] = sorted(required_roles)
        metadata["required_roles_complete"] = False
        metadata["required_role_evidence"] = required_role_evidence
    return (
        Tool(
            name=func.name,
            kind="adk_function",
            capabilities=caps,
            resources=resources,
            destinations=destinations,
            identity=identity_name,
            location=_loc(info.path, func),
            metadata=metadata,
        ),
        identity,
    )


def _resolve_sequence(
    info: ModuleInfo,
    expr: ast.AST | None,
    sequences: dict[str, list[ast.AST]] | None = None,
) -> list[ast.AST]:
    sequences = info.sequences if sequences is None else sequences
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        result: list[ast.AST] = []
        for element in expr.elts:
            result.extend(_resolve_sequence(info, element, sequences))
        return result
    if isinstance(expr, ast.Starred):
        return _resolve_sequence(info, expr.value, sequences)
    if isinstance(expr, ast.IfExp):
        return _resolve_sequence(info, expr.body, sequences) + _resolve_sequence(info, expr.orelse, sequences)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _resolve_sequence(info, expr.left, sequences) + _resolve_sequence(
            info, expr.right, sequences
        )
    if isinstance(expr, ast.Name) and expr.id in sequences:
        result: list[ast.AST] = []
        for element in sequences[expr.id]:
            result.extend(_resolve_sequence(info, element, sequences))
        return result
    return [expr] if expr is not None else []


def _resolve_repository_sequence(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    expr: ast.AST | None,
    sequences: dict[str, list[ast.AST]] | None = None,
    visited: set[tuple[str, str]] | None = None,
) -> list[ast.AST]:
    """Resolve only statically proven repository-local sequence composition.

    This deliberately supports literal sequence containers, unpacking, addition,
    local aliases, and imported aliases. It does not execute comprehensions,
    function calls, arbitrary operators, or target imports.
    """
    if expr is None:
        return []
    sequences = info.sequences if sequences is None else sequences
    visited = set() if visited is None else set(visited)

    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        result: list[ast.AST] = []
        for element in expr.elts:
            result.extend(
                _resolve_repository_sequence(
                    modules, info, element, sequences, visited
                )
            )
        return result

    if isinstance(expr, ast.Starred):
        return _resolve_repository_sequence(
            modules, info, expr.value, sequences, visited
        )

    if isinstance(expr, ast.IfExp):
        return (
            _resolve_repository_sequence(
                modules, info, expr.body, sequences, visited
            )
            + _resolve_repository_sequence(
                modules, info, expr.orelse, sequences, visited
            )
        )

    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return (
            _resolve_repository_sequence(
                modules, info, expr.left, sequences, visited
            )
            + _resolve_repository_sequence(
                modules, info, expr.right, sequences, visited
            )
        )

    if isinstance(expr, ast.Name):
        key = (info.module, expr.id)
        if key in visited:
            return []
        next_visited = visited | {key}

        if expr.id in sequences:
            result: list[ast.AST] = []
            for element in sequences[expr.id]:
                result.extend(
                    _resolve_repository_sequence(
                        modules, info, element, sequences, next_visited
                    )
                )
            return result

        assigned = info.assignments.get(expr.id)
        if assigned is not None and not isinstance(assigned, ast.Call):
            return _resolve_repository_sequence(
                modules, info, assigned, sequences, next_visited
            )

    return [expr]


def _function_sequences(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, list[ast.AST]]:
    sequences: dict[str, list[ast.AST]] = {}
    for node in _module_statements(func.body):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if isinstance(target, ast.Name) and isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                    seq = sequences.setdefault(target.id, [])
                    _add_sequence_values(seq, list(value.elts))
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name):
                continue
            seq = sequences.get(call.func.value.id)
            if seq is None:
                continue
            if call.func.attr == "append" and len(call.args) == 1:
                _add_sequence_values(seq, [call.args[0]])
            elif call.func.attr == "extend" and len(call.args) == 1:
                arg = call.args[0]
                if isinstance(arg, (ast.List, ast.Tuple, ast.Set)):
                    _add_sequence_values(seq, list(arg.elts))
                elif isinstance(arg, ast.Name) and arg.id in sequences:
                    _add_sequence_values(seq, sequences[arg.id])
                elif isinstance(arg, ast.Call):
                    _add_sequence_values(seq, [arg])
    return sequences


def _mcp_from_repository_toolset(
    info: ModuleInfo,
    call: ast.Call,
    alias: str,
):
    """Resolve literal module constants before normal MCP normalization.

    This deliberately resolves only values captured by ``ast.literal_eval`` in
    ``ModuleInfo.constants``. Runtime configuration such as ``os.getenv`` is
    left dynamic so coverage reporting remains conservative.
    """

    class StaticConstantResolver(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name):
            value = info.constants.get(node.id)
            if (
                isinstance(value, (str, int, float, bool))
                or (value is None and node.id in info.constants)
            ):
                return ast.copy_location(ast.Constant(value=value), node)
            return node

    resolver = StaticConstantResolver()
    resolved_call = resolver.visit(copy.deepcopy(call))
    resolved_calls = {
        name: resolver.visit(copy.deepcopy(value))
        for name, value in info.calls.items()
    }
    return _mcp_from_toolset(
        info.path,
        resolved_call,
        alias,
        resolved_calls,
    )


def _function_context(
    info: ModuleInfo,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ModuleInfo:
    """Build a conservative source-only overlay for one repository helper."""
    context = copy.copy(info)
    context.calls = dict(info.calls)
    context.assignments = dict(info.assignments)
    context.constants = dict(info.constants)
    context.imports = dict(info.imports)
    context.sequences = _function_sequences(func)

    local_calls: dict[str, list[ast.Call]] = {}
    for node in _module_statements(func.body):
        if isinstance(node, ast.ImportFrom):
            module = _relative(
                info.module,
                node.level,
                node.module,
                current_is_package=info.path.name == "__init__.py",
            )
            for alias in node.names:
                if alias.name != "*":
                    context.imports[alias.asname or alias.name] = (module, alias.name)
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                context.imports[alias.asname or alias.name.split(".")[0]] = (
                    alias.name,
                    "",
                )
            continue
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        for target in targets:
            if not isinstance(target, ast.Name) or value is None:
                continue
            context.assignments[target.id] = value
            literal = _literal(value)
            if literal is not None:
                context.constants[target.id] = literal
            if isinstance(value, ast.Call):
                local_calls.setdefault(target.id, []).append(value)

    for name, calls in local_calls.items():
        if len(calls) == 1:
            context.calls[name] = calls[0]
        else:
            # A single local name reused across branches must not resolve to
            # whichever assignment happened to appear last in the file.
            context.calls.pop(name, None)
    return context


def _factory_return_values(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    result: list[ast.AST] = []
    stack: list[ast.AST] = list(reversed(func.body))
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Return):
            if node.value is not None:
                result.append(node.value)
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return result


def _factory_has_runtime_mcp_registry(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    return any(
        isinstance(node, ast.Call)
        and (_name(node.func) or "") in {"get_mcp_toolset", "list_mcp_servers"}
        for node in ast.walk(func)
    )


def _simple_factory(func: ast.FunctionDef | ast.AsyncFunctionDef | None) -> ast.Call | None:
    if func is None:
        return None
    calls = [
        node.value
        for node in ast.walk(func)
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Call)
    ]
    return calls[0] if len(calls) == 1 else None


def _resolve_tools(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    expr: ast.AST | None,
    sequences: dict[str, list[ast.AST]] | None = None,
    visited_sequences: set[tuple[str, str]] | None = None,
    visited_factories: set[tuple[str, str]] | None = None,
) -> tuple[list[Tool], list, list[Identity], set[tuple[Path, int]]]:
    tools: list[Tool] = []
    mcp_servers: list = []
    identities: list[Identity] = []
    resolved_refs: set[tuple[Path, int]] = set()
    visited_sequences = (
        set() if visited_sequences is None else set(visited_sequences)
    )
    visited_factories = (
        set() if visited_factories is None else set(visited_factories)
    )

    def add_function(target: ModuleInfo, func: ast.FunctionDef | ast.AsyncFunctionDef, ref: ast.AST) -> None:
        tool, identity = _function_tool(modules, target, func)
        tools.append(tool)
        if identity:
            identities.append(identity)
        resolved_refs.add((info.path, getattr(ref, "lineno", 1)))

    def resolve_factory_call(
        source_info: ModuleInfo,
        call: ast.Call,
        ref: ast.AST,
    ) -> tuple[list[Tool], list, list[Identity], set[tuple[Path, int]]] | None:
        helper: tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef] | None = None
        if isinstance(call.func, ast.Name):
            if call.func.id in source_info.functions:
                helper = (source_info, source_info.functions[call.func.id])
            else:
                imported = _imported_symbol(modules, source_info, call.func.id)
                if imported and imported[1] in imported[0].functions:
                    helper = (imported[0], imported[0].functions[imported[1]])
        elif isinstance(call.func, ast.Attribute):
            helper = _attribute_function(modules, source_info, call.func)
        if helper is None:
            return None

        target, factory = helper
        key = (target.module, factory.name)
        if key in visited_factories:
            return None

        context = _function_context(target, factory)
        nested_tools: list[Tool] = []
        nested_mcp: list = []
        nested_identities: list[Identity] = []
        nested_refs: set[tuple[Path, int]] = set()
        for returned in _factory_return_values(factory):
            resolved = _resolve_tools(
                modules,
                context,
                returned,
                context.sequences,
                visited_sequences,
                visited_factories | {key},
            )
            nested_tools.extend(resolved[0])
            nested_mcp.extend(resolved[1])
            nested_identities.extend(resolved[2])
            nested_refs.update(resolved[3])

        if _factory_has_runtime_mcp_registry(factory) and not nested_mcp:
            nested_mcp.append(
                MCPServer(
                    name=f"{factory.name}:runtime-mcp",
                    transport="unknown",
                    location=_loc(target.path, factory),
                    metadata={
                        "framework": "google-adk",
                        "repository_resolved": True,
                        "conditional_runtime_binding": True,
                        "dynamic_mcp_endpoint": True,
                        "dynamic_mcp_endpoint_basis": "runtime_registry",
                        "tool_catalogue_unresolved": True,
                        "source_function": factory.name,
                    },
                )
            )

        if not nested_tools and not nested_mcp and not nested_identities:
            return None
        nested_refs.add((info.path, getattr(ref, "lineno", 1)))
        return nested_tools, nested_mcp, nested_identities, nested_refs

    for item in _resolve_repository_sequence(modules, info, expr, sequences):
        if isinstance(item, ast.Name):
            if item.id in info.functions:
                add_function(info, info.functions[item.id], item)
                continue

            imported = _imported_symbol(modules, info, item.id)
            if imported:
                target, symbol = imported
                sequence_key = (target.module, symbol)
                assigned = target.assignments.get(symbol)
                if (
                    sequence_key not in visited_sequences
                    and assigned is not None
                    and not isinstance(assigned, ast.Call)
                    and (
                        symbol in target.sequences
                        or isinstance(
                            assigned,
                            (
                                ast.List,
                                ast.Tuple,
                                ast.Set,
                                ast.Starred,
                                ast.IfExp,
                                ast.BinOp,
                                ast.Name,
                            ),
                        )
                    )
                ):
                    nested_tools, nested_mcp, nested_identities, nested_refs = (
                        _resolve_tools(
                            modules,
                            target,
                            assigned,
                            target.sequences,
                            visited_sequences | {sequence_key},
                            visited_factories,
                        )
                    )
                    tools.extend(nested_tools)
                    mcp_servers.extend(nested_mcp)
                    identities.extend(nested_identities)
                    resolved_refs.update(nested_refs)
                    resolved_refs.add((info.path, item.lineno))
                    continue
                if symbol in target.functions:
                    add_function(target, target.functions[symbol], item)
                    continue
                if symbol in target.calls:
                    call = target.calls[symbol]
                    factory_result = resolve_factory_call(target, call, item)
                    if factory_result:
                        tools.extend(factory_result[0])
                        mcp_servers.extend(factory_result[1])
                        identities.extend(factory_result[2])
                        resolved_refs.update(factory_result[3])
                        continue
                    if (_name(call.func) or "") in {
                        "FunctionTool",
                        "LongRunningFunctionTool",
                        "AuthenticatedFunctionTool",
                    }:
                        wrapped = _kw(call, "func") or (call.args[0] if call.args else None)
                        wrapped_name = _name(wrapped)
                        if wrapped_name and wrapped_name in target.functions:
                            tool, identity = _function_tool(
                                modules, target, target.functions[wrapped_name]
                            )
                            tool.metadata.update(
                                {
                                    "wrapper": _name(call.func),
                                    "import_module": target.module,
                                    "source_function": wrapped_name,
                                    "repository_resolved": True,
                                }
                            )
                            approval = _literal(_kw(call, "require_confirmation"))
                            if isinstance(approval, bool):
                                tool.approval = approval
                                tool.guardrails = approval
                            tools.append(tool)
                            if identity:
                                identities.append(identity)
                            resolved_refs.add((info.path, item.lineno))
                            continue
                    mcp = _mcp_from_repository_toolset(target, call, symbol)
                    if mcp:
                        mcp_servers.append(mcp)
                        resolved_refs.add((info.path, item.lineno))
                        continue
                    tool = _tool_from_call(target.path, call, symbol, target.calls, target.functions)
                    if tool:
                        tools.append(tool)
                        resolved_refs.add((info.path, item.lineno))
                        continue
                    tools.append(
                        Tool(
                            name=item.id,
                            kind="dynamic_tool_collection",
                            capabilities=set(),
                            location=_loc(info.path, item),
                            metadata={
                                "framework": "google-adk",
                                "binding_origin": "source_bound_unresolved_tool_binding",
                                "dynamic_bound_collection": True,
                                "binding_unresolved": True,
                                "tool_scope_unresolved": True,
                                "catalogue_source": _name(call.func) or "repository_factory",
                                "import_module": target.module,
                                "source_function": symbol,
                            },
                        )
                    )
                    resolved_refs.add((info.path, item.lineno))
                    continue

            if item.id in info.calls:
                call = info.calls[item.id]
                factory_result = resolve_factory_call(info, call, item)
                if factory_result:
                    tools.extend(factory_result[0])
                    mcp_servers.extend(factory_result[1])
                    identities.extend(factory_result[2])
                    resolved_refs.update(factory_result[3])
                    continue
                mcp = _mcp_from_repository_toolset(info, call, item.id)
                if mcp:
                    mcp_servers.append(mcp)
                    resolved_refs.add((info.path, item.lineno))
                    continue
                tool = _tool_from_call(info.path, call, item.id, info.calls, info.functions)
                if tool:
                    tools.append(tool)
                    resolved_refs.add((info.path, item.lineno))
                    continue

            if item.id in BUILTIN_TOOL_CAPABILITIES:
                tool = Tool(
                    name=item.id,
                    kind="adk_builtin",
                    capabilities=set(BUILTIN_TOOL_CAPABILITIES[item.id]),
                    location=_loc(info.path, item),
                    metadata={
                        "framework": "google-adk",
                        "adk_builtin": item.id,
                        "repository_resolved": True,
                        "required_authority_provider": (
                            "gcp" if BUILTIN_TOOL_REQUIRED_ROLES.get(item.id) else None
                        ),
                        "required_roles": sorted(
                            BUILTIN_TOOL_REQUIRED_ROLES.get(item.id, set())
                        ),
                        "required_roles_complete": False,
                    },
                )
                if item.id in RETRIEVAL_TOOLS:
                    tool.metadata["untrusted_input"] = True
                    tool.metadata["network_scope"] = "fixed_managed_service"
                    tool.metadata["network_provider"] = "google"
                tools.append(tool)
                resolved_refs.add((info.path, item.lineno))
                continue

        elif isinstance(item, ast.Call):
            factory_result = resolve_factory_call(info, item, item)
            if factory_result:
                tools.extend(factory_result[0])
                mcp_servers.extend(factory_result[1])
                identities.extend(factory_result[2])
                resolved_refs.update(factory_result[3])
                continue

            alias = _name(item.func) or "tool"
            mcp = _mcp_from_repository_toolset(info, item, alias)
            if mcp:
                mcp_servers.append(mcp)
                resolved_refs.add((info.path, item.lineno))
                continue
            tool = _tool_from_call(info.path, item, alias, info.calls, info.functions)
            if tool:
                tools.append(tool)
                resolved_refs.add((info.path, item.lineno))
                continue

        elif isinstance(item, ast.Attribute):
            imported_func = _attribute_function(modules, info, item)
            if imported_func:
                add_function(imported_func[0], imported_func[1], item)
                continue
            tool_name = _name(item) or "tool"
            if tool_name in BUILTIN_TOOL_CAPABILITIES:
                tool = Tool(
                    name=tool_name,
                    kind="adk_builtin",
                    capabilities=set(BUILTIN_TOOL_CAPABILITIES[tool_name]),
                    location=_loc(info.path, item),
                    metadata={
                        "framework": "google-adk",
                        "adk_builtin": tool_name,
                        "repository_resolved": True,
                        "required_authority_provider": (
                            "gcp"
                            if BUILTIN_TOOL_REQUIRED_ROLES.get(tool_name)
                            else None
                        ),
                        "required_roles": sorted(
                            BUILTIN_TOOL_REQUIRED_ROLES.get(tool_name, set())
                        ),
                        "required_roles_complete": False,
                    },
                )
                if tool_name in RETRIEVAL_TOOLS:
                    tool.metadata["untrusted_input"] = True
                    tool.metadata["network_scope"] = "fixed_managed_service"
                    tool.metadata["network_provider"] = "google"
                tools.append(tool)
                resolved_refs.add((info.path, item.lineno))

    return tools, mcp_servers, identities, resolved_refs


def _resolve_agent_name(
    modules: dict[str, ModuleInfo], info: ModuleInfo, child: ast.Name
) -> str:
    child_call = info.calls.get(child.id)
    if child_call and (_name(child_call.func) or "") in AGENT_TYPES:
        return _string(_kw(child_call, "name")) or child.id
    imported = _imported_symbol(modules, info, child.id)
    if imported:
        target, symbol = imported
        call = target.calls.get(symbol)
        if call and (_name(call.func) or "") in AGENT_TYPES:
            return _string(_kw(call, "name")) or child.id
    return child.id


def _agent_from_call(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    call: ast.Call,
    alias: str,
    sequences: dict[str, list[ast.AST]] | None = None,
) -> tuple[Agent, list[Identity], set[tuple[Path, int]]]:
    runtime_name = _string(_kw(call, "name")) or alias
    tools, mcp_servers, identities, resolved_refs = _resolve_tools(
        modules, info, _kw(call, "tools"), sequences
    )
    agent_type = _name(call.func) or "Agent"
    agent = Agent(
        name=runtime_name,
        tools=tools,
        mcp_servers=mcp_servers,
        location=_loc(info.path, call),
        metadata={
            "framework": "google-adk",
            "agent_type": agent_type,
            "repository_resolved": True,
        },
    )
    if alias == "root_agent":
        agent.inputs.append(
            InputSource(
                name="user-or-remote-input",
                trust="untrusted",
                kind="user",
                location=agent.location,
                metadata={"inferred": True},
            )
        )
    if any(tool.metadata.get("untrusted_input") for tool in tools) or any(server.url for server in mcp_servers):
        agent.inputs.append(
            InputSource(
                name="retrieved-external-content",
                trust="untrusted",
                kind="retrieval",
                location=agent.location,
                metadata={"inferred": True},
            )
        )

    delegates: list[str] = []
    for child in _resolve_repository_sequence(
        modules, info, _kw(call, "sub_agents"), sequences
    ):
        if isinstance(child, ast.Name):
            delegates.append(_resolve_agent_name(modules, info, child))
        elif isinstance(child, ast.Call) and (_name(child.func) or "") in AGENT_TYPES:
            delegates.append(_string(_kw(child, "name")) or (_name(child.func) or "agent"))
    if delegates:
        agent.metadata["delegates_to"] = list(dict.fromkeys(delegates))
    return agent, identities, resolved_refs


def _merge_agent(existing: Agent, incoming: Agent) -> None:
    by_name = {
        tool.name: (index, tool)
        for index, tool in enumerate(existing.tools)
    }
    for tool in incoming.tools:
        current = by_name.get(tool.name)
        if current is None:
            existing.tools.append(tool)
            by_name[tool.name] = (len(existing.tools) - 1, tool)
            continue

        index, existing_tool = current
        replace_placeholder = (
            tool.metadata.get("repository_resolved") is True
            and (
                (
                    existing_tool.kind == "adk_builtin"
                    and existing_tool.metadata.get("adk_builtin")
                    not in BUILTIN_TOOL_CAPABILITIES
                )
                or existing_tool.kind == "unresolved_bound_tool"
                or existing_tool.metadata.get("binding_unresolved") is True
            )
        )
        if replace_placeholder:
            existing.tools[index] = tool
            by_name[tool.name] = (index, tool)
            continue

        if tool.metadata.get("repository_resolved") is True:
            # Repository resolution can prove additional authority requirements.
            # Source-proven file-flow semantics are also safe to merge because
            # they require an explicit model-selected file sink and, for external
            # transfer, read-derived dataflow to the external call.
            existing_tool.metadata["repository_resolved"] = True
            for key in (
                "model_selected_file_read",
                "model_selected_path_parameters",
                "filesystem_path_constrained",
                "file_read_external_transfer",
                "file_read_external_sinks",
            ):
                if key in tool.metadata:
                    existing_tool.metadata[key] = tool.metadata[key]
            if tool.metadata.get("model_selected_file_read"):
                existing_tool.resources.extend(
                    resource
                    for resource in tool.resources
                    if resource not in existing_tool.resources
                )
            if tool.metadata.get("file_read_external_transfer"):
                existing_tool.capabilities.update(
                    tool.capabilities & {"data.read", "network.external"}
                )
                existing_tool.destinations.extend(
                    destination
                    for destination in tool.destinations
                    if destination not in existing_tool.destinations
                )

            required_roles = set(
                existing_tool.metadata.get("required_roles") or []
            )
            required_roles.update(tool.metadata.get("required_roles") or [])
            if required_roles:
                existing_tool.metadata["required_authority_provider"] = (
                    tool.metadata.get("required_authority_provider")
                    or existing_tool.metadata.get("required_authority_provider")
                )
                existing_tool.metadata["required_roles"] = sorted(required_roles)
                existing_tool.metadata["required_roles_complete"] = (
                    existing_tool.metadata.get("required_roles_complete") is True
                    or tool.metadata.get("required_roles_complete") is True
                )

            evidence = list(
                existing_tool.metadata.get("required_role_evidence") or []
            )
            for item in tool.metadata.get("required_role_evidence") or []:
                if item not in evidence:
                    evidence.append(item)
            if evidence:
                existing_tool.metadata["required_role_evidence"] = evidence

    known_servers = {server.name for server in existing.mcp_servers}
    for server in incoming.mcp_servers:
        if server.name not in known_servers:
            existing.mcp_servers.append(server)
            known_servers.add(server.name)
    known_inputs = {(item.name, item.kind) for item in existing.inputs}
    for item in incoming.inputs:
        if (item.name, item.kind) not in known_inputs:
            existing.inputs.append(item)
            known_inputs.add((item.name, item.kind))
    delegates = list(existing.metadata.get("delegates_to") or [])
    for target in incoming.metadata.get("delegates_to") or []:
        if target not in delegates:
            delegates.append(target)
    if delegates:
        existing.metadata["delegates_to"] = delegates


def enrich_repository_graph(
    graph: Graph,
    root: Path,
    *,
    python_paths: list[Path],
) -> None:
    root = root.resolve()
    modules: dict[str, ModuleInfo] = {}
    for path in python_paths:
        resolved = path.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        info = _build(root, resolved)
        if info:
            modules[info.module] = info

    existing = {agent.name: agent for agent in graph.agents}
    identities_by_key = {(identity.name, identity.provider): identity for identity in graph.identities}
    resolved_refs: set[tuple[Path, int]] = set()

    for info in modules.values():
        functions = list(info.functions.values())
        for call in [node for node in ast.walk(info.tree) if isinstance(node, ast.Call)]:
            if (_name(call.func) or "") not in AGENT_TYPES:
                continue
            runtime_name = _string(_kw(call, "name"))
            if not runtime_name:
                continue
            enclosing = [
                func for func in functions
                if getattr(func, "lineno", 0) <= getattr(call, "lineno", 0) <= getattr(func, "end_lineno", 0)
            ]
            enclosing.sort(key=lambda func: getattr(func, "end_lineno", 0) - getattr(func, "lineno", 0))
            sequences = _function_sequences(enclosing[0]) if enclosing else info.sequences
            incoming, identities, refs = _agent_from_call(
                modules, info, call, runtime_name, sequences
            )
            resolved_refs.update(refs)
            current = existing.get(incoming.name)
            if current is None:
                graph.agents.append(incoming)
                existing[incoming.name] = incoming
            else:
                _merge_agent(current, incoming)
            for identity in identities:
                key = (identity.name, identity.provider)
                current_identity = identities_by_key.get(key)
                if current_identity is None:
                    graph.identities.append(identity)
                    identities_by_key[key] = identity
                else:
                    current_identity.oauth_scopes.update(identity.oauth_scopes)

    # Root aliases still establish user reachability.
    for info in modules.values():
        for node in info.tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(target, ast.Name) and target.id == "root_agent" for target in node.targets):
                continue
            if not isinstance(node.value, ast.Name):
                continue
            referenced = info.calls.get(node.value.id)
            if referenced is None or (_name(referenced.func) or "") not in AGENT_TYPES:
                continue
            runtime_name = _string(_kw(referenced, "name")) or node.value.id
            agent = existing.get(runtime_name)
            if agent is not None and not any(item.trust == "untrusted" for item in agent.inputs):
                agent.inputs.append(
                    InputSource(
                        name="user-or-remote-input",
                        trust="untrusted",
                        kind="user",
                        location=agent.location,
                        metadata={"inferred": True},
                    )
                )

    resolved_keys = {(path.resolve(), line) for path, line in resolved_refs}
    graph.coverage.diagnostics = [
        diagnostic
        for diagnostic in graph.coverage.diagnostics
        if not (
            diagnostic.kind == "unresolved_tool"
            and diagnostic.location is not None
            and (diagnostic.location.path.resolve(), diagnostic.location.line) in resolved_keys
        )
    ]

    for agent in graph.agents:
        helpers = set(agent.metadata.get("unresolved_helpers") or [])
        if not helpers:
            continue
        resolved_names = {tool.name for tool in agent.tools}
        remaining = sorted(helpers - resolved_names)
        agent.metadata["unresolved_helpers"] = remaining
        agent.metadata["external_helper_semantics_unresolved"] = bool(remaining)
