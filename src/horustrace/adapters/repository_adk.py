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
from horustrace.heuristics import infer_capabilities
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
    classes: dict[str, ast.ClassDef] = field(default_factory=dict)
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
        elif isinstance(node, ast.ClassDef):
            info.classes[node.name] = node
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


def _has_google_adk_evidence(info: ModuleInfo) -> bool:
    """Require source provenance before treating a generic Agent call as Google ADK."""
    for node in ast.walk(info.tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "google.adk" or module.startswith("google.adk."):
                return True
        elif isinstance(node, ast.Import):
            if any(
                alias.name == "google.adk" or alias.name.startswith("google.adk.")
                for alias in node.names
            ):
                return True
    return False


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


def _enclosing_function(
    info: ModuleInfo,
    node: ast.AST,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    line = getattr(node, "lineno", 0) or 0
    candidates = [
        func
        for func in info.functions.values()
        if getattr(func, "lineno", 0) <= line <= getattr(func, "end_lineno", 0)
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda func: (
            getattr(func, "end_lineno", 0) - getattr(func, "lineno", 0)
        )
    )
    return candidates[0]


def _function_calls(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, ast.Call]:
    result: dict[str, ast.Call] = {}
    for node in ast.walk(func):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not isinstance(node.value, ast.Call):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                result[target.id] = node.value
    return result


def _local_imported_symbol(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    symbol: str,
    node: ast.AST,
) -> tuple[ModuleInfo, str] | None:
    func = _enclosing_function(info, node)
    if func is None:
        return None
    for item in ast.walk(func):
        if isinstance(item, ast.ImportFrom):
            module_name = _relative(
                info.module,
                item.level,
                item.module,
                current_is_package=False,
            )
            for imported in item.names:
                if imported.name == "*":
                    continue
                local_name = imported.asname or imported.name
                if local_name != symbol:
                    continue
                target = _find_module(modules, module_name)
                if target is None:
                    target = _find_module(
                        modules, f"{module_name}.{imported.name}"
                    )
                if target is not None:
                    return target, imported.name
        elif isinstance(item, ast.Import):
            for imported in item.names:
                local_name = imported.asname or imported.name.split(".")[0]
                if local_name != symbol:
                    continue
                target = _find_module(modules, imported.name)
                if target is not None:
                    return target, ""
    return None


def _symbol_import(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    symbol: str,
    node: ast.AST,
) -> tuple[ModuleInfo, str] | None:
    return (
        _imported_symbol(modules, info, symbol)
        or _local_imported_symbol(modules, info, symbol, node)
    )


_ADK_AGENT_BASE_TYPES = set(AGENT_TYPES) | {"BaseAgent"}


def _class_inherits_adk_agent(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    class_node: ast.ClassDef,
    visited: set[tuple[str, str]] | None = None,
) -> bool:
    """Return True when a repository-local class derives from an ADK agent type."""
    visited = set() if visited is None else set(visited)
    key = (info.module, class_node.name)
    if key in visited:
        return False
    visited.add(key)

    for base in class_node.bases:
        base_name = _name(base) or ((_dotted(base) or "").rsplit(".", 1)[-1] or None)
        if base_name in _ADK_AGENT_BASE_TYPES:
            return True
        if isinstance(base, ast.Name):
            local = info.classes.get(base.id)
            if local is not None and _class_inherits_adk_agent(
                modules, info, local, visited
            ):
                return True
            imported = _imported_symbol(modules, info, base.id)
            if imported:
                target, symbol = imported
                imported_class = target.classes.get(symbol)
                if imported_class is not None and _class_inherits_adk_agent(
                    modules, target, imported_class, visited
                ):
                    return True
    return False


def _custom_agent_class_for_call(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    call: ast.Call,
) -> tuple[ModuleInfo, str, ast.ClassDef] | None:
    """Resolve a repository-local custom ADK agent constructor without imports."""
    leaf = _name(call.func)
    if not leaf or leaf in AGENT_TYPES:
        return None

    if isinstance(call.func, ast.Name):
        local = info.classes.get(leaf)
        if local is not None and _class_inherits_adk_agent(modules, info, local):
            return info, leaf, local
        imported = _symbol_import(modules, info, leaf, call)
        if imported:
            target, symbol = imported
            imported_class = target.classes.get(symbol)
            if imported_class is not None and _class_inherits_adk_agent(
                modules, target, imported_class
            ):
                return target, symbol, imported_class

    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        imported = _symbol_import(modules, info, call.func.value.id, call)
        if imported:
            target, remote = imported
            nested = (
                _find_module(modules, f"{target.module}.{remote}")
                if remote
                else target
            )
            candidate = nested or target
            imported_class = candidate.classes.get(call.func.attr)
            if imported_class is not None and _class_inherits_adk_agent(
                modules, candidate, imported_class
            ):
                return candidate, call.func.attr, imported_class
    return None


_ADK_TOOL_BASE_TYPES = {"BaseTool"}


def _class_inherits_adk_tool(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    class_node: ast.ClassDef,
    visited: set[tuple[str, str]] | None = None,
) -> bool:
    """Return True when a repository-local class derives from ADK BaseTool."""
    visited = set() if visited is None else set(visited)
    key = (info.module, class_node.name)
    if key in visited:
        return False
    visited.add(key)

    for base in class_node.bases:
        base_name = _name(base) or ((_dotted(base) or "").rsplit(".", 1)[-1] or None)
        if base_name in _ADK_TOOL_BASE_TYPES:
            return True
        if isinstance(base, ast.Name):
            local = info.classes.get(base.id)
            if local is not None and _class_inherits_adk_tool(
                modules, info, local, visited
            ):
                return True
            imported = _imported_symbol(modules, info, base.id)
            if imported:
                target, symbol = imported
                imported_class = target.classes.get(symbol)
                if imported_class is not None and _class_inherits_adk_tool(
                    modules, target, imported_class, visited
                ):
                    return True
    return False


def _custom_tool_class_for_call(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    call: ast.Call,
) -> tuple[ModuleInfo, str, ast.ClassDef] | None:
    """Resolve a repository-local custom ADK BaseTool constructor."""
    leaf = _name(call.func)
    if not leaf:
        return None

    if isinstance(call.func, ast.Name):
        local = info.classes.get(leaf)
        if local is not None and _class_inherits_adk_tool(modules, info, local):
            return info, leaf, local
        imported = _symbol_import(modules, info, leaf, call)
        if imported:
            target, symbol = imported
            imported_class = target.classes.get(symbol)
            if imported_class is not None and _class_inherits_adk_tool(
                modules, target, imported_class
            ):
                return target, symbol, imported_class

    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        imported = _symbol_import(modules, info, call.func.value.id, call)
        if imported:
            target, remote = imported
            nested = (
                _find_module(modules, f"{target.module}.{remote}")
                if remote
                else target
            )
            candidate = nested or target
            imported_class = candidate.classes.get(call.func.attr)
            if imported_class is not None and _class_inherits_adk_tool(
                modules, candidate, imported_class
            ):
                return candidate, call.func.attr, imported_class
    return None


def _custom_tool_runtime_name(
    class_node: ast.ClassDef,
    fallback: str,
) -> str:
    for statement in class_node.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        value = statement.value
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        if not any(isinstance(target, ast.Name) and target.id == "name" for target in targets):
            continue
        resolved = _string(value)
        if resolved:
            return resolved
    return fallback


def _custom_tool_from_repository_call(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    call: ast.Call,
    alias: str,
) -> Tool | None:
    custom_ref = _custom_tool_class_for_call(modules, info, call)
    if custom_ref is None:
        return None
    class_info, class_name, class_node = custom_ref
    runtime_name = _custom_tool_runtime_name(class_node, alias)
    capabilities: set[str] = set()
    destinations: list[NetworkDestination] = []
    seen_destinations: set[tuple[str, bool, str]] = set()

    for method in class_node.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if method.name not in {"run", "run_async", "invoke"}:
            continue
        method_caps, method_destinations, _ = _analyze_function(
            modules,
            class_info,
            method,
            model_callable=True,
        )
        capabilities.update(method_caps)
        for destination in method_destinations:
            key = (
                destination.target,
                destination.restricted,
                str(destination.metadata.get("source") or ""),
            )
            if key in seen_destinations:
                continue
            seen_destinations.add(key)
            destinations.append(destination)

    metadata: dict[str, object] = {
        "framework": "google-adk",
        "repository_resolved": True,
        "custom_base_tool": True,
        "custom_tool_class": class_name,
        "source_alias": alias,
        "binding_origin": "custom_base_agent_constructor",
    }
    model_selected_destinations = [
        item
        for item in destinations
        if item.metadata.get("source") == "model_selected_url_argument"
    ]
    if model_selected_destinations:
        metadata.update(
            {
                "model_selected_url_fetch": True,
                "destination_provenance": "model_selected_url_argument",
                "network_abstraction": model_selected_destinations[0].metadata.get(
                    "network_abstraction"
                ),
            }
        )
    if any(not item.restricted for item in destinations):
        metadata["network_scope"] = "dynamic_destination"
    elif destinations:
        metadata["network_scope"] = "explicit_destination"

    return Tool(
        name=runtime_name,
        kind="adk_custom_tool",
        capabilities=capabilities,
        destinations=destinations,
        location=_loc(info.path, call),
        metadata=metadata,
    )


def _class_init(class_node: ast.ClassDef) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    return next(
        (
            node
            for node in class_node.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "__init__"
        ),
        None,
    )


def _constructor_bindings(
    call: ast.Call,
    init: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, ast.AST]:
    positional = [*init.args.posonlyargs, *init.args.args]
    if positional and positional[0].arg in {"self", "cls"}:
        positional = positional[1:]

    bindings: dict[str, ast.AST] = {}
    defaults = list(init.args.defaults)
    if defaults:
        for param, default in zip(positional[-len(defaults):], defaults):
            bindings[param.arg] = default

    for param, value in zip(positional, call.args):
        bindings[param.arg] = value

    for param, default in zip(init.args.kwonlyargs, init.args.kw_defaults):
        if default is not None:
            bindings[param.arg] = default

    for keyword in call.keywords:
        if keyword.arg is not None:
            bindings[keyword.arg] = keyword.value
    return bindings


def _bound_expr(node: ast.AST | None, bindings: dict[str, ast.AST]) -> ast.AST | None:
    seen: set[str] = set()
    while isinstance(node, ast.Name) and node.id in bindings and node.id not in seen:
        seen.add(node.id)
        node = bindings[node.id]
    return node


def _super_init_calls(
    init: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Call]:
    result: list[ast.Call] = []
    for node in ast.walk(init):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "__init__" or not isinstance(node.func.value, ast.Call):
            continue
        if _name(node.func.value.func) == "super":
            result.append(node)
    return result


def _custom_agent_runtime_name(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    call: ast.Call,
    alias: str,
    custom_ref: tuple[ModuleInfo, str, ast.ClassDef] | None = None,
) -> str:
    explicit = _string(_kw(call, "name"))
    if explicit:
        return explicit
    custom_ref = custom_ref or _custom_agent_class_for_call(modules, info, call)
    if custom_ref is None:
        return alias
    _, _, class_node = custom_ref
    init = _class_init(class_node)
    if init is None:
        return alias
    bindings = _constructor_bindings(call, init)
    for super_call in _super_init_calls(init):
        name_expr = _bound_expr(_kw(super_call, "name"), bindings)
        runtime_name = _string(name_expr)
        if runtime_name:
            return runtime_name
    return alias


def _resolve_agent_expr_name(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    expr: ast.AST,
) -> str | None:
    if isinstance(expr, ast.Name):
        call = info.calls.get(expr.id)
        if call is None:
            func = _enclosing_function(info, expr)
            if func is not None:
                call = _function_calls(func).get(expr.id)
        if call is not None:
            call_type = _name(call.func) or ""
            if call_type in AGENT_TYPES:
                return _string(_kw(call, "name")) or expr.id
            custom_ref = _custom_agent_class_for_call(modules, info, call)
            if custom_ref is not None:
                return _custom_agent_runtime_name(
                    modules, info, call, expr.id, custom_ref
                )
        imported = _symbol_import(modules, info, expr.id, expr)
        if imported:
            target, symbol = imported
            call = target.calls.get(symbol)
            if call is not None:
                call_type = _name(call.func) or ""
                if call_type in AGENT_TYPES:
                    return _string(_kw(call, "name")) or expr.id
                custom_ref = _custom_agent_class_for_call(modules, target, call)
                if custom_ref is not None:
                    return _custom_agent_runtime_name(
                        modules, target, call, expr.id, custom_ref
                    )
        return expr.id

    if isinstance(expr, ast.Call):
        call_type = _name(expr.func) or ""
        if call_type in AGENT_TYPES:
            return _string(_kw(expr, "name")) or call_type
        custom_ref = _custom_agent_class_for_call(modules, info, expr)
        if custom_ref is not None:
            return _custom_agent_runtime_name(
                modules, info, expr, custom_ref[1], custom_ref
            )
    return None


def _custom_agent_delegates(
    modules: dict[str, ModuleInfo],
    caller_info: ModuleInfo,
    call: ast.Call,
    custom_ref: tuple[ModuleInfo, str, ast.ClassDef],
) -> list[str]:
    """Resolve source-proven child agents held by a custom ADK agent constructor."""
    class_info, _, class_node = custom_ref
    init = _class_init(class_node)
    if init is None:
        return []

    bindings = _constructor_bindings(call, init)
    sequences = _function_sequences(init)
    delegates: list[str] = []

    def add_expr(expr: ast.AST) -> None:
        owner_info = class_info
        resolved = expr
        if isinstance(expr, ast.Name) and expr.id in bindings:
            resolved = _bound_expr(expr, bindings) or expr
            owner_info = caller_info
        target = _resolve_agent_expr_name(modules, owner_info, resolved)
        if target and target not in delegates:
            delegates.append(target)

    for super_call in _super_init_calls(init):
        for child in _resolve_repository_sequence(
            modules,
            class_info,
            _kw(super_call, "sub_agents"),
            sequences,
        ):
            add_expr(child)

    # Custom orchestrators often retain constructor-provided agents on self and
    # invoke them directly instead of passing them to BaseAgent.sub_agents.
    # Only preserve a delegation when the stored attribute is later called
    # through a known agent execution method.
    attr_params: dict[str, str] = {}
    for node in ast.walk(init):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not isinstance(node.value, ast.Name):
            continue
        for target in targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "self"
            ):
                attr_params[target.attr] = node.value.id

    # Follow trivial property forwarding such as:
    #   @property
    #   def implementation_loop(self):
    #       return self._implementation_loop
    # This is common in custom ADK orchestrators that keep child agents in
    # private attributes but expose them through read-only properties.
    property_aliases: dict[str, str] = {}
    for method in class_node.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_property = any(
            (_name(decorator) or "") == "property"
            for decorator in method.decorator_list
        )
        if not is_property:
            continue
        returned_attrs = {
            node.value.attr
            for node in ast.walk(method)
            if isinstance(node, ast.Return)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "self"
        }
        if len(returned_attrs) == 1:
            property_aliases[method.name] = next(iter(returned_attrs))

    def backing_attr(name: str) -> str:
        seen: set[str] = set()
        while name in property_aliases and name not in seen:
            seen.add(name)
            name = property_aliases[name]
        return name

    invoked_attrs: set[str] = set()
    for method in class_node.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(method):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"run_async", "run", "run_sync", "invoke"}:
                continue
            receiver = node.func.value
            if (
                isinstance(receiver, ast.Attribute)
                and isinstance(receiver.value, ast.Name)
                and receiver.value.id == "self"
            ):
                invoked_attrs.add(backing_attr(receiver.attr))

    for attr in sorted(invoked_attrs):
        param = attr_params.get(attr)
        if not param or param not in bindings:
            continue
        resolved = _bound_expr(bindings[param], bindings) or bindings[param]
        target = _resolve_agent_expr_name(modules, caller_info, resolved)
        if target and target not in delegates:
            delegates.append(target)

    return delegates


def _custom_agent_bound_tools(
    modules: dict[str, ModuleInfo],
    custom_ref: tuple[ModuleInfo, str, ast.ClassDef],
) -> list[Tool]:
    """Resolve custom ADK tools assigned to self.tools inside a custom agent."""
    class_info, _, class_node = custom_ref
    init = _class_init(class_node)
    if init is None:
        return []

    local_calls = _function_calls(init)
    local_sequences = _function_sequences(init)
    result: list[Tool] = []
    seen: set[str] = set()

    def sequence(expr: ast.AST | None) -> list[ast.AST]:
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return list(expr.elts)
        if isinstance(expr, ast.Name):
            return list(local_sequences.get(expr.id, []))
        return []

    for assignment in ast.walk(init):
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
            continue
        value = assignment.value
        if value is None:
            continue
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        binds_tools = any(
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
            and target.attr == "tools"
            for target in targets
        )
        if not binds_tools:
            continue

        for element in sequence(value):
            call: ast.Call | None = None
            alias = _name(element) or "tool"
            if isinstance(element, ast.Call):
                call = element
                alias = _name(element.func) or alias
            elif isinstance(element, ast.Name):
                call = local_calls.get(element.id)
                alias = element.id
            if call is None:
                continue
            tool = _custom_tool_from_repository_call(
                modules,
                class_info,
                call,
                alias,
            )
            if tool is None or tool.name in seen:
                continue
            seen.add(tool.name)
            result.append(tool)

    return result


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
    model_selected_names: set[str] | None = None,
) -> NetworkDestination | None:
    # urllib.parse/string helpers are not network sinks. Only urlopen performs
    # I/O; Request(...) is a local request-object constructor whose wrapped URL
    # is resolved when it reaches urlopen().
    a2a_card_resolver = called.endswith("a2acardresolver")
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
        or a2a_card_resolver
    )
    if not network_call:
        return None

    target_node = (
        _kw(call, "base_url")
        if a2a_card_resolver
        else (call.args[0] if call.args else _kw(call, "url"))
    )
    if model_selected_names and _expr_uses_names(target_node, model_selected_names):
        destination = _destination(
            info.path,
            call,
            "<model-selected-url>",
            restricted=False,
            source="model_selected_url_argument",
        )
        destination.metadata["destination_provenance"] = "model_selected_url_argument"
        if a2a_card_resolver:
            destination.metadata["network_abstraction"] = "a2a_agent_card"
        return destination

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
    *,
    model_callable: bool = False,
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

    model_selected_names: set[str] = set()
    if model_callable:
        excluded = {"self", "cls", "ctx", "context", "tool_context"}
        model_selected_names.update(
            arg.arg
            for arg in [
                *func.args.posonlyargs,
                *func.args.args,
                *func.args.kwonlyargs,
            ]
            if arg.arg not in excluded
        )
        kwarg_name = func.args.kwarg.arg if func.args.kwarg is not None else None

        def from_tool_args(expr: ast.AST) -> bool:
            if kwarg_name is None:
                return False
            if (
                isinstance(expr, ast.Subscript)
                and isinstance(expr.value, ast.Name)
                and expr.value.id == kwarg_name
            ):
                key = _string(expr.slice)
                return key == "args"
            if (
                isinstance(expr, ast.Call)
                and isinstance(expr.func, ast.Attribute)
                and isinstance(expr.func.value, ast.Name)
                and expr.func.value.id == kwarg_name
                and expr.func.attr == "get"
                and expr.args
            ):
                return _string(expr.args[0]) == "args"
            return False

        changed = True
        while changed:
            changed = False
            for name, value in local_assignments.items():
                if name in model_selected_names:
                    continue
                if from_tool_args(value) or _expr_uses_names(
                    value, model_selected_names
                ):
                    model_selected_names.add(name)
                    changed = True

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
                model_selected_names,
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


def _function_external_resource_id_semantics(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    capabilities: set[str],
) -> tuple[list[ResourceScope], dict[str, object]]:
    """Bind model-selected external resource IDs to source-visible SDK calls.

    ADK function parameters are model-callable inputs. Preserve identifier scope
    only when an *_id / *_ids parameter actually reaches an imported external
    SDK/helper call; repository-local helpers are handled by normal source
    composition instead of being treated as opaque external authority.
    """
    parameters = {
        arg.arg
        for arg in [
            *func.args.posonlyargs,
            *func.args.args,
            *func.args.kwonlyargs,
        ]
        if arg.arg not in {"self", "cls", "ctx", "context", "tool_context"}
    }
    id_parameters = {
        name
        for name in parameters
        if name.endswith(("_id", "_ids"))
    }
    if not id_parameters:
        return [], {}

    resources: list[ResourceScope] = []
    seen: set[tuple[str, str, str]] = set()
    for call in (node for node in ast.walk(func) if isinstance(node, ast.Call)):
        imported_module: str | None = None
        imported_symbol: str | None = None
        if isinstance(call.func, ast.Name):
            ref = info.imports.get(call.func.id)
            if ref is not None:
                imported_module, imported_symbol = ref
        elif (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
        ):
            ref = info.imports.get(call.func.value.id)
            if ref is not None:
                imported_module = ref[0]
                imported_symbol = call.func.attr

        if not imported_module:
            continue
        if _find_module(modules, imported_module) is not None:
            continue

        values = [*call.args, *(keyword.value for keyword in call.keywords)]
        used = sorted(
            name
            for name in id_parameters
            if any(_expr_uses_names(value, {name}) for value in values)
        )
        if not used:
            continue

        called = imported_symbol or _name(call.func) or ""
        call_access = infer_capabilities(called) & {
            "data.read",
            "data.write",
            "destructive.write",
        }
        if not call_access:
            call_access = capabilities & {
                "data.read",
                "data.write",
                "destructive.write",
            }
        if not call_access:
            continue

        provider_root = imported_module.split(".", 1)[0]
        provider = provider_root.split("_", 1)[0] or provider_root
        for parameter in used:
            base = parameter[:-4] if parameter.endswith("_ids") else parameter[:-3]
            resource_type = base.split("_")[-1] or "resource"
            key = (provider, resource_type, parameter)
            if key in seen:
                continue
            seen.add(key)
            resources.append(
                ResourceScope(
                    kind="external_resource",
                    selector=parameter,
                    access=set(call_access),
                    classification="external",
                    location=_loc(info.path, call),
                    metadata={
                        "source": "external_sdk_resource_identifier",
                        "selector_provenance": "model_selected",
                        "selector_type": "identifier",
                        "provider": provider,
                        "external_sdk_module": imported_module,
                        "external_sdk_symbol": called,
                        "resource_type": resource_type,
                    },
                )
            )

    if not resources:
        return [], {}
    return resources, {
        "model_selected_external_resource_ids": sorted(
            {resource.selector for resource in resources}
        ),
        "external_resource_scope_source": "source_visible_sdk_identifier",
    }


def _function_tool(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[Tool, Identity | None]:
    caps, destinations, scopes = _analyze_function(
        modules,
        info,
        func,
        model_callable=True,
    )
    resources, file_metadata = _function_file_transfer_semantics(info, func)
    external_resources, external_resource_metadata = (
        _function_external_resource_id_semantics(
            modules,
            info,
            func,
            caps,
        )
    )
    for resource in external_resources:
        if resource not in resources:
            resources.append(resource)
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
        **external_resource_metadata,
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
    local aliases, imported aliases, and the element templates of comprehensions.
    Comprehensions are never executed and their cardinality remains unresolved;
    only source-visible possible members are projected.
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

    if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        # Preserve the source-visible member template without evaluating the
        # comprehension or claiming that any particular runtime element exists.
        return _resolve_repository_sequence(
            modules, info, expr.elt, sequences, visited
        )

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


def _simple_factory(func: ast.FunctionDef | ast.AsyncFunctionDef | None) -> ast.Call | None:
    if func is None:
        return None
    calls = [
        node.value
        for node in ast.walk(func)
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Call)
    ]
    return calls[0] if len(calls) == 1 else None


def _dynamic_mcp_factory_server(
    info: ModuleInfo,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    alias: str,
) -> MCPServer | None:
    """Represent repository-local MCP factories without inventing runtime members.

    This is intentionally a source-summary fallback used only when a helper
    function visibly reaches MCP construction/registry APIs but cannot be reduced
    to one concrete returned constructor.  It preserves the authority boundary
    while leaving endpoint and tool catalogue dimensions unresolved.
    """

    mcp_calls: list[str] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        called = ast.unparse(node.func)
        lowered = called.lower()
        if "mcp" in lowered or "get_adk_toolset" in lowered:
            mcp_calls.append(called)
    if not mcp_calls:
        return None

    return MCPServer(
        name=alias,
        transport="unknown",
        location=_loc(info.path, func),
        metadata={
            "framework": "google-adk",
            "binding_origin": "repository_mcp_factory",
            "repository_resolved": True,
            "dynamic_bound_collection": True,
            "tool_catalogue_unresolved": True,
            "configuration_dependent": True,
            "dynamic_mcp_endpoint": True,
            "dynamic_mcp_endpoint_basis": "operator_configuration",
            "source_function": func.name,
            "catalogue_sources": sorted(set(mcp_calls)),
        },
    )


def _resolve_tools(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    expr: ast.AST | None,
    sequences: dict[str, list[ast.AST]] | None = None,
    visited_sequences: set[tuple[str, str]] | None = None,
) -> tuple[list[Tool], list, list[Identity], set[tuple[Path, int]]]:
    tools: list[Tool] = []
    mcp_servers: list = []
    identities: list[Identity] = []
    resolved_refs: set[tuple[Path, int]] = set()
    visited_sequences = (
        set() if visited_sequences is None else set(visited_sequences)
    )

    def add_function(target: ModuleInfo, func: ast.FunctionDef | ast.AsyncFunctionDef, ref: ast.AST) -> None:
        tool, identity = _function_tool(modules, target, func)
        tools.append(tool)
        if identity:
            identities.append(identity)
        resolved_refs.add((info.path, getattr(ref, "lineno", 1)))

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
                                ast.ListComp,
                                ast.SetComp,
                                ast.GeneratorExp,
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
            # Resolve helper factories returning a concrete ADK tool/toolset.
            helper: tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef] | None = None
            if isinstance(item.func, ast.Name):
                if item.func.id in info.functions:
                    helper = (info, info.functions[item.func.id])
                else:
                    imported = _imported_symbol(modules, info, item.func.id)
                    if imported and imported[1] in imported[0].functions:
                        helper = (imported[0], imported[0].functions[imported[1]])
            if helper:
                target, factory = helper
                returned = _simple_factory(factory)
                if returned is not None:
                    alias = _name(returned.func) or _name(item.func) or "tool"
                    mcp = _mcp_from_repository_toolset(target, returned, alias)
                    if mcp:
                        mcp_servers.append(mcp)
                        resolved_refs.add((info.path, item.lineno))
                        continue
                    tool = _tool_from_call(target.path, returned, alias, target.calls, target.functions)
                    if tool:
                        tools.append(tool)
                        resolved_refs.add((info.path, item.lineno))
                        continue

                dynamic_mcp = _dynamic_mcp_factory_server(
                    target,
                    factory,
                    _name(item.func) or factory.name,
                )
                if dynamic_mcp is not None:
                    mcp_servers.append(dynamic_mcp)
                    resolved_refs.add((info.path, item.lineno))
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
    resolved = _resolve_agent_expr_name(modules, info, child)
    return resolved or child.id


def _function_reads_adk_user_content(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted: set[str],
    visited: set[tuple[str, str, tuple[str, ...]]] | None = None,
) -> bool:
    """Prove that tainted ADK invocation context reaches ctx.user_content."""
    visited = set() if visited is None else set(visited)
    key = (info.module, func.name, tuple(sorted(tainted)))
    if key in visited:
        return False
    visited.add(key)

    for node in ast.walk(func):
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "user_content"
            and _expr_uses_names(node.value, tainted)
        ):
            return True

    def target_for_call(
        call: ast.Call,
    ) -> tuple[ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        if isinstance(call.func, ast.Name):
            local = info.functions.get(call.func.id)
            if local is not None:
                return info, local
            imported = _imported_symbol(modules, info, call.func.id)
            if imported and imported[1] in imported[0].functions:
                return imported[0], imported[0].functions[imported[1]]
        if isinstance(call.func, ast.Attribute):
            return _attribute_function(modules, info, call.func)
        return None

    for call in (node for node in ast.walk(func) if isinstance(node, ast.Call)):
        target = target_for_call(call)
        if target is None:
            continue
        target_info, target_func = target
        params = [
            *target_func.args.posonlyargs,
            *target_func.args.args,
            *target_func.args.kwonlyargs,
        ]
        if params and params[0].arg in {"self", "cls"}:
            params = params[1:]
        target_taint: set[str] = set()
        for index, argument in enumerate(call.args):
            if index >= len(params):
                break
            if _expr_uses_names(argument, tainted):
                target_taint.add(params[index].arg)
        by_name = {parameter.arg: parameter.arg for parameter in params}
        for keyword in call.keywords:
            if (
                keyword.arg in by_name
                and _expr_uses_names(keyword.value, tainted)
            ):
                target_taint.add(keyword.arg)
        if target_taint and _function_reads_adk_user_content(
            modules,
            target_info,
            target_func,
            target_taint,
            visited,
        ):
            return True
    return False


def _custom_agent_has_runtime_user_ingress(
    modules: dict[str, ModuleInfo],
    custom_ref: tuple[ModuleInfo, str, ast.ClassDef],
) -> bool:
    class_info, _, class_node = custom_ref
    for method in class_node.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if method.name not in {"_run_async_impl", "run_async", "run", "invoke"}:
            continue
        tainted = {
            arg.arg
            for arg in [
                *method.args.posonlyargs,
                *method.args.args,
                *method.args.kwonlyargs,
            ]
            if arg.arg not in {"self", "cls"}
        }
        if tainted and _function_reads_adk_user_content(
            modules,
            class_info,
            method,
            tainted,
        ):
            return True
    return False


def _agent_from_call(
    modules: dict[str, ModuleInfo],
    info: ModuleInfo,
    call: ast.Call,
    alias: str,
    sequences: dict[str, list[ast.AST]] | None = None,
    custom_ref: tuple[ModuleInfo, str, ast.ClassDef] | None = None,
) -> tuple[Agent, list[Identity], set[tuple[Path, int]]]:
    runtime_name = (
        _custom_agent_runtime_name(modules, info, call, alias, custom_ref)
        if custom_ref is not None
        else (_string(_kw(call, "name")) or alias)
    )
    tools, mcp_servers, identities, resolved_refs = _resolve_tools(
        modules, info, _kw(call, "tools"), sequences
    )
    if custom_ref is not None:
        existing_tool_names = {tool.name for tool in tools}
        for custom_tool in _custom_agent_bound_tools(modules, custom_ref):
            if custom_tool.name not in existing_tool_names:
                tools.append(custom_tool)
                existing_tool_names.add(custom_tool.name)

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
            "custom_base_agent": custom_ref is not None,
            "source_alias": alias,
        },
    )
    if custom_ref is not None and _custom_agent_has_runtime_user_ingress(
        modules,
        custom_ref,
    ):
        agent.inputs.append(
            InputSource(
                name="adk-invocation-context:user-content",
                trust="untrusted",
                kind="user",
                location=agent.location,
                metadata={
                    "basis": "source_bound_adk_invocation_context",
                    "runtime_invocation_proven": True,
                    "ingress_framework": "google-adk",
                },
            )
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
        target = _resolve_agent_expr_name(modules, info, child)
        if target:
            delegates.append(target)
    if custom_ref is not None:
        delegates.extend(_custom_agent_delegates(modules, info, call, custom_ref))
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
        if not _has_google_adk_evidence(info):
            continue
        functions = list(info.functions.values())
        for call in [node for node in ast.walk(info.tree) if isinstance(node, ast.Call)]:
            call_type = _name(call.func) or ""
            custom_ref = _custom_agent_class_for_call(modules, info, call)
            if call_type not in AGENT_TYPES and custom_ref is None:
                continue
            alias = next(
                (name for name, assigned in info.calls.items() if assigned is call),
                call_type or "agent",
            )
            runtime_name = (
                _custom_agent_runtime_name(modules, info, call, alias, custom_ref)
                if custom_ref is not None
                else _string(_kw(call, "name"))
            )
            if not runtime_name:
                continue
            enclosing = [
                func for func in functions
                if getattr(func, "lineno", 0) <= getattr(call, "lineno", 0) <= getattr(func, "end_lineno", 0)
            ]
            enclosing.sort(key=lambda func: getattr(func, "end_lineno", 0) - getattr(func, "lineno", 0))
            sequences = _function_sequences(enclosing[0]) if enclosing else info.sequences
            incoming, identities, refs = _agent_from_call(
                modules,
                info,
                call,
                alias,
                sequences,
                custom_ref,
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
        if not _has_google_adk_evidence(info):
            continue
        for node in info.tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(target, ast.Name) and target.id == "root_agent" for target in node.targets):
                continue
            if not isinstance(node.value, ast.Name):
                continue
            referenced = info.calls.get(node.value.id)
            if referenced is None:
                continue
            custom_ref = _custom_agent_class_for_call(modules, info, referenced)
            if (_name(referenced.func) or "") not in AGENT_TYPES and custom_ref is None:
                continue
            runtime_name = (
                _custom_agent_runtime_name(
                    modules, info, referenced, node.value.id, custom_ref
                )
                if custom_ref is not None
                else (_string(_kw(referenced, "name")) or node.value.id)
            )
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

    # File-level analysis can conservatively retain an unresolved source alias
    # (for example `custom`) before repository enrichment resolves an imported
    # custom agent to its runtime name (for example `imported_orchestrator`).
    # Reconcile only globally unambiguous aliases so the normalized topology does
    # not contain both the stale alias and the resolved runtime target.
    alias_targets: dict[str, set[str]] = {}
    for agent in graph.agents:
        source_alias = agent.metadata.get("source_alias")
        if (
            isinstance(source_alias, str)
            and source_alias
            and source_alias != agent.name
        ):
            alias_targets.setdefault(source_alias, set()).add(agent.name)

    unambiguous_aliases = {
        alias: next(iter(targets))
        for alias, targets in alias_targets.items()
        if len(targets) == 1
    }
    if unambiguous_aliases:
        for agent in graph.agents:
            delegates = agent.metadata.get("delegates_to")
            if not isinstance(delegates, list):
                continue
            normalized: list[str] = []
            for target in delegates:
                target_name = str(target)
                target_name = unambiguous_aliases.get(target_name, target_name)
                if target_name not in normalized:
                    normalized.append(target_name)
            if normalized:
                agent.metadata["delegates_to"] = normalized
            else:
                agent.metadata.pop("delegates_to", None)

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
