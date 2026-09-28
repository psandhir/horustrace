from __future__ import annotations

import ast
import json
import tempfile
import tomllib
from copy import deepcopy
from pathlib import Path

import yaml

from horustrace.adapters.adk_config import scan_adk_config, scan_adk_env
from horustrace.adapters.fast_agent_config import (
    FAST_AGENT_CONFIG_FILENAMES,
    scan_fast_agent_config,
)
from horustrace.adapters.iac_identity import scan_terraform
from horustrace.adapters.manifest import MANIFEST_FILENAMES, scan_manifest
from horustrace.adapters.mcp_config import MCP_FILENAMES, scan_mcp_config
from horustrace.adapters.registry import detect_python_frameworks, scan_python_file
from horustrace.adapters.repository_adk import enrich_repository_graph
from horustrace.adg import build_adg
from horustrace.analysis import build_attack_paths
from horustrace.authority_source import (
    AuthoritySourceError,
    enrich_from_terraform_authority_source,
)
from horustrace.config import ScanConfig
from horustrace.config import apply as apply_config
from horustrace.coverage import add_diagnostic, diagnose_dynamic_constructs, diagnose_python
from horustrace.entrypoint_provenance import annotate_flow_entrypoints
from horustrace.flow import analyze_repository_flows
from horustrace.heuristics import PRIVILEGED_CAPABILITIES
from horustrace.limits import (
    MAX_FILE_SIZE_BYTES,
    MAX_FILES_VISITED,
    MAX_NOTEBOOK_FILE_SIZE_BYTES,
    MAX_REPOSITORY_ENTRIES_VISITED,
    ScanLimitError,
    validate_json_safety,
    validate_yaml_safety,
)
from horustrace.mcp_authority import reconstruct_mcp_authority
from horustrace.mcp_context import (
    reconstruct_mcp_context,
    resolve_fast_agent_mcp_references,
    resolve_imported_mcp_placeholders,
    resolve_local_stdio_implementations,
)
from horustrace.mcp_resolution import unresolved_mcp_summary
from horustrace.models import (
    Agent,
    AgentReachability,
    EvidenceFact,
    FlowExecutionContext,
    FlowPath,
    Graph,
    Identity,
    InputSource,
    NetworkDestination,
    ResourceScope,
    ScanDiagnostic,
    SourceLocation,
    Tool,
)
from horustrace.path_safety import canonical_root, is_within_root
from horustrace.provenance import annotate, attach_findings, context
from horustrace.registry_config import (
    enrich_config_registry_agents,
    is_registry_config_filename,
)
from horustrace.rules.builtin import evaluate
from horustrace.semantics import annotate_risk_semantics
from horustrace.source_context import classify_source_context, path_parts_match
from horustrace.source_provenance import annotate_tool_source_provenance
from horustrace.suppressions import SUPPRESSION_FILENAMES, SuppressionError
from horustrace.suppressions import apply as apply_suppressions


class ScannerError(ValueError):
    """A scan could not continue safely."""

DEFAULT_IGNORES = {
    ".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__",
}
IGNORE_MARKERS = {".horustrace-ignore"}
SOURCE_FRAGMENT_DIRS = {"snippets", "snippets_py", "code_snippets"}

_FLOW_CLI_DIRS = {"cli", "command", "commands"}
_FLOW_SUPPORT_DIRS = {
    "ci",
    "cicd",
    "deploy",
    "deployment",
    "infra",
    "infrastructure",
    "migration",
    "migrations",
    "script",
    "scripts",
    "setup",
}
_NON_AGENT_FLOW_CONTEXTS = {
    FlowExecutionContext.CLI,
    FlowExecutionContext.TEST,
    FlowExecutionContext.EXAMPLE,
    FlowExecutionContext.TUTORIAL,
    FlowExecutionContext.NOTEBOOK,
    FlowExecutionContext.TEMPLATE_GENERATED,
    FlowExecutionContext.APPLICATION_SUPPORT,
}


def _flow_function_paths(flow: FlowPath, root: Path) -> list[Path]:
    paths: list[Path] = []
    for step in flow.steps:
        if step.kind != "function" or step.location is None:
            continue
        path = step.location.path
        try:
            path = path.resolve().relative_to(root.resolve())
        except ValueError:
            pass
        paths.append(path)
    return paths


def _module_name_for_path(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _is_main_guard(node: ast.If) -> bool:
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    left, right = test.left, test.comparators[0]

    def _name(value: ast.AST) -> bool:
        return isinstance(value, ast.Name) and value.id == "__name__"

    def _main(value: ast.AST) -> bool:
        return isinstance(value, ast.Constant) and value.value == "__main__"

    return (_name(left) and _main(right)) or (_main(left) and _name(right))


def _collect_main_guard_entrypoints(root: Path, python_paths: list[Path]) -> set[str]:
    entrypoints: set[str] = set()
    for path in python_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        local_functions = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if not local_functions:
            continue
        module = _module_name_for_path(path, root)
        for node in tree.body:
            if not isinstance(node, ast.If) or not _is_main_guard(node):
                continue
            for descendant in ast.walk(node):
                if (
                    isinstance(descendant, ast.Call)
                    and isinstance(descendant.func, ast.Name)
                    and descendant.func.id in local_functions
                ):
                    name = descendant.func.id
                    entrypoints.add(f"{module}.{name}" if module else name)
    return entrypoints


def _collect_project_script_entrypoints(
    root: Path,
    candidates: list[Path],
) -> set[tuple[str, str]]:
    entrypoints: set[tuple[str, str]] = set()
    for path in candidates:
        if path.name != "pyproject.toml":
            continue
        try:
            if not is_within_root(path, canonical_root(root)):
                continue
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
            document = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            continue
        project = document.get("project")
        if not isinstance(project, dict):
            continue
        for section in ("scripts", "gui-scripts"):
            scripts = project.get(section)
            if not isinstance(scripts, dict):
                continue
            for target in scripts.values():
                if not isinstance(target, str) or ":" not in target:
                    continue
                module, function = (part.strip() for part in target.split(":", 1))
                function = function.split()[0]
                if (
                    module
                    and function
                    and all(part.isidentifier() for part in module.split("."))
                    and function.isidentifier()
                ):
                    entrypoints.add((module, function))
    return entrypoints


def _matches_project_script_entrypoint(
    function_key: str,
    entrypoints: set[tuple[str, str]],
) -> bool:
    for module, function in entrypoints:
        exact = f"{module}.{function}"
        if function_key == exact or function_key.endswith(f".{exact}"):
            return True
        # A package-level script target may lazily re-export a CLI-named function
        # from a submodule. Keep this fallback deliberately narrow to avoid treating
        # generic main functions anywhere in the package as proven CLI entrypoints.
        if (
            "." not in module
            and "cli" in function.lower()
            and function_key.endswith(f".{function}")
            and f".{module}." in f".{function_key}"
        ):
            return True
    return False


def _looks_like_test_path(path: Path) -> bool:
    name = path.name.lower()
    return (
        classify_source_context(path) == "test"
        or name in {"smoketest.py", "smoke_test.py", "integration_test.py"}
        or name.endswith("_test.py")
    )


def _classify_flow_execution_context(
    flow: FlowPath,
    root: Path,
    main_guard_entrypoints: set[str],
    project_script_entrypoints: set[tuple[str, str]],
) -> FlowExecutionContext:
    if flow.agent is not None:
        return FlowExecutionContext.AGENT_TOOL

    paths = _flow_function_paths(flow, root)
    if not paths:
        return FlowExecutionContext.UNKNOWN

    if any(_looks_like_test_path(path) for path in paths):
        return FlowExecutionContext.TEST

    source_contexts = {classify_source_context(path) for path in paths}
    source_mapping = {
        "example": FlowExecutionContext.EXAMPLE,
        "tutorial": FlowExecutionContext.TUTORIAL,
        "notebook": FlowExecutionContext.NOTEBOOK,
        "template-generated": FlowExecutionContext.TEMPLATE_GENERATED,
    }
    for source_context, execution_context in source_mapping.items():
        if source_context in source_contexts:
            return execution_context

    call_chain = flow.metadata.get("call_chain")
    if isinstance(call_chain, list):
        for function_key in call_chain:
            if not isinstance(function_key, str):
                continue
            if function_key in main_guard_entrypoints:
                flow.metadata["execution_context_basis"] = "python_main_guard"
                return FlowExecutionContext.CLI
            if _matches_project_script_entrypoint(
                function_key,
                project_script_entrypoints,
            ):
                flow.metadata["execution_context_basis"] = "project_script_entrypoint"
                return FlowExecutionContext.CLI

    for path in paths:
        lowered_parts = {part.lower() for part in path.parts}
        name = path.name.lower()
        if (
            path_parts_match(lowered_parts, _FLOW_CLI_DIRS)
            or name == "__main__.py"
            or name == "cli.py"
            or name.endswith("_cli.py")
        ):
            return FlowExecutionContext.CLI

    for path in paths:
        lowered_parts = {part.lower() for part in path.parts}
        if path_parts_match(lowered_parts, _FLOW_SUPPORT_DIRS):
            return FlowExecutionContext.APPLICATION_SUPPORT

    return FlowExecutionContext.RUNTIME


def _classify_flow_agent_reachability(
    flow: FlowPath,
    graph: Graph,
) -> AgentReachability:
    if flow.agent is not None:
        binding = flow.metadata.get("agent_binding")
        basis = binding.get("basis") if isinstance(binding, dict) else None
        flow.metadata["agent_reachability_basis"] = (
            basis or "explicit_agent_binding"
        )
        return AgentReachability.PROVEN_AGENT_REACHABLE

    binding = flow.metadata.get("agent_binding")
    if isinstance(binding, dict) and str(binding.get("basis", "")).startswith(
        "ambiguous"
    ):
        flow.metadata["agent_reachability_basis"] = "ambiguous_agent_binding"
        return AgentReachability.UNKNOWN

    if (
        flow.execution_context in _NON_AGENT_FLOW_CONTEXTS
        and binding is None
    ):
        flow.metadata["agent_reachability_basis"] = (
            "non_agent_execution_context_without_tool_binding"
        )
        return AgentReachability.PROVEN_NON_AGENT

    flow.metadata["agent_reachability_basis"] = "no_agent_tool_binding_evidence"
    return AgentReachability.UNKNOWN


def _flow_has_attribution_gap(flow: FlowPath) -> bool:
    if flow.agent is not None:
        return False
    binding = flow.metadata.get("agent_binding")
    return (
        isinstance(binding, dict)
        and str(binding.get("basis", "")).startswith("ambiguous")
    )


def _annotate_flow_semantics(
    graph: Graph,
    root: Path,
    main_guard_entrypoints: set[str],
    project_script_entrypoints: set[tuple[str, str]],
) -> None:
    for flow in graph.flow_paths:
        flow.execution_context = _classify_flow_execution_context(
            flow,
            root,
            main_guard_entrypoints,
            project_script_entrypoints,
        )
        flow.agent_reachability = _classify_flow_agent_reachability(flow, graph)




def _enrich_web_ingress_inputs(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Attach source-proven untrusted web ingress to factory-built agents."""
    agents_by_factory: dict[tuple[str, str], list[Agent]] = {}
    for agent in graph.agents:
        factory = agent.metadata.get("factory_function")
        if not isinstance(factory, str) or not factory or agent.location is None:
            continue
        agents_by_factory.setdefault((agent.location.path.stem, factory), []).append(agent)

    if not agents_by_factory:
        return

    for path in python_paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue

        web_module = False
        imported_factories: dict[str, tuple[str, str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "fastapi" or module.startswith("fastapi."):
                    web_module = True
                module_leaf = module.split(".")[-1] if module else ""
                for alias in node.names:
                    key = (module_leaf, alias.name)
                    if key in agents_by_factory:
                        imported_factories[alias.asname or alias.name] = key
            elif isinstance(node, ast.Import):
                if any(
                    alias.name == "fastapi" or alias.name.startswith("fastapi.")
                    for alias in node.names
                ):
                    web_module = True

        if not web_module or not imported_factories:
            continue

        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = {
                arg.arg
                for arg in (
                    list(fn.args.posonlyargs)
                    + list(fn.args.args)
                    + list(fn.args.kwonlyargs)
                )
            }
            created: dict[str, tuple[str, str]] = {}
            request_params: set[str] = set()
            invoked_vars: set[str] = set()

            for node in ast.walk(fn):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
                    call_name = node.value.func.id if isinstance(node.value.func, ast.Name) else None
                    if call_name in imported_factories:
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for target in targets:
                            if isinstance(target, ast.Name):
                                created[target.id] = imported_factories[call_name]

                if not isinstance(node, ast.Call):
                    continue

                call_leaf = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else None
                )
                if call_leaf == "HumanMessage":
                    content_node = next(
                        (
                            keyword.value
                            for keyword in node.keywords
                            if keyword.arg == "content"
                        ),
                        node.args[0] if node.args else None,
                    )
                    if isinstance(content_node, ast.Name) and content_node.id in params:
                        request_params.add(content_node.id)

                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"invoke", "ainvoke", "stream", "astream"}
                    and isinstance(node.func.value, ast.Name)
                ):
                    invoked_vars.add(node.func.value.id)

            if not request_params:
                continue

            for variable in sorted(invoked_vars & set(created)):
                key = created[variable]
                candidates = agents_by_factory.get(key, [])
                if len(candidates) != 1:
                    continue
                agent = candidates[0]
                existing = {(item.name, item.kind, item.trust) for item in agent.inputs}
                for param in sorted(request_params):
                    input_name = f"{path.stem}.{fn.name}:{param}"
                    signature = (input_name, "web", "untrusted")
                    if signature in existing:
                        continue
                    agent.inputs.append(
                        InputSource(
                            name=input_name,
                            trust="untrusted",
                            kind="web",
                            location=SourceLocation(path, fn.lineno, fn.col_offset + 1),
                            metadata={
                                "basis": "web_factory_message_invoke",
                                "factory_function": key[1],
                                "factory_module": key[0],
                            },
                        )
                    )


def _is_source_fragment(path: Path) -> bool:
    return any(part.lower() in SOURCE_FRAGMENT_DIRS for part in path.parts)


def _is_supported_scan_candidate(path: Path) -> bool:
    return (
        path.suffix.lower() in {".py", ".ipynb", ".tf", ".yaml", ".yml"}
        or path.name
        in (
            MCP_FILENAMES
            | MANIFEST_FILENAMES
            | SUPPRESSION_FILENAMES
            | FAST_AGENT_CONFIG_FILENAMES
        )
        or path.name == ".env"
        or path.name.startswith(".env.")
    )


def _is_repository_candidate(path: Path) -> bool:
    # pyproject.toml is retained for console-script entrypoint provenance even
    # though it is not parsed as a primary security-analysis input.
    return (
        _is_supported_scan_candidate(path)
        or path.name == "pyproject.toml"
        or is_registry_config_filename(path.name)
    )


def _ignored(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if any(part in DEFAULT_IGNORES for part in relative.parts):
        return True
    current = path.parent
    while current != root and root in current.parents:
        if any((current / marker).exists() for marker in IGNORE_MARKERS):
            return True
        current = current.parent
    return False


def _unreadable_path_diagnostic(
    graph: Graph,
    *,
    root: Path,
    path: Path,
    operation: str,
    exc: OSError | RuntimeError,
) -> None:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.name
    graph.coverage.files_failed += 1
    add_diagnostic(
        graph.coverage,
        ScanDiagnostic(
            "unreadable_path",
            "Repository path could not be read; analysis continued with incomplete coverage.",
            SourceLocation(path),
            details={
                "path": relative or ".",
                "operation": operation,
                "exception_type": type(exc).__name__,
            },
        ),
    )


def _repository_candidates(root: Path, graph: Graph) -> list[Path]:
    """Walk a repository without letting irrelevant payload exhaust scan limits."""
    candidates: list[Path] = []
    stack = [root]
    containment_root = canonical_root(root)
    entries_visited = 0

    def add_candidate(candidate: Path) -> None:
        if not _is_repository_candidate(candidate):
            # Preserve historical coverage accounting even though irrelevant
            # payload no longer consumes the analysis-candidate safety budget.
            graph.coverage.files_considered += 1
            graph.coverage.files_skipped += 1
            return
        if len(candidates) >= MAX_FILES_VISITED:
            raise ScannerError(
                f"{root}: repository analysis exceeds the "
                f"{MAX_FILES_VISITED}-candidate safety limit"
            )
        candidates.append(candidate)

    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            _unreadable_path_diagnostic(
                graph,
                root=root,
                path=directory,
                operation="list_directory",
                exc=exc,
            )
            continue

        for candidate in entries:
            entries_visited += 1
            if entries_visited > MAX_REPOSITORY_ENTRIES_VISITED:
                raise ScannerError(
                    f"{root}: repository traversal exceeds the "
                    f"{MAX_REPOSITORY_ENTRIES_VISITED}-entry safety limit"
                )
            try:
                if candidate.is_symlink():
                    target = candidate.resolve(strict=True)
                    if not is_within_root(target, containment_root):
                        graph.coverage.files_skipped += 1
                        add_diagnostic(
                            graph.coverage,
                            ScanDiagnostic(
                                "unsupported_security_construct",
                                "Symlink resolves outside the scan root; analysis was skipped.",
                                SourceLocation(candidate),
                                incomplete=False,
                            ),
                        )
                        continue
                    if target.is_dir():
                        graph.coverage.files_skipped += 1
                        continue
                    if target.is_file() and not _ignored(candidate, root):
                        add_candidate(candidate)
                    continue

                if candidate.is_dir():
                    if not _ignored(candidate, root):
                        stack.append(candidate)
                    continue
                if candidate.is_file() and not _ignored(candidate, root):
                    add_candidate(candidate)
            except (OSError, RuntimeError) as exc:
                _unreadable_path_diagnostic(
                    graph,
                    root=root,
                    path=candidate,
                    operation="inspect_path",
                    exc=exc,
                )
    return candidates


def _merge(target: Graph, source: Graph, path: Path) -> None:
    annotate(source, path)
    # Manifest overlays must not alter another agent sharing the same source tool.
    for agent in source.agents:
        agent.tools = deepcopy(agent.tools)
    target.agents.extend(source.agents)
    target.workflow_nodes.extend(source.workflow_nodes)
    target.unbound_tools.extend(source.unbound_tools)
    target.unbound_mcp_servers.extend(source.unbound_mcp_servers)
    target.identities.extend(source.identities)
    for diagnostic in source.coverage.diagnostics:
        add_diagnostic(target.coverage, diagnostic)


def _merge_tool(existing: Tool, incoming: Tool) -> None:
    existing.provenance.extend(f for f in incoming.provenance if f not in existing.provenance)
    existing.capabilities.update(incoming.capabilities)
    if existing.approval is not False:
        if incoming.approval is False:
            existing.approval = False
        elif incoming.approval is True:
            existing.approval = True
    existing.guardrails = existing.guardrails or incoming.guardrails
    if existing.kind == "generic" and incoming.kind != "generic":
        existing.kind = incoming.kind
        existing.location = incoming.location or existing.location
    if incoming.identity:
        existing.identity = incoming.identity
    existing.resources.extend(r for r in incoming.resources if r not in existing.resources)
    existing.destinations.extend(d for d in incoming.destinations if d not in existing.destinations)
    existing.metadata.update(incoming.metadata)


def _merge_identity(existing: Identity, incoming: Identity) -> None:
    existing.provenance.extend(f for f in incoming.provenance if f not in existing.provenance)
    existing.roles.update(incoming.roles)
    existing.permissions.update(incoming.permissions)
    existing.oauth_scopes.update(incoming.oauth_scopes)
    existing.resource_scope = incoming.resource_scope or existing.resource_scope
    existing.credential_source = incoming.credential_source or existing.credential_source
    existing.metadata.update(incoming.metadata)


def _consolidate_global_identities(graph: Graph) -> None:
    by_key: dict[tuple[str, str], Identity] = {}
    for identity in graph.identities:
        key = (identity.name, identity.provider)
        if key not in by_key:
            by_key[key] = identity
        else:
            _merge_identity(by_key[key], identity)
    graph.identities = list(by_key.values())


def _merge_agent(existing: Agent, incoming: Agent) -> None:
    # Keep a framework source location when policy was discovered first;
    # delegation aliases depend on the actual module/config filename.
    if (
        existing.location
        and existing.location.path.name in MANIFEST_FILENAMES
        and incoming.location
        and incoming.location.path.name not in MANIFEST_FILENAMES
    ):
        existing.location = incoming.location

    tool_by_name = {tool.name: tool for tool in existing.tools}
    for tool in incoming.tools:
        current = tool_by_name.get(tool.name)
        if current is None:
            existing.tools.append(tool)
            tool_by_name[tool.name] = tool
        else:
            _merge_tool(current, tool)

    source_keys = {
        (s.name, s.classification, s.capability, s.selector)
        for s in existing.data_sources
    }
    for source in incoming.data_sources:
        key = (source.name, source.classification, source.capability, source.selector)
        if key not in source_keys:
            existing.data_sources.append(source)
            source_keys.add(key)

    input_keys = {(i.name, i.trust, i.kind) for i in existing.inputs}
    for item in incoming.inputs:
        key = (item.name, item.trust, item.kind)
        if key not in input_keys:
            existing.inputs.append(item)
            input_keys.add(key)

    server_names = {server.name for server in existing.mcp_servers}
    for server in incoming.mcp_servers:
        if server.name not in server_names:
            existing.mcp_servers.append(server)
            server_names.add(server.name)

    identity_by_name = {identity.name: identity for identity in existing.identities}
    for identity in incoming.identities:
        if identity.name in identity_by_name:
            _merge_identity(identity_by_name[identity.name], identity)
        else:
            existing.identities.append(identity)
            identity_by_name[identity.name] = identity

    existing.network.extend(d for d in incoming.network if d not in existing.network)
    # A manifest policy is authoritative when it declares any constraints.
    p = incoming.policy
    if (
        p.required_capabilities
        or p.denied_capabilities
        or p.allowed_resources
        or p.allowed_destinations
        or p.require_approval_for
        or p.max_privileged_capabilities is not None
    ):
        existing.policy = p
    existing.provenance.extend(
        fact for fact in incoming.provenance if fact not in existing.provenance
    )
    existing.metadata.update(incoming.metadata)


def _consolidate_agents(graph: Graph) -> None:
    """Merge declarations without conflating source-scoped agent instances.

    Repository manifests are logical-name overlays rather than source instances.
    Apply an unscoped manifest declaration to every matching source-scoped agent
    while keeping those source instances distinct.
    """
    by_key: dict[tuple[str, str | None], Agent] = {}
    overlays: list[Agent] = []

    for incoming in graph.agents:
        instance_key = incoming.metadata.get("instance_key")
        is_manifest_overlay = bool(
            not instance_key
            and incoming.location
            and incoming.location.path.name in MANIFEST_FILENAMES
        )
        if is_manifest_overlay:
            overlays.append(incoming)
            continue

        key = (incoming.name, str(instance_key) if instance_key else None)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = incoming
        else:
            _merge_agent(existing, incoming)

    for overlay in overlays:
        matches = [
            existing
            for (name, _instance_key), existing in by_key.items()
            if name == overlay.name
        ]
        if not matches:
            by_key[(overlay.name, None)] = overlay
            continue
        for existing in matches:
            _merge_agent(existing, deepcopy(overlay))

    graph.agents = list(by_key.values())


def _propagate_adk_delegation(graph: Graph) -> None:
    """Propagate child-agent effective authority into delegating ADK parents.

    This turns sub_agents/AgentTool relationships into concrete capabilities so
    Layers 2-5 can reason about privilege reachable through delegation.
    """
    by_name = {agent.name: agent for agent in graph.agents}
    # ADK Agent Config and multi-file Python projects often refer to children by
    # config/module name rather than the child's runtime `name`. Build stable
    # aliases from source locations so privilege still propagates cross-file.
    by_alias: dict[str, Agent] = dict(by_name)
    for agent in graph.agents:
        if agent.location:
            source = agent.location.path
            aliases = {source.stem, source.parent.name}
            aliases.update({f"{a}_agent" for a in list(aliases) if a and a != "."})
            aliases.add(str(source.resolve()))
            for alias in aliases:
                if alias and alias not in by_alias:
                    by_alias[alias] = agent
    # Resolve edges before adding synthetic tools. Traverse original authority
    # for each edge so results are independent of scan order and cycles terminate.
    children: dict[str, list[Agent]] = {}
    for parent in graph.agents:
        children[parent.name] = []
        for target_name in parent.metadata.get("delegates_to") or []:
            target = str(target_name)
            child = by_name.get(target) or by_alias.get(target)
            if child is None:
                base = target.removesuffix("_agent")
                child = by_alias.get(base) or by_alias.get(f"{base}_agent")
            if child is None:
                add_diagnostic(graph.coverage, ScanDiagnostic(
                    "unresolved_delegation", "Delegated agent could not be resolved.", parent.location,
                ))
            if (
                child is not None and child is not parent
                and child.name not in {a.name for a in children[parent.name]}
            ):
                children[parent.name].append(child)

    authority = {
        a.name: (
            set(a.capabilities),
            a.effective_resources,
            a.effective_destinations,
            context(a),
            list(a.tools),
        )
        for a in graph.agents
    }
    for parent in graph.agents:
        for child in children[parent.name]:
            provenance = [EvidenceFact(parent.name, f"delegates_to={child.name}",
                                       "inferred", parent.location)]
            capabilities = {"agent.delegate"}
            resources: list[ResourceScope] = []
            destinations: list[NetworkDestination] = []
            privileged_tools: list[Tool] = []
            outbound_tools: list[Tool] = []
            pending = [child]
            visited = {parent.name}
            while pending:
                reachable = pending.pop()
                if reachable.name in visited:
                    continue
                visited.add(reachable.name)
                caps, scopes, targets, original_facts, original_tools = authority[reachable.name]
                for original_tool in original_tools:
                    if (
                        original_tool.capabilities & PRIVILEGED_CAPABILITIES
                        and original_tool not in privileged_tools
                    ):
                        privileged_tools.append(original_tool)
                    if (
                        {"network.external", "external.write"} & original_tool.capabilities
                        and original_tool not in outbound_tools
                    ):
                        outbound_tools.append(original_tool)
                provenance.extend(f for f in original_facts if f not in provenance)
                capabilities.update(caps)
                if children[reachable.name]:
                    capabilities.add("agent.delegate")
                for resource in scopes:
                    copied = ResourceScope(
                        kind=resource.kind, selector=resource.selector,
                        access=set(resource.access), classification=resource.classification,
                        location=resource.location,
                        metadata={**resource.metadata, "via_agent": reachable.name},
                        provenance=list(resource.provenance),
                    )
                    if copied not in resources:
                        resources.append(copied)
                for destination in targets:
                    copied_destination = NetworkDestination(
                        target=destination.target, direction=destination.direction,
                        restricted=destination.restricted, location=destination.location,
                        metadata={**destination.metadata, "via_agent": reachable.name},
                        provenance=list(destination.provenance),
                    )
                    if copied_destination not in destinations:
                        destinations.append(copied_destination)
                pending.extend(children[reachable.name])
            delegated_approval = (
                True
                if privileged_tools
                and all(tool.approval is True for tool in privileged_tools)
                else None
            )
            managed_outbound = bool(outbound_tools) and all(
                tool.metadata.get("network_scope") == "fixed_managed_service"
                for tool in outbound_tools
            )
            parent.tools.append(Tool(
                name=f"delegate:{child.name}", kind="delegated_agent",
                capabilities=capabilities, approval=delegated_approval,
                guardrails=bool(child.metadata.get("safety_plugin")) or bool(
                    (child.metadata.get("callbacks") or {}).get("before_tool_callback")
                ),
                resources=resources, destinations=destinations, location=parent.location,
                provenance=provenance,
                metadata={
                    "framework": parent.metadata.get("framework", "generic"),
                    "delegate_target": child.name,
                    # Synthetic summary for delegated reachability. The real
                    # authority relationship is DELEGATES_TO, not Agent -> Tool.
                    "authority_binding": "delegation_projection",
                    "authority_binding_basis": "adk_delegates_to",
                    "transitive": True,
                    "approval_inherited": delegated_approval is True,
                    "network_scope": (
                        "fixed_managed_service" if managed_outbound else "inherited"
                    ),
                },
            ))



def _notebook_python_source(raw_text: str) -> tuple[str, list[dict[str, object]]]:
    """Extract parseable Python code cells without executing notebook content."""
    raw = json.loads(raw_text)
    if not isinstance(raw, dict) or not isinstance(raw.get("cells"), list):
        raise TypeError("invalid Jupyter notebook structure")
    chunks: list[str] = []
    skipped: list[dict[str, object]] = []
    non_python_magics = {
        "%%html", "%%bash", "%%javascript", "%%js", "%%shell",
        "%%script", "%%svg", "%%latex",
    }
    shell_prefixes = (
        "pip install ", "pip3 install ", "python -m pip install ",
        "apt install ", "apt-get ", "git clone ", "wget ", "curl ",
    )
    for index, cell in enumerate(raw["cells"]):
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        source = cell.get("source", "")
        if isinstance(source, list):
            source = "".join(str(part) for part in source)
        if not isinstance(source, str):
            continue
        lines = source.splitlines()
        first = next((line.strip() for line in lines if line.strip()), "")
        if any(first.startswith(magic) for magic in non_python_magics):
            skipped.append({
                "cell": index,
                "reason": first.split()[0] if first else "cell_magic",
            })
            continue
        cleaned: list[str] = []
        for line in lines:
            stripped = line.lstrip()
            indent = line[: len(line) - len(stripped)]
            lower = stripped.lower()
            if stripped.startswith(("%", "!")) or lower.startswith(shell_prefixes):
                cleaned.append(f"{indent}pass  # notebook magic/shell command omitted")
            else:
                cleaned.append(line)
        cell_source = "\n".join(cleaned) + "\n"
        try:
            ast.parse(cell_source)
        except SyntaxError as exc:
            skipped.append({
                "cell": index,
                "reason": f"non_python_or_invalid_syntax: {exc.msg}",
                "line": exc.lineno,
            })
            continue
        chunks.append(f"# notebook-cell-{index}\n" + cell_source)
    return "\n".join(chunks) + "\n", skipped


def _looks_templated_source(text: str) -> bool:
    return any(marker in text for marker in ("{%", "{%-", "{#"))

def _remap_source_locations(graph: Graph, old_path: Path, new_path: Path) -> None:
    def remap(location: SourceLocation | None) -> None:
        if location is not None and location.path == old_path:
            location.path = new_path

    def remap_tool(tool: Tool) -> None:
        remap(tool.location)
        for resource in tool.resources:
            remap(resource.location)
        for destination in tool.destinations:
            remap(destination.location)
        for fact in tool.provenance:
            remap(fact.location)

    for agent in graph.agents:
        remap(agent.location)
        for tool in agent.tools:
            remap_tool(tool)
        for server in agent.mcp_servers:
            remap(server.location)
            for fact in server.provenance:
                remap(fact.location)
        for source in agent.data_sources:
            remap(source.location)
            for fact in source.provenance:
                remap(fact.location)
        for source in agent.inputs:
            remap(source.location)
            for fact in source.provenance:
                remap(fact.location)
        for identity in agent.identities:
            remap(identity.location)
            for fact in identity.provenance:
                remap(fact.location)
        for destination in agent.network:
            remap(destination.location)
        for fact in agent.provenance:
            remap(fact.location)
    for tool in graph.unbound_tools:
        remap_tool(tool)
    for server in graph.unbound_mcp_servers:
        remap(server.location)
    for identity in graph.identities:
        remap(identity.location)
    for diagnostic in graph.coverage.diagnostics:
        remap(diagnostic.location)


def _remap_flow_locations(graph: Graph, path_map: dict[Path, Path]) -> None:
    for flow in graph.flow_paths:
        for step in flow.steps:
            if step.location and step.location.path in path_map:
                step.location.path = path_map[step.location.path]
    for diagnostic in graph.coverage.diagnostics:
        if diagnostic.location and diagnostic.location.path in path_map:
            diagnostic.location.path = path_map[diagnostic.location.path]


def _resolve_imported_tool_placeholders(graph: Graph) -> None:
    """Resolve imported tool references against concrete tools found in the repository."""
    concrete: dict[str, list[Tool]] = {}
    for tool in graph.all_tools():
        if not tool.metadata.get("placeholder"):
            concrete.setdefault(tool.name, []).append(tool)

    for agent in graph.agents:
        unresolved: list[str] = []
        for tool in agent.tools:
            if not tool.metadata.get("placeholder"):
                continue
            matches = concrete.get(tool.name, [])
            if len(matches) == 1:
                source = matches[0]
                tool.kind = source.kind
                tool.capabilities = set(source.capabilities)
                tool.approval = source.approval
                tool.guardrails = source.guardrails
                tool.resources = list(source.resources)
                tool.destinations = list(source.destinations)
                tool.identity = source.identity
                binding_metadata = {
                    key: value
                    for key, value in tool.metadata.items()
                    if key
                    in {
                        "authority_binding",
                        "authority_binding_basis",
                        "tool_node",
                        "import_module",
                    }
                }
                tool.metadata = {
                    **source.metadata,
                    **binding_metadata,
                    "repository_resolved": True,
                }
            else:
                unresolved.append(tool.name)
        if unresolved:
            existing = set(agent.metadata.get("unresolved_helpers") or [])
            existing.update(unresolved)
            agent.metadata["unresolved_helpers"] = sorted(existing)
            agent.metadata["external_helper_semantics_unresolved"] = True


def _link_global_identities(graph: Graph) -> None:
    """Enrich agent/tool identity references with matching IaC-discovered identities."""
    by_name = {identity.name: identity for identity in graph.identities}
    for agent in graph.agents:
        existing = {identity.name for identity in agent.identities}
        for identity in agent.identities:
            discovered = by_name.get(identity.name)
            if discovered is not None and discovered.provider in {identity.provider, "generic"}:
                _merge_identity(identity, discovered)
            elif discovered is not None and identity.provider == "generic":
                identity.provider = discovered.provider
                _merge_identity(identity, discovered)
        referenced = {tool.identity for tool in agent.tools if tool.identity}
        referenced.update(server.identity for server in agent.mcp_servers if server.identity)
        for name in referenced:
            if name and name in by_name and name not in existing:
                agent.identities.append(by_name[name])


def scan(
    path: Path,
    suppressions_path: Path | None = None,
    use_default_suppressions: bool = True,
    config: ScanConfig | None = None,
    authority_source: Path | None = None,
) -> tuple[Graph, list]:
    root = path.resolve()
    containment_root = canonical_root(root)
    graph = Graph()

    if root.is_file():
        candidates = [root]
    else:
        candidates = _repository_candidates(root, graph)

    seen_real_paths: set[Path] = set()
    approved_python_paths: list[Path] = []
    framework_evidence: dict[str, list[SourceLocation]] = {}
    notebook_tempdir = tempfile.TemporaryDirectory(prefix="horustrace-notebooks-")
    notebook_path_map: dict[Path, Path] = {}
    for candidate in sorted(candidates):
        graph.coverage.files_considered += 1
        try:
            real_candidate = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            _unreadable_path_diagnostic(
                graph,
                root=root if root.is_dir() else root.parent,
                path=candidate,
                operation="resolve_path",
                exc=exc,
            )
            continue
        if not is_within_root(candidate, containment_root):
            graph.coverage.files_skipped += 1
            add_diagnostic(graph.coverage, ScanDiagnostic(
                "unsupported_security_construct",
                "Path resolves outside the scan root; analysis was skipped.",
                SourceLocation(candidate),
            ))
            continue
        if real_candidate in seen_real_paths:
            graph.coverage.files_skipped += 1
            continue
        supported = _is_supported_scan_candidate(candidate)
        if not supported:
            graph.coverage.files_skipped += 1
            continue
        security_config = candidate.name in (
            MANIFEST_FILENAMES
            | MCP_FILENAMES
            | SUPPRESSION_FILENAMES
            | FAST_AGENT_CONFIG_FILENAMES
        )
        seen_real_paths.add(real_candidate)
        try:
            size_limit = (
                MAX_NOTEBOOK_FILE_SIZE_BYTES
                if candidate.suffix.lower() == ".ipynb"
                else MAX_FILE_SIZE_BYTES
            )
            if candidate.stat().st_size > size_limit:
                raise ScanLimitError("file exceeds the configured size limit")
            text = candidate.read_text(encoding="utf-8")
            if candidate.suffix == ".py" and _looks_templated_source(text):
                graph.coverage.files_skipped += 1
                add_diagnostic(
                    graph.coverage,
                    ScanDiagnostic(
                        "templated_source",
                        "Templated Python source was not parsed as executable Python.",
                        SourceLocation(candidate),
                        incomplete=False,
                        details={"template_syntax": "jinja"},
                    ),
                )
                continue
            if candidate.name in MCP_FILENAMES:
                validate_json_safety(text)
                raw = json.loads(text)
                if not isinstance(raw, dict):
                    raise ValueError("invalid MCP configuration")
            elif candidate.suffix.lower() in {".yaml", ".yml"}:
                validate_yaml_safety(text)
                yaml.safe_load(text)
            elif candidate.suffix == ".py":
                ast.parse(text)
            elif candidate.suffix.lower() == ".ipynb":
                notebook_source, _ = _notebook_python_source(text)
                ast.parse(notebook_source)
        except (OSError, UnicodeDecodeError, SyntaxError, TypeError, ValueError, yaml.YAMLError) as exc:
            if isinstance(exc, SyntaxError) and candidate.suffix == ".py" and _is_source_fragment(candidate):
                graph.coverage.files_skipped += 1
                add_diagnostic(
                    graph.coverage,
                    ScanDiagnostic(
                        "source_fragment",
                        "Non-executable Python source fragment was not parsed as a module.",
                        SourceLocation(candidate, line=getattr(exc, "lineno", 1) or 1),
                        incomplete=False,
                        details={
                            "exception_type": type(exc).__name__,
                            "reason": str(exc),
                        },
                    ),
                )
                continue
            if candidate.name in MANIFEST_FILENAMES and not isinstance(exc, ScanLimitError):
                # Keep the manifest adapter's established fail-closed diagnostics,
                # including its secret-safe YAML and encoding error messages.
                pass
            elif security_config:
                raise ScannerError(f"{candidate}: cannot safely analyze security configuration ({exc})") from exc
            else:
                graph.coverage.files_failed += 1
                diagnostic_kind = (
                    "unsupported_security_construct"
                    if isinstance(exc, ScanLimitError)
                    else "parse_error"
                )
                add_diagnostic(graph.coverage, ScanDiagnostic(
                    diagnostic_kind,
                    (
                        "File exceeded a scanner safety limit; analysis was skipped."
                        if isinstance(exc, ScanLimitError)
                        else f"File could not be parsed; analysis was skipped: {type(exc).__name__}: {exc}"
                    ),
                    SourceLocation(candidate, line=getattr(exc, "lineno", 1) or 1),
                    details={
                        "exception_type": type(exc).__name__,
                        "reason": str(exc),
                        "file_type": candidate.suffix.lower() or candidate.name,
                    },
                ))
                continue
        graph.coverage.files_scanned += 1
        if candidate.name in SUPPRESSION_FILENAMES:
            continue
        if candidate.suffix == ".py":
            approved_python_paths.append(candidate)
            frameworks = detect_python_frameworks(candidate)
            for framework in frameworks:
                framework_evidence.setdefault(framework, []).append(SourceLocation(candidate))
            _merge(graph, scan_python_file(candidate), candidate)
            diagnose_python(candidate, graph)
        elif candidate.suffix.lower() == ".ipynb":
            notebook_source, notebook_skips = _notebook_python_source(text)
            for item in notebook_skips:
                add_diagnostic(
                    graph.coverage,
                    ScanDiagnostic(
                        "notebook_non_python_cell",
                        "Notebook cell was omitted because it is not parseable Python source.",
                        SourceLocation(candidate),
                        incomplete=False,
                        details=item,
                    ),
                )
            temp_path = Path(notebook_tempdir.name) / (
                candidate.name.replace(".ipynb", "") + f"-{len(notebook_path_map)}.py"
            )
            temp_path.write_text(notebook_source, encoding="utf-8")
            notebook_path_map[temp_path] = candidate
            approved_python_paths.append(temp_path)
            frameworks = detect_python_frameworks(temp_path)
            for framework in frameworks:
                framework_evidence.setdefault(framework, []).append(SourceLocation(candidate))
            notebook_graph = scan_python_file(temp_path)
            diagnose_python(temp_path, notebook_graph)
            _remap_source_locations(notebook_graph, temp_path, candidate)
            _merge(graph, notebook_graph, candidate)
        elif candidate.suffix == ".tf":
            _merge(graph, scan_terraform(candidate), candidate)
        elif candidate.name in MCP_FILENAMES:
            _merge(graph, scan_mcp_config(candidate), candidate)
        elif candidate.name in FAST_AGENT_CONFIG_FILENAMES:
            _merge(graph, scan_fast_agent_config(candidate), candidate)
        elif candidate.name in MANIFEST_FILENAMES:
            _merge(graph, scan_manifest(candidate), candidate)
        elif candidate.suffix.lower() in {".yaml", ".yml"}:
            _merge(graph, scan_adk_config(candidate), candidate)
        elif candidate.name == ".env" or candidate.name.startswith(".env."):
            _merge(graph, scan_adk_env(candidate), candidate)

    _consolidate_global_identities(graph)
    _consolidate_agents(graph)
    enrich_repository_graph(
        graph,
        root if root.is_dir() else root.parent,
        python_paths=approved_python_paths,
    )
    _consolidate_agents(graph)
    _propagate_adk_delegation(graph)
    resolve_imported_mcp_placeholders(
        graph,
        root if root.is_dir() else root.parent,
    )
    resolve_fast_agent_mcp_references(graph)
    resolve_local_stdio_implementations(
        graph,
        root if root.is_dir() else root.parent,
    )
    reconstruct_mcp_authority(graph, approved_python_paths)
    reconstruct_mcp_context(graph)
    authority_enrichment = None
    if authority_source is not None:
        try:
            authority_enrichment = enrich_from_terraform_authority_source(
                graph,
                authority_source,
            )
        except AuthoritySourceError as exc:
            raise ScannerError(str(exc)) from exc
    _link_global_identities(graph)
    _resolve_imported_tool_placeholders(graph)
    enrich_config_registry_agents(
        graph,
        root if root.is_dir() else root.parent,
        python_paths=approved_python_paths,
        config_paths=[
            candidate
            for candidate in candidates
            if is_registry_config_filename(candidate.name)
        ],
    )
    _consolidate_agents(graph)
    annotate_tool_source_provenance(
        graph,
        root if root.is_dir() else root.parent,
        approved_python_paths,
    )
    diagnose_dynamic_constructs(graph)
    for agent in graph.agents:
        if agent.metadata.get("dynamic_control_flow"):
            add_diagnostic(
                graph.coverage,
                ScanDiagnostic(
                    "unresolved_handoff",
                    "Dynamic graph/handoff control flow could not be fully resolved.",
                    agent.location,
                ),
            )
    normalized_frameworks = {
        str(agent.metadata.get("framework"))
        for agent in graph.agents
        if agent.metadata.get("framework")
    }
    for framework in ("google-adk", "langgraph", "openai-agents", "fast-agent"):
        if framework in framework_evidence and framework not in normalized_frameworks:
            location = framework_evidence[framework][0]
            add_diagnostic(
                graph.coverage,
                ScanDiagnostic(
                    "framework_not_normalized",
                    f"Detected {framework} source constructs but no agent could be normalized.",
                    location,
                    details={
                        "framework": framework,
                        "evidence_files": len(framework_evidence[framework]),
                    },
                ),
            )

    if not (graph.agents or graph.all_tools() or graph.all_mcp_servers() or graph.identities):
        add_diagnostic(graph.coverage, ScanDiagnostic(
            "no_targets", "No supported agent, tool, MCP server, or identity was discovered.",
        ))
    unresolved_tools = sum(
        diagnostic.kind == "unresolved_tool"
        for diagnostic in graph.coverage.diagnostics
    )
    resolved_tools = len(graph.all_tools()) + len(graph.all_mcp_servers())
    unresolved_delegations = sum(
        diagnostic.kind == "unresolved_delegation"
        for diagnostic in graph.coverage.diagnostics
    )
    resolved_delegations = sum(
        tool.kind == "delegated_agent"
        for tool in graph.all_tools()
    )
    analysis_root = root if root.is_dir() else root.parent
    _enrich_web_ingress_inputs(graph, analysis_root, approved_python_paths)
    graph.flow_paths = analyze_repository_flows(analysis_root, approved_python_paths, graph)
    _remap_flow_locations(graph, notebook_path_map)
    main_guard_entrypoints = _collect_main_guard_entrypoints(
        analysis_root,
        approved_python_paths,
    )
    project_script_entrypoints = _collect_project_script_entrypoints(
        analysis_root,
        candidates,
    )
    _annotate_flow_semantics(
        graph,
        analysis_root,
        main_guard_entrypoints,
        project_script_entrypoints,
    )
    unknown_flows = [
        flow
        for flow in graph.flow_paths
        if flow.agent_reachability is AgentReachability.UNKNOWN
    ]
    if unknown_flows:
        annotate_flow_entrypoints(
            analysis_root,
            approved_python_paths,
            unknown_flows,
        )
    notebook_tempdir.cleanup()

    flow_execution_contexts = {
        context.value: sum(
            flow.execution_context == context for flow in graph.flow_paths
        )
        for context in FlowExecutionContext
    }
    flow_agent_reachability = {
        reachability.value: sum(
            flow.agent_reachability == reachability for flow in graph.flow_paths
        )
        for reachability in AgentReachability
    }

    mcp_unresolved = unresolved_mcp_summary(graph)["summary"]

    graph.coverage.resolution = {
        "tools": {
            "resolved_entities": resolved_tools,
            "unresolved_references": unresolved_tools,
            "ratio": (
                resolved_tools / (resolved_tools + unresolved_tools)
                if resolved_tools + unresolved_tools
                else 1.0
            ),
        },
        "delegations": {
            "resolved": resolved_delegations,
            "unresolved": unresolved_delegations,
            "ratio": (
                resolved_delegations / (resolved_delegations + unresolved_delegations)
                if resolved_delegations + unresolved_delegations
                else 1.0
            ),
        },
        "identities": {"discovered": len(graph.all_identities())},
        "external_helpers_unresolved": sum(
            diagnostic.kind == "external_helper_semantics_unresolved"
            for diagnostic in graph.coverage.diagnostics
        ),
        "flows": {
            "supported_paths": len(graph.flow_paths),
            "agent_mapped": sum(flow.agent is not None for flow in graph.flow_paths),
            "agent_attribution_gaps": sum(
                _flow_has_attribution_gap(flow) for flow in graph.flow_paths
            ),
            "execution_contexts": flow_execution_contexts,
            "agent_reachability": flow_agent_reachability,
            "unknown_reachability_by_basis": {
                basis: sum(
                    flow.agent_reachability == AgentReachability.UNKNOWN
                    and flow.metadata.get("agent_reachability_basis") == basis
                    for flow in graph.flow_paths
                )
                for basis in sorted(
                    {
                        str(flow.metadata.get("agent_reachability_basis"))
                        for flow in graph.flow_paths
                        if flow.agent_reachability == AgentReachability.UNKNOWN
                    }
                )
            },
        },
        "mcp": {
            "bound": sum(len(agent.mcp_servers) for agent in graph.agents),
            "unbound": len(graph.unbound_mcp_servers),
            "unresolved_references": mcp_unresolved["unresolved_references"],
            "unresolved_agent_references": mcp_unresolved["agent_references"],
            "unbound_by_reason": mcp_unresolved[
                "declaration_by_reason"
            ],
            "unresolved_by_reason": mcp_unresolved["by_reason"],
            "unresolved_by_resolution_class": mcp_unresolved[
                "by_resolution_class"
            ],
        },
    }
    if authority_enrichment is not None:
        graph.coverage.resolution["authority_source"] = authority_enrichment.as_dict()

    annotate_risk_semantics(graph)
    graph.attack_paths = build_attack_paths(graph)
    graph.adg = build_adg(graph, analysis_root)
    findings = evaluate(graph)
    for finding in findings:
        finding.source_context = classify_source_context(
            finding.location.path if finding.location else None
        )
    attach_findings(graph, findings)
    findings, disabled_rules = apply_config(config or ScanConfig(), findings)
    graph.configuration_audit = {"disabled_rules": disabled_rules}
    suppression_file = suppressions_path
    if suppression_file is None and use_default_suppressions:
        base = root if root.is_dir() else root.parent
        defaults = [base / name for name in sorted(SUPPRESSION_FILENAMES)
                    if (base / name).exists()]
        if len(defaults) > 1:
            raise SuppressionError(f"{base}: multiple default suppression files found")
        suppression_file = defaults[0] if defaults else None
    elif suppression_file is not None and not suppression_file.exists():
        raise SuppressionError(f"{suppression_file}: suppression file does not exist")
    if suppression_file is not None and not is_within_root(suppression_file, containment_root):
        raise ScannerError(f"{suppression_file}: suppression file resolves outside the scan root")
    findings, graph.suppressed_findings, graph.suppression_diagnostics = apply_suppressions(
        findings, root if root.is_dir() else root.parent, suppression_file,
    )
    return graph, findings
