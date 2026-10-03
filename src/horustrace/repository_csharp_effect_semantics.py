from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from horustrace.adapters.csharp_source import balanced_end, mask_non_code, statement_end
from horustrace.models import Graph, NetworkDestination, SourceLocation, Tool


FRAMEWORK = "microsoft-agent-framework-dotnet"

_CLASS_RE = re.compile(
    r"\b(?:class|struct|record(?:\s+(?:class|struct))?)\s+"
    r"(?P<name>[A-Za-z_]\w*)\b[^;{}]*\{",
    re.MULTILINE,
)
_METHOD_RE = re.compile(
    r"""
    (?:
        (?:public|private|protected|internal|static|async|virtual|override|
           sealed|partial|unsafe|extern|new)\s+
    )*
    (?:[\w.<>,?\[\]]+\s+)+
    (?P<name>[A-Za-z_]\w*)\s*\(
    """,
    re.VERBOSE,
)
_CALL_RE = re.compile(
    r"\b(?:(?P<qualifier>[A-Za-z_]\w*)\s*\.)?"
    r"(?P<name>[A-Za-z_]\w*)\s*\("
)
_URL_RE = re.compile(r"https?://[^\s\"')};]+")
_BASE_ADDRESS_RE = re.compile(
    r"\bBaseAddress\s*=\s*new\s+(?:Uri\s*)?\(\s*@?\"([^\"]+)\"",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class _ClassSpan:
    name: str
    start: int
    end: int
    fixed_urls: tuple[str, ...]


@dataclass(frozen=True)
class _MethodInfo:
    path: Path
    class_name: str | None
    name: str
    body: str
    offset: int
    fixed_class_urls: tuple[str, ...] = ()


@dataclass
class _Effect:
    capabilities: set[str] = field(default_factory=set)
    destinations: list[NetworkDestination] = field(default_factory=list)
    evidence: set[str] = field(default_factory=set)


def _body_capabilities(body: str) -> set[str]:
    value = body.lower()
    capabilities: set[str] = set()
    if any(
        marker in value
        for marker in (
            "process.start",
            "processstartinfo",
            "powershell.create",
            "system.management.automation",
            "shell.execute",
        )
    ):
        capabilities.add("process.execute")
    if any(
        marker in value
        for marker in (
            "httpclient",
            ".getasync(",
            ".postasync(",
            ".putasync(",
            ".patchasync(",
            ".sendasync(",
            "webrequest",
            "restclient",
        )
    ):
        capabilities.add("network.external")
    if any(
        marker in value
        for marker in (
            ".postasync(",
            ".putasync(",
            ".patchasync(",
            "sendmail",
            "sendemail",
            "sendmessage",
        )
    ):
        capabilities.update({"external.write", "data.write"})
    if any(
        marker in value
        for marker in (
            "file.write",
            "file.append",
            "file.create",
            "directory.create",
            "savechanges",
            "executenonquery",
            ".insert(",
            ".update(",
            ".upsert(",
        )
    ):
        capabilities.add("data.write")
    if any(
        marker in value
        for marker in (
            "file.delete",
            "directory.delete",
            ".deleteasync(",
            ".remove(",
            ".drop(",
        )
    ):
        capabilities.update({"data.write", "destructive.write"})
    if any(
        marker in value
        for marker in (
            "file.read",
            "file.openread",
            ".getasync(",
            ".query",
            ".tolistasync(",
            ".findasync(",
        )
    ):
        capabilities.add("data.read")
    if any(
        marker in value
        for marker in (
            "secretclient",
            "getsecret",
            "keyvault",
            "tokencredential",
        )
    ):
        capabilities.add("secrets.read")
    return capabilities


def _location(path: Path, source: str, offset: int) -> SourceLocation:
    line = source.count("\n", 0, max(offset, 0)) + 1
    line_start = source.rfind("\n", 0, max(offset, 0))
    column = max(offset, 0) - line_start
    return SourceLocation(path=path, line=line, column=column)


def _class_spans(source: str, masked: str) -> list[_ClassSpan]:
    spans: list[_ClassSpan] = []
    for match in _CLASS_RE.finditer(masked):
        brace = masked.find("{", match.start(), match.end())
        if brace < 0:
            continue
        end = balanced_end(masked, brace, "{", "}")
        if end is None:
            continue
        class_source = source[brace + 1:end]
        urls = tuple(
            dict.fromkeys(
                item.rstrip(",;")
                for item in _BASE_ADDRESS_RE.findall(class_source)
            )
        )
        spans.append(
            _ClassSpan(
                name=match.group("name"),
                start=match.start(),
                end=end + 1,
                fixed_urls=urls,
            )
        )
    return spans


def _containing_class(
    offset: int,
    spans: list[_ClassSpan],
) -> _ClassSpan | None:
    candidates = [
        span for span in spans
        if span.start <= offset < span.end
    ]
    return min(candidates, key=lambda span: span.end - span.start) if candidates else None


def _methods_in_file(path: Path) -> list[_MethodInfo]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    masked = mask_non_code(source)
    classes = _class_spans(source, masked)
    methods: list[_MethodInfo] = []

    for match in _METHOD_RE.finditer(masked):
        params = masked.find("(", match.start(), match.end() + 1)
        if params < 0:
            continue
        params_end = balanced_end(masked, params, "(", ")")
        if params_end is None:
            continue
        cursor = params_end + 1
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1

        body: str | None = None
        if masked.startswith("=>", cursor):
            end = statement_end(masked, cursor + 2)
            body = source[cursor + 2:end]
        elif cursor < len(masked) and masked[cursor] == "{":
            end = balanced_end(masked, cursor, "{", "}")
            if end is not None:
                body = source[cursor + 1:end]
        if body is None:
            continue

        owner = _containing_class(match.start(), classes)
        methods.append(
            _MethodInfo(
                path=path,
                class_name=owner.name if owner else None,
                name=match.group("name"),
                body=body,
                offset=match.start(),
                fixed_class_urls=owner.fixed_urls if owner else (),
            )
        )
    return methods


def _destination(
    method: _MethodInfo,
    target: str,
    *,
    source_kind: str,
) -> NetworkDestination:
    return NetworkDestination(
        target=target.rstrip(",;"),
        restricted=True,
        location=_location(method.path, method.body, 0),
        metadata={
            "source": source_kind,
            "network_scope": "fixed_literal_destination",
            "repository_effect_summary": True,
            "language": "csharp",
        },
    )


def _merge_effect(target: _Effect, incoming: _Effect) -> None:
    target.capabilities.update(incoming.capabilities)
    target.evidence.update(incoming.evidence)
    seen = {
        (
            destination.target,
            destination.restricted,
            str(destination.metadata.get("source") or ""),
        )
        for destination in target.destinations
    }
    for destination in incoming.destinations:
        key = (
            destination.target,
            destination.restricted,
            str(destination.metadata.get("source") or ""),
        )
        if key not in seen:
            target.destinations.append(destination)
            seen.add(key)


def _method_key(method: _MethodInfo) -> tuple[str, str | None, str, int]:
    return (
        str(method.path.resolve()),
        method.class_name,
        method.name,
        method.offset,
    )


def _candidate_callees(
    method: _MethodInfo,
    *,
    by_class: dict[tuple[str, str], list[_MethodInfo]],
    by_name: dict[str, list[_MethodInfo]],
) -> list[_MethodInfo]:
    masked = mask_non_code(method.body)
    result: list[_MethodInfo] = []
    seen: set[tuple[str, str | None, str, int]] = set()

    for match in _CALL_RE.finditer(masked):
        name = match.group("name")
        qualifier = match.group("qualifier")
        candidates: list[_MethodInfo] = []

        if qualifier:
            candidates = by_class.get((qualifier, name), [])
        elif method.class_name and (method.class_name, name) in by_class:
            candidates = by_class[(method.class_name, name)]
        else:
            named = by_name.get(name, [])
            groups = {
                (
                    str(item.path.resolve()),
                    item.class_name,
                )
                for item in named
            }
            if len(groups) == 1:
                candidates = named

        for candidate in candidates:
            key = _method_key(candidate)
            if key == _method_key(method) or key in seen:
                continue
            seen.add(key)
            result.append(candidate)
    return result


def _summarize_method(
    method: _MethodInfo,
    *,
    by_class: dict[tuple[str, str], list[_MethodInfo]],
    by_name: dict[str, list[_MethodInfo]],
    cache: dict[tuple[str, str | None, str, int], _Effect],
    stack: set[tuple[str, str | None, str, int]],
) -> _Effect:
    key = _method_key(method)
    if key in cache:
        return cache[key]
    if key in stack:
        return _Effect()

    stack = set(stack)
    stack.add(key)
    effect = _Effect(capabilities=_body_capabilities(method.body))
    effect.evidence.add(
        f"{method.path}:{method.name}"
    )

    for url in sorted(set(_URL_RE.findall(method.body))):
        effect.destinations.append(
            _destination(method, url, source_kind="csharp_method_literal_url")
        )

    if "network.external" in effect.capabilities:
        for url in method.fixed_class_urls:
            effect.destinations.append(
                _destination(method, url, source_kind="csharp_class_base_address")
            )

    for callee in _candidate_callees(
        method,
        by_class=by_class,
        by_name=by_name,
    ):
        _merge_effect(
            effect,
            _summarize_method(
                callee,
                by_class=by_class,
                by_name=by_name,
                cache=cache,
                stack=stack,
            ),
        )

    deduped = _Effect(
        capabilities=set(effect.capabilities),
        evidence=set(effect.evidence),
    )
    _merge_effect(deduped, effect)
    cache[key] = deduped
    return deduped


def _resolve_tool_methods(
    tool: Tool,
    *,
    by_class: dict[tuple[str, str], list[_MethodInfo]],
    by_name: dict[str, list[_MethodInfo]],
) -> list[_MethodInfo]:
    wrapped = tool.metadata.get("wrapped")
    if not isinstance(wrapped, str) or not wrapped:
        return []
    parts = wrapped.rsplit(".", 1)

    if len(parts) == 2:
        class_name, method_name = parts
        return list(by_class.get((class_name, method_name), []))

    method_name = parts[0]
    named = list(by_name.get(method_name, []))
    if not named:
        return []

    if tool.location is not None:
        same_file = [
            item
            for item in named
            if item.path.resolve() == tool.location.path.resolve()
        ]
        if same_file:
            return same_file

    groups = {
        (str(item.path.resolve()), item.class_name)
        for item in named
    }
    return named if len(groups) == 1 else []


def enrich_csharp_repository_tool_effects(
    graph: Graph,
    root: Path,
    csharp_paths: list[Path],
) -> None:
    """Resolve source-visible effects for .NET MAF function tools across files.

    The resolver is intentionally narrow: it only enriches tools already proven
    to be Microsoft Agent Framework function bindings. Qualified class methods
    are resolved directly; unqualified cross-file methods are used only when
    the repository has a unique source owner.
    """
    del root  # Reserved for future namespace/project-aware resolution.

    methods: list[_MethodInfo] = []
    for path in csharp_paths:
        methods.extend(_methods_in_file(path))
    if not methods:
        return

    by_class: dict[tuple[str, str], list[_MethodInfo]] = {}
    by_name: dict[str, list[_MethodInfo]] = {}
    for method in methods:
        by_name.setdefault(method.name, []).append(method)
        if method.class_name:
            by_class.setdefault(
                (method.class_name, method.name),
                [],
            ).append(method)

    cache: dict[tuple[str, str | None, str, int], _Effect] = {}

    for agent in graph.agents:
        for tool in agent.tools:
            if (
                tool.kind != "function"
                or tool.metadata.get("framework") != FRAMEWORK
            ):
                continue

            resolved = _resolve_tool_methods(
                tool,
                by_class=by_class,
                by_name=by_name,
            )
            if not resolved:
                continue

            effect = _Effect()
            for method in resolved:
                _merge_effect(
                    effect,
                    _summarize_method(
                        method,
                        by_class=by_class,
                        by_name=by_name,
                        cache=cache,
                        stack=set(),
                    ),
                )

            if not effect.capabilities and not effect.destinations:
                continue

            before = set(tool.capabilities)
            tool.capabilities.update(effect.capabilities)

            seen = {
                (
                    destination.target,
                    destination.restricted,
                    str(destination.metadata.get("source") or ""),
                )
                for destination in tool.destinations
            }
            for destination in effect.destinations:
                key = (
                    destination.target,
                    destination.restricted,
                    str(destination.metadata.get("source") or ""),
                )
                if key not in seen:
                    tool.destinations.append(destination)
                    seen.add(key)

            tool.metadata.update(
                {
                    "method_source_resolved": True,
                    "repository_effect_resolved": True,
                    "repository_effect_evidence": sorted(effect.evidence),
                    "repository_effect_capabilities": sorted(
                        effect.capabilities
                    ),
                    "repository_effect_sources": sorted(
                        {
                            str(method.path)
                            for method in resolved
                        }
                    ),
                }
            )
            if tool.capabilities != before:
                tool.metadata["repository_effect_enriched"] = True

            suppressed = tool.metadata.get(
                "name_only_capabilities_suppressed"
            )
            if isinstance(suppressed, list):
                remaining = [
                    item for item in suppressed
                    if item not in tool.capabilities
                ]
                if remaining:
                    tool.metadata[
                        "name_only_capabilities_suppressed"
                    ] = remaining
                else:
                    tool.metadata.pop(
                        "name_only_capabilities_suppressed",
                        None,
                    )
