from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from horustrace.adapters.csharp_source import (
    balanced_end,
    mask_comments,
    mask_non_code,
    statement_end,
)
from horustrace.models import (
    EvidenceFact,
    Graph,
    NetworkDestination,
    SourceLocation,
    Tool,
)

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

_NON_METHOD_NAMES = {
    "catch",
    "do",
    "else",
    "finally",
    "for",
    "foreach",
    "if",
    "lock",
    "switch",
    "using",
    "while",
}


@dataclass(frozen=True)
class _FixedUrl:
    target: str
    offset: int
    source_kind: str


@dataclass(frozen=True)
class _ClassSpan:
    name: str
    start: int
    end: int
    fixed_urls: tuple[_FixedUrl, ...]


@dataclass(frozen=True)
class _MethodInfo:
    path: Path
    class_name: str | None
    name: str
    source: str
    body: str
    body_start: int
    offset: int
    fixed_class_urls: tuple[_FixedUrl, ...] = ()


@dataclass(frozen=True, order=True)
class _EvidenceRef:
    path: Path
    line: int
    column: int
    symbol: str
    kind: str = "csharp_method"


@dataclass
class _Effect:
    capabilities: set[str] = field(default_factory=set)
    destinations: list[NetworkDestination] = field(default_factory=list)
    evidence: set[_EvidenceRef] = field(default_factory=set)
    capability_evidence: dict[str, set[_EvidenceRef]] = field(
        default_factory=dict
    )
    unresolved_calls: set[str] = field(default_factory=set)


def _first_marker_offset(body: str, markers: tuple[str, ...]) -> int | None:
    lowered = body.lower()
    offsets = [
        offset
        for marker in markers
        if (offset := lowered.find(marker)) >= 0
    ]
    return min(offsets) if offsets else None


def _body_capability_offsets(body: str) -> dict[str, int]:
    groups: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
        (
            (
                "process.start",
                "processstartinfo",
                "powershell.create",
                "system.management.automation",
                "shell.execute",
            ),
            ("process.execute",),
        ),
        (
            (
                "httpclient",
                ".getasync(",
                ".postasync(",
                ".putasync(",
                ".patchasync(",
                ".sendasync(",
                "webrequest",
                "restclient",
            ),
            ("network.external",),
        ),
        (
            (
                ".postasync(",
                ".putasync(",
                ".patchasync(",
                "sendmail",
                "sendemail",
                "sendmessage",
            ),
            ("external.write", "data.write"),
        ),
        (
            (
                "file.write",
                "file.append",
                "file.create",
                "directory.create",
                "savechanges",
                "executenonquery",
                ".insert(",
                ".update(",
                ".upsert(",
            ),
            ("data.write",),
        ),
        (
            (
                "file.delete",
                "directory.delete",
                ".deleteasync(",
                ".remove(",
                ".drop(",
            ),
            ("data.write", "destructive.write"),
        ),
        (
            (
                "file.read",
                "file.openread",
                ".getasync(",
                ".query",
                ".tolistasync(",
                ".findasync(",
            ),
            ("data.read",),
        ),
        (
            (
                "secretclient",
                "getsecret",
                "keyvault",
                "tokencredential",
            ),
            ("secrets.read",),
        ),
    )
    result: dict[str, int] = {}
    for markers, capabilities in groups:
        offset = _first_marker_offset(body, markers)
        if offset is None:
            continue
        for capability in capabilities:
            current = result.get(capability)
            if current is None or offset < current:
                result[capability] = offset
    return result


def _body_capabilities(body: str) -> set[str]:
    return set(_body_capability_offsets(body))

def _location(path: Path, source: str, offset: int) -> SourceLocation:
    line = source.count("\n", 0, max(offset, 0)) + 1
    line_start = source.rfind("\n", 0, max(offset, 0))
    column = max(offset, 0) - line_start
    return SourceLocation(path=path, line=line, column=column)


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def _class_spans(source: str, masked: str) -> list[_ClassSpan]:
    spans: list[_ClassSpan] = []
    for match in _CLASS_RE.finditer(masked):
        brace = masked.find("{", match.start(), match.end())
        if brace < 0:
            continue
        end = balanced_end(masked, brace, "{", "}")
        if end is None:
            continue
        class_source = mask_comments(source[brace + 1:end])
        fixed_urls: dict[str, _FixedUrl] = {}
        for url_match in _BASE_ADDRESS_RE.finditer(class_source):
            target = url_match.group(1).rstrip(",;")
            fixed_urls.setdefault(
                target,
                _FixedUrl(
                    target=target,
                    offset=brace + 1 + url_match.start(1),
                    source_kind="csharp_class_base_address",
                ),
            )
        spans.append(
            _ClassSpan(
                name=match.group("name"),
                start=match.start(),
                end=end + 1,
                fixed_urls=tuple(fixed_urls.values()),
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
        if match.group("name") in _NON_METHOD_NAMES:
            continue
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
        body_start: int | None = None
        if masked.startswith("=>", cursor):
            body_start = cursor + 2
            end = statement_end(masked, body_start)
            body = source[body_start:end]
        elif cursor < len(masked) and masked[cursor] == "{":
            end = balanced_end(masked, cursor, "{", "}")
            if end is not None:
                body_start = cursor + 1
                body = source[body_start:end]
        if body is None or body_start is None:
            continue

        owner = _containing_class(match.start(), classes)
        methods.append(
            _MethodInfo(
                path=path,
                class_name=owner.name if owner else None,
                name=match.group("name"),
                source=source,
                body=body,
                body_start=body_start,
                offset=match.start(),
                fixed_class_urls=owner.fixed_urls if owner else (),
            )
        )
    return methods


def _destination(
    method: _MethodInfo,
    target: str,
    *,
    offset: int,
    source_kind: str,
) -> NetworkDestination:
    return NetworkDestination(
        target=target.rstrip(",;"),
        restricted=True,
        location=_location(method.path, method.source, offset),
        metadata={
            "source": source_kind,
            "network_scope": "fixed_literal_destination",
            "repository_effect_summary": True,
            "language": "csharp",
            "source_symbol": (
                f"{method.class_name}.{method.name}"
                if method.class_name
                else method.name
            ),
        },
    )


def _merge_effect(target: _Effect, incoming: _Effect) -> None:
    target.capabilities.update(incoming.capabilities)
    target.evidence.update(incoming.evidence)
    for capability, refs in incoming.capability_evidence.items():
        target.capability_evidence.setdefault(capability, set()).update(refs)
    target.unresolved_calls.update(incoming.unresolved_calls)
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
) -> tuple[list[_MethodInfo], set[str]]:
    masked = mask_non_code(method.body)
    result: list[_MethodInfo] = []
    unresolved: set[str] = set()
    seen: set[tuple[str, str | None, str, int]] = set()

    for match in _CALL_RE.finditer(masked):
        name = match.group("name")
        qualifier = match.group("qualifier")
        candidates: list[_MethodInfo] = []
        candidate_label = f"{qualifier}.{name}" if qualifier else name

        if qualifier:
            matching = by_class.get((qualifier, name), [])
            if len(matching) == 1:
                candidates = matching
            elif len(matching) > 1:
                unresolved.add(candidate_label)
        elif method.class_name and (method.class_name, name) in by_class:
            matching = by_class[(method.class_name, name)]
            if len(matching) == 1:
                candidates = matching
            elif len(matching) > 1:
                unresolved.add(candidate_label)
        else:
            named = by_name.get(name, [])
            if len(named) == 1:
                candidates = named
            elif len(named) > 1:
                unresolved.add(candidate_label)

        for candidate in candidates:
            key = _method_key(candidate)
            if key == _method_key(method) or key in seen:
                continue
            seen.add(key)
            result.append(candidate)
    return result, unresolved

def _summarize_method(
    method: _MethodInfo,
    *,
    root: Path,
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
    method_location = _location(method.path, method.source, method.offset)
    evidence = _EvidenceRef(
        path=method.path,
        line=method_location.line,
        column=method_location.column,
        symbol=(
            f"{method.class_name}.{method.name}"
            if method.class_name
            else method.name
        ),
    )
    capability_offsets = _body_capability_offsets(
        mask_non_code(method.body)
    )
    method_capabilities = set(capability_offsets)
    effect = _Effect(capabilities=set(method_capabilities))
    effect.evidence.add(evidence)
    for capability, local_offset in capability_offsets.items():
        capability_location = _location(
            method.path,
            method.source,
            method.body_start + local_offset,
        )
        effect.capability_evidence.setdefault(
            capability,
            set(),
        ).add(
            _EvidenceRef(
                path=method.path,
                line=capability_location.line,
                column=capability_location.column,
                symbol=evidence.symbol,
                kind="csharp_effect",
            )
        )

    seen_urls: set[str] = set()
    comment_masked_body = mask_comments(method.body)
    for url_match in _URL_RE.finditer(comment_masked_body):
        url = url_match.group(0).rstrip(",;")
        if url in seen_urls:
            continue
        seen_urls.add(url)
        effect.destinations.append(
            _destination(
                method,
                url,
                offset=method.body_start + url_match.start(),
                source_kind="csharp_method_literal_url",
            )
        )

    if "network.external" in effect.capabilities:
        for fixed_url in method.fixed_class_urls:
            effect.destinations.append(
                _destination(
                    method,
                    fixed_url.target,
                    offset=fixed_url.offset,
                    source_kind=fixed_url.source_kind,
                )
            )

    callees, unresolved_calls = _candidate_callees(
        method,
        by_class=by_class,
        by_name=by_name,
    )
    effect.unresolved_calls.update(unresolved_calls)
    for callee in callees:
        _merge_effect(
            effect,
            _summarize_method(
                callee,
                root=root,
                by_class=by_class,
                by_name=by_name,
                cache=cache,
                stack=stack,
            ),
        )

    deduped = _Effect(
        capabilities=set(effect.capabilities),
        evidence=set(effect.evidence),
        capability_evidence={
            capability: set(refs)
            for capability, refs in effect.capability_evidence.items()
        },
        unresolved_calls=set(effect.unresolved_calls),
    )
    _merge_effect(deduped, effect)
    cache[key] = deduped
    return deduped


def _resolve_tool_methods(
    tool: Tool,
    *,
    by_class: dict[tuple[str, str], list[_MethodInfo]],
    by_name: dict[str, list[_MethodInfo]],
) -> tuple[list[_MethodInfo], str | None]:
    wrapped = tool.metadata.get("wrapped")
    if not isinstance(wrapped, str) or not wrapped:
        return [], None
    parts = wrapped.rsplit(".", 1)

    if len(parts) == 2:
        class_name, method_name = parts
        candidates = list(by_class.get((class_name, method_name), []))
        if len(candidates) == 1:
            return candidates, None
        if len(candidates) > 1:
            return [], "ambiguous_overload"
        return [], None

    method_name = parts[0]
    named = list(by_name.get(method_name, []))
    if not named:
        return [], None

    if tool.location is not None:
        same_file = [
            item
            for item in named
            if item.path.resolve() == tool.location.path.resolve()
        ]
        if len(same_file) == 1:
            return same_file, None
        if len(same_file) > 1:
            return [], "ambiguous_overload"

    groups = {
        (str(item.path.resolve()), item.class_name)
        for item in named
    }
    if len(named) == 1:
        return named, None
    if len(groups) == 1:
        return [], "ambiguous_overload"
    return [], "ambiguous_method_reference"


def _evidence_dict(ref: _EvidenceRef, root: Path) -> dict[str, object]:
    return {
        "path": _display_path(ref.path, root),
        "line": ref.line,
        "column": ref.column,
        "symbol": ref.symbol,
        "kind": ref.kind,
    }


def _append_fact(
    facts: list[EvidenceFact],
    fact: EvidenceFact,
) -> None:
    if fact not in facts:
        facts.append(fact)


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

            resolved, unresolved_reason = _resolve_tool_methods(
                tool,
                by_class=by_class,
                by_name=by_name,
            )
            if not resolved:
                if unresolved_reason:
                    tool.metadata["repository_effect_resolution"] = (
                        unresolved_reason
                    )
                    tool.metadata["repository_effect_resolved"] = False
                continue

            effect = _Effect()
            for method in resolved:
                _merge_effect(
                    effect,
                    _summarize_method(
                        method,
                        root=root,
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

            evidence_details = [
                _evidence_dict(ref, root)
                for ref in sorted(effect.evidence)
            ]
            tool.metadata.update(
                {
                    "method_source_resolved": True,
                    "repository_effect_resolved": True,
                    "repository_effect_resolution": "resolved",
                    "repository_effect_evidence": [
                        f"{item['path']}:{item['symbol']}"
                        for item in evidence_details
                    ],
                    "repository_effect_evidence_details": evidence_details,
                    "repository_effect_capabilities": sorted(
                        effect.capabilities
                    ),
                    "repository_effect_capability_evidence": {
                        capability: [
                            _evidence_dict(ref, root)
                            for ref in sorted(refs)
                        ]
                        for capability, refs in sorted(
                            effect.capability_evidence.items()
                        )
                    },
                    "repository_effect_partial": bool(
                        effect.unresolved_calls
                    ),
                    "repository_effect_unresolved_calls": sorted(
                        effect.unresolved_calls
                    ),
                    "repository_effect_sources": sorted(
                        {
                            str(item["path"])
                            for item in evidence_details
                        }
                    ),
                }
            )

            for capability in sorted(effect.capabilities):
                refs = sorted(
                    effect.capability_evidence.get(capability) or ()
                )
                for ref in refs:
                    _append_fact(
                        tool.provenance,
                        EvidenceFact(
                            subject=tool.name,
                            fact=f"capability={capability}",
                            origin="observed",
                            location=SourceLocation(
                                ref.path,
                                ref.line,
                                ref.column,
                            ),
                        ),
                    )

            for destination in tool.destinations:
                if not destination.metadata.get(
                    "repository_effect_summary"
                ):
                    continue
                _append_fact(
                    destination.provenance,
                    EvidenceFact(
                        subject=tool.name,
                        fact=f"destination={destination.target}",
                        origin="observed",
                        location=destination.location,
                    ),
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
