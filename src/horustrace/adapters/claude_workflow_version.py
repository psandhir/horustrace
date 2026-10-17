"""Source-bounded Claude SDK Workflow compatibility evidence.

This does not infer the installed runtime version. It only rules out Workflow
when declared dependency constraints cannot admit its minimum bundled SDK.
Absent/ambiguous source remains unresolved, never assumed compatible.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from horustrace.models import Agent

_MIN_WORKFLOW_SDK = (0, 2, 90)
_VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")
_PY_DEP = re.compile(r"^claude-agent-sdk(?:\[[^\]]*\])?(.*)$", re.I)
_TOKEN = re.compile(r"(>=|<=|==|>|<|\^|~|=)\s*(\d+\.\d+(?:\.\d+)?)")


def _version(value: str) -> tuple[int, int, int] | None:
    match = _VERSION.match(value.strip())
    if match is None:
        return None
    return (int(match[1]), int(match[2]), int(match[3] or 0))


def _range_status(specifier: str) -> str:
    """Classify only provable upper/lower bounds; everything else is unknown."""
    text = specifier.strip().strip('"').strip("'")
    if not text or any(token in text for token in ("||", "*", "git+", "file:", "workspace:")):
        return "unknown"
    if text[:1].isdigit():
        text = "==" + text
    matches = list(_TOKEN.finditer(text))
    if not matches:
        return "unknown"
    # Never trust a partially understood range (extras, branch selectors, etc.).
    remaining = _TOKEN.sub("", text).strip(" ,")
    if remaining:
        return "unknown"
    supported = False
    for match in matches:
        operator, literal = match.group(1), match.group(2)
        version = _version(literal)
        if version is None:
            return "unknown"
        if operator in {"==", "="}:
            return "supported" if version >= _MIN_WORKFLOW_SDK else "unsupported"
        if operator == "<" and version <= _MIN_WORKFLOW_SDK:
            return "unsupported"
        if operator == "<=" and version < _MIN_WORKFLOW_SDK:
            return "unsupported"
        if operator == "^" and version[0] == 0 and version[1] < 2:
            return "unsupported"
        if operator == "~" and version[:2] < _MIN_WORKFLOW_SDK[:2]:
            return "unsupported"
        if operator in {">=", ">"} and version >= _MIN_WORKFLOW_SDK:
            supported = True
    return "supported" if supported else "unknown"


def _python_specs(directory: Path) -> list[str]:
    specs: list[str] = []
    requirements = directory / "requirements.txt"
    if requirements.is_file():
        try:
            for line in requirements.read_text(encoding="utf-8").splitlines():
                match = _PY_DEP.match(line.partition("#")[0].strip())
                if match:
                    specs.append(match.group(1).split(";")[0].strip())
        except (OSError, UnicodeError):
            return []
    pyproject = directory / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            declared = data.get("project", {}).get("dependencies", [])
            for line in declared if isinstance(declared, list) else []:
                if isinstance(line, str):
                    match = _PY_DEP.match(line.strip())
                    if match:
                        specs.append(match.group(1).split(";")[0].strip())
        except (OSError, UnicodeError, tomllib.TOMLDecodeError, TypeError, ValueError):
            return []
    return specs


def _typescript_specs(directory: Path) -> list[str]:
    manifest = directory / "package.json"
    if not manifest.is_file():
        return []
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return []
        specs: list[str] = []
        for key in ("dependencies", "peerDependencies", "optionalDependencies", "devDependencies"):
            dependencies = data.get(key)
            if isinstance(dependencies, dict):
                declared = dependencies.get("@anthropic-ai/claude-agent-sdk")
                if isinstance(declared, str):
                    specs.append(declared)
        return specs
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []


def declared_workflow_support(path: Path, *, language: str) -> str:
    """Return supported/unsupported/unknown for the nearest declarative SDK range.

    The first directory with SDK declarations wins (monorepo package locality).
    Disagreeing declarations remain unknown. Does not inspect installed runtime.
    """
    for directory in list(path.resolve().parents)[:8]:
        specs = _python_specs(directory) if language == "python" else _typescript_specs(directory)
        if specs:
            statuses = {_range_status(spec) for spec in specs}
            return next(iter(statuses)) if len(statuses) == 1 else "unknown"
    return "unknown"


def annotate_workflow_tool_availability(
    agents: list[Agent], path: Path, *, language: str
) -> None:
    status = declared_workflow_support(path, language=language)
    for agent in agents:
        workflow_tools = [tool for tool in agent.tools if tool.name == "Workflow"]
        if not workflow_tools:
            continue
        agent.metadata["workflow_sdk_version_support"] = status
        agent.metadata["workflow_sdk_version_source"] = "declared_dependency_not_installed"
        if status == "unsupported":
            # A known-incompatible dependency range cannot yield the new Workflow tool.
            agent.tools = [tool for tool in agent.tools if tool.name != "Workflow"]
            agent.metadata["workflow_tool_omitted_incompatible_sdk"] = True
        elif status == "unknown":
            agent.metadata["workflow_sdk_version_unresolved"] = True
            for tool in workflow_tools:
                # Keep potential visibility but prevent fully-resolved authority.
                tool.metadata["tool_catalogue_unresolved"] = True
                tool.metadata["workflow_version_unresolved"] = True
