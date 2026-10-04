"""Agent Skills discovery and conservative repository binding.

HorusTrace treats portable SKILL.md packages as first-class inventory. A skill only
contributes to effective agent policy when a framework adapter/source proves the
binding; merely existing in a repository is inventory, not authority.
"""
from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from horustrace.models import Graph, ScanDiagnostic, Skill, SourceLocation

SKILL_FILENAME = "SKILL.md"
_SKILL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MAX_SUPPORT_FILES = 256


def _frontmatter(text: str) -> tuple[dict[str, Any] | None, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, text
    end = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
        None,
    )
    if end is None:
        return None, text
    raw = yaml.safe_load("\n".join(lines[1:end]))
    if not isinstance(raw, dict):
        return None, "\n".join(lines[end + 1 :])
    return raw, "\n".join(lines[end + 1 :])


def _allowed_tools(raw: object) -> set[str]:
    if isinstance(raw, str):
        return {item for item in raw.replace(",", " ").split() if item}
    if isinstance(raw, list):
        return {str(item).strip() for item in raw if str(item).strip()}
    return set()


def _support_files(skill_root: Path, directory: str) -> list[str]:
    base = skill_root / directory
    if not base.is_dir():
        return []
    result: list[str] = []
    for path in sorted(base.rglob("*")):
        if len(result) >= _MAX_SUPPORT_FILES:
            break
        try:
            if path.is_symlink() or not path.is_file():
                continue
            path.resolve().relative_to(skill_root.resolve())
        except (OSError, RuntimeError, ValueError):
            continue
        result.append(path.relative_to(skill_root).as_posix())
    return result


def scan_skill_file(path: Path) -> Graph:
    """Parse one portable Agent Skills package without executing its contents."""
    graph = Graph()
    if path.name != SKILL_FILENAME:
        return graph
    try:
        text = path.read_text(encoding="utf-8")
        raw, body = _frontmatter(text)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        graph.coverage.diagnostics.append(
            ScanDiagnostic(
                "invalid_skill_manifest",
                "Agent skill metadata could not be parsed safely.",
                SourceLocation(path),
                incomplete=False,
                details={"exception_type": type(exc).__name__},
            )
        )
        return graph

    if raw is None:
        graph.coverage.diagnostics.append(
            ScanDiagnostic(
                "invalid_skill_manifest",
                "Agent skill is missing valid YAML frontmatter.",
                SourceLocation(path),
                incomplete=False,
            )
        )
        return graph

    name = str(raw.get("name") or "").strip()
    description = str(raw.get("description") or "").strip()
    if not name or not description:
        graph.coverage.diagnostics.append(
            ScanDiagnostic(
                "invalid_skill_manifest",
                "Agent skill frontmatter must declare name and description.",
                SourceLocation(path),
                incomplete=False,
            )
        )
        return graph

    scripts = _support_files(path.parent, "scripts")
    references = _support_files(path.parent, "references")
    assets = _support_files(path.parent, "assets")
    allowed_tools = _allowed_tools(raw.get("allowed-tools") or raw.get("allowed_tools"))
    broad_tool_surface = any(
        item.strip().lower() in {"*", "all", "all-tools", "all_tools"} or "*" in item
        for item in allowed_tools
    )

    metadata: dict[str, Any] = {
        "framework": "agent-skills",
        "package_root": path.parent.as_posix(),
        "directory_name": path.parent.name,
        "name_matches_directory": name == path.parent.name,
        "name_conforms": bool(_SKILL_NAME.fullmatch(name)),
        "instructions_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "instructions_length": len(body),
        "content_included": False,
        "has_scripts": bool(scripts),
        "script_count": len(scripts),
        "reference_count": len(references),
        "asset_count": len(assets),
        "broad_tool_surface": broad_tool_surface,
    }
    for key in ("license", "compatibility", "metadata"):
        if key in raw:
            metadata[key.replace("-", "_")] = raw[key]

    graph.unbound_skills.append(
        Skill(
            name=name,
            description=description,
            allowed_tools=allowed_tools,
            scripts=scripts,
            location=SourceLocation(path),
            metadata=metadata,
        )
    )
    return graph


def _skill_key(skill: Skill) -> tuple[str, str]:
    location = str(skill.location.path.resolve()) if skill.location else ""
    return (skill.name, location)


def bind_discovered_skills(graph: Graph, root: Path) -> None:
    """Bind only exact skill names already emitted by framework adapters."""
    by_name: dict[str, list[Skill]] = {}
    for skill in graph.unbound_skills:
        by_name.setdefault(skill.name, []).append(skill)

    bound: set[tuple[str, str]] = set()
    for agent in graph.agents:
        requested = agent.metadata.get("skills")
        if not isinstance(requested, (list, tuple, set)):
            continue
        seen = {_skill_key(item) for item in agent.skills}
        for raw_name in requested:
            name = str(raw_name).strip()
            if not name:
                continue
            matches = by_name.get(name, [])
            if len(matches) != 1:
                graph.coverage.diagnostics.append(
                    ScanDiagnostic(
                        "unresolved_skill",
                        (
                            f"Skill reference '{name}' could not be resolved uniquely "
                            f"for agent '{agent.name}'."
                        ),
                        agent.location,
                        details={
                            "agent": agent.name,
                            "skill": name,
                            "matches": len(matches),
                        },
                    )
                )
                continue
            skill = deepcopy(matches[0])
            key = _skill_key(skill)
            if key in seen:
                continue
            skill.metadata = {
                **skill.metadata,
                "binding_state": "bound",
                "binding_origin": "framework_skill_reference",
                "bound_agent": agent.name,
            }
            agent.skills.append(skill)
            seen.add(key)
            bound.add(key)

    if bound:
        graph.unbound_skills = [
            skill for skill in graph.unbound_skills if _skill_key(skill) not in bound
        ]
