"""Google ADK runtime semantics for bound Agent Skills.

The adapter records source-visible SkillToolset configuration. This module composes
that declaration with bound Skill packages after repository-wide Skill discovery, so
only runtime-proven ADK surfaces become effective Skill authority.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from horustrace.models import (
    Graph,
    NetworkDestination,
    ResourceScope,
    ScanDiagnostic,
    Skill,
    SourceLocation,
)


def _requested_additional_tools(skill: Skill) -> list[str]:
    raw = skill.metadata.get("metadata")
    if not isinstance(raw, dict):
        return []
    value = raw.get("adk_additional_tools")
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return []


def _toolset_matches_skill(skill: Skill, spec: dict[str, Any]) -> bool:
    names = spec.get("skill_names")
    if isinstance(names, list) and skill.name in names:
        return True
    binding_source = skill.metadata.get("binding_source_path")
    source_paths = spec.get("source_paths")
    return (
        isinstance(binding_source, str)
        and isinstance(source_paths, list)
        and binding_source in source_paths
    )


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _analyze_python_script(
    source: str,
    location: SourceLocation,
) -> tuple[set[str], list[NetworkDestination]]:
    """Infer concrete effects from a Skill Python script without executing it."""
    try:
        tree = ast.parse(source, filename=str(location.path))
    except SyntaxError:
        return set(), []

    capabilities: set[str] = set()
    destinations: list[NetworkDestination] = []
    seen_destinations: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            owner = _call_name(node.value)
            if owner == "os.environ":
                capabilities.add("secrets.read")
            continue
        if not isinstance(node, ast.Call):
            continue

        called = _call_name(node.func).lower()
        leaf = called.rsplit(".", 1)[-1]

        if (
            called in {
                "exec",
                "eval",
                "compile",
                "builtins.exec",
                "builtins.eval",
                "builtins.compile",
                "os.system",
                "os.popen",
            }
            or called.startswith("subprocess.")
            or "create_subprocess_" in called
        ):
            capabilities.add("process.execute")

        if called in {"os.getenv", "os.environ.get"}:
            capabilities.add("secrets.read")

        if leaf == "open":
            mode = _literal_string(node.args[1] if len(node.args) > 1 else None) or "r"
            capabilities.add(
                "data.write" if any(flag in mode for flag in "wax+") else "data.read"
            )

        if leaf in {"unlink", "rmdir", "remove", "rmtree"}:
            capabilities.update({"data.write", "destructive.write"})
        elif leaf in {"write", "write_text", "write_bytes", "mkdir", "rename", "replace"}:
            capabilities.add("data.write")
        elif leaf in {"read", "read_text", "read_bytes"}:
            capabilities.add("data.read")

        network_call = any(
            marker in called
            for marker in (
                "requests.",
                "httpx.",
                "aiohttp.",
                "urllib.request.",
            )
        )
        if not network_call:
            continue

        capabilities.add("network.external")
        if leaf in {"post", "put", "patch", "delete"}:
            capabilities.update({"data.write", "external.write"})
        if leaf == "delete":
            capabilities.add("destructive.write")

        target = _literal_string(node.args[0] if node.args else None)
        if target and target.startswith(("http://", "https://")):
            if target not in seen_destinations:
                destinations.append(
                    NetworkDestination(
                        target=target,
                        restricted=True,
                        location=location,
                        metadata={
                            "source": "adk_skill_script_literal",
                            "network_scope": "fixed_literal_destination",
                        },
                    )
                )
                seen_destinations.add(target)

    return capabilities, destinations


def _script_source(
    skill: Skill,
    relative_path: str,
) -> tuple[str | None, SourceLocation]:
    inline = skill.metadata.get("inline_scripts")
    if isinstance(inline, dict):
        value = inline.get(relative_path) or inline.get(
            relative_path.removeprefix("scripts/")
        )
        if isinstance(value, str):
            return value, skill.location or SourceLocation(Path("<inline-skill>"))

    if skill.location is None:
        return None, SourceLocation(Path(relative_path))

    root = skill.location.path.parent.resolve()
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None, SourceLocation(skill.location.path)

    try:
        if candidate.is_symlink() or not candidate.is_file():
            return None, SourceLocation(candidate)
        return candidate.read_text(encoding="utf-8"), SourceLocation(candidate)
    except (OSError, UnicodeDecodeError):
        return None, SourceLocation(candidate)


def _candidate_map(specs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for spec in specs:
        candidates = spec.get("additional_tools")
        if not isinstance(candidates, list):
            continue
        for item in candidates:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if isinstance(name, str) and name:
                result.setdefault(name, item)
    return result


def _executor_semantics(
    agent_tools: list[Any],
    specs: list[dict[str, Any]],
) -> dict[str, Any] | None:
    for spec in specs:
        execution = spec.get("script_execution")
        if isinstance(execution, dict) and execution.get("available") is True:
            return dict(execution)

    for tool in agent_tools:
        if getattr(tool, "kind", None) != "adk_code_executor":
            continue
        metadata = getattr(tool, "metadata", {})
        return {
            "available": True,
            "source": "agent_code_executor",
            "executor": metadata.get("code_executor") or tool.name,
            "sandboxed": metadata.get("sandboxed"),
            "executor_kind": metadata.get("executor_kind"),
            "capabilities": sorted(getattr(tool, "capabilities", set())),
            "sandbox_network_disabled": metadata.get("sandbox_network_disabled"),
            "sandbox_filesystem_constrained": metadata.get(
                "sandbox_filesystem_constrained"
            ),
        }
    return None


def _apply_candidate_authority(skill: Skill, candidate: dict[str, Any]) -> None:
    skill.capabilities.update(
        str(value) for value in candidate.get("capabilities", []) if str(value)
    )
    for raw in candidate.get("resources", []):
        if not isinstance(raw, dict):
            continue
        selector = raw.get("selector")
        if not isinstance(selector, str) or not selector:
            continue
        resource = ResourceScope(
            kind=str(raw.get("kind") or "unknown"),
            selector=selector,
            access={
                str(value)
                for value in raw.get("access", [])
                if isinstance(value, str)
            },
            classification=str(raw.get("classification") or "internal"),
            location=skill.location,
            metadata={"source": "adk_skill_additional_tool"},
        )
        if resource not in skill.resources:
            skill.resources.append(resource)
    for raw in candidate.get("destinations", []):
        if not isinstance(raw, dict):
            continue
        target = raw.get("target")
        if not isinstance(target, str) or not target:
            continue
        if any(item.target == target for item in skill.destinations):
            continue
        skill.destinations.append(
            NetworkDestination(
                target=target,
                direction=str(raw.get("direction") or "outbound"),
                restricted=bool(raw.get("restricted")),
                location=skill.location,
                metadata={"source": "adk_skill_additional_tool"},
            )
        )


def enrich_adk_skill_authority(graph: Graph) -> None:
    """Compose ADK SkillToolset bindings into effective Skill authority."""
    for agent in graph.agents:
        if agent.metadata.get("framework") != "google-adk":
            continue
        raw_specs = agent.metadata.get("adk_skill_toolsets")
        if not isinstance(raw_specs, list):
            continue
        specs = [item for item in raw_specs if isinstance(item, dict)]
        for skill in agent.skills:
            matching = [spec for spec in specs if _toolset_matches_skill(skill, spec)]
            if not matching:
                continue

            skill.metadata["adk_skilltoolset"] = True
            skill.metadata["adk_toolsets"] = [
                str(spec.get("alias") or "SkillToolset") for spec in matching
            ]

            requested = _requested_additional_tools(skill)
            if requested:
                skill.metadata["adk_requested_additional_tools"] = requested
            candidates = _candidate_map(matching)
            resolved: list[str] = []
            unresolved: list[str] = []
            for tool_name in requested:
                candidate = candidates.get(tool_name)
                if candidate is None:
                    unresolved.append(tool_name)
                    continue
                _apply_candidate_authority(skill, candidate)
                resolved.append(tool_name)
            if resolved:
                skill.metadata["adk_resolved_additional_tools"] = sorted(set(resolved))
            if unresolved:
                skill.metadata["adk_unresolved_additional_tools"] = sorted(
                    set(unresolved)
                )
                graph.coverage.diagnostics.append(
                    ScanDiagnostic(
                        "unresolved_skill",
                        (
                            f"ADK skill '{skill.name}' requests additional tools "
                            "that are not source-proven in its SkillToolset."
                        ),
                        skill.location,
                        details={
                            "agent": agent.name,
                            "skill": skill.name,
                            "tools": sorted(set(unresolved)),
                            "source": "google-adk-adk_additional_tools",
                        },
                    )
                )

            scripts = list(skill.scripts)
            inline = skill.metadata.get("inline_scripts")
            if isinstance(inline, dict):
                for name in inline:
                    relative = (
                        name if str(name).startswith("scripts/") else f"scripts/{name}"
                    )
                    if relative not in scripts:
                        scripts.append(relative)

            observed_caps: set[str] = set()
            observed_destinations: list[str] = []
            unsupported_scripts: list[str] = []
            for script in scripts:
                if not script.endswith(".py"):
                    unsupported_scripts.append(script)
                    continue
                source, location = _script_source(skill, script)
                if source is None:
                    unsupported_scripts.append(script)
                    continue
                capabilities, destinations = _analyze_python_script(source, location)
                observed_caps.update(capabilities)
                for destination in destinations:
                    if not any(
                        item.target == destination.target
                        for item in skill.destinations
                    ):
                        skill.destinations.append(destination)
                    observed_destinations.append(destination.target)

            if observed_caps:
                skill.metadata["adk_script_observed_capabilities"] = sorted(observed_caps)
            if observed_destinations:
                skill.metadata["adk_script_observed_destinations"] = sorted(
                    set(observed_destinations)
                )
            if unsupported_scripts:
                skill.metadata["adk_script_semantics_unresolved"] = sorted(
                    set(unsupported_scripts)
                )

            executor = _executor_semantics(agent.tools, matching)
            if scripts and executor is not None:
                skill.metadata["adk_script_execution"] = {
                    **executor,
                    "state": "enabled",
                }
                executor_caps = {
                    str(value)
                    for value in executor.get("capabilities", [])
                    if isinstance(value, str)
                }
                if not executor_caps:
                    executor_caps.add("process.execute")
                skill.capabilities.update(executor_caps)

                # Static script effects become effective only for an explicitly
                # unsandboxed executor. For sandboxed or unknown boundaries they
                # remain observable intent/effect evidence, not host authority.
                if executor.get("sandboxed") is False:
                    skill.capabilities.update(observed_caps)
            elif scripts:
                skill.metadata["adk_script_execution"] = {
                    "available": False,
                    "state": "disabled_no_executor",
                }

            skill.metadata["effective_authority_source"] = "google-adk-skilltoolset"
