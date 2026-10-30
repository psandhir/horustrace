"""Portable instance and delegation metadata for extracted notebook Python cells.

Adapters analyze temporary Python source for static safety. Their instance keys
must not retain the randomized temporary extraction directory in authority and
ADG relationship identifiers. This module changes only keys derived from that
specific temporary extraction path, never general workspace paths or source code.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from horustrace.models import Graph


def _cell_positions(temp: Path) -> dict[int, tuple[int, int]]:
    """Synthetic line -> (original notebook cell index, 1-based cell line)."""
    result: dict[int, tuple[int, int]] = {}
    marker = re.compile(r"# notebook-cell-(\d+)\s*$")
    current: int | None = None
    header = 0
    for line_number, text in enumerate(temp.read_text(encoding="utf-8").splitlines(), 1):
        found = marker.fullmatch(text)
        if found:
            current = int(found.group(1))
            header = line_number
        elif current is not None:
            result[line_number] = (current, line_number - header)
    return result


def remap_notebook_instance_metadata(
    graph: Graph, temp_path: Path, notebook_path: Path, repository_root: Path,
) -> int:
    """Rewrite only temporary extractor path-prefixed instance/authority refs.

    The notebook-relative cell key is independent of system temp directories,
    workspace absolute paths, checkout roots and scan order. All matching refs
    are rewritten together so downstream delegation comparisons remain aligned.
    """
    old = str(temp_path.resolve())
    root = repository_root.resolve()
    target = notebook_path.resolve()
    try:
        relative = target.relative_to(root).as_posix()
    except ValueError:
        # A single-file scan uses its parent as containment root.
        relative = target.name
    positions = _cell_positions(temp_path)
    prefix = f"notebook:{relative}"
    changed = 0

    def normalize(value: Any) -> Any:
        nonlocal changed
        if isinstance(value, str):
            if value == old:
                changed += 1
                return prefix
            if not value.startswith(old + ":"):
                return value
            suffix = value[len(old) + 1:]
            first, sep, trailing = suffix.partition(":")
            if first.isdecimal() and int(first) in positions:
                cell_index, cell_line = positions[int(first)]
                replaced = f"{prefix}#cell-{cell_index}:line-{cell_line}"
                if sep:
                    replaced += ":" + trailing
            else:
                replaced = prefix + ":" + suffix
            changed += 1
            return replaced
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, tuple):
            return tuple(normalize(item) for item in value)
        return value

    for agent in graph.agents:
        agent.metadata = normalize(agent.metadata)
        for tool in agent.tools:
            tool.metadata = normalize(tool.metadata)
        for skill in agent.skills:
            skill.metadata = normalize(skill.metadata)
        for server in agent.mcp_servers:
            server.metadata = normalize(server.metadata)
        for identity in agent.identities:
            identity.metadata = normalize(identity.metadata)
        for source in agent.inputs:
            source.metadata = normalize(source.metadata)
    for tool in graph.unbound_tools:
        tool.metadata = normalize(tool.metadata)
    for skill in graph.unbound_skills:
        skill.metadata = normalize(skill.metadata)
    for server in graph.unbound_mcp_servers:
        server.metadata = normalize(server.metadata)
    for diagnostic in graph.coverage.diagnostics:
        diagnostic.details = normalize(diagnostic.details)
    return changed
