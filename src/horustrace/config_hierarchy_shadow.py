"""Opt-in source-only inventory of explicitly configured JSON agent hierarchies.

No application import, target execution, scanner Graph mutation, deployment
verification, or inference that configured tool groups are MCP tool exports.
Use only with an explicitly supplied hierarchy manifest; never auto-detect
arbitrary JSON based on labels.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

_MAX_BYTES = 1024 * 1024
_MAX_AGENTS = 256
_MAX_EDGES = 2048
_ROLES = frozenset({"frontend", "orchestrator", "worker"})
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_PATH = re.compile(r"[a-zA-Z0-9_./-]+\.json\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,127}\Z")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True,
        capture_output=True, timeout=20,
    ).stdout.decode("utf-8").strip()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON configuration key: " + key)
        result[key] = value
    return result


def _pointer(*parts: str | int) -> str:
    return "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def _attested_json(checkout: Path, relative_path: str) -> tuple[dict, dict]:
    if (not isinstance(relative_path, str)
            or not _SAFE_PATH.fullmatch(relative_path)
            or relative_path.startswith(("/", "./"))
            or ".." in Path(relative_path).parts):
        raise ValueError("unsafe configured hierarchy path")
    root = checkout.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("configured hierarchy checkout is not a directory")
    try:
        if Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root:
            raise ValueError("source scope must be Git repository root")
        if _git(root, "rev-parse", "--show-object-format") != "sha1":
            raise ValueError("source inventory requires Git SHA-1")
        head = _git(root, "rev-parse", "--verify", "HEAD")
        if not _SHA1.fullmatch(head):
            raise ValueError("invalid exact Git revision")
        source = (root / relative_path).resolve(strict=True)
        if not source.is_relative_to(root) or not source.is_file():
            raise ValueError("hierarchy escapes source scope")
        if source.stat().st_size > _MAX_BYTES:
            raise ValueError("configured hierarchy exceeds source size limit")
        raw = source.read_bytes()
        blob_sha = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        ).hexdigest()
        row = _git(root, "ls-tree", head, "--", relative_path)
        if row not in (
            f"100644 blob {blob_sha}\t{relative_path}",
            f"100755 blob {blob_sha}\t{relative_path}",
        ):
            raise ValueError("hierarchy is untracked, a symlink or differs from Git HEAD")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise ValueError("configured hierarchy needs intact Git source") from exc
    if not isinstance(value, dict):
        raise TypeError("configured hierarchy must be JSON object")
    return value, {
        "commit_sha": head, "path": relative_path,
        "git_blob_sha": blob_sha, "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw), "witness_granularity": "git_blob_and_json_pointer",
    }


def build_configured_hierarchy_source_shadow(
    checkout: Path, relative_path: str,
) -> dict[str, Any]:
    """Return bounded declared identities and links; NEVER authoritative ADG.

    The manifest must contain named agents with known type and source
    directory. Children and tool groups are JSON-declared configuration, not
    evidence of deployed delegation, runtime callability or effective access.
    """
    hierarchy, revision = _attested_json(checkout, relative_path)
    if not 1 <= len(hierarchy) <= _MAX_AGENTS:
        raise ValueError("configured agent count outside bounded scope")
    agents: list[dict[str, Any]] = []
    groups: dict[str, dict[str, Any]] = {}
    links: list[dict[str, Any]] = []
    declared_children: dict[str, list[str]] = {}

    for name, config in sorted(hierarchy.items()):
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("invalid configured agent identity")
        if not isinstance(config, dict) or config.get("type") not in _ROLES:
            raise ValueError("unsupported agent role or configuration")
        directory = config.get("dir")
        if (not isinstance(directory, str) or not directory
                or directory.startswith(("/", "./"))
                or any(part in ("", ".", "..") for part in directory.split("/"))
                or "\\" in directory):
            raise ValueError("invalid configured agent source directory")
        children = config.get("children", [])
        tools = config.get("tools", [])
        if not isinstance(children, list) or not isinstance(tools, list):
            raise TypeError("agent children and tools must be explicit lists")
        if (any(not isinstance(x, str) or not _NAME.fullmatch(x) for x in children)
                or len(set(children)) != len(children)
                or any(not isinstance(x, str) or not _NAME.fullmatch(x) for x in tools)
                or len(set(tools)) != len(tools)):
            raise ValueError("invalid or duplicate configuration relationship")
        declared_children[name] = children
        agents.append({
            "id": "config-agent:" + name, "kind": "configured_agent",
            "name": name, "role": config["type"],
            "source_directory": directory,
            "json_pointer": _pointer(name),
            "source_only": True, "runtime_instance_verified": False,
        })
        for index, group in enumerate(tools):
            if group not in groups:
                groups[group] = {
                    "id": "config-group:" + group, "kind": "declared_tool_group",
                    "name": group, "source_only": True,
                    "mcp_tool_export_verified": False,
                }
            links.append({
                "kind": "CONFIG_DECLARES_TOOL_GROUP",
                "source": "config-agent:" + name,
                "target": "config-group:" + group,
                "json_pointer": _pointer(name, "tools", index),
                "source_only": True, "effective_agent_can_call": None,
            })
    for name, children in sorted(declared_children.items()):
        for index, child in enumerate(children):
            if child not in declared_children or child == name:
                raise ValueError("dangling or self-referential configured child")
            links.append({
                "kind": "CONFIG_DECLARES_CHILD",
                "source": "config-agent:" + name,
                "target": "config-agent:" + child,
                "json_pointer": _pointer(name, "children", index),
                "source_only": True, "runtime_delegation_verified": False,
            })
    if len(links) > _MAX_EDGES or len(groups) > _MAX_AGENTS:
        raise ValueError("configured hierarchy relationship count exceeds limits")
    kinds = sorted({"CONFIG_DECLARES_CHILD", "CONFIG_DECLARES_TOOL_GROUP"})
    return {
        "schema_version": 1,
        "mode": "opt_in_configured_hierarchy_source_shadow_not_production_adg",
        "source_revision": revision,
        "nodes": [*agents, *[groups[k] for k in sorted(groups)]],
        "edges": sorted(
            links, key=lambda row: (row["kind"], row["source"],
                                    row["target"], row["json_pointer"])
        ),
        "edge_kinds": {
            kind: sum(link["kind"] == kind for link in links) for kind in kinds
        },
        "source_only": True,
        "runtime_authority_verified": False,
        "independently_adjudicated": False,
        "certified_precision": None,
        "certified_recall": None,
        "production_cutover_authorized": False,
    }
