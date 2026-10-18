"""Wave B rw-004 source-negative ADK ontology adjudication.

Immutable source-only review. Source imports, AST constructor sites and
repository dependency declarations do not prove installed SDK importability,
runtime agent instances, actual tool calls or effective authority.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from horustrace.adapters.google_adk import scan_python_file

REPO = "JoanMarinPages/agentGemini"
SHA = "0160690bb47cca17e70ceb8486209d7b1cacaf76"
BLOBS = {
    "agent.py": "c5641b32eac1d58f94ebd1b06a792f4d740b4ddb",
    "agentGemini/agent.py": "4e540509642a70802c03e66f4067d3f58b5ab9df",
    "example_simple_agent.py": "bf16fe70ab20a2625c88451197866fb3c84908b4",
    "agentGemini/models.py": "a081c68afc94f39031d2026b58bb2c7a12ba6e6b",
    "requirements.txt": "4a18ae319979d7df518a0f4f5c8295af403b7926",
    "pyproject.toml": "a87363a6342650e322d65b7c19920967ed409afa",
}


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + bytes([0]) + raw
    ).hexdigest()


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _call_name(node.value) + "." + node.attr
    return ""


def _declarations(code: bytes, path: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tree = ast.parse(code.decode("utf-8"), filename=path)
    imported: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for item in node.names:
                imported[item.asname or item.name] = (
                    (node.module or "") + "." + item.name
                )
    agents = []
    negatives = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [t.id for t in targets if isinstance(t, ast.Name)]
            value = node.value
            if names and isinstance(value, ast.Call):
                name = _call_name(value.func)
                origin = imported.get(name)
                literal_name = next((
                    kw.value.value for kw in value.keywords
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ), None)
                if (origin in {"google.adk.agents.LlmAgent",
                               "google.genai.adk.Agent"}
                        and literal_name):
                    agents.append({
                        "symbol": names[0], "agent_name": literal_name,
                        "path": path, "line": node.lineno,
                        "constructor": origin,
                        "source_classification": "declaration_conditional",
                        "runtime_verified": False,
                    })
            if names and isinstance(value, ast.Name) and names[0] == "root_agent":
                negatives.append({
                    "symbol": names[0], "path": path, "line": node.lineno,
                    "referent": value.id, "kind": "alias_not_new_agent",
                })
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            origin = imported.get(name)
            if origin == "google.adk.runners.Runner":
                negatives.append({
                    "symbol": name, "path": path, "line": node.lineno,
                    "kind": "runner_not_agent",
                })
            if origin == "google.genai.Client":
                negatives.append({
                    "symbol": name, "path": path, "line": node.lineno,
                    "kind": "model_api_client_not_agent",
                })
        if isinstance(node, ast.ClassDef):
            if any(_call_name(b) == "BaseModel" for b in node.bases):
                negatives.append({
                    "symbol": node.name, "path": path, "line": node.lineno,
                    "kind": "pydantic_data_model_not_agent",
                })
    return agents, negatives


def audit(sources: dict[str, bytes], source_root: Path) -> dict[str, Any]:
    if set(sources) != set(BLOBS):
        raise ValueError("six exact frozen source files required")
    for path, body in sources.items():
        if git_blob(body) != BLOBS[path]:
            raise ValueError(f"pinned Git blob source mismatch: {path}")

    all_agents: list[dict[str, Any]] = []
    all_negative: list[dict[str, Any]] = []
    for path in ("agent.py", "agentGemini/agent.py",
                 "example_simple_agent.py", "agentGemini/models.py"):
        positive, negative = _declarations(sources[path], path)
        all_agents.extend(positive)
        all_negative.extend(negative)

    expected = {
        ("agent.py", "funnel_agent", "FunnelAgent", 98,
         "google.adk.agents.LlmAgent"),
        ("agentGemini/agent.py", "root_agent", "AgroAsesorIA", 38,
         "google.genai.adk.Agent"),
    }
    observed = {
        (a["path"], a["symbol"], a["agent_name"], a["line"], a["constructor"])
        for a in all_agents
    }
    if observed != expected:
        raise ValueError("two source agent constructor identities changed")
    if not any(n["kind"] == "alias_not_new_agent"
               and n["referent"] == "funnel_agent"
               and n["path"] == "agent.py" for n in all_negative):
        raise ValueError("source root_agent alias missing")
    for kind in ("runner_not_agent", "model_api_client_not_agent",
                 "pydantic_data_model_not_agent"):
        if not any(n["kind"] == kind for n in all_negative):
            raise ValueError(f"source hard-negative missing: {kind}")

    requirements = sources["requirements.txt"].decode("utf-8")
    toml = sources["pyproject.toml"].decode("utf-8")
    if "google-genai" not in requirements or "google-genai" not in toml:
        raise ValueError("dependency source declaration changed")
    # Distinguish source-specified dependencies from environment contents.
    if any(
        line.strip().lower().startswith(("google-adk=", "google-adk>", "google-adk "))
        for line in requirements.splitlines()
    ) or any(
        line.strip().lower().startswith("google-adk =")
        for line in toml.splitlines()
    ):
        raise ValueError("standalone google-adk dependency declaration changed")

    adapter = []
    for path in ("agent.py", "agentGemini/agent.py"):
        result = scan_python_file(source_root / path)
        adapter.append({
            "path": path, "detected_agents": [
                {"name": a.name, "line": a.location.line if a.location else None}
                for a in result.agents
            ],
            "source_declared_agent_count": sum(
                a["path"] == path for a in all_agents
            ),
        })
    return {
        "schema_version": 1, "case_id": "rw-004",
        "repository": REPO, "source_sha": SHA,
        "scope": "six_pinned_source_files_not_installed_runtime",
        "blob_witnesses": dict(BLOBS),
        "source_agents": all_agents,
        "source_agent_declaration_count": 2,
        "source_hard_negatives": all_negative,
        "source_native_scanner": adapter,
        "source_import_resolution": {
            "google.adk.agents.LlmAgent": "source_import_declared",
            "google.genai.adk.Agent": "source_import_declared_sdk_binding_unresolved",
        },
        "standalone_google_adk_dependency_declared": False,
        "google_genai_dependency_declared": True,
        "installed_sdk_version_verified": False,
        "source_alias_creates_new_agent": False,
        "effective_tool_authority_verified": False,
        "source_review_method": "posthoc_bounded_not_blind",
        "original_frozen_truth_modified": False,
        "independent_exhaustive_negative_truth": False,
        "agent_precision": None, "agent_recall": None,
        "wave_b_go": False, "wave_c_go": False,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    root = args.source.resolve()
    sources = {}
    for path in BLOBS:
        file = (root / path).resolve()
        if not file.is_relative_to(root):
            raise ValueError("pinned source path escaped root")
        sources[path] = file.read_bytes()
    result = audit(sources, root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({
        "case": "rw-004", "source_agents": 2,
        "hard_negative": len(result["source_hard_negatives"]),
        "wave_b_go": False,
    }))


if __name__ == "__main__":
    main()
