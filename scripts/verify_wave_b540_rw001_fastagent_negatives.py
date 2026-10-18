"""rw-001 bounded source-typed FastAgent proof, with negative factory evidence.

Original locked source reference reports agent inventory complete but includes
six FastAgent app factories as agent identities. Do not rewrite it or claim a
new independent V2 reference. Target files are never imported or executed.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from horustrace.adapters.fast_agent import scan_python_file

REPO = "Klavis-AI/klavis"
SHA = "45c9f7da83d1cf43f7429b96f9c8e8153542ea1e"
ROOT = "mcp_servers/hugging_face/packages/e2e-python"
BLOBS = {
    "agent.py": "d22ad9d235f399293244c6deef9ee1e89274cf18",
    "gradio-files.py": "917f4ab68123e29474ad0323ed26711c1adcc38f",
    "jobs-testing/agent.py": "544368caaab50680b0827a5fbe84015ebb93c473",
    "prompts.py": "f62c7c53c6a8279954945a420312d8ba862fec4b",
    "qwen-test/qwen-test.py": "739a8725ba6889abbf937a904b5f6e9ecf835c05",
    "skybridge1.py": "b6c794923cc657bff3ee6555a3516db37810a23e",
}
FACTORY_LINES = {
    "agent.py": 5, "gradio-files.py": 5,
    "jobs-testing/agent.py": 10, "prompts.py": 5,
    "qwen-test/qwen-test.py": 6, "skybridge1.py": 5,
}
AGENT_LINES = {
    ("agent.py", "anon", 9),
    ("agent.py", "DVe0UTvm4", 10),
    ("agent.py", "all", 11),
    ("gradio-files.py", "DVe0UTvm4", 10),
    ("jobs-testing/agent.py", "jobs", 21),
    ("prompts.py", "anon", 9),
    ("qwen-test/qwen-test.py", "DVe0UTvm4", 12),
    ("skybridge1.py", "skybridge", 9),
}
COMMENTED_DECORATORS = {
    "gradio-files.py": 1,
    "qwen-test/qwen-test.py": 1,
}


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + bytes([0]) + data).hexdigest()


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return (prefix + "." if prefix else "") + node.attr
    return ""


def _ast_roles(source: bytes) -> tuple[list[int], set[tuple[str, int]]]:
    parsed = ast.parse(source.decode("utf-8"))
    factories: list[int] = []
    agents: set[tuple[str, int]] = set()
    for node in ast.walk(parsed):
        if (isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and _dotted(node.value.func) == "FastAgent"
            and any(isinstance(target, ast.Name) and target.id == "fast"
                    for target in node.targets)):
            factories.append(node.lineno)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                if _dotted(decorator.func) != "fast.agent":
                    continue
                names = [
                    kw.value.value for kw in decorator.keywords
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ]
                if len(names) != 1:
                    raise ValueError("dynamic source-defined FastAgent name unresolved")
                agents.add((names[0], decorator.lineno))
    return factories, agents


def prove(files: dict[str, bytes], root: Path,
          original: dict[str, Any]) -> dict[str, Any]:
    if set(files) != set(BLOBS):
        raise ValueError("complete pinned six-file source panel required")
    positives: set[tuple[str, str, int]] = set()
    factory_rows = []
    ignored_comments = 0
    for rel, raw in files.items():
        if git_blob(raw) != BLOBS[rel]:
            raise ValueError(f"rw001 pinned source blob changed: {rel}")
        factory_lines, decorated = _ast_roles(raw)
        if factory_lines != [FACTORY_LINES[rel]]:
            raise ValueError(f"source app factory role/line changed: {rel}")
        positives.update((rel, name, line) for name, line in decorated)
        scanner = scan_python_file(root / ROOT / rel)
        actual = {(a.name, a.location.line) for a in scanner.agents
                  if a.location is not None}
        if len(scanner.agents) != len(actual) or actual != decorated:
            raise ValueError(f"scanner agent identity diverged from source AST: {rel}")
        if scanner.workflow_nodes:
            raise ValueError("source-declared FastAgent agents were assigned workflows")
        if any(a.name == "fast" for a in scanner.agents):
            raise ValueError("FastAgent app factory promoted to source agent")
        factory_rows.append({"path": f"{ROOT}/{rel}", "line": FACTORY_LINES[rel],
                             "symbol": "fast",
                             "label": "source_negative_app_factory_not_agent"})
        comments = sum(line.lstrip().startswith("# @fast.agent(")
                       for line in raw.decode("utf-8").splitlines())
        if comments != COMMENTED_DECORATORS.get(rel, 0):
            raise ValueError("commented source declarations changed")
        ignored_comments += comments
    if positives != AGENT_LINES:
        raise ValueError("pinned eight decorated source agents changed")
    if len(factory_rows) != 6 or ignored_comments != 2:
        raise ValueError("app factory/comment source negative census changed")

    frozen = original
    if (frozen.get("case_id") != "rw-001"
        or frozen.get("source_reference", {}).get("sha") != SHA
        or frozen["source_reference"].get("repo") != REPO
        or frozen["truth_lock"].get("reviewed") is not True
        or frozen["truth_lock"].get("horustrace_output_seen") is not False
        or frozen["tier_a"]["reference_completeness"].get("agent_entities") is not True):
        raise ValueError("original complete-flagged source reference drift")
    original_factories = [
        item for item in frozen["assertions"]
        if item.get("expected_state") == "present"
        and item.get("predicate") == "explicit_agent_entity"
        and item.get("subject") == "fast"
        and (item.get("evidence") or [{}])[0].get("path", "").startswith(ROOT + "/")
    ]
    if len(original_factories) != 6:
        raise ValueError("historical factory-as-agent evidence changed")
    return {
        "schema_version": 1,
        "case_id": "rw-001",
        "repository": REPO, "source_sha": SHA,
        "source_blob_shas": dict(BLOBS),
        "scope": "six_exact_files_not_independent_full_repo_ontology",
        "source_positive_agent_count": len(positives),
        "source_agent_declarations": [
            {"path": f"{ROOT}/{rel}", "name": name, "line": line,
             "label": "source_declared_conditional_runtime_unverified"}
            for rel, name, line in sorted(positives)
        ],
        "source_hard_negative_factory_count": len(factory_rows),
        "source_hard_negative_factories": sorted(factory_rows, key=lambda x: x["path"]),
        "commented_decorators_not_active": ignored_comments,
        "original_reference_agent_complete_flag": True,
        "historical_agent_positive_factory_conflicts": len(original_factories),
        "historical_reference_rewritten": False,
        "independent_blind_v2_source_truth": False,
        "source_negative_panel_limited": True,
        "runtime_instance_verified": False,
        "agent_precision": None, "agent_recall": None,
        "wave_b_go": False, "wave_c_go": False,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-root", type=Path, required=True)
    ap.add_argument("--truth", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    root = args.source_root.resolve()
    files = {}
    for rel in BLOBS:
        path = (root / ROOT / rel).resolve()
        if not path.is_relative_to(root):
            raise ValueError("source path escapes pinned repository")
        files[rel] = path.read_bytes()
    result = prove(files, root, json.loads(args.truth.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "case_id": result["case_id"],
        "source_agent_declarations": result["source_positive_agent_count"],
        "factory_hard_negatives": result["source_hard_negative_factory_count"],
        "reference_conflicts": result["historical_agent_positive_factory_conflicts"],
        "go": False,
    }))


if __name__ == "__main__":
    main()
