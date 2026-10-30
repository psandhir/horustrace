"""WAB-FastAgent rw-003: source-authenticated agent/workflow ontology.

This pinned positive/hard-negative observation is **post-hoc model review**,
not an independent full-145 V2 source reference or verified runtime instance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from horustrace.adapters.fast_agent import scan_python_file

REPO = "angrysky56/ai_writers_workshop"
SHA = "c160a299706dd0cd1dc9ae114b97aba905e9261d"
PATH = "mcp_server/components/fast_agent_integration.py"
BLOB = "6e092dc8083c45b99b4908125c181bd88637eeaf"

AGENTS = {
    ("concept_developer", 56),
    ("narrative_architect", 65),
    ("character_developer", 76),
    ("prose_generator", 87),
    ("editor", 97),
    ("story_generator", 107),
    ("story_evaluator", 119),
    ("narrative_assistant", 138),
}
WORKFLOWS = {
    ("writing_workflow", "chain", 153),
    ("story_refinement", "evaluator_optimizer", 169),
}


def verify(path: Path) -> dict:
    raw = path.read_bytes()
    expected = hashlib.sha1(
        b"blob " + str(len(raw)).encode() + bytes([0]) + raw
    ).hexdigest()
    if expected != BLOB:
        raise ValueError("pinned FastAgent source Git blob drift")
    graph = scan_python_file(path)
    agents = {
        (agent.name, agent.location.line)
        for agent in graph.agents if agent.location is not None
    }
    workflows = {
        (node.name, node.method, node.location.line)
        for node in graph.workflow_nodes if node.location is not None
    }
    if agents != AGENTS:
        raise ValueError(f"source-declared FastAgent agent identity mismatch: {agents}")
    if workflows != WORKFLOWS:
        raise ValueError(f"source-declared FastAgent workflow identity mismatch: {workflows}")
    if not all(w.metadata.get("runtime_instance_verified") is False
               and w.metadata.get("runtime_effectiveness") == "not_verified"
               for w in graph.workflow_nodes):
        raise ValueError("source workflow promoted to live runtime instance")
    names = {a.name for a in graph.agents}
    if set(w.name for w in graph.workflow_nodes) & names:
        raise ValueError("workflow name duplicated as agent node")
    if any(w.method == "chain" and w.members != [
        "concept_developer", "narrative_architect", "character_developer",
        "prose_generator", "editor"
    ] for w in graph.workflow_nodes):
        raise ValueError("literal chain source ordering changed")
    return {
        "case_id": "rw-003", "repository": REPO, "source_sha": SHA,
        "source_path": PATH, "source_blob_sha": BLOB,
        "declared_agents": sorted(
            [{"name": name, "line": line} for name, line in agents],
            key=lambda x: x["line"],
        ),
        "declared_workflows": sorted(
            [{"name": name, "method": method, "line": line}
             for name, method, line in workflows],
            key=lambda x: x["line"],
        ),
        "agent_count": len(agents),
        "nonagent_workflow_count": len(workflows),
        "source_declarations_conditional_on_fastagent_availability": True,
        "runtime_instances_verified": False,
        "workflow_delegation_runtime_verified": False,
        "original_frozen_reference_complete": False,
        "source_truth_method": "posthoc_source_inspection_not_independent_blind",
        "agent_precision": None, "agent_recall": None,
        "wave_b_go": False, "wave_c_go": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = (args.source_root.resolve() / PATH).resolve()
    if not source.is_relative_to(args.source_root.resolve()):
        raise ValueError("target source path escapes pin")
    result = verify(source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "case_id": result["case_id"],
        "agents": result["agent_count"],
        "workflows_not_agents": result["nonagent_workflow_count"],
        "wave_b_go": False,
    }))


if __name__ == "__main__":
    main()
