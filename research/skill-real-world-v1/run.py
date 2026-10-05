from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from horustrace.effective_authority import effective_authority_relationships
from horustrace.scanner import scan


CATALOGS = [
    {
        "id": "anthropics-skills",
        "repo": "https://github.com/anthropics/skills.git",
        "sha": "683bc88e56f3e09ba94f7055977f3d3aa499f202",
        "sparse": ["skills"],
        "scan_root": "skills",
        "kind": "catalog",
    },
    {
        "id": "openai-skills",
        "repo": "https://github.com/openai/skills.git",
        "sha": "49f948faa9258a0c61caceaf225e179651397431",
        "sparse": ["skills"],
        "scan_root": "skills",
        "kind": "catalog",
    },
    {
        "id": "google-skills",
        "repo": "https://github.com/google/skills.git",
        "sha": "d6eee396ed6a51871cc3f0979c5ff1be26d35d10",
        "sparse": ["skills"],
        "scan_root": "skills",
        "kind": "catalog",
    },
    {
        "id": "vercel-agent-skills",
        "repo": "https://github.com/vercel-labs/agent-skills.git",
        "sha": "063bee94c3f4df8453406c830b0a7df0f2860278",
        "sparse": ["skills"],
        "scan_root": "skills",
        "kind": "catalog",
    },
    {
        "id": "addyosmani-agent-skills",
        "repo": "https://github.com/addyosmani/agent-skills.git",
        "sha": "1401c8b8030e023baeebb31781a6653fe8e93026",
        "sparse": ["skills"],
        "scan_root": "skills",
        "kind": "catalog",
    },
]

ADK_SHA = "ec7756b969bd2f3df64ffedde98e396ee6d5a589"
ADK_REPO = "https://github.com/google/adk-python.git"
ADK_SAMPLES = [
    {
        "id": "google-adk-skills-agent",
        "path": "contributing/samples/environment_and_skills/skills_agent",
        "kind": "bound_sample",
    },
    {
        "id": "google-adk-skills-inject-state",
        "path": "contributing/samples/environment_and_skills/skills_inject_state",
        "kind": "bound_sample",
    },
    {
        "id": "google-adk-local-env-skill-toolset",
        "path": "contributing/samples/environment_and_skills/local_env_skill_toolset",
        "kind": "bound_sample",
    },
    {
        "id": "google-adk-e2b-env-skill-toolset",
        "path": "contributing/samples/environment_and_skills/e2b_env_skill_toolset",
        "kind": "bound_sample",
    },
    {
        "id": "google-adk-skills-agent-gcs",
        "path": "contributing/samples/environment_and_skills/skills_agent_gcs",
        "kind": "dynamic_remote_sample",
    },
]


def _run(args: list[str], cwd: Path | None = None) -> None:
    subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def _checkout(repo: str, sha: str, paths: list[str], dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    _run(["git", "init", "-q"], dest)
    _run(["git", "remote", "add", "origin", repo], dest)
    _run(["git", "sparse-checkout", "init", "--cone"], dest)
    _run(["git", "sparse-checkout", "set", *paths], dest)
    _run(["git", "fetch", "--depth", "1", "origin", sha], dest)
    _run(["git", "checkout", "--detach", "FETCH_HEAD"], dest)


def _skill_summary(skill) -> dict[str, object]:
    metadata = skill.metadata if isinstance(skill.metadata, dict) else {}
    return {
        "name": skill.name,
        "source": str(skill.location.path) if skill.location else None,
        "allowed_tools": list(skill.allowed_tools),
        "scripts": list(skill.scripts),
        "capabilities": sorted(skill.capabilities),
        "binding_state": metadata.get("binding_state"),
        "binding_origin": metadata.get("binding_origin"),
        "broad_tool_surface": metadata.get("broad_tool_surface"),
        "declared_instruction_capabilities": metadata.get(
            "declared_instruction_capabilities"
        ),
        "script_count": metadata.get("script_count"),
        "reference_count": metadata.get("reference_count"),
        "adk_script_execution": metadata.get("adk_script_execution"),
        "adk_additional_tools": metadata.get("adk_additional_tools"),
    }


def _scan_target(
    target_id: str,
    kind: str,
    root: Path,
    *,
    repo: str,
    sha: str,
) -> dict[str, object]:
    try:
        graph, findings = scan(root)
        relationships = effective_authority_relationships(graph)
    except Exception as exc:
        return {
            "id": target_id,
            "kind": kind,
            "repo": repo,
            "sha": sha,
            "root": str(root),
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        }

    bound = []
    for agent in graph.agents:
        for skill in agent.skills:
            bound.append(
                {
                    "agent": agent.name,
                    **_skill_summary(skill),
                }
            )

    unbound = [_skill_summary(skill) for skill in graph.unbound_skills]
    skill_relationships = [
        {
            "agent": item.agent,
            "target_kind": item.target_kind,
            "target_name": item.target_name,
            "resolution": item.resolution,
            "unresolved": list(item.unresolved),
            "semantics": item.semantics,
        }
        for item in relationships
        if item.target_kind == "skill"
    ]
    semantic_rule_ids = {
        f"SKL{number:03d}" for number in range(20, 31)
    }
    semantic_findings = [
        {
            "rule_id": finding.rule_id,
            "agent": finding.agent,
            "title": finding.title,
        }
        for finding in findings
        if finding.rule_id in semantic_rule_ids
    ]
    all_skill_findings = [
        {
            "rule_id": finding.rule_id,
            "agent": finding.agent,
            "title": finding.title,
        }
        for finding in findings
        if finding.rule_id.startswith("SKL")
    ]

    diagnostics = [
        {
            "code": getattr(item, "code", ""),
            "message": getattr(item, "message", ""),
            "details": getattr(item, "details", None),
        }
        for item in graph.coverage.diagnostics
        if "skill" in getattr(item, "code", "").lower()
        or "skill" in getattr(item, "message", "").lower()
    ]

    checks: dict[str, bool] = {
        "scan_completed": True,
        "skill_inventory_present": bool(bound or unbound),
        "semantic_findings_require_bound_skill": not semantic_findings or bool(bound),
    }
    if kind == "catalog":
        checks["catalog_skills_discovered"] = bool(unbound or bound)
    elif kind == "bound_sample":
        checks["bound_skill_discovered"] = bool(bound)
        checks["skill_authority_relationship_projected"] = bool(skill_relationships)
    elif kind == "dynamic_remote_sample":
        checks["dynamic_or_remote_skill_unresolved"] = any(
            item["code"] == "unresolved_skill" for item in diagnostics
        )

    return {
        "id": target_id,
        "kind": kind,
        "repo": repo,
        "sha": sha,
        "root": str(root),
        "status": "completed",
        "checks": checks,
        "agents": len(graph.agents),
        "bound_skill_count": len(bound),
        "unbound_skill_count": len(unbound),
        "bound_skills": bound,
        "unbound_skill_sample": unbound[:30],
        "skill_relationships": skill_relationships,
        "semantic_findings": semantic_findings,
        "skill_findings": all_skill_findings,
        "skill_diagnostics": diagnostics,
        "coverage_resolution": graph.coverage.resolution,
    }


def main() -> int:
    out_dir = Path("artifacts/skill-real-world-v1")
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="horustrace-real-skills-") as raw:
        workspace = Path(raw)

        for item in CATALOGS:
            checkout = workspace / item["id"]
            try:
                _checkout(item["repo"], item["sha"], item["sparse"], checkout)
                results.append(
                    _scan_target(
                        item["id"],
                        item["kind"],
                        checkout / item["scan_root"],
                        repo=item["repo"],
                        sha=item["sha"],
                    )
                )
            except Exception as exc:
                results.append(
                    {
                        "id": item["id"],
                        "kind": item["kind"],
                        "repo": item["repo"],
                        "sha": item["sha"],
                        "status": "checkout_error",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )

        adk_checkout = workspace / "google-adk-python"
        try:
            _checkout(
                ADK_REPO,
                ADK_SHA,
                [item["path"] for item in ADK_SAMPLES],
                adk_checkout,
            )
            for item in ADK_SAMPLES:
                results.append(
                    _scan_target(
                        item["id"],
                        item["kind"],
                        adk_checkout / item["path"],
                        repo=ADK_REPO,
                        sha=ADK_SHA,
                    )
                )
        except Exception as exc:
            for item in ADK_SAMPLES:
                results.append(
                    {
                        "id": item["id"],
                        "kind": item["kind"],
                        "repo": ADK_REPO,
                        "sha": ADK_SHA,
                        "status": "checkout_error",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )

    completed = [item for item in results if item.get("status") == "completed"]
    errors = [item for item in results if item.get("status") != "completed"]
    failed_checks = [
        {
            "id": item["id"],
            "failed": [
                key
                for key, value in item.get("checks", {}).items()
                if value is False
            ],
        }
        for item in completed
        if any(value is False for value in item.get("checks", {}).values())
    ]

    summary = {
        "study": "skill-real-world-v1",
        "targets": len(results),
        "completed": len(completed),
        "errors": len(errors),
        "failed_check_targets": len(failed_checks),
        "total_bound_skills": sum(
            int(item.get("bound_skill_count", 0)) for item in completed
        ),
        "total_unbound_skills": sum(
            int(item.get("unbound_skill_count", 0)) for item in completed
        ),
        "semantic_findings": sum(
            len(item.get("semantic_findings", [])) for item in completed
        ),
        "failed_checks": failed_checks,
    }

    (out_dir / "results.json").write_text(
        json.dumps({"summary": summary, "targets": results}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Real-world Agent Skills study v1",
        "",
        "| Metric | Result |",
        "| --- | ---: |",
        f"| Targets | {summary['targets']} |",
        f"| Completed | {summary['completed']} |",
        f"| Infrastructure/scan errors | {summary['errors']} |",
        f"| Targets with failed study checks | {summary['failed_check_targets']} |",
        f"| Bound Skills | {summary['total_bound_skills']} |",
        f"| Unbound Skills | {summary['total_unbound_skills']} |",
        f"| Semantic SKL020-SKL030 findings | {summary['semantic_findings']} |",
        "",
        "## Targets",
        "",
        "| Target | Kind | Status | Agents | Bound | Unbound | Semantic findings | Failed checks |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for item in results:
        failed = [
            key
            for key, value in item.get("checks", {}).items()
            if value is False
        ]
        lines.append(
            f"| {item['id']} | {item['kind']} | {item['status']} | "
            f"{item.get('agents', 0)} | {item.get('bound_skill_count', 0)} | "
            f"{item.get('unbound_skill_count', 0)} | "
            f"{len(item.get('semantic_findings', []))} | "
            f"{', '.join(failed) or '-'} |"
        )

    if errors:
        lines.extend(["", "## Errors", ""])
        for item in errors:
            lines.append(f"- **{item['id']}**: {item.get('error')}")

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "This first real-world run deliberately disables LLM semantics. It tests the "
            "deterministic Skill discovery, binding, unresolved-source, script/executor "
            "and Effective Authority projection layers against pinned public source. "
            "Semantic classification of the bound real-world Skills is adjudicated "
            "separately in-chat so no API credential is required.",
            "",
        ]
    )

    (out_dir / "summary.md").write_text(
        "\n".join(lines),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
