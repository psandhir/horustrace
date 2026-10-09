"""Pinned, source-only cdxgen vs HorusScan inventory study. No target dependencies are installed."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import traceback
from collections import Counter
from pathlib import Path

PILOT = Path(__file__).resolve().parents[1] / "independent-20261008-pilot12"
sys.path.insert(0, str(PILOT))
from run_case import CONFIG, application_root, clone_case, agent_inventory  # noqa: E402

MODES = ("ai", "mcp", "ai-skill")


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")


def invoke(argv: list[str], *, cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)


def inventory_summary(bom: dict, mode: str) -> dict:
    components = bom.get("components") if isinstance(bom.get("components"), list) else []
    services = bom.get("services") if isinstance(bom.get("services"), list) else []
    dependencies = bom.get("dependencies") if isinstance(bom.get("dependencies"), list) else []
    observations = []
    for item in components:
        if not isinstance(item, dict):
            continue
        observations.append({
            "mode": mode,
            "record_kind": "component",
            "name": item.get("name"),
            "bom_ref": item.get("bom-ref"),
            "cyclonedx_type": item.get("type"),
            "group": item.get("group"),
            "purl": item.get("purl"),
            "properties": item.get("properties") or [],
            "evidence": item.get("evidence") or {},
        })
    for item in services:
        if not isinstance(item, dict):
            continue
        observations.append({
            "mode": mode,
            "record_kind": "service",
            "name": item.get("name"),
            "bom_ref": item.get("bom-ref"),
            "endpoints": item.get("endpoints") or [],
            "properties": item.get("properties") or [],
            "evidence": item.get("evidence") or {},
        })
    return {
        "components": len(components),
        "services": len(services),
        "dependencies": len(dependencies),
        "component_types": dict(sorted(Counter(str(x.get("type", "unspecified")) for x in components if isinstance(x, dict)).items())),
        "observations": observations,
    }


def run_case(case: dict, output_root: Path) -> int:
    out = output_root / case["case_id"]
    out.mkdir(parents=True, exist_ok=True)
    result: dict = {
        "schema_version": 1,
        "study": "cdxgen-pilot12-20261009",
        "case_id": case["case_id"],
        "framework": case["framework"],
        "repo": case["repo"],
        "sha": case["sha"],
        "application_path": case.get("application_path") or ".",
        "cdxgen_version_pin": "13.3.0",
        "cdxgen": {},
        "horusscan": {},
        "limitations": [
            "Inventory quantities are not precision/recall or semantic correctness.",
            "cdxgen project modes are not synonymous with component semantic types.",
            "LLM source-review verdicts are not automatically assumed.",
            "No runtime execution or deployed-authority assertions are made.",
        ],
    }
    try:
        with tempfile.TemporaryDirectory(prefix="cdxgen-pilot12-") as tmp:
            target = clone_case(Path(tmp), case)
            app = application_root(target, case)
            sha = invoke(["git", "-C", str(target), "rev-parse", "HEAD"])
            if sha.returncode != 0 or sha.stdout.strip() != case["sha"]:
                raise RuntimeError("target commit failed immutable SHA check")
            result["source_verified"] = True
            for mode in MODES:
                bom_path = out / f"cdxgen-{mode}.json"
                proc = invoke(
                    [
                        "cdxgen", "-t", mode, "--no-install-deps",
                        "--spec-version", "1.7", "-o", str(bom_path.resolve()),
                        str(app.resolve()),
                    ],
                    timeout=900,
                )
                (out / f"cdxgen-{mode}.log").write_text(
                    (proc.stdout + "\n--- STDERR ---\n" + proc.stderr)[-30000:],
                    encoding="utf-8",
                )
                entry: dict = {"exit_code": proc.returncode, "bom_file": bom_path.name}
                if proc.returncode == 0 and bom_path.exists():
                    try:
                        bom = json.loads(bom_path.read_text(encoding="utf-8"))
                        if bom.get("bomFormat") != "CycloneDX" or not isinstance(bom.get("components", []), list):
                            raise ValueError("invalid or unexpected BOM shape")
                        detail = inventory_summary(bom, mode)
                        write_json(out / f"cdxgen-{mode}-observations.json", detail["observations"])
                        entry.update({k: v for k, v in detail.items() if k != "observations"})
                        entry["status"] = "ok"
                    except (ValueError, json.JSONDecodeError) as exc:
                        entry["status"] = "invalid_output"
                        entry["error"] = str(exc)
                else:
                    entry["status"] = "failed"
                    entry["error"] = proc.stderr[-2000:]
                result["cdxgen"][mode] = entry

            # Use the same source tree and repository revision as cdxgen, not
            # a separate clone or a historical aggregate from another revision.
            scan_json = out / "horusscan-scan.json"
            scan_proc = invoke([
                "horustrace", "scan", str(app), "--format", "json",
                "--output", str(scan_json.resolve()), "--fail-on", "none",
            ], timeout=900)
            graph_proc = invoke(["horustrace", "security-graph", str(app)], timeout=900)
            if scan_proc.returncode == 0 and graph_proc.returncode == 0 and scan_json.exists():
                scan_doc = json.loads(scan_json.read_text(encoding="utf-8"))
                graph_doc = json.loads(graph_proc.stdout)
                write_json(out / "horusscan-security-graph.json", graph_doc)
                from horustrace.scanner import scan  # noqa: PLC0415
                from horustrace.effective_authority import effective_authority_report  # noqa: PLC0415
                graph, _ = scan(app)
                agent_rows = agent_inventory(graph)
                authority = effective_authority_report(graph)
                write_json(out / "horusscan-authority.json", authority)
                write_json(out / "horusscan-agents.json", agent_rows)
                finding_rows = scan_doc.get("findings") or []
                path_rows = graph_doc.get("attack_paths") or []
                auth_summary = authority.get("summary") or {}
                result["horusscan"] = {
                    "status": "ok",
                    "counts": {
                        "agents": len(agent_rows),
                        "tools": sum(len(a.get("tools") or []) for a in agent_rows),
                        "mcp_bindings": sum(len(a.get("mcp_servers") or []) for a in agent_rows),
                        "skill_bindings": sum(len(a.get("skills") or []) for a in agent_rows),
                        "identities": sum(len(a.get("identities") or []) for a in agent_rows),
                        "findings": len(finding_rows),
                        "attack_paths": len(path_rows),
                        "authority_relationships": int(auth_summary.get("relationships") or len(authority.get("relationships") or [])),
                    },
                }
            else:
                result["horusscan"] = {
                    "status": "failed",
                    "scan_exit": scan_proc.returncode,
                    "graph_exit": graph_proc.returncode,
                    "error": (scan_proc.stderr + "\n" + graph_proc.stderr)[-3000:],
                }
            (out / "horusscan.log").write_text(
                ("SCAN\n" + scan_proc.stderr + "\nGRAPH\n" + graph_proc.stderr)[-30000:],
                encoding="utf-8",
            )
    except Exception as exc:
        result["error"] = str(exc)
        result["traceback"] = traceback.format_exc()[-6000:]
    result["status"] = (
        "complete" if not result.get("error")
        and result["horusscan"].get("status") == "ok"
        and all(result["cdxgen"].get(mode, {}).get("status") == "ok" for mode in MODES)
        else "incomplete"
    )
    write_json(out / "result.json", result)
    print(json.dumps({
        "case_id": case["case_id"],
        "status": result["status"],
        "cdxgen_modes": {k: v.get("status") for k, v in result["cdxgen"].items()},
        "horusscan": result["horusscan"].get("status"),
        "error": result.get("error"),
    }, indent=2))
    return 0 if result["status"] == "complete" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = parser.parse_args()
    matches = [x for x in CONFIG["cases"] if x["case_id"] == args.case_id]
    if len(matches) != 1:
        parser.error("case ID must be exactly one entry in the locked pilot manifest")
    return run_case(matches[0], args.output_dir)


if __name__ == "__main__":
    raise SystemExit(main())
