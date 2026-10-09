"""Collect exact pinned source excerpts for every cdxgen model observation.

This is evidence extraction, NOT an independent LLM review, runtime claim,
or classifier precision assessment. Target source is never imported/executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

PILOT=Path(__file__).resolve().parents[1] / "independent-20261008-pilot12"
sys.path.insert(0,str(PILOT))
import subprocess

CONFIG=json.loads((PILOT / "cohort.json").read_text(encoding="utf-8"))

def run(argv):
    p=subprocess.run(argv,text=True,capture_output=True,timeout=1200)
    if p.returncode:raise RuntimeError(f"git failed: {p.stderr[-3000:]}")
    return p.stdout.strip()

def clone_case(root,case):
    target=root/"target"
    run(["git","init","-q",str(target)])
    run(["git","-C",str(target),"remote","add","origin",f"https://github.com/{case['repo']}.git"])
    run(["git","-C",str(target),"fetch","--quiet","--depth=1","--filter=blob:none","origin",case["sha"]])
    run(["git","-C",str(target),"checkout","--quiet","--detach","FETCH_HEAD"])
    if run(["git","-C",str(target),"rev-parse","HEAD"])!=case["sha"]:
        raise ValueError("target SHA mismatch")
    return target

def application_root(target,case):
    app=(target / (case.get("application_path") or ".")).resolve()
    app.relative_to(target.resolve())
    if not app.exists():raise ValueError("missing application root")
    return app


def props(x,name):
    return [p.get("value") for p in x.get("properties",[]) if isinstance(p,dict) and p.get("name")==name]

def source_rel(path):
    path=str(path or "").replace("\\","/")
    if "/target/" in path: return path.rsplit("/target/",1)[1]
    if path.startswith("target/"): return path[len("target/"):]
    return path.lstrip("./")

def inspect_source(root:Path, loc:str):
    raw=str(loc or "")
    match=re.match(r"^(.*?)#L(\d+)$",raw)
    path=source_rel(match.group(1) if match else raw)
    line=int(match.group(2)) if match else None
    info={"original":raw,"source_path":path,"source_line":line}
    try:
        file=(root/path).resolve()
        file.relative_to(root.resolve())
        if not file.is_file():
            raise ValueError("source file absent or not regular file")
        if file.stat().st_size>5_000_000:
            raise ValueError("source file exceeds 5MB source-only threshold")
        text=file.read_text("utf-8")
        lines=text.splitlines()
        if line is None or line<1 or line>len(lines):
            raise ValueError(f"anchor line outside file: {line}/{len(lines)}")
        lo=max(1,line-3);hi=min(len(lines),line+3)
        info.update({"status":"exact_sha_source_read","file_sha256":hashlib.sha256(text.encode("utf-8")).hexdigest(),
                     "line_count":len(lines),"excerpt_first_line":lo,
                     "excerpt":[{"line":i,"text":lines[i-1]} for i in range(lo,hi+1)]})
    except Exception as exc:
        info.update({"status":"source_unavailable_or_unresolved","error":str(exc)})
    return info

def skill_files(root:Path,scan:dict,cdx:list):
    h=(scan.get("skills") or {})
    observed={}
    for s in h.get("unbound",[])+h.get("bound",[]):
        path=source_rel((s.get("location") or {}).get("path"))
        if path: observed.setdefault(path,{}).update({"horus":True,"name":s.get("name")})
    for c in cdx:
        if "skill-file" not in props(c,"cdx:file:kind"):continue
        path=source_rel((props(c,"internal:SrcFile") or [""])[0])
        observed.setdefault(path,{}).update({"cdx":True,"cdx_name":c.get("name")})
    out=[]
    for path,v in sorted(observed.items()):
        p=root/path
        rec={"path":path,"reported_by":sorted(k for k in ("horus","cdx") if v.get(k)),
             "skill_name":v.get("name") or v.get("cdx_name")}
        try:
            if p.is_file():
                data=p.read_bytes()
                rec.update({"status":"verified_on_pinned_source","file_sha256":hashlib.sha256(data).hexdigest(),
                            "has_yaml_frontmatter":data.startswith(b"---\n")})
            else:
                rec.update({"status":"unavailable","reason":"not a regular file at pinned tree"})
        except Exception as exc:rec.update({"status":"unavailable","reason":str(exc)})
        out.append(rec)
    # Enumerate symlinks in repo source, avoid executing contents.
    aliases=[]
    for p in sorted((root/".claude"/"skills").glob("*")):
        if p.is_symlink():
            link=p.readlink()
            resolved=(p.parent/link).resolve()
            try:rel=str(resolved.relative_to(root.resolve()))
            except ValueError:rel="OUT_OF_REPO"
            aliases.append({"path":str(p.relative_to(root)),"raw_link_target":str(link),
                            "resolved_target_path":rel,
                            "target_exists":resolved.exists(),
                            "target_skill_md_exists":(resolved/"SKILL.md").is_file()})
    return {"file_observations":out,"git_symlink_aliases":aliases}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--case-id",required=True)
    parser.add_argument("--input",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    case=next(x for x in CONFIG["cases"] if x["case_id"]==args.case_id)
    def read(n):return json.loads((args.input/n).read_text("utf-8"))
    meta=read("result.json")
    if (meta["case_id"],meta["sha"],meta["repo"])!=(case["case_id"],case["sha"],case["repo"]):
        raise ValueError("artifacts do not match frozen case manifest")
    ai=read("cdxgen-ai-observations.json")
    sk=read("cdxgen-ai-skill-observations.json")
    scan=read("horusscan-scan.json")
    with tempfile.TemporaryDirectory(prefix="pilot12-sourcecheck-") as tmp:
        src=clone_case(Path(tmp),case)
        app=application_root(src,case)
        evidence=[]
        for component in ai:
            if component.get("cyclonedx_type")!="machine-learning-model":continue
            locs=[o.get("location") for o in (component.get("evidence") or {}).get("occurrences",[]) if o.get("location")]
            evidence.append({"name":component.get("name"),"provider":props(component,"cdx:ai:provider"),
                             "source_occurrences_total":len(locs),
                             "source_anchors":[inspect_source(src,loc) for loc in locs],
                             "extraction_assessment":"candidate_only_not_source_adjudicated"})
        skill=skill_files(src,scan,sk)
    result={"study":"cdxgen-pilot12-20261009","case_id":case["case_id"],
            "repo":case["repo"],"sha":case["sha"],"application_path":case.get("application_path"),
            "cdx_model_records":len(evidence),"models":evidence,"skills":skill,
            "source_anchor_reads":sum(x["status"]=="exact_sha_source_read" for m in evidence for x in m["source_anchors"]),
            "source_anchor_unresolved":sum(x["status"]!="exact_sha_source_read" for m in evidence for x in m["source_anchors"]),
            "quality_status":"source-excerpt-collection-only-no-independent-adjudication"}
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/"source-evidence.json").write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("case_id","cdx_model_records","source_anchor_reads","source_anchor_unresolved")}))
    return 0 if not result["source_anchor_unresolved"] else 1

if __name__=="__main__":
    raise SystemExit(main())
