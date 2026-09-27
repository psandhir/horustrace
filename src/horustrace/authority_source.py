"""Offline enrichment from a separately checked-out Terraform authority repository."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from horustrace.adapters.iac_identity import scan_terraform
from horustrace.limits import MAX_FILE_SIZE_BYTES, MAX_FILES_VISITED
from horustrace.models import EvidenceFact, Graph, Identity, SourceLocation
from horustrace.path_safety import canonical_root, is_within_root
from horustrace.principals import normalize_gcp_service_account

_IGNORED_DIRS = {
    ".git",
    ".terraform",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
}
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
_GITHUB_HTTP_RE = re.compile(
    r"^https?://(?:[^/@]+@)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
_GITHUB_SSH_RE = re.compile(
    r"^(?:ssh://)?git@github\.com[:/]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


class AuthoritySourceError(ValueError):
    """An explicit authority source could not be analyzed safely."""


@dataclass(frozen=True, slots=True)
class AuthorityEnrichmentResult:
    source: str
    repository: str | None
    commit: str | None
    terraform_files: int
    discovered_service_accounts: int
    matched_identities: int
    matched_bindings: int
    unmatched_service_accounts: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "terraform",
            "state": "declared",
            "source": self.source,
            "repository": self.repository,
            "commit": self.commit,
            "terraform_files": self.terraform_files,
            "discovered_service_accounts": self.discovered_service_accounts,
            "matched_identities": self.matched_identities,
            "matched_bindings": self.matched_bindings,
            "unmatched_service_accounts": self.unmatched_service_accounts,
        }


def _run_git(root: Path, args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def _git_commit(root: Path) -> str | None:
    value = _run_git(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    if value is None:
        return None
    lowered = value.lower()
    return lowered if _FULL_SHA_RE.fullmatch(lowered) else None


def _github_repository(root: Path) -> str | None:
    value = _run_git(root, ["config", "--get", "remote.origin.url"])
    if value is None:
        return None
    for pattern in (_GITHUB_HTTP_RE, _GITHUB_SSH_RE):
        match = pattern.fullmatch(value.strip())
        if match:
            owner, repo = match.groups()
            return f"https://github.com/{owner}/{repo}"
    return None


def _authority_files(root: Path) -> list[Path]:
    containment_root = canonical_root(root)
    files: list[Path] = []
    visited = 0
    for candidate in root.rglob("*"):
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            continue
        if any(part in _IGNORED_DIRS for part in relative.parts):
            continue
        if not candidate.is_file():
            continue
        visited += 1
        if visited > MAX_FILES_VISITED:
            raise AuthoritySourceError(
                f"{root}: authority-source traversal exceeds the "
                f"{MAX_FILES_VISITED}-file safety limit"
            )
        if candidate.suffix.lower() != ".tf":
            continue
        if not is_within_root(candidate, containment_root):
            raise AuthoritySourceError(
                f"{candidate}: Terraform authority source resolves outside its repository"
            )
        try:
            if candidate.stat().st_size > MAX_FILE_SIZE_BYTES:
                raise AuthoritySourceError(
                    f"{candidate}: Terraform authority source exceeds the file safety limit"
                )
            candidate.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise AuthoritySourceError(
                f"{candidate}: Terraform authority source is not valid UTF-8"
            ) from exc
        except OSError as exc:
            raise AuthoritySourceError(
                f"{candidate}: cannot inspect Terraform authority source"
            ) from exc
        files.append(candidate)
    return sorted(files)


def _safe_location(root: Path, location: SourceLocation | None) -> SourceLocation | None:
    if location is None:
        return None
    try:
        relative = location.path.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return SourceLocation(
        path=Path(root.name) / relative,
        line=location.line,
        column=location.column,
    )


def _binding_record(
    root: Path,
    source: Identity,
    *,
    repository: str | None,
    commit: str | None,
) -> dict[str, Any]:
    safe_location = _safe_location(root, source.location)
    return {
        "state": "declared",
        "provider": "gcp",
        "roles": sorted(source.roles),
        "resource_scope": source.resource_scope,
        "terraform_resource": source.metadata.get("terraform_resource"),
        "repository": repository,
        "commit": commit,
        "path": str(safe_location.path) if safe_location else None,
        "line": safe_location.line if safe_location else None,
    }


def enrich_from_terraform_authority_source(
    graph: Graph,
    source_path: Path,
) -> AuthorityEnrichmentResult:
    """Enrich only already-discovered GCP service-account identities from Terraform."""
    root = source_path.resolve()
    if not root.exists():
        raise AuthoritySourceError(f"{source_path}: authority source does not exist")
    if not root.is_dir():
        raise AuthoritySourceError(f"{source_path}: authority source must be a directory")

    repository = _github_repository(root)
    commit = _git_commit(root)
    targets: dict[str, list[Identity]] = {}
    for identity in graph.all_identities():
        if identity.provider not in {"gcp", "generic"}:
            continue
        canonical = normalize_gcp_service_account(identity.name)
        if canonical is None:
            continue
        bucket = targets.setdefault(canonical, [])
        if all(id(existing) != id(identity) for existing in bucket):
            bucket.append(identity)

    files = _authority_files(root)
    discovered: set[str] = set()
    matched_names: set[str] = set()
    matched_bindings = 0
    scopes_by_target: dict[int, set[str]] = {}
    targets_by_id: dict[int, Identity] = {}

    for path in files:
        terraform_graph = scan_terraform(path)
        for source in terraform_graph.identities:
            if source.provider != "gcp":
                continue
            canonical = normalize_gcp_service_account(source.name)
            if canonical is None:
                continue
            discovered.add(canonical)
            matched_targets = targets.get(canonical, [])
            if not matched_targets:
                continue
            matched_names.add(canonical)
            matched_bindings += 1
            record = _binding_record(
                root,
                source,
                repository=repository,
                commit=commit,
            )
            for target in matched_targets:
                targets_by_id[id(target)] = target
                if target.provider == "generic":
                    target.provider = "gcp"
                target.roles.update(source.roles)
                if source.resource_scope:
                    scopes_by_target.setdefault(id(target), set()).add(source.resource_scope)

                metadata = target.metadata.setdefault(
                    "declared_authority",
                    {
                        "state": "declared",
                        "kind": "terraform",
                        "repository": repository,
                        "commit": commit,
                        "source": root.name,
                        "bindings": [],
                    },
                )
                bindings = metadata.setdefault("bindings", [])
                if record not in bindings:
                    bindings.append(record)

                safe_location = _safe_location(root, source.location)
                role_text = ",".join(sorted(source.roles)) or "unknown"
                scope_text = source.resource_scope or "unknown"
                fact = EvidenceFact(
                    subject=target.name,
                    fact=f"declared_roles={role_text};resource_scope={scope_text}",
                    origin="terraform_authority_source",
                    location=safe_location,
                )
                if fact not in target.provenance:
                    target.provenance.append(fact)

    for target_id, scopes in scopes_by_target.items():
        target = targets_by_id[target_id]
        if target.resource_scope is None and len(scopes) == 1:
            target.resource_scope = next(iter(scopes))

    return AuthorityEnrichmentResult(
        source=root.name,
        repository=repository,
        commit=commit,
        terraform_files=len(files),
        discovered_service_accounts=len(discovered),
        matched_identities=len(matched_names),
        matched_bindings=matched_bindings,
        unmatched_service_accounts=len(discovered - set(targets)),
    )
