"""Discover literal repository-declared IAM/RBAC bindings for deployment evidence."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from horustrace.deployment_evidence import IAMBindingEvidence
from horustrace.principals import canonical_principal

_RESOURCE_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
_LITERAL_ATTR = r'\b{attribute}\s*=\s*"([^"]+)"'
_LIST_ATTR = r"\b{attribute}\s*=\s*\[([^\]]*)\]"
_QUOTED = re.compile(r'"([^"]+)"')

_GCP_IAM_RESOURCES: dict[str, tuple[str, str, str]] = {
    "google_project_iam_member": ("project", "project", "member"),
    "google_project_iam_binding": ("project", "project", "members"),
    "google_folder_iam_member": ("folder", "folder", "member"),
    "google_folder_iam_binding": ("folder", "folder", "members"),
    "google_organization_iam_member": ("organization", "org_id", "member"),
    "google_organization_iam_binding": ("organization", "org_id", "members"),
    "google_service_account_iam_member": ("service_account", "service_account_id", "member"),
    "google_service_account_iam_binding": ("service_account", "service_account_id", "members"),
}


def _blocks(text: str):
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        match = _RESOURCE_RE.match(lines[index])
        if not match:
            index += 1
            continue
        resource_type, resource_name = match.groups()
        start = index
        depth = lines[index].count("{") - lines[index].count("}")
        index += 1
        while index < len(lines) and depth > 0:
            depth += lines[index].count("{") - lines[index].count("}")
            index += 1
        yield resource_type, resource_name, start + 1, "\n".join(lines[start:index])


def _literal(block: str, attribute: str) -> str | None:
    match = re.search(_LITERAL_ATTR.format(attribute=re.escape(attribute)), block)
    return match.group(1).strip() if match else None


def _literal_list(block: str, attribute: str) -> list[str]:
    match = re.search(
        _LIST_ATTR.format(attribute=re.escape(attribute)),
        block,
        flags=re.DOTALL,
    )
    return [value.strip() for value in _QUOTED.findall(match.group(1))] if match else []


def discover_terraform_bindings(path: Path) -> tuple[list[IAMBindingEvidence], list[dict[str, Any]]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], []

    bindings: list[IAMBindingEvidence] = []
    unresolved: list[dict[str, Any]] = []
    for resource_type, resource_name, line, block in _blocks(text):
        config = _GCP_IAM_RESOURCES.get(resource_type)
        if config is not None:
            scope_kind, scope_attr, principal_attr = config
            role = _literal(block, "role")
            scope = _literal(block, scope_attr)
            principals = (
                [_literal(block, principal_attr)]
                if principal_attr == "member"
                else _literal_list(block, principal_attr)
            )
            principals = [item for item in principals if item]
            canonical = [
                canonical_principal("gcp", principal)
                for principal in principals
            ]
            if role is None or scope is None or not canonical or any(x is None for x in canonical):
                unresolved.append({
                    "provider": "gcp",
                    "kind": "iam_binding",
                    "name": resource_name,
                    "reason": "non_literal_or_unsupported_iam_binding",
                    "path": str(path),
                    "line": line,
                })
                continue
            for principal in canonical:
                assert principal is not None
                bindings.append(IAMBindingEvidence(
                    principal=principal,
                    role=role,
                    scope_kind=scope_kind,
                    scope_name=scope,
                    metadata={
                        "evidence_kind": "terraform",
                        "terraform_resource": resource_type,
                        "path": str(path),
                        "line": line,
                    },
                ))
            continue

        if resource_type == "azurerm_role_assignment":
            principal = _literal(block, "principal_id")
            role = _literal(block, "role_definition_name") or _literal(block, "role_definition_id")
            scope = _literal(block, "scope")
            canonical = canonical_principal("azure", principal) if principal else None
            if canonical is None or role is None or scope is None:
                unresolved.append({
                    "provider": "azure",
                    "kind": "role_assignment",
                    "name": resource_name,
                    "reason": "non_literal_or_unsupported_role_assignment",
                    "path": str(path),
                    "line": line,
                })
                continue
            bindings.append(IAMBindingEvidence(
                principal=canonical,
                role=role,
                scope_kind="azure_scope",
                scope_name=scope,
                metadata={
                    "evidence_kind": "terraform",
                    "terraform_resource": resource_type,
                    "path": str(path),
                    "line": line,
                },
            ))
    return bindings, unresolved


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def discover_kubernetes_bindings(path: Path) -> tuple[list[IAMBindingEvidence], list[dict[str, Any]]]:
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return [], []

    bindings: list[IAMBindingEvidence] = []
    unresolved: list[dict[str, Any]] = []
    for raw in documents:
        document = _mapping(raw)
        kind = document.get("kind")
        if kind not in {"RoleBinding", "ClusterRoleBinding"}:
            continue
        metadata = _mapping(document.get("metadata"))
        name = metadata.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        name = name.strip()
        role_ref = _mapping(document.get("roleRef"))
        role_kind = role_ref.get("kind")
        role_name = role_ref.get("name")
        subjects = document.get("subjects")
        if role_kind not in {"Role", "ClusterRole"} or not isinstance(role_name, str) or not isinstance(subjects, list):
            unresolved.append({
                "provider": "kubernetes",
                "kind": str(kind).lower(),
                "name": name,
                "reason": "incomplete_role_binding",
                "path": str(path),
                "line": None,
            })
            continue

        for raw_subject in subjects:
            subject = _mapping(raw_subject)
            if subject.get("kind") != "ServiceAccount":
                continue
            subject_name = subject.get("name")
            subject_namespace = subject.get("namespace")
            if not isinstance(subject_name, str) or not isinstance(subject_namespace, str):
                unresolved.append({
                    "provider": "kubernetes",
                    "kind": str(kind).lower(),
                    "name": name,
                    "reason": "service_account_subject_not_explicit",
                    "path": str(path),
                    "line": None,
                })
                continue
            principal = canonical_principal(
                "kubernetes",
                f"{subject_namespace.strip()}/{subject_name.strip()}",
            )
            if principal is None:
                continue
            if kind == "RoleBinding":
                namespace = metadata.get("namespace")
                if not isinstance(namespace, str) or not namespace.strip():
                    unresolved.append({
                        "provider": "kubernetes",
                        "kind": "rolebinding",
                        "name": name,
                        "reason": "binding_namespace_not_explicit",
                        "path": str(path),
                        "line": None,
                    })
                    continue
                scope_kind, scope_name = "namespace", namespace.strip()
            else:
                scope_kind, scope_name = "cluster", "cluster"
            bindings.append(IAMBindingEvidence(
                principal=principal,
                role=f"k8s:{role_kind}/{role_name.strip()}",
                scope_kind=scope_kind,
                scope_name=scope_name,
                metadata={
                    "evidence_kind": "kubernetes_rbac",
                    "binding_kind": kind,
                    "binding_name": name,
                    "path": str(path),
                },
            ))
    return bindings, unresolved
