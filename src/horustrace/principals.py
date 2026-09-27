"""Provider-neutral canonicalization for repository-declared workload identities.

This module is deliberately syntactic and offline-only. It normalizes only identity
forms whose canonical representation can be established without contacting a cloud or
cluster API. Unsupported/dynamic forms return None and remain unresolved upstream.
"""
from __future__ import annotations

import re

_GCP_SERVICE_ACCOUNT_RE = re.compile(
    r"^[^@\s:/]+@[^@\s/]+\.gserviceaccount\.com$",
    re.IGNORECASE,
)
_AWS_IAM_ROLE_ARN_RE = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z0-9-]+)?):iam::(?P<account>[0-9]{12}):role/(?P<name>[^\s]+)$"
)
_AZURE_OBJECT_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_K8S_CANONICAL_RE = re.compile(
    r"^system:serviceaccount:(?P<namespace>[a-z0-9]([-a-z0-9]*[a-z0-9])?):(?P<name>[a-z0-9]([-a-z0-9.]*[a-z0-9])?)$"
)
_K8S_SHORT_RE = re.compile(
    r"^(?P<namespace>[a-z0-9]([-a-z0-9]*[a-z0-9])?)/(?P<name>[a-z0-9]([-a-z0-9.]*[a-z0-9])?)$"
)


def normalize_gcp_service_account(value: str) -> str | None:
    principal = value.strip()
    if principal.lower().startswith("serviceaccount:"):
        principal = principal.split(":", 1)[1]
    if "/serviceAccounts/" in principal:
        principal = principal.rsplit("/serviceAccounts/", 1)[1]
    principal = principal.strip().lower()
    if not _GCP_SERVICE_ACCOUNT_RE.fullmatch(principal):
        return None
    return principal


def normalize_aws_role(value: str) -> str | None:
    """Normalize a literal IAM role ARN without rewriting the role path/name."""
    principal = value.strip()
    match = _AWS_IAM_ROLE_ARN_RE.fullmatch(principal)
    if not match:
        return None
    return (
        f"arn:{match.group('partition').lower()}:iam::"
        f"{match.group('account')}:role/{match.group('name')}"
    )


def normalize_azure_principal(value: str) -> str | None:
    """Normalize an Azure Entra object/principal UUID used by role assignments."""
    principal = value.strip()
    if not _AZURE_OBJECT_ID_RE.fullmatch(principal):
        return None
    return principal.lower()


def normalize_kubernetes_service_account(value: str) -> str | None:
    """Normalize canonical or namespace/name Kubernetes service-account identities."""
    principal = value.strip().lower()
    canonical = _K8S_CANONICAL_RE.fullmatch(principal)
    if canonical:
        return (
            "system:serviceaccount:"
            f"{canonical.group('namespace')}:{canonical.group('name')}"
        )
    short = _K8S_SHORT_RE.fullmatch(principal)
    if short:
        return (
            "system:serviceaccount:"
            f"{short.group('namespace')}:{short.group('name')}"
        )
    return None


def canonical_principal(provider: str, value: str) -> str | None:
    """Return a stable principal identity for a supported literal provider form."""
    kind = provider.strip().lower()
    if kind == "gcp":
        return normalize_gcp_service_account(value)
    if kind == "aws":
        return normalize_aws_role(value)
    if kind == "azure":
        return normalize_azure_principal(value)
    if kind in {"kubernetes", "k8s"}:
        return normalize_kubernetes_service_account(value)
    return None
