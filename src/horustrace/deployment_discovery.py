"""Offline discovery of repository-declared deployment workload identities.

Only literal workload-to-identity bindings are emitted. Computed Terraform references,
missing Kubernetes namespaces, and unsupported provider constructs are retained as
unresolved evidence rather than guessed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from horustrace.deployment_bindings import (
    discover_kubernetes_bindings,
    discover_terraform_bindings,
)
from horustrace.deployment_evidence import (
    DeploymentEvidenceBundle,
    DeploymentWorkloadEvidence,
    IAMBindingEvidence,
)
from horustrace.limits import MAX_FILE_SIZE_BYTES, MAX_REPOSITORY_ENTRIES_VISITED
from horustrace.path_safety import canonical_root, is_within_root
from horustrace.principals import canonical_principal

_RESOURCE_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
_LITERAL_ATTR = r'\b{attribute}\s*=\s*"([^"]+)"'
_EXPRESSION_ATTR = r"\b{attribute}\s*=\s*([^\s#\n]+)"
_REFERENCE_LIST_ATTR = r"\b{attribute}\s*=\s*\[([^\]]*)\]"
_TERRAFORM_REFERENCE_RE = re.compile(
    r"^(?P<resource_type>[a-zA-Z0-9_]+)\."
    r"(?P<resource_name>[a-zA-Z0-9_-]+)"
    r"(?:\[[^\]]+\])?\."
    r"(?P<projection>[a-zA-Z0-9_]+)$"
)

_TERRAFORM_WORKLOADS: dict[str, tuple[str, str, str]] = {
    "google_cloud_run_v2_service": ("gcp", "cloud_run_v2", "service_account"),
    "google_cloud_run_v2_job": ("gcp", "cloud_run_v2_job", "service_account"),
    "google_cloud_run_service": ("gcp", "cloud_run", "service_account_name"),
    "aws_ecs_task_definition": ("aws", "ecs_task_definition", "task_role_arn"),
    "aws_lambda_function": ("aws", "lambda_function", "role"),
}

_TERRAFORM_IDENTITY_REFERENCES: dict[str, tuple[str, set[str]]] = {
    "gcp": ("google_service_account", {"email"}),
    "aws": ("aws_iam_role", {"arn"}),
    "azure": ("azurerm_user_assigned_identity", {"id", "principal_id", "client_id"}),
}

_AZURE_WORKLOADS: dict[str, str] = {
    "azurerm_container_app": "container_app",
    "azurerm_container_app_job": "container_app_job",
}

_K8S_TEMPLATE_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
}
_K8S_SUPPORTED_KINDS = _K8S_TEMPLATE_KINDS | {"CronJob", "Pod"}
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


class DeploymentDiscoveryError(ValueError):
    """Repository deployment evidence could not be discovered safely."""



@dataclass(frozen=True, slots=True)
class UnresolvedDeploymentEvidence:
    provider: str
    kind: str
    name: str
    reason: str
    path: str
    line: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "kind": self.kind,
            "name": self.name,
            "reason": self.reason,
            "path": self.path,
            "line": self.line,
        }


@dataclass(frozen=True, slots=True)
class DeploymentDiscoveryResult:
    bundles: tuple[DeploymentEvidenceBundle, ...]
    unresolved: tuple[UnresolvedDeploymentEvidence, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "bundles": [bundle.as_dict() for bundle in self.bundles],
            "unresolved": [item.as_dict() for item in self.unresolved],
        }


def _terraform_blocks(text: str):
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
    if not match:
        return None
    value = match.group(1).strip()
    return value or None


def _expression(block: str, attribute: str) -> str | None:
    match = re.search(_EXPRESSION_ATTR.format(attribute=re.escape(attribute)), block)
    if not match:
        return None
    value = match.group(1).strip().rstrip(",")
    return value or None


def _terraform_identity_reference(
    provider: str,
    expression: str,
) -> tuple[str, str] | None:
    match = _TERRAFORM_REFERENCE_RE.fullmatch(expression.strip())
    if match is None:
        return None
    expected = _TERRAFORM_IDENTITY_REFERENCES.get(provider)
    if expected is None:
        return None
    expected_type, projections = expected
    if match.group("resource_type") != expected_type:
        return None
    projection = match.group("projection")
    if projection not in projections:
        return None
    key = (
        f"terraform:{match.group('resource_type')}."
        f"{match.group('resource_name')}"
    )
    return key, projection


def _identity_attribute(
    block: str,
    provider: str,
    attribute: str,
) -> tuple[str, dict[str, Any]] | None:
    literal = _literal(block, attribute)
    if literal is not None:
        canonical = canonical_principal(provider, literal)
        if canonical is not None:
            return canonical, {
                "identity_resolution": "literal",
                "identity_projection": None,
            }

    expression = _expression(block, attribute)
    if expression is None:
        return None
    reference = _terraform_identity_reference(provider, expression)
    if reference is None:
        return None
    key, projection = reference
    return key, {
        "identity_resolution": "terraform_reference",
        "identity_reference": key,
        "identity_projection": projection,
        "identity_expression": expression,
    }


def _reference_list(block: str, attribute: str) -> list[str]:
    match = re.search(
        _REFERENCE_LIST_ATTR.format(attribute=re.escape(attribute)),
        block,
        flags=re.DOTALL,
    )
    if match is None:
        return []
    return [
        item.strip().rstrip(",")
        for item in match.group(1).split(",")
        if item.strip()
    ]


def _azure_identity_attributes(block: str) -> list[tuple[str, dict[str, Any]]]:
    result: list[tuple[str, dict[str, Any]]] = []
    for expression in _reference_list(block, "identity_ids"):
        reference = _terraform_identity_reference("azure", expression)
        if reference is None:
            continue
        key, projection = reference
        result.append(
            (
                key,
                {
                    "identity_resolution": "terraform_reference",
                    "identity_reference": key,
                    "identity_projection": projection,
                    "identity_expression": expression,
                },
            )
        )
    return result


def discover_terraform_workloads(
    path: Path,
) -> tuple[list[DeploymentWorkloadEvidence], list[UnresolvedDeploymentEvidence]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], []

    workloads: list[DeploymentWorkloadEvidence] = []
    unresolved: list[UnresolvedDeploymentEvidence] = []
    for resource_type, resource_name, line, block in _terraform_blocks(text):
        config = _TERRAFORM_WORKLOADS.get(resource_type)
        if config is not None:
            provider, kind, identity_attr = config
            identity_result = _identity_attribute(block, provider, identity_attr)
            if identity_result is None:
                unresolved.append(
                    UnresolvedDeploymentEvidence(
                        provider=provider,
                        kind=kind,
                        name=resource_name,
                        reason=f"unresolved_identity:{identity_attr}",
                        path=str(path),
                        line=line,
                    )
                )
                continue
            identity, identity_metadata = identity_result
            project = _literal(block, "project") if provider == "gcp" else None
            region = (
                _literal(block, "location") or _literal(block, "region")
                if provider == "gcp"
                else None
            )
            workloads.append(
                DeploymentWorkloadEvidence(
                    workload_id=f"terraform:{resource_type}.{resource_name}",
                    kind=kind,
                    name=_literal(block, "name") or resource_name,
                    identity=identity,
                    project=project,
                    region=region,
                    metadata={
                        "evidence_kind": "terraform",
                        "terraform_resource": resource_type,
                        "provider": provider,
                        "path": str(path),
                        "line": line,
                        "identity_attribute": identity_attr,
                        **identity_metadata,
                    },
                )
            )
            continue

        azure_kind = _AZURE_WORKLOADS.get(resource_type)
        if azure_kind is None:
            continue
        identities = _azure_identity_attributes(block)
        if not identities:
            unresolved.append(
                UnresolvedDeploymentEvidence(
                    provider="azure",
                    kind=azure_kind,
                    name=resource_name,
                    reason="unresolved_identity:identity_ids",
                    path=str(path),
                    line=line,
                )
            )
            continue
        for identity, identity_metadata in identities:
            workloads.append(
                DeploymentWorkloadEvidence(
                    workload_id=f"terraform:{resource_type}.{resource_name}",
                    kind=azure_kind,
                    name=_literal(block, "name") or resource_name,
                    identity=identity,
                    metadata={
                        "evidence_kind": "terraform",
                        "terraform_resource": resource_type,
                        "provider": "azure",
                        "path": str(path),
                        "line": line,
                        "identity_attribute": "identity_ids",
                        **identity_metadata,
                    },
                )
            )
    return workloads, unresolved


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _k8s_pod_spec(document: dict[str, Any]) -> dict[str, Any]:
    kind = document.get("kind")
    spec = _mapping(document.get("spec"))
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job_template = _mapping(spec.get("jobTemplate"))
        job_spec = _mapping(job_template.get("spec"))
        template = _mapping(job_spec.get("template"))
        return _mapping(template.get("spec"))
    if kind in _K8S_TEMPLATE_KINDS:
        template = _mapping(spec.get("template"))
        return _mapping(template.get("spec"))
    return {}


def discover_kubernetes_workloads(
    path: Path,
) -> tuple[list[DeploymentWorkloadEvidence], list[UnresolvedDeploymentEvidence]]:
    try:
        text = path.read_text(encoding="utf-8")
        documents = list(yaml.safe_load_all(text))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return [], []

    workloads: list[DeploymentWorkloadEvidence] = []
    unresolved: list[UnresolvedDeploymentEvidence] = []
    for index, raw in enumerate(documents):
        document = _mapping(raw)
        kind = document.get("kind")
        if kind not in _K8S_SUPPORTED_KINDS:
            continue
        metadata = _mapping(document.get("metadata"))
        name = metadata.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        name = name.strip()
        namespace = metadata.get("namespace")
        pod_spec = _k8s_pod_spec(document)
        service_account = pod_spec.get("serviceAccountName")
        if not isinstance(service_account, str) or not service_account.strip():
            unresolved.append(
                UnresolvedDeploymentEvidence(
                    provider="kubernetes",
                    kind=str(kind).lower(),
                    name=name,
                    reason="service_account_not_explicit",
                    path=str(path),
                )
            )
            continue
        if not isinstance(namespace, str) or not namespace.strip():
            unresolved.append(
                UnresolvedDeploymentEvidence(
                    provider="kubernetes",
                    kind=str(kind).lower(),
                    name=name,
                    reason="namespace_not_explicit",
                    path=str(path),
                )
            )
            continue

        namespace = namespace.strip()
        service_account = service_account.strip()
        identity = f"{namespace}/{service_account}"
        canonical = canonical_principal("kubernetes", identity)
        if canonical is None:
            unresolved.append(
                UnresolvedDeploymentEvidence(
                    provider="kubernetes",
                    kind=str(kind).lower(),
                    name=name,
                    reason="invalid_service_account_identity",
                    path=str(path),
                )
            )
            continue
        workloads.append(
            DeploymentWorkloadEvidence(
                workload_id=f"kubernetes:{kind}:{namespace}:{name}",
                kind=str(kind).lower(),
                name=name,
                identity=canonical,
                metadata={
                    "evidence_kind": "kubernetes_manifest",
                    "path": str(path),
                    "document_index": index,
                    "namespace": namespace,
                },
            )
        )
    return workloads, unresolved


def _provider_for_workload(workload: DeploymentWorkloadEvidence) -> str | None:
    declared_provider = workload.metadata.get("provider")
    if declared_provider in {"gcp", "aws", "azure", "kubernetes"}:
        return str(declared_provider)
    if workload.identity.startswith("system:serviceaccount:"):
        return "kubernetes"
    for candidate in ("gcp", "aws", "azure"):
        if canonical_principal(candidate, workload.identity) is not None:
            return candidate
    return None


def _provider_for_binding(binding: IAMBindingEvidence) -> str | None:
    if binding.principal.startswith("system:serviceaccount:"):
        return "kubernetes"
    for candidate in ("gcp", "aws", "azure"):
        if canonical_principal(candidate, binding.principal) is not None:
            return candidate
    return None


def discover_deployment_evidence(paths: list[Path]) -> DeploymentDiscoveryResult:
    workloads_by_provider: dict[str, list[DeploymentWorkloadEvidence]] = {}
    bindings_by_provider: dict[str, list[IAMBindingEvidence]] = {}
    unresolved: list[UnresolvedDeploymentEvidence] = []

    for path in sorted(paths):
        suffix = path.suffix.lower()
        workloads: list[DeploymentWorkloadEvidence] = []
        bindings: list[IAMBindingEvidence] = []
        workload_unresolved: list[UnresolvedDeploymentEvidence] = []
        raw_binding_unresolved: list[dict[str, Any]] = []

        if suffix == ".tf":
            workloads, workload_unresolved = discover_terraform_workloads(path)
            bindings, raw_binding_unresolved = discover_terraform_bindings(path)
        elif suffix in {".yaml", ".yml"}:
            workloads, workload_unresolved = discover_kubernetes_workloads(path)
            bindings, raw_binding_unresolved = discover_kubernetes_bindings(path)

        unresolved.extend(workload_unresolved)
        unresolved.extend(
            UnresolvedDeploymentEvidence(**item)
            for item in raw_binding_unresolved
        )

        for workload in workloads:
            provider = _provider_for_workload(workload)
            if provider is not None:
                workloads_by_provider.setdefault(provider, []).append(workload)
        for binding in bindings:
            provider = _provider_for_binding(binding)
            if provider is not None:
                bindings_by_provider.setdefault(provider, []).append(binding)

    providers = sorted(set(workloads_by_provider) | set(bindings_by_provider))
    bundles = tuple(
        DeploymentEvidenceBundle(
            provider=provider,
            source="repository_discovery",
            workloads=tuple(
                sorted(
                    workloads_by_provider.get(provider, []),
                    key=lambda item: (item.workload_id, item.identity),
                )
            ),
            iam_bindings=tuple(
                sorted(
                    bindings_by_provider.get(provider, []),
                    key=lambda item: (
                        item.principal,
                        item.scope_kind,
                        item.scope_name,
                        item.role,
                    ),
                )
            ),
            metadata={"evidence_kind": "repository_declared"},
        )
        for provider in providers
    )
    return DeploymentDiscoveryResult(
        bundles=bundles,
        unresolved=tuple(
            sorted(
                unresolved,
                key=lambda item: (item.path, item.line or 0, item.provider, item.name),
            )
        ),
    )


def discover_repository_deployment_evidence(root: Path) -> DeploymentDiscoveryResult:
    """Discover supported deployment evidence beneath a checked-out repository."""
    source = root.resolve()
    if not source.exists() or not source.is_dir():
        raise DeploymentDiscoveryError(
            f"{root}: deployment source must be an existing directory"
        )

    containment_root = canonical_root(source)
    files: list[Path] = []
    unresolved: list[UnresolvedDeploymentEvidence] = []
    entries = 0

    try:
        candidates = source.rglob("*")
        for candidate in candidates:
            entries += 1
            if entries > MAX_REPOSITORY_ENTRIES_VISITED:
                raise DeploymentDiscoveryError(
                    f"{root}: deployment-source traversal exceeds the "
                    f"{MAX_REPOSITORY_ENTRIES_VISITED}-entry safety limit"
                )
            try:
                relative = candidate.relative_to(source)
            except ValueError:
                continue
            if any(part in _IGNORED_DIRS for part in relative.parts):
                continue
            try:
                if not candidate.is_file():
                    continue
            except OSError:
                unresolved.append(
                    UnresolvedDeploymentEvidence(
                        provider="unknown",
                        kind="repository_path",
                        name=str(relative),
                        reason="path_unreadable",
                        path=str(candidate),
                    )
                )
                continue
            if candidate.suffix.lower() not in {".tf", ".yaml", ".yml"}:
                continue
            if not is_within_root(candidate, containment_root):
                unresolved.append(
                    UnresolvedDeploymentEvidence(
                        provider="unknown",
                        kind="repository_path",
                        name=str(relative),
                        reason="path_outside_repository",
                        path=str(candidate),
                    )
                )
                continue
            try:
                if candidate.stat().st_size > MAX_FILE_SIZE_BYTES:
                    unresolved.append(
                        UnresolvedDeploymentEvidence(
                            provider="unknown",
                            kind="repository_path",
                            name=str(relative),
                            reason="file_too_large",
                            path=str(candidate),
                        )
                    )
                    continue
            except OSError:
                unresolved.append(
                    UnresolvedDeploymentEvidence(
                        provider="unknown",
                        kind="repository_path",
                        name=str(relative),
                        reason="path_unreadable",
                        path=str(candidate),
                    )
                )
                continue
            files.append(candidate)
    except OSError as exc:
        raise DeploymentDiscoveryError(
            f"{root}: cannot traverse deployment source"
        ) from exc

    discovered = discover_deployment_evidence(files)
    return DeploymentDiscoveryResult(
        bundles=discovered.bundles,
        unresolved=tuple(
            sorted(
                [*discovered.unresolved, *unresolved],
                key=lambda item: (
                    item.path,
                    item.line or 0,
                    item.provider,
                    item.name,
                ),
            )
        ),
    )
