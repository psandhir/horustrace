"""Conservative model and data inventory normalization.

This module only projects source-visible facts into audit inventory. Unknown provider,
version, hosting, tenant, account, sensitivity, or scope stays explicit rather than
being inferred from naming alone.
"""
from __future__ import annotations

from typing import Any

from horustrace.models import ResourceScope
from horustrace.semantic_contract import canonical_data_connection_type

_KNOWN_MODEL_PROVIDER_PREFIXES = {
    "anthropic": "anthropic",
    "azure": "microsoft-azure",
    "azure-openai": "microsoft-azure-openai",
    "bedrock": "amazon-bedrock",
    "cohere": "cohere",
    "google": "google",
    "google-gla": "google",
    "google-vertex": "google-cloud-vertex",
    "groq": "groq",
    "mistral": "mistral",
    "ollama": "ollama",
    "openai": "openai",
    "openrouter": "openrouter",
    "vertex": "google-cloud-vertex",
}

_PROVIDER_HOSTING = {
    "amazon-bedrock": "provider_hosted",
    "anthropic": "provider_hosted",
    "cohere": "provider_hosted",
    "google": "provider_hosted",
    "google-cloud-vertex": "provider_hosted",
    "groq": "provider_hosted",
    "microsoft-azure": "provider_hosted",
    "microsoft-azure-openai": "provider_hosted",
    "mistral": "provider_hosted",
    "ollama": "self_hosted",
    "openai": "provider_hosted",
    "openrouter": "provider_hosted",
}

def _scalar(metadata: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, (str, int, float)) and str(value):
            return str(value)
    return None


def _model_provider_from_identifier(identifier: str | None) -> str | None:
    if not identifier or ":" not in identifier:
        return None
    prefix = identifier.split(":", 1)[0].strip().lower()
    return _KNOWN_MODEL_PROVIDER_PREFIXES.get(prefix)


def model_inventory_attributes(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return aggregation-ready model attributes without guessing missing facts."""
    identifier = metadata.get("model")
    identifier = identifier if isinstance(identifier, str) and identifier else None

    provider = _scalar(metadata, "model_provider")
    if provider is None:
        provider = _model_provider_from_identifier(identifier)

    hosting = _scalar(metadata, "model_hosting")
    if hosting is None and provider is not None:
        hosting = _PROVIDER_HOSTING.get(provider)

    family = _scalar(metadata, "model_family")
    version = _scalar(metadata, "model_version")
    endpoint = _scalar(metadata, "model_endpoint")
    region = _scalar(metadata, "model_region")
    source_reference = _scalar(
        metadata,
        "model_source_reference",
        "model_package",
        "model_repository",
    )
    license_value = _scalar(metadata, "model_license")
    digest = _scalar(metadata, "model_digest", "model_hash")
    signature = _scalar(metadata, "model_signature")
    fine_tuned_from = _scalar(metadata, "model_fine_tuned_from")

    input_modalities = metadata.get("model_input_modalities")
    output_modalities = metadata.get("model_output_modalities")
    if not isinstance(input_modalities, (list, tuple, set)):
        input_modalities = []
    if not isinstance(output_modalities, (list, tuple, set)):
        output_modalities = []

    declared_resolution = _scalar(metadata, "model_resolution")
    model_reference = _scalar(metadata, "model_reference")
    limitation = _scalar(metadata, "model_provenance_limitation")

    if identifier and provider:
        identity_resolution = "provider_and_identifier"
    elif identifier:
        identity_resolution = "identifier_only"
    elif provider:
        identity_resolution = "provider_only"
    elif declared_resolution in {"unresolved_reference", "dynamic", "not_exposed"}:
        identity_resolution = declared_resolution
    else:
        identity_resolution = "unknown"

    provider_value = provider or "unknown"
    identifier_value = identifier or "unknown"
    model_key_suffix = (
        identifier_value
        if identifier
        else model_reference
        if model_reference
        else declared_resolution
        if declared_resolution
        else "unknown"
    )
    return {
        "model_identifier": identifier_value,
        "model_provider": provider_value,
        "model_family": family or "unknown",
        "model_version": version or "unknown",
        "model_hosting": hosting or "unknown",
        "model_endpoint": endpoint or "unknown",
        "model_region": region or "unknown",
        "model_source_reference": source_reference or "unknown",
        "model_license": license_value or "unknown",
        "model_digest": digest or "unknown",
        "model_signature": signature or "unknown",
        "fine_tuned_from": fine_tuned_from or "unknown",
        "input_modalities": sorted({str(item) for item in input_modalities}),
        "output_modalities": sorted({str(item) for item in output_modalities}),
        "identity_resolution": identity_resolution,
        "model_resolution": declared_resolution or identity_resolution,
        "model_reference": model_reference or "unknown",
        "model_provenance_limitation": limitation or "unknown",
        "model_key": f"{provider_value}:{model_key_suffix}",
    }


def data_connection_type(kind: str, metadata: dict[str, Any]) -> str:
    explicit = _scalar(metadata, "data_connection_type", "connection_type")
    return explicit or canonical_data_connection_type(kind)


def data_resource_attributes(resource: ResourceScope) -> dict[str, Any]:
    """Normalize a ResourceScope into inventory and lineage attributes."""
    metadata = resource.metadata
    connection_type = data_connection_type(resource.kind, metadata)
    provider = _scalar(
        metadata,
        "data_provider",
        "provider",
        "workspace_provider",
    ) or "unknown"
    account = _scalar(
        metadata,
        "data_account",
        "account",
        "account_id",
        "account_name",
    )
    project = _scalar(metadata, "data_project", "project", "project_id")
    tenant = _scalar(metadata, "data_tenant", "tenant", "tenant_id")

    selector = resource.selector or "<unknown>"
    declared_resolution = _scalar(metadata, "data_connection_resolution")
    if declared_resolution:
        scope_resolution = declared_resolution
    else:
        lowered = selector.strip().lower()
        if lowered in {"*", "<unknown>", "unknown"}:
            scope_resolution = "broad_or_unknown"
        elif lowered.startswith("<model-selected"):
            scope_resolution = "model_selected"
        elif lowered.startswith("<") and lowered.endswith(">"):
            scope_resolution = "dynamic"
        else:
            scope_resolution = "resolved"

    provenance = _scalar(
        metadata,
        "resource_provenance",
        "selector_provenance",
        "data_source_reference",
        "source",
    ) or "source_location"

    return {
        "resource_kind": resource.kind,
        "connection_type": connection_type,
        "selector": selector,
        "scope_resolution": scope_resolution,
        "classification": resource.classification or "unknown",
        "access": sorted(resource.access),
        "provider": provider,
        "account": account or "unknown",
        "project": project or "unknown",
        "tenant": tenant or "unknown",
        "provenance": provenance,
        "selector_provenance": _scalar(metadata, "selector_provenance") or "unknown",
        "resource_provenance": _scalar(metadata, "resource_provenance") or "unknown",
        "data_source_reference": _scalar(metadata, "data_source_reference") or "unknown",
        "data_connection_resolution": scope_resolution,
        "data_connection_limitation": _scalar(metadata, "data_connection_limitation") or "unknown",
        "source": _scalar(metadata, "source") or "unknown",
        "resource_key": f"{connection_type}:{provider}:{selector}",
    }


def network_destination_attributes(
    target: str,
    *,
    restricted: bool,
    direction: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    provider = _scalar(metadata, "provider", "network_provider") or "unknown"
    return {
        "direction": direction,
        "restricted": restricted,
        "provider": provider,
        "network_scope": _scalar(metadata, "network_scope") or "unknown",
        "destination_provenance": _scalar(
            metadata,
            "destination_provenance",
            "source",
        )
        or "source_location",
        "account": _scalar(metadata, "account", "account_id") or "unknown",
        "project": _scalar(metadata, "project", "project_id") or "unknown",
        "tenant": _scalar(metadata, "tenant", "tenant_id") or "unknown",
        "destination_key": f"{provider}:{target}",
    }
