# Audit-grade AI-BOM

HorusTrace AI-BOM schema v2 is the native inventory contract for aggregation, audit and security governance.

It preserves stable repository-scoped asset and relationship identifiers, source revision and scan provenance, ownership/environment metadata, explicit resolution state, posture slots, skills, and semantic deltas.

## Native export

```bash
horustrace aibom . --output aibom.json
```

The native format is the lossless HorusTrace representation. It retains authority and evidence semantics that do not have direct equivalents in general-purpose BOM standards.

## CycloneDX 1.6 export

```bash
horustrace aibom . --format cyclonedx --output horustrace.cdx.json
```

The CycloneDX export targets JSON schema 1.6.

Mapping principles:

- HorusTrace model assets become CycloneDX `machine-learning-model` components.
- Agents and other executable/control assets are represented as compatible CycloneDX components.
- Data resources and memory assets are represented as `data` components.
- ADG relationships are projected into the CycloneDX dependency graph.
- HorusTrace-specific authority, posture, provenance, resolution and relationship evidence are retained as `horustrace:*` component properties.
- A CycloneDX `modelCard` is emitted only when source-supported model-card fields are present; HorusTrace does not invent model metadata.
- Prompt contents are not exported. The same credential/prompt safety rules as the native AI-BOM apply.

The CycloneDX view is intended for interoperability with enterprise xBOM tooling. The native AI-BOM remains the authoritative representation for HorusTrace-specific security semantics.

## Inventory metadata

Optional repository-level metadata can be supplied in `.horustrace.yaml`:

```yaml
version: 1
inventory:
  repository_id: github.com/acme/agents
  project: payments-ai
  owner: security@example.com
  team: ai-platform
  business_service: payments
  environment: production
  lifecycle: active
```

When `repository_id` is not configured, HorusTrace derives a credential-safe repository identity from Git origin where possible. Local-only fallback identities are explicitly qualified and must not be treated as globally unique by an aggregator.

## Aggregation semantics

`first_seen` and `last_seen` are intentionally not fabricated during a local scan. They belong to the aggregation boundary that observes successive snapshots.

Use the native AI-BOM delta to identify added, removed and semantically changed assets and relationships across snapshots.
