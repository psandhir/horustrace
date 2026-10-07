# Model and data lineage

HorusTrace projects source-supported model and data-connection facts into the existing Agent Dependency Graph and AI-BOM.

## Model inventory

A model asset records the exact source-visible identifier plus normalized fields for:

- provider;
- family and version;
- provider-hosted vs self-hosted use;
- endpoint and region;
- source/package/repository reference;
- license;
- digest/signature;
- fine-tuned parent;
- declared modalities.

Missing facts stay `unknown`. A provider is only normalized when explicit metadata or an explicit provider namespace supports it. A model name alone is not used to invent endpoint, region, license, provenance, or hosting.

The native AI-BOM groups model use by `model_key`, allowing an auditor to answer which agents use a given model while retaining each source relationship as evidence.

## Data connections

Data resources are normalized into connection categories when the source resource kind supports the classification:

- filesystem;
- object store;
- database;
- vector store;
- messaging;
- RAG source;
- SaaS/API;
- unknown.

Each resource retains access semantics, selector/scope, classification, provider/account/project/tenant where explicit, and selector/resource provenance.

A model-selected selector is represented as model-selected scope rather than as a fixed resource.

## Identity-aware lineage

Where a tool or MCP server explicitly binds an identity, the ADG preserves both:

```text
Agent -> Tool/MCP -> Data Resource / Destination
              \
               -> Identity -> Data Resource / Destination
```

The identity-to-resource/destination edge is only created from an explicit bound identity. HorusTrace does not assume that every agent identity authorizes every resource.

If a tool/MCP source names an identity that cannot otherwise be resolved, the identity remains visible with `resolution=unresolved_reference` rather than disappearing from inventory.

## Audit queries

AI-BOM v2 exposes grouped lineage indexes for:

- model usage;
- data-resource reachability;
- external-destination reachability.

Each access path identifies the principal agent, the intervening tool/MCP object, bound identity when present, relationship IDs and source evidence location.

The Agent Security Graph carries the same model/data/identity relationships in its topology projection.
