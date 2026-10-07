# Cross-framework data-connection provenance contract

HorusTrace treats data/resource reachability as a framework-neutral security semantic.

Framework and language adapters extract source-visible resource evidence into `ResourceScope`. The semantic contract normalizes that evidence before the ADG, AI-BOM, lineage and reporting layers consume it.

## Canonical resource fields

Every canonicalized data resource can carry:

- resource `kind`;
- `data_connection_type`;
- selector/scope;
- access semantics (`data.read`, `data.write`, `destructive.write`);
- classification when source-supported;
- `data_provider`;
- `data_account`;
- `data_project`;
- `data_tenant`;
- `selector_provenance`;
- `resource_provenance`;
- `data_source_reference`;
- `data_connection_resolution`;
- `data_connection_limitation`.

Optional ownership dimensions remain unknown unless the source proves them.

## Connection types

The common vocabulary is:

- `filesystem`;
- `object_store`;
- `database`;
- `vector_store`;
- `messaging`;
- `rag_source`;
- `saas_api`;
- `memory`;
- `cloud_resource`;
- `unknown`.

Resource-kind to connection-type normalization is centralized in the semantic contract so adapters do not invent their own category names.

## Resolution states

- `resolved` — the selector/scope is statically resolved.
- `model_selected` — the resource selector is controlled by a model-callable input.
- `dynamic` — a source-visible resource binding exists but its concrete selector is runtime/configuration dependent.
- `broad_or_unknown` — scope is broad or the source provides no narrower selector.
- `not_exposed` — the scanned configuration surface genuinely does not expose the data-resource identity. A limitation reason is mandatory.

`not_exposed` must not be used to hide an adapter deficiency. If source code contains a resource identifier that HorusTrace does not parse, that is an adapter gap.

## Current support matrix

| Framework / surface | Source-backed data scope currently normalized | Known limitation / next gap |
| --- | --- | --- |
| Google ADK Python | Managed search/data-store IDs, BigQuery dataset/project scopes, repository-resolved model-selected files and external SDK object IDs | Additional provider-specific toolset configuration should be added only where source-visible |
| OpenAI Agents SDK Python | `FileSearchTool.vector_store_ids`, including explicit dynamic configuration | Other hosted tools often expose provider-managed capability without a concrete data-resource identifier |
| Pydantic AI / Harness Python | Workspace filesystem roots, memory stores, skills directories, capability-creation workspaces and other existing `ResourceScope` producers | Provider-specific SaaS/data connectors should be normalized when their source config exposes resource scope |
| Amazon Strands / AgentCore Python | Literal S3 URIs, AgentCore knowledge-base sources and AgentCore memory | Additional AWS service/resource identifiers can be promoted when they represent data reachability rather than generic cloud infrastructure |
| Amazon Strands TypeScript | Capability inventory exists | First-class source-visible data-resource extraction remains an adapter gap where TS configuration exposes concrete data scope |
| Claude Agent SDK Python | `cwd` and `add_dirs` filesystem scope | MCP/provider backing data is normally not exposed by the SDK option surface |
| Claude Agent SDK TypeScript | `cwd` and `addDirs` filesystem scope | Same runtime/provider limitation as Python |
| Anthropic Managed Agents | MCP/server topology and managed tool authority | Backing provider data-resource IDs are generally runtime-managed unless explicitly present in source |
| Microsoft Agent Framework Python | Provider file-search `vector_store_ids`, including dynamic configuration, plus tool/MCP topology | Other provider-specific backing data should be added only where the client call exposes concrete scope |
| Microsoft Agent Framework .NET | Harness persistent file memory and FileAccessStore read/write/destructive scope | Other chat-client/provider data resources require source-specific extraction |
| Microsoft Foundry `azure.yaml` | Toolbox/MCP topology and destinations | Backing hosted data stores are not exposed by this deployment surface and should remain unknown/not exposed |

## Conformance rule

Cross-framework tests assert consistency of the canonical fields, resolution vocabulary and ADG projection. They do not require every framework to produce every optional dimension.

The rule is:

1. extract what the source proves;
2. normalize it into the common contract;
3. preserve unresolved/dynamic state explicitly;
4. never infer provider/account/project/tenant/classification from naming alone;
5. document genuine source limitations and move on;
6. treat parseable-but-unhandled source evidence as an adapter gap.
