# Cross-framework model provenance contract

HorusTrace treats model provenance as a framework-neutral inventory semantic.

Framework and language adapters are responsible only for extracting source-visible model evidence. They must project that evidence into the same canonical metadata keys; inventory, ADG, AI-BOM and lineage consumers do not implement framework-specific model rules.

## Canonical fields

Adapters may populate, when source-supported:

- `model` — exact source-visible model identifier;
- `model_provider`;
- `model_hosting` — `provider_hosted` or `self_hosted`;
- `model_endpoint`;
- `model_region`;
- `model_source_reference`;
- `model_provider_source_reference`;
- `model_constructor`;
- `model_reference` for unresolved source references;
- `model_resolution`;
- `model_provenance_limitation` when the source surface does not expose model identity.

The inventory layer may additionally normalize family, version, license, digest/signature, fine-tune parent and modalities when explicit metadata exists. It does not invent them from a model name.

## Resolution states

- `resolved_identifier` — an exact identifier is source-visible.
- `provider_only` — provider is proven but the identifier is not.
- `unresolved_reference` — source names a model variable/reference that cannot be resolved statically.
- `dynamic` — model selection is computed dynamically.
- `not_exposed` — the scanned configuration surface genuinely does not expose the backing model. A limitation reason is mandatory.

`not_exposed` is not a substitute for an unimplemented adapter. If the source contains model evidence that HorusTrace does not yet parse, that is an adapter gap.

## Current support matrix

| Framework / surface | Identifier | Provider / hosting | Endpoint / region | Notes |
| --- | --- | --- | --- | --- |
| Google ADK Python | Yes for literal `model` | Gemini literals normalize to Google/provider-hosted; other literals remain provider-unknown | Not currently normalized from custom LLM objects | Custom/BaseLlm object provenance remains an adapter gap where source-visible |
| OpenAI Agents SDK Python | Yes for literal `model` | Deliberately unknown for bare strings because model-provider overrides can exist | Not currently normalized from custom model-provider objects | Avoids assuming every `gpt-*` string uses the default OpenAI provider |
| Pydantic AI Python | Yes | Yes for supported model/provider objects | Yes when provider object contains literal endpoint/region | Richest current object-level extraction |
| Amazon Strands Python | Yes when literal/model constructor exposes it | Yes for Bedrock/OpenAI/Anthropic/Google/Ollama constructors; default is Bedrock provider-only | Not yet normalized from provider-specific constructor configuration | Unknown custom constructors do not invent providers |
| Amazon Strands TypeScript | Yes where `modelId` is literal | Same canonical provider/hosting semantics as Python for supported constructors | Not yet normalized | Python/TypeScript contract parity enforced |
| Claude Agent SDK Python | Yes for explicit option | Anthropic/provider-hosted | Agent model option does not expose endpoint/region | Provider follows the SDK model surface |
| Claude Agent SDK TypeScript | Yes for explicit option/subagent model | Anthropic/provider-hosted | Agent model option does not expose endpoint/region | Python/TypeScript contract parity enforced |
| Anthropic Managed Agents Python/TypeScript | Yes | Anthropic/provider-hosted | Managed service placement is not exposed by the agent model field | Server-managed runtime |
| Microsoft Agent Framework Python | Yes when client constructor exposes literal model/deployment | Provider derives from the explicit Agent Framework client type | Literal endpoint/region preserved where present | Model evidence belongs to the client construction, not necessarily the Agent constructor |
| Microsoft Foundry hosted `azure.yaml` | No | No | No backing-model provenance in this deployment surface | Recorded as `not_exposed`, not guessed |
| Microsoft Agent Framework .NET | Not yet normalized from chat-client graph | Not yet normalized | Not yet normalized | **Adapter gap**, not a framework limitation |

## Conformance

Cross-framework tests assert that supported adapters emit the same canonical field names and resolution vocabulary. Framework-specific tests may additionally verify constructor-specific evidence.

A framework is not required to populate evidence its source surface cannot provide. Such values remain unknown or `not_exposed`, with the distinction documented above.
