# Anthropic unseen holdout 8 — baseline results

## Validation identity

- scanner baseline: `2015d0c0f5983210c1e0a6f8bc3fe06cf1b03f4d`
- workflow run: **37222905985**
- cases completed: **8/8**
- zero-agent cases: **4**
- framework agents: **11**
- tools: **8**
- MCP servers: **0**
- effective-authority relationships: **8**
- cohort inputs changed after scanner reveal: **no**

Raw counts are not accuracy scores. These findings compare each frozen source signal with the normalized output.

## Executive result

Canonical Anthropic depth parity is strong, but real-world generalisation is not yet closed for the newly added surfaces.

The existing Python Agent SDK cohort remains independently strong at 12/12. The unseen failures are concentrated in three architectural classes.

## P0 — TypeScript Agent SDK repository composition loses authority

Cases:
- `anth-hold-001` — terminalAgent
- `anth-hold-002` — harnss
- `anth-hold-003` — pr-cockpit
- `anth-hold-004` — salazar

Observed:
- three cases create one or more Claude roots but project **zero tools/MCP/authority relationships**;
- harnss has no Claude root at all.

Source patterns include:
- dynamic SDK import (`await import("@anthropic-ai/claude-agent-sdk")`);
- repository-local SDK wrapper (`getSDK()`);
- `query({ ..., options: buildReviewOptions(...) })`;
- `const options = makeQueryOptions(...); query({..., options})`;
- object spread (`{ ...options, abortController }`);
- preset tool surface (`tools: { type: "preset", preset: "claude_code" }`).

Required:
- resolve bounded repository-local option builders and aliases without executing code;
- recognize direct, dynamic-import and repository-wrapper query provenance;
- preserve preset/default Claude Code tool authority;
- retain unresolved builder dimensions explicitly instead of emitting an empty principal.

## P0 — async/helper-built Managed Agents Python can disappear or lose MCP scope

Cases:
- `anth-hold-005` — DashClaw
- `anth-hold-006` — Perplexity search_evals

Observed:
- DashClaw root is found with managed built-ins, but source-visible MCP server, optional skill and environment network scope disappear because literal evaluation fails on f-strings/conditional expressions;
- search_evals uses `await self.client.beta.agents.create(...)` and produces zero Managed Agent roots.

Required:
- unwrap awaited Managed Agent/environment/session calls;
- preserve mixed literal/dynamic lists/dicts field-by-field;
- keep source-visible MCP names, header-auth evidence and dynamic/operator-configured endpoints;
- preserve environment/network/session bindings when source values are variable rather than dropping them.

## P0 — Managed Agents TypeScript is a missing first-class language surface

Cases:
- `anth-hold-007` — Fluint agent-quickstarts
- `anth-hold-008` — Slashtalk

Observed:
- both produce zero Managed Agent roots.

Source patterns include:
- `@anthropic-ai/sdk`;
- `await client.beta.agents.create({...})`;
- repository-local config builders and object spreads;
- managed built-in toolset, MCP toolsets, skills;
- environment creation;
- vault credentials and session `vault_ids`.

Required:
- first-class Managed Agents TypeScript adapter;
- one-level repository-local config-builder/spread resolution;
- same normalized permission/MCP/environment/vault semantics as Managed Agents Python;
- unresolved values remain conditional rather than silently disappearing.

## Build decision

No redesign of the normalized graph/effective-authority model is indicated.

The next fix slice is:
1. repository-aware TypeScript Claude option/config composition;
2. awaited and partially-static Managed Agents Python;
3. Managed Agents TypeScript.

Keep the exact eight cases and SHAs unchanged and rerun after fixes.
