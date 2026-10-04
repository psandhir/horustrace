# Microsoft expansion holdout 16 — initial results

## Executive result

The frozen post-#348 scanner completed **16/16** cases without runner failure.

That does **not** mean the Microsoft expansion is ready. Source review of the framework fundamentals found:

- **12/16** cases with the expected application-level agent surface materially detected.
- **4/16** structural/root failures.
- **4 additional cases** where the root was detected but material authority was not projected.
- **59 findings**, **19 effective-authority relationships**, **0 attack paths** in the raw output.
- Finding precision is **not adjudicated in this pass**; raw finding counts are not used as an accuracy metric.

The strongest coverage is the current .NET Microsoft 365 / Agent 365 construction surface. The weakest area is real-world Copilot SDK indirection, especially Python attribute assignments/config objects and .NET wrapper/config-variable patterns.

## Raw run

- scanner baseline: `3ccf9bc2124bd7f6307091a9a5c49c5851db2a56`
- workflow: `Microsoft Expansion Holdout 16`
- workflow run: **37188588773**
- cases completed: **16/16**
- technical workflow result: **success**

| Surface | Cases | Agents | Authority relationships | Findings | Attack paths |
|---|---:|---:|---:|---:|---:|
| Agent 365 | 5 | 6 | 6 | 11 | 0 |
| Core MAF regression | 1 | 3 | 0 | 0 | 0 |
| GitHub Copilot SDK | 5 | 5 | 4 | 20 | 0 |
| M365 Agents SDK | 3 | 4 | 0 | 0 | 0 |
| M365 + Copilot hybrid | 1 | 2 | 1 | 8 | 0 |
| MAF + Copilot hybrid | 1 | 4 | 8 | 20 | 0 |

Zero-agent cases:

- `msx-a365-001`
- `msx-cop-002`
- `msx-cop-003`

A fourth structural failure, `msx-cop-005`, emitted an agent named `ct` from a cancellation-token argument rather than the actual Copilot session.

## Source-adjudicated fundamental gaps

### P0 — Python MAF current construction: `ChatAgent`

**Case:** `msx-a365-001` — `microsoft/Agent365-Samples/python/agent-framework/sample-agent`

Source constructs:

```python
from agent_framework import ChatAgent
...
self.agent = ChatAgent(...)
```

and later replaces/binds the agent through `McpToolRegistrationService.add_tool_servers_to_agent(...)`.

HorusTrace result: **0 agents**.

This is a fundamental current Microsoft Agent Framework construction surface, not a corner case. The Python MAF normalizer needs to recognize `ChatAgent` and instance-attribute assignment construction conservatively.

### P0 — Copilot Python instance-attribute session assignment

**Case:** `msx-cop-003` — `ricard0g/conviertlo`

Source:

```python
self.client = CopilotClient()
...
self.session = await self.client.create_session(
    on_permission_request=PermissionHandler.approve_all,
    ...
)
```

HorusTrace result: **0 agents**.

The call itself is canonical. The miss is caused by requiring a simple-name assignment target instead of accepting source-proven attribute targets such as `self.session`.

### P0 — Copilot Python positional/config-dictionary indirection

**Case:** `msx-cop-002` — `koushilab/copilot-sdk-hands-on`

Source builds:

```python
session_config = {"model": "gpt-4.1"}
session_config["tools"] = tools
self.session = await self.client.create_session(session_config)
```

HorusTrace result: **0 agents**.

Required behavior is conservative config resolution: detect the session, recover the statically knowable configuration, and mark dynamically mutated tool contents unresolved/conditional rather than dropping the agent.

### P0 — Copilot .NET wrapper/config-variable construction

**Case:** `msx-cop-005` — `Azure/azure-sdk-tools`

Source constructs a `SessionConfig` variable containing custom tools, available-tool names and approve-all behavior, then passes it through an interface wrapper:

```csharp
var sessionConfig = new SessionConfig
{
    Tools = ...,
    AvailableTools = ...,
    OnPermissionRequest = (...) => PermissionHandler.ApproveAll(...)
};

await using var session = await client.CreateSessionAsync(sessionConfig, ct);
```

The wrapper ultimately delegates to the real `CopilotClient.CreateSessionAsync`.

HorusTrace result: one synthetic agent named **`ct`**, with no tools/capabilities and no authority relationships.

This is a parser correctness defect. Cancellation-token arguments must never become session identities; config-variable/wrapper resolution must either recover the source-proven session authority or explicitly remain unresolved.

### P1 — MAF → Copilot MCP options are dropped

**Case:** `msx-mafcop-001` — official `microsoft/agent-framework` GitHub Copilot samples.

The MCP sample defines both:

- local stdio filesystem MCP;
- remote HTTP MCP at `https://learn.microsoft.com/api/mcp`;

then passes the dictionary through:

```python
GitHubCopilotOptions(
    on_permission_request=PermissionHandler.approve_all,
    mcp_servers=mcp_servers,
)
```

HorusTrace detects the Copilot agent and built-in authority but reports **no MCP servers** for the agents.

The MAF bridge therefore preserves generic Copilot CLI authority but does not yet preserve source-visible MCP authority passed through `GitHubCopilotOptions` indirection.

### P1 — M365 delegated-token downstream Graph authority is not projected

**Case:** `msx-m365-002` — official `microsoft/Agents` auto-sign-in sample.

Source obtains a user token through:

```csharp
UserAuthorization.GetTurnTokenAsync(...)
```

and uses it in an authenticated HTTP GET to:

```text
https://graph.microsoft.com/v1.0/me
```

HorusTrace correctly inventories the signed-in user identity but reports no network/data-read authority.

This loses an important part of the effective-authority chain:

```text
untrusted message -> delegated user token -> Microsoft Graph read
```

### P1 — M365 + Copilot inline custom tools are not bound

**Case:** `msx-m365cop-001` — official `microsoft/Agents` Copilot SDK sample.

The Copilot session is detected with delegated GitHub token evidence and approve-all built-in authority, but source-visible inline tools:

```csharp
Tools = [DiceRoller.CreateTool(), InventoryManager.CreateTool(sessionKey)]
```

do not appear on the session.

This is a material authority-recall gap in the hybrid case even though the Copilot root is found.

### P1 — Agent 365 runtime/configured MCP authority can disappear

**Case:** `msx-a365-003` — Windows 365 computer-use sample.

The agent is detected, but source shows runtime MCP URL configuration, a fixed W365 gateway fallback and conditional W365 tool loading. HorusTrace reports no MCP or network authority for the agent.

The correct conservative result is not necessarily a fully resolved MCP server, but it should preserve that the agent can conditionally obtain remote W365 MCP/computer-use authority and represent unresolved/operator-configured scope where necessary.

## Cases that behaved materially well at the structural level

The following cases found the intended application roots without an obvious fundamental construction miss in this review:

- `msx-maf-001` — core .NET MAF regression sentinel
- `msx-a365-002` — Agent 365 + M365 .NET, Mail MCP and delegated identities
- `msx-a365-004` — Windows 365 Agent 365 with three MCP servers
- `msx-a365-005` — independent Agent 365 teammate/WorkIQ overlay
- `msx-m365-001` — OBO authorization application
- `msx-m365-003` — multi-agent M365 host
- `msx-cop-001` — MassGen Copilot integration
- `msx-cop-004` — Agent Workbench Copilot integration

These still require deeper relationship/finding adjudication before making a precision claim.

## Product conclusion

The earlier Microsoft cohort was right to give confidence in the **core .NET/Python MAF architecture**. This expansion cohort shows that the newer Microsoft support is not yet at the same confidence level.

The gaps are architectural families rather than a long tail of special cases:

1. Python object/attribute construction normalization.
2. Source-proven config-object/config-dictionary resolution.
3. .NET wrapper and `await using var` Copilot session resolution.
4. Authority propagation through provider/options wrappers.
5. Delegated-token downstream HTTP effects.
6. Conditional/runtime Agent 365 MCP binding.

These are appropriate P0/P1 fixes because they generalize across real application patterns.

## Recommended next build slice

Keep this cohort frozen and preserve run **37188588773** as the pre-fix baseline.

Implement the four P0 construction fixes in a **separate scanner PR**, then rerun the exact frozen 16 cases. After structural recovery, address the four authority-projection gaps and run a second fixed-baseline comparison.

Do not change the cohort to make the scanner look better.
