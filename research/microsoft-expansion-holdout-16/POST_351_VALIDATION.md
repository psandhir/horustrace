# Microsoft expansion holdout 16 — post-#351 validation

## Validation identity

- frozen cohort: `research/microsoft-expansion-holdout-16/cohort.json`
- pre-fix baseline run: **37188588773**
- post-fix run: **37190695024**
- scanner-under-test SHA: `3513f376a266424bc928e1c76e50948f9e8b5101`
- cases completed: **16/16**
- cohort inputs changed: **no**
- target repository SHAs changed: **no**

The post-fix run uses the same frozen cases and runner as the pre-fix baseline. A temporary branch-only workflow was used to execute the frozen runner and was removed after validation.

## Structural result

| Metric | Pre-fix | Post-fix |
|---|---:|---:|
| Material application roots detected | 12/16 | **16/16** |
| Zero-agent cases | 3 | **0** |
| Malformed Copilot session identity | `ct` in msx-cop-005 | **none** |
| Agents | 24 | **27** |
| Effective-authority relationships | 19 | **31** |
| Findings | 59 | 83 |
| Attack paths | 0 | 0 |

The findings increase is not treated as a precision improvement by itself. It is primarily a consequence of recovering previously missing agents and authority surfaces; finding precision requires separate source adjudication.

## P0 acceptance

### 1. Python MAF `ChatAgent`

**Case:** `msx-a365-001`

Pre-fix: 0 agents.

Post-fix: `agent` is recognized as Microsoft Agent Framework, the Agent 365 Mail MCP server is bound, delegated identity is retained, and one partially-resolved effective-authority relationship is emitted.

**Status: fixed.**

### 2. Python Copilot instance-attribute session construction

**Case:** `msx-cop-003`

Pre-fix: 0 agents for `self.client` / `self.session`.

Post-fix: `session` is detected as a GitHub Copilot SDK session and the Copilot CLI authority surface is retained.

**Status: fixed.**

### 3. Python Copilot positional/config-dictionary construction

**Case:** `msx-cop-002`

Pre-fix: 0 agents.

Post-fix: `session` is detected. The source-visible dynamic `session_config["tools"] = tools` assignment is retained conservatively as `copilot-custom-tools` / dynamic unresolved tool authority instead of being discarded.

**Status: fixed.**

### 4. .NET Copilot `SessionConfig` variable / wrapper construction

**Case:** `msx-cop-005`

Pre-fix: scanner emitted a bogus agent named `ct` from the cancellation-token argument and missed the session.

Post-fix: scanner emits the actual `session`; `ct` is not an agent. The dynamic custom-tool expression is retained as unresolved authority.

**Status: fixed.**

## P1 acceptance

### 5. MAF -> Copilot MCP option propagation

**Case:** `msx-mafcop-001`

Post-fix `GitHubCopilotAgent` authority includes both source-visible MCP servers:

- local stdio `filesystem`
- fixed remote `https://learn.microsoft.com/api/mcp`

The remote destination and local command are retained in effective authority.

**Status: fixed.**

### 6. M365 delegated-token downstream Graph authority

**Case:** `msx-m365-002`

Post-fix authority includes:

`AuthAgent -> signed-in-turn-user -> m365-delegated-http -> https://graph.microsoft.com/v1.0/me`

with `data.read` + `network.external` and a fixed restricted destination.

The delegated-HTTP inference was tightened so unrelated SDK `SendAsync` calls are not promoted to HTTP authority.

**Status: fixed.**

### 7. M365 + Copilot inline custom tools

**Case:** `msx-m365cop-001`

The Copilot `session` now binds:

- `DiceRoller`
- `InventoryManager`
- Copilot CLI built-ins

The M365 host is kept separate from Copilot session authority; the scanner no longer manufactures generic HTTP authority merely because the class calls `CopilotSession.SendAsync`.

Cross-file effect inference for the tool factories remains conservative rather than inventing capabilities.

**Status: fixed.**

### 8. Agent 365 / W365 conditional MCP authority

**Case:** `msx-a365-003`

Post-fix `MyAgent` binds `mcp_W365ComputerUse` and retains:

- fixed Agent 365 gateway fallback
- operator-configured endpoint semantics
- delegated Agent 365 identity
- conditional runtime binding
- partially-resolved MCP authority rather than silently dropping the server

**Status: fixed.**

## Post-fix raw cohort

| Surface | Cases | Agents | Authority relationships | Findings | Attack paths |
|---|---:|---:|---:|---:|---:|
| Agent 365 | 5 | 7 | 8 | 11 | 0 |
| Core MAF regression | 1 | 3 | 0 | 0 | 0 |
| GitHub Copilot SDK | 5 | 7 | 9 | 33 | 0 |
| M365 Agents SDK | 3 | 4 | 1 | 0 | 0 |
| M365 + Copilot hybrid | 1 | 2 | 3 | 8 | 0 |
| MAF + Copilot hybrid | 1 | 4 | 10 | 31 | 0 |
| **Total** | **16** | **27** | **31** | **83** | **0** |

## Conclusion

All eight P0/P1 defect families identified by the frozen Microsoft expansion study are addressed at the intended architectural level.

This closes the structural/generalization gaps found by the study. It does **not** convert the raw 83 findings into a precision claim; finding and rule precision should continue to be evaluated independently of framework construction coverage.
