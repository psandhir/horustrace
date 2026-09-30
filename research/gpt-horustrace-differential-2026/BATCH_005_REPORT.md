# GPT ↔ HorusTrace differential — Batch 005

## Integrity

Batch 005 preserved the blind order: **selection → source-only GPT review → HorusTrace reveal → source adjudication → scanner repairs**.

The locked artifacts are carried into this publication by their original Git blob SHAs rather than being regenerated:

- review packet: `6ca88ef13a1dc2e9a47f55a354d14e75488980f0`
- GPT source review: `2bf86b770ff0dcd7394247e068dd9d68be0c5d7c`
- scanner result: `7c328c1a0c99d016330af319d698bb468e925879`
- scanner Markdown summary: `328832b4e9a93cb30580b698868bc5e44a5ed974`

The source review explicitly records that case-specific HorusTrace findings were not inspected before the GPT review was locked.

The five fresh pinned cases were:

| Case | Framework | Repository |
| --- | --- | --- |
| rw-029 | Google ADK | git791/GreenAI-Agent |
| rw-074 | LangGraph | MKRNaqeebi/GenAlima |
| rw-115 | custom MCP / LiveKit | Meer-Promethean/Voice_Agent |
| rw-142 | OpenAI Agents | totalhack/zillion |
| rw-178 | Pydantic AI | MhankBarBar/zero-ichi |

## Locked baseline reveal

The pre-repair HorusTrace reveal used scanner SHA `95885cc341b2900a2ad8eac22db131c700e6701e`.

All 5 repositories scanned successfully. The locked baseline emitted **11 findings and 3 attack paths**. Those raw counts were not treated as truth: source adjudication showed that the batch contained both false-positive clusters and genuine missed security compositions.

GPT identified **2 semantic findings and 2 source-supported attack paths**:

- **rw-074:** authenticated application input could reach a model-callable chat-title mutation that reopened an owner-scoped `Chat` by model-supplied ID and committed without carrying the API's `owner_id == current_user.id` authorization check into the tool boundary.
- **rw-115:** an unauthenticated caller could obtain a publish-capable LiveKit session, feed the voice model, and reach MCP-backed mutations of the repository's local SQLite banking state without participant-to-account authorization or per-action approval.

HorusTrace's baseline emitted neither finding nor attack path for those two cases.

The same batch also exposed two precision defects:

- **rw-029:** provider-managed ADK code execution and read-only "policy" naming were over-promoted into local process/IAM authority, producing a nine-finding cluster and three attack paths that the source review did not support.
- **rw-178:** the Pydantic tool name `run_command` was treated as host process execution even though the implementation was an application command registry with permission/policy checks and no concrete process sink.

**rw-142** remained clean in both reviews and serves as the agreement precision control.

## Repair tranche

### rw-178 → PR #261

HorusTrace now requires a **concrete process/eval sink** for Pydantic tool process authority. A name such as `run_command` is no longer sufficient by itself.

This removes the baseline `AGT020` / `AGT040` false-positive family while retaining true subprocess/`os.system`/`exec`/`eval` cases.

### rw-029 → PR #262

The ADK semantic model now distinguishes provider-managed `BuiltInCodeExecutor` from repository-local host process execution and stops inferring IAM/admin authority from the word `policy` alone.

The repair targets the semantic roots of the rw-029 finding cascade rather than suppressing individual rule IDs.

### rw-074 → PR #263

A new repository-level object-authorization pass resolves LangChain `BaseTool` instances hidden behind local `bind_tools(...)` factories, proves model-controlled object IDs reach committed mutations, and compares that tool boundary with owner/tenant checks visible in the normal application route.

New rules:

- `DATA004` — model-callable object mutation bypasses owner scope.
- `PATH014` — source-bound user input reaches the unscoped model-driven object mutation.

The negative regression requires a **principal-bound** owner check; comparing against another model/user-supplied owner identifier does not count as authorization.

### rw-115 → PR #267

HorusTrace now composes:

`public realtime capability issuance → LiveKit participant/model session → bound function tool → local MCP dispatch → repository helper → committed state mutation`

The implementation resolves the actual repository backend and records `local_sqlite`, preventing the finding from being overstated as a production banking integration.

New rules:

- `IDN005` — unauthenticated publish-capable realtime session reaches state-changing MCP-backed agent authority.
- `PATH015` — unauthenticated realtime session reaches the model and MCP-backed state mutation.

Precision controls cover authenticated token issuance and non-publishing session credentials.

## What Batch 005 changes in our understanding

This batch reinforces that HorusTrace's main remaining challenge is **security-boundary composition**, not basic framework/entity recognition.

The two recall misses both required joining facts that lived in different parts of the repository:

1. **application authorization → model tool → object mutation**; and
2. **session admission → realtime model ingress → MCP tool → concrete persistence**.

At the same time, the two precision failures show the inverse requirement: authority must not be inferred merely because a construct *sounds* privileged. Provider-managed execution is not automatically host execution, and a function/tool name is not a substitute for a concrete sink.

That is a useful convergence: the scanner is becoming less keyword-driven and more dependent on **source-proven effective authority and boundary crossings**.

## Validation status

All four repair PRs include targeted positive/negative regression coverage and passed their respective PR validation gates. PR #267, the final repair in the tranche, passed both CI and CodeQL before merge.

This publication **does not claim a new Frozen-180 post-repair metric**. The broad corpus workflow is intentionally manual-only during the rapid semantic-fix loop. The locked baseline remains the pre-repair comparison; the repairs are recorded separately and transparently.

## Next step

Proceed to **Differential Batch 006** with fresh, previously unused cases under the same blind protocol.

Do not add speculative scanner semantics before the new source review. Let the next fresh batch determine whether the remaining gaps are still dominated by authorization/session composition, or whether a new class of weakness is emerging.
