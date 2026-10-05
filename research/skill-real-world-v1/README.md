# Real-world Agent Skills study v1

This study validates HorusScan's first-class Agent Skill architecture against pinned,
public repositories rather than synthetic fixtures.

## Cohort

### Public Skill catalogs

- `anthropics/skills` @ `683bc88e56f3e09ba94f7055977f3d3aa499f202`
- `openai/skills` @ `49f948faa9258a0c61caceaf225e179651397431`
- `google/skills` @ `d6eee396ed6a51871cc3f0979c5ff1be26d35d10`
- `vercel-labs/agent-skills` @ `063bee94c3f4df8453406c830b0a7df0f2860278`
- `addyosmani/agent-skills` @ `1401c8b8030e023baeebb31781a6653fe8e93026`

Catalog repositories test the inventory invariant: portable Skills should be discovered
without pretending that catalog presence alone grants an agent effective authority.

### Official Google ADK bound/dynamic samples

Pinned from `google/adk-python` @
`ec7756b969bd2f3df64ffedde98e396ee6d5a589`:

- `skills_agent`
- `skills_inject_state`
- `local_env_skill_toolset`
- `e2b_env_skill_toolset`
- `skills_agent_gcs`

These exercise source-proven SkillToolset binding, local versus sandboxed execution,
reference/state behavior and dynamic/remote Skill sources.

## Two-stage evaluation

1. CI runs HorusScan with its deterministic/default configuration against the pinned
   source and records inventory, bindings, Skill authority relationships, diagnostics
   and SKL findings.
2. Bound real-world Skill instructions are then semantically adjudicated with the
   GPT-5.6 Sol model available in this chat. No external LLM/API credential is needed.

The study intentionally does not turn catalog Skills into fake agent bindings.
