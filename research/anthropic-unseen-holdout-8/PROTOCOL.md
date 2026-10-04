# Anthropic unseen holdout 8

## Purpose

Test real-world generalisation of the current Anthropic coverage after canonical depth parity reached 15/15.

The cohort is intentionally concentrated on surfaces not covered by the older Claude Python cohort:

- Claude Agent SDK TypeScript wrappers/composition
- Managed Agents Python composition
- Managed Agents TypeScript

## Freeze

- scanner baseline: `2015d0c0f5983210c1e0a6f8bc3fe06cf1b03f4d`
- 8 cases / 8 repositories
- all repositories pinned to exact SHAs
- selected from source before HorusTrace execution
- no target may be replaced in response to scanner output

## Adjudication questions

For each application:

1. Is the material Anthropic agent/runtime root represented?
2. Are source-proven built-in, MCP, custom tool and delegation surfaces retained?
3. Do repository-local option/config builders preserve authority rather than disappear?
4. Are permission modes/policies, canUseTool/hooks and vault/network controls represented without being overstated?
5. Are dynamic MCP endpoints/catalogues retained as unresolved authority?
6. Are filesystem/network scopes and managed execution boundaries preserved?
7. Does TypeScript receive the same normalized security semantics as the corresponding Python construct?

Raw counts are not accuracy scores. Any fixes must be made separately and rerun against this unchanged cohort.
