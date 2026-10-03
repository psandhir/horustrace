# OWASP Agentic Security Initiative coverage

This document maps HorusTrace's supported static rules to the OWASP Agentic
Security Initiative categories. It is a coverage reference, not a certification or
a claim that every agentic risk is detected.

| OWASP category | Coverage | HorusTrace evidence |
| --- | --- | --- |
| ASI01 Agent Goal Hijack | Partial/static evidence | `PATH001` identifies untrusted input combined with command execution. It does not prove a goal-hijack exploit. |
| ASI02 Tool Misuse | Direct static detection | Approval and tool-surface rules such as `AGT021`, `AGT022`, `AGT032`, and `ADK005`. |
| ASI03 Identity and Privilege Abuse | Direct static detection | `IDN001` through `IDN004` identify broad roles, wildcard permissions, broad OAuth scopes, and unsafe credential sources. |
| ASI04 Agentic Supply Chain | Direct static detection | `AGT050` detects unpinned MCP package execution. |
| ASI05 Unexpected Code Execution | Direct static detection | Execution rules include `AGT020`, `ADK002` through `ADK004`, `ADK012`, and `PATH001`. |
| ASI06 Memory and Context Poisoning | Partial/static evidence | `PATH007` detects supported untrusted-input paths to persistent memory/checkpoint writes and `PATH012` captures tool-returned local/repository content re-entering model context alongside unconstrained filesystem authority. This is static evidence, not semantic prompt or runtime memory-poisoning proof. |
| ASI07 Insecure Inter-Agent Communication | Direct static detection | Remote MCP and A2A transport and authentication rules include `AGT030`, `AGT031`, and `ADK009` through `ADK011`. |
| ASI08 Cascading Failures | Not currently covered | The scanner does not model runtime cascade or recovery behavior. |
| ASI09 Human-Agent Trust Exploitation | Runtime/evaluation required | Static configuration cannot establish misleading interaction or human reliance. |
| ASI10 Rogue Agents | Runtime/evaluation required | Runtime intent, autonomy, and observed behavior are outside static analysis. |

The scanner records configuration and normalized-graph evidence only. It does not
verify runtime authorization, control effectiveness, exploitability, or complete
live cloud authority. Empty mappings mean a rule does not directly provide evidence
for an OWASP category; they do not mean the underlying risk is absent.
