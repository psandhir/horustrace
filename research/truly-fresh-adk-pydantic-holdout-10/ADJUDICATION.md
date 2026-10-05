# Truly fresh ADK + Pydantic AI holdout — source adjudication

Scanner under test: `e0639c218867d3f2f4adc315831c48f4a7f59e68`

Workflow: `Truly Fresh ADK Pydantic Holdout 10`, run `37290773502`.

## Method

This is the strict unseen validation set.

The ten repositories were discovered live from GitHub after the P0/P1 fixes and are
outside the entire prior frozen-180 corpus. Exact commit SHAs were frozen before
execution. The source-only reference was generated and committed in the workflow
before the HorusScan scanner was installed or executed. The reference uses the
existing independent AST + lexical source-review harness and does not execute target
code.

A second source adjudication was then applied to raw mismatches because the automated
reference has known normalization limits (wrapper runtime names, workflow nodes,
list-contained MCP constructors, and syntactically invalid source).

## Raw result

- Successful scans: **10/10**
- Failed scans: **0**
- Analysis incomplete: **4**
- Findings: **19**
- Attack paths: **4**

| Framework | Agent P/R | Tool P/R | MCP P/R | Authority P/R |
| --- | ---: | ---: | ---: | ---: |
| Google ADK | 76.9% / 100.0% | 100.0% / 100.0% | n/a / n/a | 75.0% / 90.9% |
| Pydantic AI | 100.0% / 80.0% | 100.0% / 94.4% | 0.0% / n/a | 66.7% / 85.7% |

The raw precision/recall values should not be interpreted as product accuracy without
the source adjudication below.

## Google ADK adjudication

### Agent and tool discovery

No source-supported ADK agent or ordinary tool miss was found.

The raw three agent false positives in `fresh-004 customer-support-agent` are a
reference/scoring taxonomy issue. HorusScan's graph contains the two actual agents
(`shipping_faq_agent` and `customer_support_workflow`) and additionally preserves
the workflow's routing/function nodes. The automated reference counts only constructor
agents while the structural scorer includes those workflow entities.

`fresh-005 Multi-Agent-System-Google-ADK` also contains a source-supported custom
`DynamicOrchestratorAgent(BaseAgent)` that is visible to HorusScan as an additional
agent entity even though the source reference is incomplete for that dynamic class.

Tool discovery is **11/11 raw (100% precision and recall)**.

### Authority normalization

`fresh-003 adk-hiring-agent` wraps `github_validator` with
`FunctionTool(func=github_validator)` and binds the wrapper variable
`github_validate_tool`. The reference records the wrapper variable while HorusScan
normalizes the concrete callable. The apparent one FN + one FP is a naming artifact;
the authority binding is source-supported.

`fresh-004` has a real Workflow route to `shipping_faq_agent`; the reference
extractor does not normalize ADK 2.x Workflow edge dictionaries, so the scanner's
reported delegation is source-supported rather than a false positive.

### Genuine residual ADK gap

`fresh-005` independently reproduces the same architectural gap observed in the
post-fix frozen holdout: a custom `BaseAgent` subclass used as a composed sub-agent is
not fully represented in delegation topology.

Source:
- `DynamicOrchestratorAgent(BaseAgent)` declares four sub-agents through
  `super().__init__(sub_agents=...)`.
- `RootPlannerOrchestrator` is a `SequentialAgent` with
  `sub_agents=[master_planner_agent, orchestrator_agent]`.

HorusScan captures one of the two root delegation edges but misses the custom
orchestrator relationship. This is a coherent generic ADK composition gap, not a
repository-specific syntax corner case.

## Pydantic AI adjudication

### Invalid-source case

The only raw agent miss is `fresh-008 gtsbahamas/text-moderation`.

Direct debug of the exact SHA shows:

- `is_pydantic_ai_file = False`
- no framework adapter runs
- scanner diagnostic:
  `SyntaxError: '{' was never closed (<unknown>, line 112)`

The pinned Python source is syntactically invalid. HorusScan correctly refuses to
invent entities from an unparseable file and marks analysis incomplete. The automated
reference's lexical fallback counted the visible `Agent(...)` and decorators despite
the parse failure. This case must not be counted as a Pydantic parser false negative.

For the four valid Pydantic repositories, source-adjudicated core discovery is:

- agents: **4/4**, no real misses
- ordinary tools: **34/34**, no real misses
- MCP declarations: **2/2** explicit `MCPServerStdio` bindings, both detected
- effective authority: no source-supported misses

### Raw MCP false positives are reference defects

Both `fresh-007 youtube-manager-mcp` and `fresh-009 pharmiq` explicitly declare:

`mcp_servers = [MCPServerStdio(...)]`

The source-reference extractor currently recognizes directly assigned MCP constructor
calls but not MCP constructors nested in a list assignment. HorusScan correctly
discovers and binds both servers.

### Wrapper-name authority normalization

`fresh-006 speedagent` binds:

`python_tool = tool_from_langchain(PythonREPLTool())`

The reference uses the variable name `python_tool`; HorusScan resolves the wrapped
runtime tool as `PythonREPLTool`. The apparent authority FN/FP pair is normalization,
not a missing binding.

## Finding adjudication

All **19 emitted findings are source-supported in their underlying security premise**.

Notable examples:

- `fresh-001`: `store_pdf` uploads generated content to Google Cloud Storage
  without an approval boundary.
- `fresh-005`: the news agent performs network access and reads credential material
  without a detected action approval/guardrail.
- `fresh-006`: public Pydantic web input reaches both a LangChain
  `PythonREPLTool` and an explicit `subprocess.run(..., shell=True)` bash tool.
  Both reported command-execution paths are source-supported.
- `fresh-007`: local YouTube MCP implements update and permanent delete operations;
  the reported destructive MCP authority is source-supported.
- `fresh-009`: local healthcare MCP implements FHIR create/update operations and
  credential-bearing OAuth flows; state-changing MCP authority is source-supported.
- `fresh-010`: `delete_transaction` performs real budget-data deletion without a
  source-visible approval requirement.

All four attack paths are source-supported after direct source review. The automated
reference only marked one path as supported because its Tier-B structural reference
does not model wrapped execution or local MCP implementation semantics exhaustively.

## Conclusion

The strict unseen holdout does **not** show evidence that the P0/P1 changes were
overfit to the frozen 20.

### Pydantic AI

Core native Pydantic AI coverage is mature on this sample. On valid Python source,
agent, tool, MCP and authority construction all generalize without a source-supported
miss. No new Pydantic parser fix is justified from this holdout.

### Google ADK

Agent and ordinary tool discovery generalize strongly. The remaining repeatable
framework-level issue is custom `BaseAgent` subclass composition/delegation. The same
class of miss now appears in independent repositories, making it an architectural
backlog item rather than a corner case.

## Recommended next action

1. Implement generic ADK custom-`BaseAgent` composition resolution:
   - recognize repository-local subclasses of `BaseAgent`, `LoopAgent`, etc.;
   - normalize their instantiated runtime names;
   - follow `super().__init__(sub_agents=...)` and constructor-held sub-agents;
   - bind custom instances appearing in `sub_agents=[...]` as delegation targets.
2. Add regression cases from `fresh-005` plus the earlier custom-agent holdout cases.
3. Keep Pydantic core parser unchanged; treat external wrappers such as
   `pydantic-collab` as a separate extension/framework decision.
4. Improve the research reference normalizer separately so wrapper names, Workflow
   routing nodes, list-contained MCP constructors, and invalid-source lexical fallback
   do not distort raw accuracy metrics.
5. Retain the previously identified shared semantic backlog for indirect/proxy
   downstream destinations; it is not a Pydantic parser issue.
