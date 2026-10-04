# Amazon expansion holdout 14 — initial results

## Executive result

The frozen post-#350 scanner completed **14/14** cases without runner failure.

That does **not** mean the Amazon expansion is ready. Source adjudication found a small set of fundamental generalisation gaps:

- **5 cases** have clear P0 application-authority failures: three current Strands Python patterns, one real CloudFormation Bedrock Agent, and one first-party AgentCore gateway-backed application.
- **1 additional Bedrock Terraform case** reconstructs the execution-role IAM correctly in the graph but drops that identity from the action-group effective-authority relationship.
- Several additional cases expose P1 authority/configuration gaps rather than root-detection failures.
- **15 agents**, **5 effective-authority relationships**, **1 finding**, and **0 attack paths** were emitted in the raw run.
- Raw counts are diagnostics, not accuracy. Finding precision is not inferred from the count.

The strongest current coverage is **Strands TypeScript**, simple/current **AgentCore runtime configuration**, and directly referenced **Bedrock Terraform** resources. The weakest areas are real-world **Strands Python composition**, CloudFormation intrinsic syntax, and cross-layer authority propagation.

## Raw run

- scanner baseline: `18caca37b992402351b3c53d93d47c783f218d82`
- workflow: `Amazon Expansion Holdout 14`
- workflow run: **37197757475**
- cases completed: **14/14**
- technical workflow result: **success**
- repositories: **10**
- cohort selection used HorusTrace output: **no**

| Surface | Cases | Agents | Authority rels | Partial | Unknown | Findings | Attack paths |
|---|---:|---:|---:|---:|---:|---:|---:|
| AgentCore current config | 4 | 5 | 0 | 0 | 0 | 0 | 0 |
| AgentCore Terraform | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| Bedrock Agent CloudFormation | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| Bedrock Agent Terraform | 3 | 4 | 2 | 2 | 0 | 1 | 0 |
| Strands Python | 3 | 3 | 1 | 1 | 0 | 0 | 0 |
| Strands TypeScript | 1 | 1 | 2 | 2 | 0 | 0 | 0 |

Zero-agent cases:

- `amz-br-cfn-001`

Authority Contract reports were generated for every case, but none of the public target applications declares a Horus Authority Contract. Therefore this cohort validates inventory/effective-authority reconstruction, not adoption-time contract pass/violation semantics.

## Source-adjudicated fundamental gaps

### P0 — Real CloudFormation Bedrock Agent disappears on intrinsic tags

**Case:** `amz-br-cfn-001` — `awslabs/amazon-bedrock-agent-samples/examples/agents/connected_house_agent`

The application contains a normal managed Bedrock Agent:

```yaml
ConnectedHouseAgent:
  Type: AWS::Bedrock::Agent
  Properties:
    AgentName: connected-house-agent
    FoundationModel: !Sub ...
    AgentResourceRoleArn: !GetAtt BedrockAgentRole.Arn
    ActionGroups:
      - ActionGroupName: HouseAPI
        ActionGroupExecutor:
          Lambda: !GetAtt HouseAgentFunction.Arn
```

HorusTrace result: **0 agents**.

The Amazon CloudFormation adapter currently loads templates with `yaml.safe_load`. Real CloudFormation intrinsic tags such as `!Sub`, `!GetAtt`, `!Ref` and related forms are not registered with that loader, causing the template to be rejected before `AWS::Bedrock::Agent` discovery.

The repository-level CloudFormation IAM authority parser uses the same loading strategy, so even after root discovery the role-authority path would be at risk.

This is a fundamental P0 because CloudFormation managed Bedrock Agents are an explicitly supported Amazon surface.

### P0 — Current Strands Python vended-tool namespace is not recognized

**Cases:** `amz-str-001`, `amz-str-002`

Current official Strands samples import high-authority tools through `strands_tools`, for example:

```python
from strands_tools import (
    editor,
    file_read,
    file_write,
    http_request,
    python_repl,
    retrieve,
    shell,
    use_aws,
)
```

The Amazon adapter currently recognizes vended imports only from `strands.vended_tools...`.

Consequences in the frozen run:

- the AWS audit assistant exposes shell/HTTP/editor/Python/file tools in source but HorusTrace binds only `report_generator`;
- the research agent exposes a broad tool dictionary including shell, HTTP, Python, file and AWS tools but its detected agent has **zero bound tools**.

This is not a sample-specific alias. It is a current Strands package/import surface and should be normalized centrally.

### P0 — Strands Python common tool/MCP data-flow patterns collapse to empty authority

**Cases:** `amz-str-001`, `amz-str-002`, `amz-str-003`

The Python adapter currently resolves mostly direct simple-name bindings. Real official examples use common composition forms such as:

```python
tools = get_tools()
mcp_tools = stdio_mcp_client.list_tools_sync()

agent = Agent(
    tools=list(tools.values()) + mcp_tools,
)
```

and:

```python
self.documentation_mcp_server = MCPClient(...)
self.tools = self.documentation_mcp_server.list_tools_sync() + [file_write]

agent = Agent(tools=self.tools)
```

and helper-return / imported-agent tools:

```python
aws_client = MCPClient(...)
with aws_client:
    agent = Agent(tools=aws_client.list_tools_sync())

agent = Agent(tools=[doc_agent, code_assistant, report_generator])
```

HorusTrace finds the agent roots but loses most or all of the source-proven tool/MCP authority.

Required behavior is conservative source data-flow, not arbitrary program execution: preserve statically knowable members, preserve the MCP relationship, and mark dynamically returned tool sets unresolved rather than representing the agent as authority-empty.

### P0 — First-party AgentCore gateway-backed application has zero effective authority

**Case:** `amz-ac-json-002` — `awslabs/agentcore-samples/02-use-cases/data-analyst-conversational-assistant`

The current AgentCore project defines a runtime and `DataAnalystToolsGateway`. The application creates a Strands `MCPClient` for the gateway and binds the returned tools:

```python
mcp_client = get_mcp_client()
with mcp_client:
    gateway_tools = mcp_client.list_tools_sync()
    agent = Agent(..., tools=[current_time] + gateway_tools)
```

HorusTrace detects both the AgentCore runtime and the Strands agent but reports **zero tools, zero MCP servers and zero effective-authority relationships**.

The current `agentcore.json` adapter only obtains tool authority from inline `gateway.targets`, while current AgentCore projects may materialize target/deployment detail elsewhere and use the gateway URL from application configuration.

The scanner must preserve the runtime/agent → AgentCore Gateway → MCP authority path when it is source-proven, while leaving target detail unresolved when the repository does not statically expose it.

### P0 — Bedrock action-group relationships drop the agent execution role

**Case:** `amz-br-tf-003` — `aws-samples/sample-fraud-investigation-assistance-using-aws-bedrock-strandsagents-mcp`

This case demonstrates that the repository IAM enrichment is substantially working:

- the Bedrock Agent is found;
- its action group is bound through the Terraform `agent_id` reference;
- the action-group Lambda resource is captured;
- the agent execution role is enriched with source-visible permissions, including Bedrock, Lambda, S3, KMS and OpenSearch permissions;
- the run emits `IDN002` for wildcard identity authority from that reconstructed IAM evidence.

However, the effective-authority relationship for the action group has **no identity** and remains partially resolved.

The generic relationship resolver looks only at `tool.identity`. A Bedrock action group executes under the owning agent's execution role, so the relationship should inherit the source-proven agent identity unless the tool explicitly overrides it.

This is a product-level authority reconstruction gap: the graph knows the role, but the effective-authority output drops it at the relationship layer.

## P1 authority/configuration gaps

### P1 — Terraform module inputs prevent Bedrock role-authority resolution

**Case:** `amz-br-tf-001` — `aws-samples/intelligent-rag-bedrockagent-iac`

The Bedrock Agent is discovered, but its role is expressed inside a module as:

```hcl
agent_resource_role_arn = var.agent_role_arn
```

The concrete IAM role and policies exist elsewhere in the repository and are passed through module inputs.

HorusTrace therefore retains `var.agent_role_arn` but does not correlate it to the concrete role authority. This is a common Terraform module-boundary problem and should be addressed with bounded module-variable/reference propagation rather than repository-specific logic.

### P1 — AgentCore Terraform inbound CUSTOM_JWT evidence is dropped

**Case:** `amz-ac-tf-001` — first-party AgentCore Terraform MCP runtime

The runtime, execution role and IAM permissions are detected correctly. Source also declares:

```hcl
authorizer_configuration {
  custom_jwt_authorizer {
    allowed_clients = [...]
    discovery_url   = "..."
  }
}
```

The security graph does not preserve the `CUSTOM_JWT` posture, allowed clients or discovery URL.

For security posture and authority reasoning, inbound authentication is material evidence and should survive normalization.

### P1 — AgentCore runtime is not linked to locally hosted MCP tools

**Case:** `amz-ac-tf-001`

The same project declares an AgentCore runtime with server protocol `MCP` and source-visible MCP tools. HorusTrace can discover the runtime and can separately discover tool/MCP elements, but they remain unbound.

A source-proven AgentCore MCP runtime should own/host its local MCP surface. If ownership cannot be proved, the relationship should be explicit and unresolved rather than silently absent.

### P1 — Current AgentCore security fields are not retained

**Case:** `amz-ac-json-003` — `twilio/twilio-agent-connect-aws`

The current config correctly yields the runtime root and core deployment metadata. It also declares security-relevant fields including `requestHeaderAllowlist` and session filesystem configuration. These do not currently survive into the normalized graph.

This does not invalidate runtime discovery, but it limits deployment-security reporting.

### P1/P2 — AgentCore Gateway / Identity / Cedar policy Terraform semantics are incomplete

**Case:** `amz-ac-tf-002` — independent `ai-agents-in-production` AWS example

The scanner successfully detects the runtime despite a divergent `aws_bedrockagentcore_runtime` resource spelling, which is a useful generalization result.

The same example also expresses a gateway, workload identity and Cedar policy. Those are not projected into effective authority.

This is best treated as controlled expansion work rather than a root-detection P0 because the primary runtime survives and the example exercises a divergent/illustrative Terraform shape.

## Deliberate unresolved pressure test

### Multi-agent orchestration through Step Functions/Lambda

**Case:** `amz-br-tf-002` — `aws-samples/amazon-bedrock-multiagent-orchestrator-terraform`

HorusTrace correctly inventories the Terraform supervisor and child-agent resource families. The repository performs orchestration through Step Functions and a Lambda router rather than a native Bedrock collaborator declaration.

The scanner does not invent a delegation relationship, which is the correct conservative default. A later enhancement can represent the source-visible orchestration as an unresolved/conditional delegation path, but this is not classified as a P0 for native Bedrock Agent support.

## Cases that behaved materially well at the structural level

The following cases found the intended root surface without an obvious fundamental construction miss in this review:

- `amz-str-ts-001` — Strands TypeScript Agent + both declared tools + AWS runtime identity
- `amz-ac-json-001` — current AgentCore container runtime config
- `amz-ac-json-003` — independent current AgentCore CodeZip runtime; P1 metadata omissions noted above
- `amz-ac-json-004` — independent AgentCore MCP runtime config
- `amz-ac-tf-001` — AgentCore Terraform runtime + execution-role IAM; P1 auth/linkage gaps noted above
- `amz-ac-tf-002` — alternate AgentCore Terraform runtime spelling; P1/P2 gateway-policy expansion remains
- `amz-br-tf-002` — supervisor/child inventory without fabricated Step Functions delegation

The directly referenced Bedrock Terraform case `amz-br-tf-003` is also strong at the inventory/IAM-enrichment layer; its material defect is specifically the loss of that identity in effective-authority projection.

## What this says about the architecture

The cohort does **not** suggest that Amazon support needs to be rewritten.

The core architecture is viable:

- provider-specific adapters discover Amazon roots;
- the normalized graph can represent tools, MCP, identities, resources and destinations;
- repository IAM enrichment can reconstruct real AWS permissions;
- effective-authority reporting can consume that normalized evidence;
- TypeScript Strands and several AgentCore/Bedrock Terraform roots generalize to unseen source.

The weak points are normalization and correlation boundaries:

1. parse real infrastructure syntax before normalization;
2. follow common source-proven Python binding/data-flow forms;
3. connect provider configuration to runtime/application MCP authority;
4. propagate owning-agent identity into provider-owned execution surfaces;
5. resolve bounded Terraform module/reference indirection.

These are reusable fixes, not a long list of repository-specific exceptions.

## Recommended next build slice

Keep this cohort and all SHAs frozen. Preserve workflow run **37197757475** as the pre-fix baseline.

Implement a separate scanner PR covering the four fundamental fix families:

1. CloudFormation-aware YAML intrinsic loading for Amazon discovery and IAM enrichment.
2. Strands Python normalization for current `strands_tools` imports plus common tool/MCP binding expressions and attribute assignments.
3. AgentCore gateway/MCP authority correlation for current project layouts.
4. Bedrock action-group inheritance of the owning agent's source-proven execution identity.

Then rerun these exact 14 cases and compare at the **case/relationship level**, not just raw counts.

After those P0s recover, address Terraform module-role joins and AgentCore auth/runtime linkage as the P1 slice.

Do not change the cohort to improve the score.
