from pathlib import Path

from horustrace.adapters.amazon_agentic import (
    is_amazon_agentic_python_file,
    scan_amazon_agentic_config_file,
    scan_amazon_agentic_python_file,
    scan_amazon_agentic_terraform_file,
    scan_amazon_cloudformation_file,
)
from horustrace.scanner import scan


def write(tmp_path: Path, text: str, name: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_strands_agent_tools_mcp_and_delegation(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        '''
import requests
from mcp import StdioServerParameters, stdio_client
from strands import Agent, tool
from strands.tools.mcp import MCPClient
from strands.vended_tools import file_editor

@tool
def publish_ticket(body: str) -> str:
    return requests.post("https://tickets.example.test/api", json={"body": body}).text

aws_docs = MCPClient(
    lambda: stdio_client(
        StdioServerParameters(
            command="uvx",
            args=["awslabs.aws-documentation-mcp-server@latest"],
        )
    ),
    tool_filters={"allowed": ["search_documentation"]},
)

specialist = Agent(tools=[publish_ticket])
root = Agent(
    tools=[file_editor, aws_docs, specialist],
    system_prompt="Coordinate the work.",
)
''',
        "agent.py",
    )

    assert is_amazon_agentic_python_file(path)
    graph = scan_amazon_agentic_python_file(path)

    root = next(item for item in graph.agents if item.name == "root")
    specialist = next(item for item in graph.agents if item.name == "specialist")

    editor = next(item for item in root.tools if item.name == "file_editor")
    assert editor.capabilities == {"data.read", "data.write"}

    server = next(item for item in root.mcp_servers if item.name == "aws_docs")
    assert server.transport == "stdio"
    assert server.command == "uvx"
    assert server.allowed_tools == ["search_documentation"]

    publish = next(item for item in specialist.tools if item.name == "publish_ticket")
    assert "network.external" in publish.capabilities
    assert "external.write" in publish.capabilities
    assert [item.target for item in publish.destinations] == [
        "https://tickets.example.test/api"
    ]

    delegated = next(item for item in root.tools if item.kind == "delegated_agent")
    assert delegated.name == "specialist"
    assert "agent.delegate" in delegated.capabilities
    assert "network.external" in delegated.capabilities
    assert root.metadata["delegates_to"] == ["specialist"]
    assert root.identities[0].credential_source == "aws_default_credential_chain"


def test_agentcore_json_inventory_gateway_and_knowledge_base(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        '''
{
  "name": "OrdersProject",
  "version": 1,
  "runtimes": [
    {
      "name": "OrdersAgent",
      "build": "CodeZip",
      "entrypoint": "main.py",
      "networkMode": "PUBLIC",
      "protocol": "HTTP",
      "executionRoleArn": "arn:aws:iam::111122223333:role/OrdersAgentRole"
    }
  ],
  "credentials": [
    {"name": "SalesforceOAuth", "type": "OAUTH"}
  ],
  "agentCoreGateways": [
    {
      "name": "OrdersGateway",
      "roleArn": "arn:aws:iam::111122223333:role/GatewayRole",
      "authorizerType": "AWS_IAM",
      "targets": [
        {
          "name": "SalesforceTools",
          "targetType": "mcpServer",
          "endpoint": "https://mcp.salesforce.example/mcp",
          "outboundAuth": {
            "type": "OAUTH",
            "credentialName": "SalesforceOAuth",
            "scopes": ["customer:write"]
          }
        }
      ]
    }
  ],
  "knowledgeBases": [
    {
      "name": "OrderDocs",
      "dataSources": [
        {"type": "S3", "uri": "s3://order-docs/manuals/"}
      ]
    }
  ]
}
''',
        "agentcore.json",
    )

    graph = scan_amazon_agentic_config_file(path)
    agent = next(item for item in graph.agents if item.name == "OrdersAgent")
    assert agent.metadata["runtime"] == "bedrock-agentcore"
    assert agent.identities[0].name.endswith("OrdersAgentRole")

    server = next(item for item in graph.unbound_mcp_servers if item.name == "SalesforceTools")
    assert server.url == "https://mcp.salesforce.example/mcp"
    assert server.authenticated is True
    assert server.identity == "SalesforceOAuth"
    assert server.metadata["oauth_scopes"] == ["customer:write"]

    kb = next(item for item in graph.unbound_tools if item.name == "retrieve:OrderDocs")
    assert kb.capabilities == {"data.read"}
    assert kb.resources[0].selector == "s3://order-docs/manuals/"

    assert {item.name for item in graph.identities} >= {
        "SalesforceOAuth",
        "arn:aws:iam::111122223333:role/GatewayRole",
    }


def test_legacy_agentcore_yaml_preserves_execution_role_and_memory(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        '''
default_agent: order_agent
agents:
  order_agent:
    name: order_agent
    entrypoint: agent.py
    deployment_type: direct_code_deploy
    aws:
      execution_role: arn:aws:iam::111122223333:role/OrderRuntimeRole
      region: eu-west-2
      network_configuration:
        network_mode: VPC
      protocol_configuration:
        server_protocol: HTTP
    memory:
      mode: STM_AND_LTM
      memory_id: order-memory
''',
        ".bedrock_agentcore.yaml",
    )

    graph = scan_amazon_agentic_config_file(path)
    agent = graph.agents[0]
    assert agent.name == "order_agent"
    assert agent.identities[0].name.endswith("OrderRuntimeRole")
    assert agent.metadata["network_mode"] == "VPC"
    memory = next(item for item in agent.tools if item.kind == "agentcore_memory")
    assert memory.capabilities == {"data.read", "data.write"}
    assert memory.resources[0].selector == "order-memory"


def test_cloudformation_bedrock_agent_and_agentcore_resources(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        '''
Resources:
  OrderAgent:
    Type: AWS::Bedrock::Agent
    Properties:
      AgentName: order-agent
      AgentResourceRoleArn: arn:aws:iam::111122223333:role/BedrockAgentRole
      FoundationModel: anthropic.claude-sonnet-4-6-v1:0
      GuardrailConfiguration:
        GuardrailIdentifier: guardrail-123
        GuardrailVersion: "1"
      ActionGroups:
        - ActionGroupName: refund_order
          ActionGroupExecutor:
            Lambda: arn:aws:lambda:eu-west-2:111122223333:function:refund-order
        - ActionGroupName: code
          ParentActionGroupSignature: AMAZON.CodeInterpreter
      KnowledgeBases:
        - KnowledgeBaseId: KB12345678
          Description: order docs
      AgentCollaborators:
        - CollaboratorName: fraud-agent
          AgentDescriptor:
            AliasArn: arn:aws:bedrock:eu-west-2:111122223333:agent-alias/ABC/DEF
  Runtime:
    Type: AWS::BedrockAgentCore::Runtime
    Properties:
      AgentRuntimeName: OrderRuntime
      RoleArn: arn:aws:iam::111122223333:role/OrderRuntimeRole
      AgentRuntimeArtifact:
        ContainerConfiguration:
          ContainerUri: example.dkr.ecr.eu-west-2.amazonaws.com/order:latest
      NetworkConfiguration:
        NetworkMode: PUBLIC
      ProtocolConfiguration: HTTP
  Gateway:
    Type: AWS::BedrockAgentCore::Gateway
    Properties:
      Name: order-gateway
      RoleArn: arn:aws:iam::111122223333:role/GatewayRole
  Target:
    Type: AWS::BedrockAgentCore::GatewayTarget
    Properties:
      Name: partner-tools
      GatewayIdentifier: gateway-1234567890
      TargetConfiguration:
        Mcp:
          McpServer:
            Endpoint: https://partner.example/mcp
      CredentialProviderConfigurations:
        - CredentialProviderType: OAUTH
''',
        "infra.yaml",
    )

    graph = scan_amazon_cloudformation_file(path)
    agent = next(item for item in graph.agents if item.name == "order-agent")
    assert agent.metadata["guardrail_configured"] is True
    assert agent.identities[0].name.endswith("BedrockAgentRole")

    refund = next(item for item in agent.tools if item.name == "refund_order")
    assert refund.resources[0].selector.endswith(":function:refund-order")
    code = next(item for item in agent.tools if item.name == "code")
    assert "process.execute" in code.capabilities
    assert agent.data_sources[0].selector == "KB12345678"

    delegated = next(item for item in agent.tools if item.kind == "delegated_agent")
    assert delegated.name == "fraud-agent"
    assert "agent.delegate" in delegated.capabilities

    runtime = next(item for item in graph.agents if item.name == "OrderRuntime")
    assert runtime.identities[0].name.endswith("OrderRuntimeRole")
    assert runtime.metadata["networkMode"] == "PUBLIC"

    server = next(item for item in graph.unbound_mcp_servers if item.name == "partner-tools")
    assert server.url == "https://partner.example/mcp"
    assert server.authenticated is True


def test_terraform_bedrock_and_agentcore_inventory(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        '''
resource "aws_iam_role" "agent" {
  name = "OrdersAgentRole"
}

resource "aws_bedrockagent_agent" "orders" {
  agent_name              = "orders-agent"
  agent_resource_role_arn = aws_iam_role.agent.arn
  foundation_model        = "anthropic.claude-sonnet-4-6-v1:0"
}

resource "aws_bedrockagent_agent_action_group" "refund" {
  action_group_name = "refund_order"
  agent_id          = aws_bedrockagent_agent.orders.agent_id
  agent_version     = "DRAFT"
  action_group_executor {
    lambda = "arn:aws:lambda:eu-west-2:111122223333:function:refund-order"
  }
}

resource "aws_bedrockagentcore_agent_runtime" "runtime" {
  agent_runtime_name = "orders-runtime"
  role_arn           = aws_iam_role.agent.arn
  network_configuration {
    network_mode = "PUBLIC"
  }
  protocol_configuration {
    server_protocol = "MCP"
  }
}

resource "aws_bedrockagentcore_gateway_target" "partner" {
  name = "partner-tools"
  gateway_identifier = "gateway-123"
  credential_provider_configuration {
    oauth {}
  }
  target_configuration {
    mcp {
      mcp_server {
        endpoint = "https://partner.example/mcp"
      }
    }
  }
}
''',
        "main.tf",
    )

    graph = scan_amazon_agentic_terraform_file(path)
    assert {item.name for item in graph.agents} == {"orders-agent", "orders-runtime"}
    orders = next(item for item in graph.agents if item.name == "orders-agent")
    assert orders.identities[0].name == "aws_iam_role.agent.arn"
    runtime = next(item for item in graph.agents if item.name == "orders-runtime")
    assert runtime.metadata["networkMode"] == "PUBLIC"
    assert runtime.metadata["protocol"] == "MCP"

    refund = next(item for item in graph.unbound_tools if item.name == "refund_order")
    assert refund.metadata["agent_reference"] == "aws_bedrockagent_agent.orders.agent_id"
    assert refund.resources[0].selector.endswith(":function:refund-order")

    server = next(item for item in graph.unbound_mcp_servers if item.name == "partner-tools")
    assert server.authenticated is True
    assert server.metadata["credential_provider_type"] == "OAUTH"


def test_repository_scan_projects_terraform_iam_and_binds_action_group(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        '''
data "aws_iam_policy_document" "agent_access" {
  statement {
    actions = ["s3:GetObject", "s3:PutObject", "dynamodb:UpdateItem"]
    resources = ["arn:aws:s3:::orders/*", "arn:aws:dynamodb:*:*:table/orders"]
  }
}

resource "aws_iam_role" "agent" {
  name = "OrdersAgentRole"
}

resource "aws_iam_role_policy" "agent_access" {
  role   = aws_iam_role.agent.id
  policy = data.aws_iam_policy_document.agent_access.json
}

resource "aws_bedrockagent_agent" "orders" {
  agent_name              = "orders-agent"
  agent_resource_role_arn = aws_iam_role.agent.arn
  foundation_model        = "anthropic.claude-sonnet-4-6-v1:0"
}

resource "aws_bedrockagent_agent_action_group" "refund" {
  action_group_name = "refund_order"
  agent_id          = aws_bedrockagent_agent.orders.agent_id
  agent_version     = "DRAFT"
  action_group_executor {
    lambda = "arn:aws:lambda:eu-west-2:111122223333:function:refund-order"
  }
}
''',
        "main.tf",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "orders-agent")
    identity = agent.identities[0]
    assert {"s3:GetObject", "s3:PutObject", "dynamodb:UpdateItem"} <= identity.permissions
    assert identity.metadata["iam_authority_resolved"] is True
    assert "arn:aws:s3:::orders/*" in identity.metadata["iam_resource_scopes"]

    refund = next(tool for tool in agent.tools if tool.name == "refund_order")
    assert refund.kind == "bedrock_action_group"
    assert refund.metadata["authority_binding_basis"] == "terraform_agent_id_reference"
    assert not any(tool.name == "refund_order" for tool in graph.unbound_tools)


def test_repository_scan_projects_cloudformation_iam_to_bedrock_agent(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        '''
Resources:
  AgentRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: OrdersAgentRole
      Policies:
        - PolicyName: OrdersAccess
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - dynamodb:UpdateItem
                Resource: "*"
  OrderAgent:
    Type: AWS::Bedrock::Agent
    Properties:
      AgentName: order-agent
      AgentResourceRoleArn:
        Fn::GetAtt: [AgentRole, Arn]
      FoundationModel: anthropic.claude-sonnet-4-6-v1:0
''',
        "template.yaml",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "order-agent")
    identity = agent.identities[0]
    assert {"s3:GetObject", "dynamodb:UpdateItem"} <= identity.permissions
    assert identity.resource_scope == "*"
    assert identity.metadata["iam_unrestricted_resource"] is True


def test_repository_scan_dispatches_amazon_adapters(tmp_path: Path) -> None:
    write(
        tmp_path,
        '''
from strands import Agent
agent = Agent()
''',
        "agent.py",
    )
    write(
        tmp_path,
        '''
{
  "name": "Demo",
  "version": 1,
  "runtimes": [{"name": "RuntimeAgent", "entrypoint": "agent.py"}],
  "memories": [],
  "credentials": [],
  "evaluators": [],
  "onlineEvalConfigs": [],
  "agentCoreGateways": []
}
''',
        "agentcore.json",
    )

    graph, _ = scan(tmp_path)
    names = {item.name for item in graph.agents}
    assert "agent" in names
    assert "RuntimeAgent" in names
