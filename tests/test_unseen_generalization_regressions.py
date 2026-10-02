import json
from pathlib import Path

from horustrace.scanner import scan


def test_mcp_authorization_header_with_env_interpolation_is_not_literal_secret(
    tmp_path: Path,
) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "greptile": {
                        "url": "https://api.greptile.com/mcp",
                        "headers": {
                            "Authorization": "Bearer ${GREPTILE_API_KEY}",
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    server = graph.all_mcp_servers()[0]

    assert server.metadata["literal_credential_sources"] == []
    assert not any(finding.rule_id == "AGT051" for finding in findings)


def test_openai_hosted_search_and_image_tools_preserve_provider_destination(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent, ImageGenerationTool, WebSearchTool

agent = Agent(
    name="Research",
    tools=[WebSearchTool(), ImageGenerationTool()],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "Research")

    hosted = {
        tool.metadata.get("hosted_tool"): tool
        for tool in agent.tools
        if tool.metadata.get("hosted_tool")
    }
    for name in ("WebSearchTool", "ImageGenerationTool"):
        destinations = hosted[name].destinations
        assert len(destinations) == 1
        assert destinations[0].restricted is True
        assert destinations[0].metadata["network_scope"] == "fixed_provider_network"
        assert destinations[0].metadata["provider"] == "openai"

    assert not any(
        finding.rule_id == "NET002" and finding.agent == "Research"
        for finding in findings
    )


def test_pydantic_restricted_eval_is_not_host_process_authority(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import math
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-5.2")

@agent.tool
def calculate(ctx: RunContext[None], expression: str) -> str:
    allowed_names = {"sqrt": math.sqrt, "pi": math.pi}
    result = eval(expression, {"__builtins__": {}}, allowed_names)
    return str(result)

@agent.tool
async def web_search(ctx: RunContext[None], query: str) -> str:
    return await client.get("https://api.example.test/search", params={"q": query})
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    calculate = next(tool for tool in agent.tools if tool.name == "calculate")

    assert "process.execute" in calculate.capabilities
    assert calculate.metadata["process_execution_constrained"] is True
    assert calculate.metadata["host_process_execution"] is False
    assert not any(finding.rule_id == "AGT020" for finding in findings)
    assert not any(finding.rule_id == "CAP004" for finding in findings)
    assert any(
        finding.rule_id == "AGT040" and finding.agent == "agent"
        for finding in findings
    )


def test_mcp_execute_named_provider_operation_does_not_imply_host_process(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Provider API")

@mcp.tool()
def execute_batch(batch_id: str):
    return provider.execute_batch(batch_id)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(item for item in graph.unbound_tools if item.name == "execute_batch")

    assert "process.execute" not in tool.capabilities


def test_pydantic_repository_helpers_preserve_fixed_provider_destinations(
    tmp_path: Path,
) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "__init__.py").write_text("", encoding="utf-8")
    (tools / "providers.py").write_text(
        """
import httpx
from googleapiclient.discovery import build

async def brave_search(api_key: str, query: str):
    return await httpx.get(
        "https://api.search.brave.com/res/v1/web/search",
        params={"q": query},
        headers={"X-Subscription-Token": api_key},
    )

def gmail_service(credentials):
    return build("gmail", "v1", credentials=credentials)
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent, RunContext
from tools.providers import brave_search

agent = Agent("openai:gpt-5.2")

@agent.tool
async def search_web(ctx: RunContext[None], query: str):
    return await brave_search("configured-key", query)

@agent.tool
async def create_draft(ctx: RunContext[None], recipient: str):
    from tools.providers import gmail_service
    service = gmail_service(None)
    return service.users().drafts().create(
        userId="me",
        body={"to": recipient},
    ).execute()
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    search = next(tool for tool in agent.tools if tool.name == "search_web")
    draft = next(tool for tool in agent.tools if tool.name == "create_draft")

    assert any(
        destination.restricted
        and destination.metadata.get("network_scope") == "fixed_provider_network"
        and destination.target == "https://api.search.brave.com"
        for destination in search.destinations
    )
    assert any(
        destination.restricted
        and destination.metadata.get("provider") == "google"
        and destination.metadata.get("service") == "gmail"
        for destination in draft.destinations
    )
    assert not any(
        finding.rule_id == "NET002" and finding.agent == "agent"
        for finding in findings
    )

def test_pydantic_async_client_helper_preserves_fixed_destination(
    tmp_path: Path,
) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "__init__.py").write_text("", encoding="utf-8")
    (tools / "providers.py").write_text(
        """
import httpx

async def brave_search(query: str):
    async with httpx.AsyncClient() as client:
        return await client.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query},
        )
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent, RunContext
from tools.providers import brave_search

agent = Agent("openai:gpt-5.2")

@agent.tool
async def search_web(ctx: RunContext[None], query: str):
    return await brave_search(query)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    search = next(tool for tool in agent.tools if tool.name == "search_web")

    assert any(
        destination.target == "https://api.search.brave.com"
        and destination.restricted is True
        and destination.metadata.get("network_scope") == "fixed_provider_network"
        for destination in search.destinations
    )
    assert not any(
        finding.rule_id == "NET002" and finding.agent == "agent"
        for finding in findings
    )


def test_pydantic_pure_content_helper_does_not_gain_external_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent, RunContext

email_agent = Agent("openai:gpt-5.2")

@email_agent.tool
def compose_email_content(
    ctx: RunContext[None],
    recipient_email: str,
    subject: str,
    body: str,
):
    return {
        "to": recipient_email,
        "subject": subject,
        "body": body,
    }
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "email_agent")
    tool = next(item for item in agent.tools if item.name == "compose_email_content")

    assert "network.external" not in tool.capabilities
    assert "external.write" not in tool.capabilities
    assert not any(
        finding.rule_id == "AGT040"
        and finding.agent == "email_agent"
        and finding.location
        and finding.location.path.name == "agent.py"
        for finding in findings
    )


def test_pydantic_agent_run_delegation_inherits_fixed_destination(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
import httpx
from pydantic_ai import Agent, RunContext

email_agent = Agent("openai:gpt-5.2")

@email_agent.tool
async def create_gmail_draft(ctx: RunContext[None], body: str):
    return await httpx.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/drafts",
        json={"body": body},
    )

research_agent = Agent("openai:gpt-5.2")

@research_agent.tool
async def create_email_draft(ctx: RunContext[None], body: str):
    return await email_agent.run(body)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    research = next(item for item in graph.agents if item.name == "research_agent")
    wrapper = next(
        item for item in research.tools if item.name == "create_email_draft"
    )

    assert "agent.delegate" in wrapper.capabilities
    assert "network.external" in wrapper.capabilities
    assert wrapper.metadata["delegated_agent_targets"] == ["email_agent"]
    assert any(
        destination.target.startswith("https://gmail.googleapis.com/")
        for destination in wrapper.destinations
    )
    assert not any(
        finding.rule_id == "NET002" and finding.agent == "research_agent"
        for finding in findings
    )


def test_adk_urllib_request_wrapper_preserves_fixed_host(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import urllib.parse
import urllib.request
from google.adk.agents import Agent

def check_package(name: str):
    params = urllib.parse.urlencode({"q": name})
    url = "https://search.maven.org/solrsearch/select?" + params
    req = urllib.request.Request(url, headers={"User-Agent": "horus-test"})
    with urllib.request.urlopen(req, timeout=6) as response:
        return response.read().decode("utf-8")

root_agent = Agent(
    name="package_checker",
    model="gemini-2.5-flash",
    tools=[check_package],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "package_checker")
    tool = next(item for item in agent.tools if item.name == "check_package")

    assert any(
        destination.target == "https://search.maven.org"
        and destination.restricted is True
        for destination in tool.destinations
    )
    assert not any(
        destination.target == "<dynamic-url>"
        for destination in tool.destinations
    )
    assert not any(
        finding.rule_id == "NET001" and finding.agent == "package_checker"
        for finding in findings
    )

def test_adk_imported_tool_local_helpers_preserve_fixed_hosts(
    tmp_path: Path,
) -> None:
    (tmp_path / "tools.py").write_text(
        """
import json
import urllib.parse
import urllib.request

def _check_pypi(name: str):
    with urllib.request.urlopen(
        f"https://pypi.org/pypi/{name}/json",
        timeout=6,
    ) as response:
        return json.load(response)

def _check_maven(name: str):
    query = urllib.parse.urlencode({"q": name})
    url = "https://search.maven.org/solrsearch/select?" + query
    req = urllib.request.Request(url, headers={"User-Agent": "horus-test"})
    with urllib.request.urlopen(req, timeout=6) as response:
        return json.load(response)

def check_package(name: str, ecosystem: str = "auto"):
    if ecosystem == "maven":
        return _check_maven(name)
    return _check_pypi(name)
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import Agent
from tools import check_package

root_agent = Agent(
    name="package_checker",
    model="gemini-2.5-flash",
    tools=[check_package],
)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "package_checker")
    tool = next(item for item in agent.tools if item.name == "check_package")

    fixed = {
        destination.target
        for destination in tool.destinations
        if destination.restricted is True
    }
    assert "https://pypi.org" in fixed
    assert "https://search.maven.org" in fixed
    assert not any(
        destination.target == "<dynamic-url>"
        for destination in tool.destinations
    )
    assert not any(
        finding.rule_id == "NET001" and finding.agent == "package_checker"
        for finding in findings
    )

