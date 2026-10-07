import json
from pathlib import Path

from horustrace.cli import main
from horustrace.models import (
    Agent,
    Graph,
    Identity,
    NetworkDestination,
    ResourceScope,
    SourceLocation,
    Tool,
)
from horustrace.scanner import scan
from horustrace.security_graph import (
    AGENT_SECURITY_GRAPH_MODEL,
    build_agent_security_graph,
)


def _project(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        """from agents import Agent, function_tool

@function_tool
def send_message(message: str) -> str:
    return message

agent = Agent(
    name="support",
    instructions="Help support users.",
    tools=[send_message],
)
""",
        encoding="utf-8",
    )


def test_security_graph_is_deterministic_and_workspace_portable(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    _project(first_root)
    _project(second_root)

    first_graph, _ = scan(first_root)
    second_graph, _ = scan(second_root)
    first = build_agent_security_graph(first_graph, first_root)
    second = build_agent_security_graph(second_graph, second_root)

    assert first.as_dict()["schema_version"] == 1
    assert first.as_dict()["model"] == AGENT_SECURITY_GRAPH_MODEL
    assert first.canonical_digest() == second.canonical_digest()
    assert first.as_dict() == second.as_dict()

    encoded = json.dumps(first.as_dict())
    assert str(first_root) not in encoded
    assert str(second_root) not in encoded


def test_security_graph_co_locates_security_evidence(tmp_path: Path) -> None:
    _project(tmp_path)
    graph, _ = scan(tmp_path)

    document = build_agent_security_graph(graph, tmp_path).as_dict()

    assert document["topology"]["schema_version"] == 1
    assert document["effective_authority"]["schema_version"] == 1
    assert document["summary"]["topology_nodes"] >= 2
    assert document["summary"]["authority_relationships"] >= 1
    assert document["summary"]["flows"] == len(document["flows"])
    assert document["summary"]["attack_paths"] == len(document["attack_paths"])
    assert document["digest"].startswith("sha256:")
    assert document["resolution"]["coverage_incomplete"] is graph.coverage.incomplete


def test_security_graph_cli_writes_json(tmp_path: Path) -> None:
    _project(tmp_path)
    output = tmp_path / "asg.json"

    assert main(["security-graph", str(tmp_path), "--output", str(output)]) == 0

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema_version"] == 1
    assert document["model"] == AGENT_SECURITY_GRAPH_MODEL
    assert document["root"] == "."
    assert document["digest"].startswith("sha256:")


def test_security_graph_does_not_count_delegation_projection_as_tool(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import LlmAgent, SequentialAgent

writer = LlmAgent(name="writer", model="gemini-flash-latest")
formatter = LlmAgent(name="formatter", model="gemini-flash-latest")
root_agent = SequentialAgent(
    name="pipeline",
    sub_agents=[writer, formatter],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    document = build_agent_security_graph(graph, tmp_path).as_dict()
    nodes = document["topology"]["nodes"]

    assert not any(
        node["kind"] == "tool"
        and node["attributes"].get("tool_kind") == "delegated_agent"
        for node in nodes
    )
    delegation_nodes = {
        node["attributes"].get("tool_name")
        for node in nodes
        if node["kind"] == "delegation"
    }
    assert {"delegate:writer", "delegate:formatter"} <= delegation_nodes



def test_security_graph_preserves_model_data_identity_lineage(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", 3, 1)
    identity = Identity(
        name="storage-identity",
        provider="gcp",
        location=location,
        metadata={"framework": "google-adk"},
    )
    tool = Tool(
        name="read_object",
        kind="adk_function",
        capabilities={"data.read", "network.external"},
        identity="storage-identity",
        resources=[
            ResourceScope(
                kind="gcs",
                selector="gs://reports/*",
                access={"data.read"},
                location=location,
                metadata={
                    "provider": "gcp",
                    "source": "source_configuration",
                },
            )
        ],
        destinations=[
            NetworkDestination(
                target="https://storage.googleapis.com",
                restricted=True,
                location=location,
                metadata={
                    "provider": "gcp",
                    "network_scope": "fixed_provider_network",
                },
            )
        ],
        location=location,
        metadata={"framework": "google-adk"},
    )
    agent = Agent(
        name="report_agent",
        tools=[tool],
        identities=[identity],
        location=location,
        metadata={
            "framework": "google-adk",
            "model": "google:gemini-2.5-pro",
        },
    )
    graph = Graph(agents=[agent])

    document = build_agent_security_graph(graph, tmp_path).as_dict()
    nodes = document["topology"]["nodes"]
    edges = document["topology"]["edges"]

    model = next(item for item in nodes if item["kind"] == "model")
    assert model["attributes"]["model_provider"] == "google"
    assert model["attributes"]["model_identifier"] == "google:gemini-2.5-pro"

    resource = next(item for item in nodes if item["kind"] == "data_resource")
    assert resource["attributes"]["connection_type"] == "object_store"
    assert resource["attributes"]["provider"] == "gcp"

    edge_kinds = {item["kind"] for item in edges}
    assert "USES_MODEL" in edge_kinds
    assert "USES_IDENTITY" in edge_kinds
    assert "READS_FROM" in edge_kinds
    assert "AUTHORIZES_ACCESS_TO" in edge_kinds
    assert "AUTHORIZES_CONNECTION_TO" in edge_kinds

