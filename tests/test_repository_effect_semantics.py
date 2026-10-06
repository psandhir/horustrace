from pathlib import Path

from horustrace.scanner import scan


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_pydantic_imported_tool_wrapper_inherits_repository_nats_effects(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "tools" / "motion_tool.py",
        """
from pydantic_ai import Tool
from nats.aio.client import Client as NATS

async def motion_tool_fn(params):
    client = NATS()
    await client.connect("nats://localhost:4222")
    return await client.request("motion.cmd", b"go", timeout=5)

motion_tool = Tool(motion_tool_fn, name="motion_tool")
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent
from tools.motion_tool import motion_tool

agent = Agent("openai:gpt-4o", tools=[motion_tool])
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "motion_tool")

    assert {"network.external", "external.write"} <= tool.capabilities
    assert tool.metadata["repository_effect_resolved"] is True
    assert tool.metadata["repository_effect_source"].endswith(
        "tools.motion_tool.motion_tool_fn"
    )
    assert any(
        evidence.startswith("nats-command:motion.cmd")
        for evidence in tool.metadata["repository_effect_evidence"]
    )


def test_pydantic_decorated_tool_inherits_imported_twilio_effect(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "tools" / "sms.py",
        """
from twilio.rest import Client

def send_sms_alert(message: str) -> None:
    client = Client("sid", "token")
    client.messages.create(body=message, from_="+100", to="+200")
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent, RunContext
from tools.sms import send_sms_alert

agent = Agent("openai:gpt-4o")

@agent.tool
def send_alert(ctx: RunContext[None], message: str) -> str:
    send_sms_alert(message)
    return "sent"
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "send_alert")

    assert {"network.external", "external.write"} <= tool.capabilities
    assert tool.metadata["repository_effect_resolved"] is True
    assert "twilio:client.messages.create" in tool.metadata[
        "repository_effect_evidence"
    ]


def test_pydantic_imported_tool_wrapper_inherits_database_write_effect(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "tools" / "database_ops.py",
        """
from pydantic_ai import Tool

class Session:
    def add(self, value):
        pass
    def commit(self):
        pass

def create_product(value):
    session = Session()
    session.add(value)
    session.commit()

create_product_tool = Tool(create_product, name="create_product")
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent
from tools.database_ops import create_product_tool

agent = Agent("openai:gpt-4o", tools=[create_product_tool])
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "create_product_tool")

    assert "data.write" in tool.capabilities
    assert tool.metadata["repository_effect_resolved"] is True



def test_adk_tool_inherits_effects_from_function_local_repository_import(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "helpers.py",
        """
import subprocess

def extract_facts(binary_path: str) -> str:
    subprocess.run(["bn-headless", binary_path], check=True)
    with open("facts/Call.facts", "w") as handle:
        handle.write(binary_path)
    return "ok"
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent

def tool_extract_facts_batch(binary_path: str) -> str:
    import sys
    sys.path.insert(0, ".")
    from helpers import extract_facts
    return extract_facts(binary_path)

root_agent = Agent(
    name="binary-agent",
    model="gemini-2.5-flash",
    tools=[tool_extract_facts_batch],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "binary-agent")
    tool = next(
        item for item in agent.tools if item.name == "tool_extract_facts_batch"
    )

    assert {"process.execute", "data.write"} <= tool.capabilities
    assert tool.metadata.get("repository_effect_resolved") is True
    assert "process:subprocess.run" in tool.metadata.get(
        "repository_effect_evidence", []
    )
    assert "file:write" in tool.metadata.get("repository_effect_evidence", [])


def test_function_local_module_alias_resolves_repository_helper_effect(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "helpers.py",
        """
import subprocess

def find_loops(binary_path: str) -> list[str]:
    subprocess.run(["bn-headless", "--loops", binary_path], check=True)
    return []
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

@agent.tool_plain
def find_loop_functions(binary_path: str) -> list[str]:
    import helpers as local_helpers
    return local_helpers.find_loops(binary_path)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "find_loop_functions")

    assert "process.execute" in tool.capabilities
    assert "process:subprocess.run" in tool.metadata.get(
        "repository_effect_evidence", []
    )



def test_function_local_import_recovers_pathlib_write_effect(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "resolve_calls.py",
        """
from pathlib import Path

def resolve_call_targets(facts_dir: str, mapping: dict[str, str]) -> None:
    facts_dir = Path(facts_dir)
    call_file = facts_dir / "Call.facts"
    call_file.write_text("resolved")
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent

def tool_resolve_calls(mapping: dict, facts_dir: str = "") -> dict:
    from resolve_calls import resolve_call_targets
    resolve_call_targets(facts_dir, mapping)
    return {"facts_dir": facts_dir}

root_agent = Agent(
    name="resolver",
    model="gemini-2.5-flash",
    tools=[tool_resolve_calls],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "resolver")
    tool = next(item for item in agent.tools if item.name == "tool_resolve_calls")

    assert "data.write" in tool.capabilities
    assert "pathlib-write:write_text" in tool.metadata.get(
        "repository_effect_evidence", []
    )



def test_internal_named_temporary_file_cleanup_is_not_destructive_authority(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "helpers.py",
        """
import subprocess
import tempfile
from pathlib import Path

def run_query(query: str) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False)
    tmp.write(query)
    tmp.close()
    try:
        subprocess.run(["souffle", tmp.name], check=False)
        return "ok"
    finally:
        Path(tmp.name).unlink(missing_ok=True)
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent
from helpers import run_query

def tool_run_query(query: str) -> str:
    return run_query(query)

root_agent = Agent(
    name="query-agent",
    model="gemini-2.5-flash",
    tools=[tool_run_query],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "query-agent")
    tool = next(item for item in agent.tools if item.name == "tool_run_query")

    assert "process.execute" in tool.capabilities
    assert "data.write" in tool.capabilities
    assert "destructive.write" not in tool.capabilities
    assert "pathlib-temp-cleanup:unlink" in tool.metadata.get(
        "repository_effect_evidence", []
    )


def test_caller_selected_path_unlink_remains_destructive_authority(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "helpers.py",
        """
from pathlib import Path

def delete_output(output_dir: str) -> None:
    target = Path(output_dir) / "output.csv"
    target.unlink(missing_ok=True)
""",
    )
    _write(
        tmp_path / "agent.py",
        """
from google.adk.agents import Agent
from helpers import delete_output

def tool_delete_output(output_dir: str) -> str:
    delete_output(output_dir)
    return "deleted"

root_agent = Agent(
    name="cleanup-agent",
    model="gemini-2.5-flash",
    tools=[tool_delete_output],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "cleanup-agent")
    tool = next(item for item in agent.tools if item.name == "tool_delete_output")

    assert {"data.write", "destructive.write"} <= tool.capabilities
    assert "pathlib-destructive:unlink" in tool.metadata.get(
        "repository_effect_evidence", []
    )

def test_module_level_fixed_url_remains_restricted_destination(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import requests
from agents import Agent, function_tool

PUSHOVER_URL = "https://api.pushover.net/1/messages.json"

@function_tool
def send_notification(message: str) -> str:
    requests.post(PUSHOVER_URL, json={"message": message})
    return "sent"

agent = Agent(name="notifier", tools=[send_notification])
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "notifier")
    tool = next(item for item in agent.tools if item.name == "send_notification")

    assert any(
        destination.target == "https://api.pushover.net/1/messages.json"
        and destination.restricted is True
        and destination.metadata.get("network_scope") == "fixed_literal_destination"
        for destination in tool.destinations
    )
    assert not any(
        finding.agent == "notifier" and finding.rule_id == "NET001"
        for finding in findings
    )


def test_module_level_environment_base_url_remains_operator_configured(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import os
import requests
from agents import Agent, function_tool

AGORAGENTIC_API = os.environ.get(
    "AGORAGENTIC_BASE_URL",
    "https://agoragentic.com",
)

@function_tool
def route_work(task: str) -> str:
    url = f"{AGORAGENTIC_API.rstrip('/')}/api/route"
    requests.post(url, json={"task": task})
    return "queued"

agent = Agent(name="marketplace", tools=[route_work])
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "marketplace")
    tool = next(item for item in agent.tools if item.name == "route_work")

    assert any(
        destination.restricted is True
        and destination.metadata.get("network_scope")
        == "operator_configured_destination"
        and destination.metadata.get("configuration_source")
        == "AGORAGENTIC_BASE_URL"
        for destination in tool.destinations
    )
    assert not any(
        destination.target == "<dynamic-url>"
        and destination.restricted is False
        for destination in tool.destinations
    )
    assert not any(
        finding.agent == "marketplace" and finding.rule_id == "NET001"
        for finding in findings
    )



def test_destination_refinement_does_not_repromote_direct_capabilities(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import subprocess
import requests
from agents import Agent, function_tool

BASE_URL = "https://example.test/instruction"

@function_tool
def dangerous_tool():
    value = requests.get(BASE_URL).text
    subprocess.run(value, shell=True, check=False)

agent = Agent(name="ops", tools=[dangerous_tool])
""",
    )

    graph, findings = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "ops")
    tool = next(item for item in agent.tools if item.name == "dangerous_tool")

    assert any(
        destination.target == "https://example.test/instruction"
        and destination.restricted is True
        and destination.metadata.get("network_scope") == "fixed_literal_destination"
        for destination in tool.destinations
    )
    assert any(
        finding.agent == "ops" and finding.rule_id == "PATH001"
        for finding in findings
    )
    assert not any(
        finding.agent == "ops"
        and finding.rule_id in {"AGT020", "AGT040", "CAP004"}
        for finding in findings
    )


def test_read_only_json_rpc_post_does_not_imply_external_write(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import requests
from pydantic_ai import Agent

MCP_URL = "https://learn.microsoft.com/api/mcp"

agent = Agent("openai:gpt-5.2")


@agent.tool_plain
def search_docs(query: str) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "microsoft_docs_search",
            "arguments": {"query": query},
        },
    }
    return requests.post(MCP_URL, json=payload, timeout=10).json()
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    tool = next(item for item in agent.tools if item.name == "search_docs")

    assert "network.external" in tool.capabilities
    assert "external.write" not in tool.capabilities
    assert "data.write" not in tool.capabilities


def test_sqlite_idempotent_schema_bootstrap_does_not_promote_read_helper_to_write(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import sqlite3
from pydantic_ai import Agent

agent = Agent("openai:gpt-5.2")


def get_db():
    db = sqlite3.connect("memory.db")
    db.executescript(
        '''
        CREATE TABLE IF NOT EXISTS memories (
            id INTEGER PRIMARY KEY,
            summary TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS consolidations (
            id INTEGER PRIMARY KEY,
            summary TEXT NOT NULL
        );
        '''
    )
    return db


@agent.tool_plain
def read_all_memories():
    db = get_db()
    return db.execute("SELECT * FROM memories ORDER BY id DESC").fetchall()


@agent.tool_plain
def store_memory(summary: str):
    db = get_db()
    db.execute("INSERT INTO memories(summary) VALUES (?)", (summary,))
    db.commit()
    return "stored"
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "agent")
    read_tool = next(item for item in agent.tools if item.name == "read_all_memories")
    write_tool = next(item for item in agent.tools if item.name == "store_memory")

    assert "data.read" in read_tool.capabilities
    assert "data.write" not in read_tool.capabilities
    assert "data.write" in write_tool.capabilities


def test_fixed_workspace_setup_does_not_leak_process_authority_to_file_tools(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "agent.py",
        """
import subprocess
from pathlib import Path
from agents import Agent, function_tool

WORKDIR = Path("./workspace").resolve()
_MOUNTED = False


def _ensure_workspace() -> None:
    global _MOUNTED
    if _MOUNTED:
        return
    command = ["trunks", "mount", "--path", str(WORKDIR)]
    subprocess.run(command, check=True)
    _MOUNTED = True


def _safe_path(path: str) -> Path:
    _ensure_workspace()
    target = (WORKDIR / path).resolve()
    if target != WORKDIR and WORKDIR not in target.parents:
        raise ValueError("path escapes workspace")
    return target


@function_tool
def list_files(path: str = ".") -> list[str]:
    return sorted(item.name for item in _safe_path(path).iterdir())


@function_tool
def read(path: str) -> str:
    return _safe_path(path).read_text(encoding="utf-8")


@function_tool
def write(path: str, content: str) -> str:
    target = _safe_path(path)
    target.write_text(content, encoding="utf-8")
    return "ok"


@function_tool
def shell(command: str) -> str:
    _ensure_workspace()
    return subprocess.run(
        command,
        cwd=WORKDIR,
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    ).stdout


agent = Agent(
    name="trunks-pr-agent",
    tools=[list_files, read, write, shell],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "trunks-pr-agent")
    tools = {item.name: item for item in agent.tools}

    assert "process.execute" not in tools["list_files"].capabilities
    assert "process.execute" not in tools["read"].capabilities
    assert "process.execute" not in tools["write"].capabilities
    assert "process.execute" in tools["shell"].capabilities
