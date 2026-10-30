"""WAB-04 source-byte attestation, transport, consent and fail-closed tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.audit_wave_b540_dependency_resolution import (
    EXPECTED_MCP,
    git_blob_sha,
    resolution_audit,
    source_requests_consent_bypass,
    source_tree_records,
    static_mcp_witness,
)

ROOT = Path(__file__).resolve().parents[1]
LEDGERS = ROOT / "research" / "accuracy-wave-b540-model-judge-20261015"


def _ledgers() -> list[dict]:
    return [
        json.loads((LEDGERS / "high-severity-adjudication.json").read_text()),
        json.loads((LEDGERS / "medium-severity-adjudication.json").read_text()),
    ]


def _source_fixture() -> tuple[dict, dict[str, bytes], dict[str, str]]:
    sources = {"requirements.txt": b"strands-agents-tools\nmcp[cli]\nboto3\nbotocore\n",
               "src/utils/config.py":
               b'import os\nos.environ["BYPASS_TOOL_CONSENT"] = "true"\n'}
    for path, (command, args) in EXPECTED_MCP.items():
        content = (
            "from mcp import StdioServerParameters\n"
            "from strands.tools.mcp import MCPClient\n"
            f"client = MCPClient(StdioServerParameters(command={command!r},"
            f" args={list(args)!r}))\n"
            "tools = client.list_tools_sync()\n"
        )
        sources[path] = content.encode()
    shas = {name: git_blob_sha(data) for name, data in sources.items()}
    tree = {"truncated": False, "tree": [
        {"path": name, "type": "blob", "sha": sha}
        for name, sha in shas.items()
    ] + [
        {"path": f"sample-other-file-{index}.txt", "type": "blob", "sha": "0" * 40}
        for index in range(29 - len(shas))
    ]}
    return tree, sources, shas


def test_git_object_blob_hash_is_exact() -> None:
    assert git_blob_sha(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_static_inventory_preserves_all_12_unknown_claims() -> None:
    tree, sources, blobs = _source_fixture()
    result = resolution_audit(tree, sources, _ledgers(), expected_blobs=blobs)
    assert result["source_sha"] == "30d03d7c9f6512e5bf10601879382fac9c3a16b1"
    assert result["exact_source_blob_count"] == 7
    assert result["full_tree_entry_count"] == 29
    assert result["mcp_stdio_launchers"] == 5
    assert result["floating_uvx_servers"] == 2
    assert result["runtime_npx_remote_clients"] == 3
    assert result["historical_unresolved_claim_count"] == 12
    assert len(result["missing_evidence"]) == 5
    assert result["consent_bypass_env_requested"] is True
    assert result["consent_bypass_enforced"] is None
    assert result["installed_strands_agents_tools_version"] is None
    assert result["precision"] is None and result["recall"] is None
    assert result["wave_b_go"] is False and result["wave_c_go"] is False


def test_source_or_tree_byte_drift_is_rejected() -> None:
    tree, sources, blobs = _source_fixture()
    sources["requirements.txt"] += b"# unreviewed\n"
    with pytest.raises(ValueError, match="unverified source content"):
        resolution_audit(tree, sources, _ledgers(), expected_blobs=blobs)


def test_discovered_lockfile_invalidates_absence_claim() -> None:
    tree, sources, blobs = _source_fixture()
    tree["tree"][-1]["path"] = "uv.lock"
    with pytest.raises(ValueError, match="lockfile"):
        resolution_audit(tree, sources, _ledgers(), expected_blobs=blobs)


def test_incomplete_tree_is_not_evidence_of_no_lockfile() -> None:
    tree, _, blobs = _source_fixture()
    tree["truncated"] = True
    with pytest.raises(ValueError, match="full source tree"):
        source_tree_records(tree, blobs)


def test_missing_source_client_cannot_be_mislabeled_empty_mcp() -> None:
    with pytest.raises(ValueError, match="dynamic MCP source construct"):
        static_mcp_witness("client = object()\n", "src/agents/pricing_explorer.py")


def test_unknown_dynamic_command_cannot_be_guessed() -> None:
    path = "src/agents/pricing_explorer.py"
    content = (
        "client = MCPClient(StdioServerParameters(command=cmd,"
        " args=['awslabs.aws-pricing-mcp-server@latest']))\n"
        "client.list_tools_sync()\n"
    )
    with pytest.raises(ValueError, match="cannot be source attested"):
        static_mcp_witness(content, path)


def test_floating_or_changed_launcher_must_not_pass_pinned_witness() -> None:
    path = "src/agents/pricing_explorer.py"
    content = (
        'client = MCPClient(StdioServerParameters(command="uvx",'
        ' args=["awslabs.aws-pricing-mcp-server==1.0.0"]))\n'
        'client.list_tools_sync()\n'
    )
    with pytest.raises(ValueError, match="transport/cmd/source changed"):
        static_mcp_witness(content, path)


def test_requested_consent_bypass_is_not_enforcement() -> None:
    assert source_requests_consent_bypass(
        'os.environ["BYPASS_TOOL_CONSENT"] = "true"\n'
    )
    assert not source_requests_consent_bypass(
        'os.environ["BYPASS_TOOL_CONSENT"] = "false"\n'
    )


def test_model_label_change_does_not_certify_runtime() -> None:
    tree, sources, blobs = _source_fixture()
    ledgers = _ledgers()
    stale = next(x for x in ledgers[0]["claims"]
                 if x["claim_key"].endswith("34e0345cd816a7b394f5"))
    stale["status"] = "source_confirmed"
    with pytest.raises(ValueError, match="status drift"):
        resolution_audit(tree, sources, ledgers, expected_blobs=blobs)


def test_missing_source_file_rejected_even_with_complete_ledger() -> None:
    tree, sources, blobs = _source_fixture()
    sources.pop("src/agents/cfn_explorer.py")
    with pytest.raises(ValueError, match="missing or unexpected frozen source"):
        resolution_audit(tree, sources, _ledgers(), expected_blobs=blobs)
