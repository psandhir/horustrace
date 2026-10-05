from pathlib import Path

import pytest

from horustrace.adapters.manifest import ManifestError
from horustrace.scanner import scan


def test_authority_contract_v1_is_normalized_from_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        """
version: 1
agents:
  - name: support
    policy:
      authority:
        allow:
          capabilities: [external.write, data.read]
          identities: support-bot
          resources: [tickets/*]
          destinations: [https://support.example.test]
          iam_roles: [roles/viewer]
          permissions: [tickets.read]
          oauth_scopes: [issues:read]
          mcp_servers: [github]
        deny:
          capabilities: [process.execute, destructive.write]
          identities: [break-glass]
          resources: [admin/*]
          destinations: [internet]
          iam_roles: [roles/owner]
          permissions: [iam.setPolicy]
          oauth_scopes: [repo:admin]
          mcp_servers: [filesystem]
        require_approval_for: [external.write]
        mcp_tools:
          - server: github
            allow: [issues_update, issues_read]
            deny: repo_delete
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    contract = graph.agents[0].policy.authority

    assert contract is not None
    assert contract.as_dict() == {
        "schema_version": 1,
        "allow": {
            "capabilities": ["data.read", "external.write"],
            "identities": ["support-bot"],
            "resources": ["tickets/*"],
            "destinations": ["https://support.example.test"],
            "iam_roles": ["roles/viewer"],
            "permissions": ["tickets.read"],
            "oauth_scopes": ["issues:read"],
            "mcp_servers": ["github"],
            "skills": [],
        },
        "deny": {
            "capabilities": ["destructive.write", "process.execute"],
            "identities": ["break-glass"],
            "resources": ["admin/*"],
            "destinations": ["internet"],
            "iam_roles": ["roles/owner"],
            "permissions": ["iam.setPolicy"],
            "oauth_scopes": ["repo:admin"],
            "mcp_servers": ["filesystem"],
            "skills": [],
        },
        "require_approval_for": ["external.write"],
        "mcp_tools": [
            {
                "server": "github",
                "allow": ["issues_read", "issues_update"],
                "deny": ["repo_delete"],
            }
        ],
        "location": {
            "path": str(manifest),
            "line": 7,
            "column": 9,
        },
        "clause_locations": {
            "allow.capabilities": {
                "path": str(manifest),
                "line": 8,
                "column": 25,
            },
            "allow.destinations": {
                "path": str(manifest),
                "line": 11,
                "column": 25,
            },
            "allow.iam_roles": {
                "path": str(manifest),
                "line": 12,
                "column": 22,
            },
            "allow.identities": {
                "path": str(manifest),
                "line": 9,
                "column": 23,
            },
            "allow.mcp_servers": {
                "path": str(manifest),
                "line": 15,
                "column": 24,
            },
            "allow.oauth_scopes": {
                "path": str(manifest),
                "line": 14,
                "column": 25,
            },
            "allow.permissions": {
                "path": str(manifest),
                "line": 13,
                "column": 24,
            },
            "allow.resources": {
                "path": str(manifest),
                "line": 10,
                "column": 22,
            },
            "deny.capabilities": {
                "path": str(manifest),
                "line": 17,
                "column": 25,
            },
            "deny.destinations": {
                "path": str(manifest),
                "line": 20,
                "column": 25,
            },
            "deny.iam_roles": {
                "path": str(manifest),
                "line": 21,
                "column": 22,
            },
            "deny.identities": {
                "path": str(manifest),
                "line": 18,
                "column": 23,
            },
            "deny.mcp_servers": {
                "path": str(manifest),
                "line": 24,
                "column": 24,
            },
            "deny.oauth_scopes": {
                "path": str(manifest),
                "line": 23,
                "column": 25,
            },
            "deny.permissions": {
                "path": str(manifest),
                "line": 22,
                "column": 24,
            },
            "deny.resources": {
                "path": str(manifest),
                "line": 19,
                "column": 22,
            },
            "mcp_tools.github.allow": {
                "path": str(manifest),
                "line": 28,
                "column": 20,
            },
            "mcp_tools.github.deny": {
                "path": str(manifest),
                "line": 29,
                "column": 19,
            },
            "require_approval_for": {
                "path": str(manifest),
                "line": 25,
                "column": 31,
            },
        },
    }


def test_legacy_agent_policy_remains_compatible(tmp_path: Path) -> None:
    (tmp_path / "horustrace.manifest.yaml").write_text(
        """
version: 1
agents:
  - name: legacy
    policy:
      required: [data.read]
      deny: [process.execute]
      allowed_resources: [records/*]
      allowed_destinations: [api.example.test]
      require_approval_for: [data.write]
      max_privileged_capabilities: 2
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    policy = graph.agents[0].policy

    assert policy.required_capabilities == {"data.read"}
    assert policy.denied_capabilities == {"process.execute"}
    assert policy.allowed_resources == ["records/*"]
    assert policy.allowed_destinations == ["api.example.test"]
    assert policy.require_approval_for == {"data.write"}
    assert policy.max_privileged_capabilities == 2
    assert policy.authority is None


@pytest.mark.parametrize(
    "authority",
    [
        "allow: {capabilites: [data.read]}",
        "allow: {capabilities: [false]}",
        "deny: {identities: 42}",
        "require_approval_for: [false]",
        "mcp_tools: invalid",
        "mcp_tools: [{server: github, allow: 42}]",
        "mcp_tools: [{server: 42}]",
        "mcp_tools: [{server: github, unexpected: []}]",
    ],
)
def test_invalid_authority_contract_fails_closed(tmp_path: Path, authority: str) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        "version: 1\nagents:\n  - name: root\n    policy:\n"
        f"      authority: {{{authority}}}\n",
        encoding="utf-8",
    )

    with pytest.raises(ManifestError, match="invalid manifest"):
        scan(tmp_path)


def test_unknown_authority_field_reports_nested_source_location(tmp_path: Path) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        """
version: 1
agents:
  - name: root
    policy:
      authority:
        allow:
          capabilites: [data.read]
""",
        encoding="utf-8",
    )

    with pytest.raises(ManifestError) as error:
        scan(tmp_path)

    assert "agents[0].policy.authority.allow.capabilites" in str(error.value)
    assert f"{manifest}:8:" in str(error.value)



def test_single_agent_authority_contract_retains_clause_location(tmp_path: Path) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        """
version: 1
agent:
  name: single
  policy:
    authority:
      deny:
        capabilities: [process.execute]
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    contract = graph.agents[0].policy.authority

    assert contract is not None
    location = contract.clause_locations["deny.capabilities"]
    assert location.path == manifest
    assert location.line == 8
    assert location.column == 23


def test_authority_contract_v1_accepts_skill_dimension(tmp_path: Path) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        """
version: 1
agents:
  - name: reviewer
    policy:
      authority:
        allow:
          skills: [review]
        deny:
          skills: [deploy-prod]
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    contract = graph.agents[0].policy.authority

    assert contract is not None
    assert contract.allow.skills == {"review"}
    assert contract.deny.skills == {"deploy-prod"}
    assert contract.as_dict()["allow"]["skills"] == ["review"]
    assert contract.as_dict()["deny"]["skills"] == ["deploy-prod"]
    assert contract.clause_locations["allow.skills"].path == manifest
    assert contract.clause_locations["deny.skills"].path == manifest
