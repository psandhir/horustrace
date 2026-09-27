import json
from pathlib import Path

from horustrace.cli import main

IDENTITY = "support@prod.iam.gserviceaccount.com"


def _write_app(root: Path) -> None:
    root.mkdir()
    (root / "horustrace.manifest.yaml").write_text(
        f"""
version: 1
identities:
  - name: {IDENTITY}
    provider: gcp
    roles: [roles/viewer]
    permissions: [tickets.read]
    credential_source: workload_identity
agents:
  - name: support
    identities: [{IDENTITY}]
    tools:
      - name: tickets
        kind: function
        capabilities: [data.read]
        identity: {IDENTITY}
        approval: true
        resources:
          - kind: ticket
            selector: support/*
            access: [data.read]
        destinations: [https://support.example.test]
    policy:
      authority:
        allow:
          identities: [{IDENTITY}]
          iam_roles: [roles/viewer]
          permissions: [tickets.read]
""",
        encoding="utf-8",
    )


def _write_evidence(path: Path, *, excess: bool = False) -> None:
    bindings = [
        {
            "principal": IDENTITY,
            "role": "roles/viewer",
            "scope": {"kind": "project", "name": "prod"},
            "permissions": ["tickets.read"],
        }
    ]
    if excess:
        bindings.append(
            {
                "principal": IDENTITY,
                "role": "roles/storage.objectAdmin",
                "scope": {"kind": "project", "name": "prod"},
                "permissions": ["storage.objects.delete"],
            }
        )
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "provider": "gcp",
                "source": path.name,
                "workloads": [
                    {
                        "workload_id": (
                            "projects/prod/locations/europe-west1/services/support"
                        ),
                        "kind": "cloud_run",
                        "name": "support",
                        "identity": IDENTITY,
                        "agent": "support",
                        "project": "prod",
                        "region": "europe-west1",
                    }
                ],
                "iam_bindings": bindings,
            }
        ),
        encoding="utf-8",
    )


def test_reconcile_cli_reports_aligned_deployment(tmp_path: Path, capsys) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "deployment.json"
    _write_app(app)
    _write_evidence(evidence)

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(evidence),
            "--format",
            "json",
        ]
    ) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["excess_authority_agents"] == 0
    assert report["summary"]["deployed_policy_violations"] == 0
    assert report["reconciliation"]["agents"][0]["status"] == "aligned"


def test_reconcile_cli_can_fail_on_supported_excess_authority(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "deployment.json"
    _write_app(app)
    _write_evidence(evidence, excess=True)

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(evidence),
            "--format",
            "json",
            "--fail-on-excess-authority",
        ]
    ) == 2

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["excess_authority_agents"] == 1
    agent = report["reconciliation"]["agents"][0]
    assert agent["excess"]["roles"] == ["roles/storage.objectAdmin"]
    assert agent["excess"]["permissions"] == ["storage.objects.delete"]


def test_reconcile_cli_can_fail_on_deployed_contract_violation(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "deployment.json"
    _write_app(app)
    _write_evidence(evidence, excess=True)

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(evidence),
            "--format",
            "json",
            "--fail-on-deployed-policy-violation",
        ]
    ) == 2

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["deployed_policy_violations"] == 1


def test_reconcile_cli_can_fail_on_deployment_authority_regression(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    baseline = tmp_path / "baseline.json"
    head = tmp_path / "head.json"
    _write_app(app)
    _write_evidence(baseline)
    _write_evidence(head, excess=True)

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(head),
            "--baseline-deployment-evidence",
            str(baseline),
            "--format",
            "json",
            "--fail-on-deployment-regression",
        ]
    ) == 2

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["deployment_regressed_agents"] == 1
    delta = report["deployment_delta"]["agents"][0]
    assert delta["excess"]["permissions_introduced"] == ["storage.objects.delete"]


def test_deployment_regression_gate_requires_baseline(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "deployment.json"
    _write_app(app)
    _write_evidence(evidence)

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(evidence),
            "--fail-on-deployment-regression",
        ]
    ) == 1

    assert "requires --baseline-deployment-evidence" in capsys.readouterr().err



def test_reconcile_cli_joins_cloud_sql_source_and_terraform_evidence(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "chatbot"
    infra = tmp_path / "infra"
    evidence = tmp_path / "deployment-cloudsql.json"
    app.mkdir()
    infra.mkdir()

    (app / "agent.py").write_text(
        """
from google.adk.agents import LlmAgent
import asyncpg

DATABASE_URL = "postgresql://user:pass@/db"

async def startup():
    return await asyncpg.create_pool(DATABASE_URL)

root_agent = LlmAgent(
    name="shopright_assistant",
    model="gemini-flash-latest",
)
""",
        encoding="utf-8",
    )
    (infra / "main.tf").write_text(
        """
resource "google_service_account" "chatbot_sa" {
  account_id = "shopright-chatbot"
}

resource "google_cloud_run_v2_service" "chatbot" {
  name = "chatbot-service"

  template {
    service_account = google_service_account.chatbot_sa.email

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = ["prod-project:europe-west1:shopright"]
      }
    }

    containers {
      env {
        name  = "DATABASE_URL"
        value = "postgresql://user:pass@/db?host=/cloudsql/prod-project:europe-west1:shopright"
      }
      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }
    }
  }
}
""",
        encoding="utf-8",
    )
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "provider": "gcp",
                "source": "test",
                "workloads": [
                    {
                        "workload_id": "cloud-run://chatbot",
                        "kind": "cloud_run",
                        "name": "chatbot-service",
                        "identity": (
                            "shopright-chatbot@prod-project.iam.gserviceaccount.com"
                        ),
                        "agent": "shopright_assistant",
                        "project": "prod-project",
                    }
                ],
                "iam_bindings": [],
            }
        ),
        encoding="utf-8",
    )

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(evidence),
            "--authority-source",
            str(infra),
            "--format",
            "json",
        ]
    ) == 0

    report = json.loads(capsys.readouterr().out)
    agent = next(
        item
        for item in report["reconciliation"]["agents"]
        if item["agent"] == "shopright_assistant"
    )
    assert agent["status"] == "missing_authority"
    assert agent["required"]["roles"] == ["roles/cloudsql.client"]
    assert agent["missing"]["roles"] == ["roles/cloudsql.client"]
    evidence_items = agent["evidence"]["required_authority"]
    assert evidence_items[0]["rule"] == "gcp.cloud_run.cloud_sql_socket"


def test_reconcile_cli_discovers_repository_deployment_source(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    infra = tmp_path / "infra"
    app.mkdir()
    infra.mkdir()
    (app / "horustrace.manifest.yaml").write_text(
        """
version: 1
agent:
  name: support
  deployment:
    workload_id: terraform:google_cloud_run_v2_service.support
""",
        encoding="utf-8",
    )
    (infra / "main.tf").write_text(
        f"""
resource "google_cloud_run_v2_service" "support" {{
  name = "support-api"
  project = "prod"
  location = "europe-west1"
  template {{
    service_account = "{IDENTITY}"
  }}
}}

resource "google_project_iam_member" "support" {{
  project = "prod"
  role = "roles/aiplatform.user"
  member = "serviceAccount:{IDENTITY}"
}}
""",
        encoding="utf-8",
    )

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-source",
            str(infra),
            "--format",
            "json",
        ]
    ) == 0

    report = json.loads(capsys.readouterr().out)
    relationship = report["deployed_identity"]["relationships"][0]
    assert relationship["agent"] == "support"
    assert relationship["identity"] == IDENTITY
    assert relationship["binding_basis"] == "agent_workload_id"
    authority = report["deployed_authority"]["relationships"][0]
    assert authority["roles"] == ["roles/aiplatform.user"]
    assert authority["runtime_effectiveness"] == "not_verified"


def test_reconcile_cli_requires_one_deployment_evidence_source(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "deployment.json"
    infra = tmp_path / "infra"
    _write_app(app)
    _write_evidence(evidence)
    infra.mkdir()

    assert main(["reconcile", str(app), "--format", "json"]) == 1
    assert "exactly one" in capsys.readouterr().err

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(evidence),
            "--deployment-source",
            str(infra),
            "--format",
            "json",
        ]
    ) == 1
    assert "exactly one" in capsys.readouterr().err


def test_reconcile_cli_requires_provider_for_multi_provider_source(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    infra = tmp_path / "infra"
    app.mkdir()
    infra.mkdir()
    (app / "horustrace.manifest.yaml").write_text(
        """
version: 1
agent:
  name: support
  deployment:
    workload_id: terraform:google_cloud_run_v2_service.support
""",
        encoding="utf-8",
    )
    (infra / "main.tf").write_text(
        f"""
resource "google_cloud_run_v2_service" "support" {{
  template {{
    service_account = "{IDENTITY}"
  }}
}}

resource "aws_lambda_function" "worker" {{
  role = "arn:aws:iam::123456789012:role/Worker"
}}
""",
        encoding="utf-8",
    )

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-source",
            str(infra),
            "--format",
            "json",
        ]
    ) == 1
    assert "exactly one provider bundle" in capsys.readouterr().err

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-source",
            str(infra),
            "--deployment-provider",
            "gcp",
            "--format",
            "json",
        ]
    ) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["provider"] == "gcp"
