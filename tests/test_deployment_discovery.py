from pathlib import Path

from horustrace.deployment_discovery import (
    discover_deployment_evidence,
    discover_kubernetes_workloads,
    discover_terraform_workloads,
)


def test_gcp_cloud_run_v2_literal_service_account_is_discovered(tmp_path: Path) -> None:
    path = tmp_path / "main.tf"
    path.write_text(
        '''
resource "google_cloud_run_v2_service" "agent" {
  name     = "support-agent"
  location = "europe-west1"
  project  = "prod"

  template {
    service_account = "support@prod.iam.gserviceaccount.com"
  }
}
''',
        encoding="utf-8",
    )

    workloads, unresolved = discover_terraform_workloads(path)

    assert unresolved == []
    assert len(workloads) == 1
    workload = workloads[0]
    assert workload.kind == "cloud_run_v2"
    assert workload.name == "support-agent"
    assert workload.identity == "support@prod.iam.gserviceaccount.com"
    assert workload.project == "prod"
    assert workload.region == "europe-west1"
    assert workload.agent is None


def test_aws_ecs_runtime_task_role_is_discovered_but_execution_role_is_not_used(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ecs.tf"
    path.write_text(
        '''
resource "aws_ecs_task_definition" "agent" {
  family             = "agent"
  execution_role_arn = "arn:aws:iam::123456789012:role/EcsExecution"
  task_role_arn      = "arn:aws:iam::123456789012:role/AgentRuntime"
}
''',
        encoding="utf-8",
    )

    workloads, unresolved = discover_terraform_workloads(path)

    assert unresolved == []
    assert len(workloads) == 1
    assert workloads[0].identity == "arn:aws:iam::123456789012:role/AgentRuntime"


def test_aws_lambda_literal_runtime_role_is_discovered(tmp_path: Path) -> None:
    path = tmp_path / "lambda.tf"
    path.write_text(
        '''
resource "aws_lambda_function" "agent" {
  function_name = "agent"
  role          = "arn:aws:iam::123456789012:role/LambdaAgent"
}
''',
        encoding="utf-8",
    )

    workloads, unresolved = discover_terraform_workloads(path)

    assert unresolved == []
    assert workloads[0].kind == "lambda_function"
    assert workloads[0].identity.endswith(":role/LambdaAgent")


def test_computed_terraform_identity_stays_unresolved(tmp_path: Path) -> None:
    path = tmp_path / "main.tf"
    path.write_text(
        '''
resource "google_cloud_run_v2_service" "agent" {
  name = "agent"
  template {
    service_account = google_service_account.agent.email
  }
}
''',
        encoding="utf-8",
    )

    workloads, unresolved = discover_terraform_workloads(path)

    assert workloads == []
    assert len(unresolved) == 1
    assert unresolved[0].reason == "non_literal_or_unsupported_identity:service_account"


def test_kubernetes_deployment_explicit_service_account_is_discovered(
    tmp_path: Path,
) -> None:
    path = tmp_path / "deployment.yaml"
    path.write_text(
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: support-agent
  namespace: agents
spec:
  template:
    spec:
      serviceAccountName: runtime
      containers:
        - name: agent
          image: example/agent:1
""",
        encoding="utf-8",
    )

    workloads, unresolved = discover_kubernetes_workloads(path)

    assert unresolved == []
    assert len(workloads) == 1
    assert workloads[0].identity == "system:serviceaccount:agents:runtime"
    assert workloads[0].kind == "deployment"
    assert workloads[0].agent is None


def test_kubernetes_missing_namespace_is_not_guessed(tmp_path: Path) -> None:
    path = tmp_path / "deployment.yaml"
    path.write_text(
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: support-agent
spec:
  template:
    spec:
      serviceAccountName: runtime
""",
        encoding="utf-8",
    )

    workloads, unresolved = discover_kubernetes_workloads(path)

    assert workloads == []
    assert unresolved[0].reason == "namespace_not_explicit"


def test_kubernetes_implicit_default_service_account_is_not_guessed(tmp_path: Path) -> None:
    path = tmp_path / "deployment.yaml"
    path.write_text(
        """
apiVersion: v1
kind: Pod
metadata:
  name: support-agent
  namespace: agents
spec:
  containers:
    - name: agent
      image: example/agent:1
""",
        encoding="utf-8",
    )

    workloads, unresolved = discover_kubernetes_workloads(path)

    assert workloads == []
    assert unresolved[0].reason == "service_account_not_explicit"


def test_cronjob_service_account_path_is_supported(tmp_path: Path) -> None:
    path = tmp_path / "cron.yaml"
    path.write_text(
        """
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-agent
  namespace: agents
spec:
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: cron-agent
          restartPolicy: Never
""",
        encoding="utf-8",
    )

    workloads, unresolved = discover_kubernetes_workloads(path)

    assert unresolved == []
    assert workloads[0].identity == "system:serviceaccount:agents:cron-agent"


def test_repository_discovery_groups_workloads_by_provider(tmp_path: Path) -> None:
    terraform = tmp_path / "main.tf"
    terraform.write_text(
        '''
resource "aws_lambda_function" "agent" {
  role = "arn:aws:iam::123456789012:role/LambdaAgent"
}
''',
        encoding="utf-8",
    )
    manifest = tmp_path / "deployment.yaml"
    manifest.write_text(
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: support-agent
  namespace: agents
spec:
  template:
    spec:
      serviceAccountName: runtime
""",
        encoding="utf-8",
    )

    result = discover_deployment_evidence([terraform, manifest])

    assert [bundle.provider for bundle in result.bundles] == ["aws", "kubernetes"]
    assert all(bundle.source == "repository_discovery" for bundle in result.bundles)
