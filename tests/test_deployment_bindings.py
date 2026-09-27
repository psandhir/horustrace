from pathlib import Path

from horustrace.deployment_bindings import (
    discover_kubernetes_bindings,
    discover_terraform_bindings,
)
from horustrace.deployment_discovery import discover_deployment_evidence


def test_gcp_project_iam_member_is_normalized(tmp_path: Path) -> None:
    path = tmp_path / "iam.tf"
    path.write_text(
        '''
resource "google_project_iam_member" "agent" {
  project = "prod"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:agent@prod.iam.gserviceaccount.com"
}
''',
        encoding="utf-8",
    )

    bindings, unresolved = discover_terraform_bindings(path)

    assert unresolved == []
    assert len(bindings) == 1
    binding = bindings[0]
    assert binding.principal == "agent@prod.iam.gserviceaccount.com"
    assert binding.role == "roles/secretmanager.secretAccessor"
    assert binding.scope_kind == "project"
    assert binding.scope_name == "prod"


def test_gcp_binding_members_list_expands_service_accounts(tmp_path: Path) -> None:
    path = tmp_path / "iam.tf"
    path.write_text(
        '''
resource "google_project_iam_binding" "agents" {
  project = "prod"
  role    = "roles/aiplatform.user"
  members = [
    "serviceAccount:a@prod.iam.gserviceaccount.com",
    "serviceAccount:b@prod.iam.gserviceaccount.com",
  ]
}
''',
        encoding="utf-8",
    )

    bindings, unresolved = discover_terraform_bindings(path)

    assert unresolved == []
    assert [item.principal for item in bindings] == [
        "a@prod.iam.gserviceaccount.com",
        "b@prod.iam.gserviceaccount.com",
    ]


def test_computed_gcp_member_is_unresolved_not_guessed(tmp_path: Path) -> None:
    path = tmp_path / "iam.tf"
    path.write_text(
        '''
resource "google_project_iam_member" "agent" {
  project = "prod"
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.agent.email}"
}
''',
        encoding="utf-8",
    )

    bindings, unresolved = discover_terraform_bindings(path)

    assert bindings == []
    assert unresolved[0]["reason"] == "non_literal_or_unsupported_iam_binding"


def test_literal_azure_role_assignment_is_normalized(tmp_path: Path) -> None:
    path = tmp_path / "main.tf"
    path.write_text(
        '''
resource "azurerm_role_assignment" "agent" {
  principal_id         = "6F9619FF-8B86-D011-B42D-00C04FC964FF"
  role_definition_name = "Storage Blob Data Reader"
  scope                = "/subscriptions/123/resourceGroups/agents"
}
''',
        encoding="utf-8",
    )

    bindings, unresolved = discover_terraform_bindings(path)

    assert unresolved == []
    binding = bindings[0]
    assert binding.principal == "6f9619ff-8b86-d011-b42d-00c04fc964ff"
    assert binding.role == "Storage Blob Data Reader"
    assert binding.scope_kind == "azure_scope"


def test_kubernetes_role_binding_maps_service_account(tmp_path: Path) -> None:
    path = tmp_path / "rbac.yaml"
    path.write_text(
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: agent-reader
  namespace: agents
subjects:
  - kind: ServiceAccount
    name: runtime
    namespace: agents
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
""",
        encoding="utf-8",
    )

    bindings, unresolved = discover_kubernetes_bindings(path)

    assert unresolved == []
    binding = bindings[0]
    assert binding.principal == "system:serviceaccount:agents:runtime"
    assert binding.role == "k8s:Role/secret-reader"
    assert binding.scope_kind == "namespace"
    assert binding.scope_name == "agents"


def test_cluster_role_binding_retains_cluster_scope(tmp_path: Path) -> None:
    path = tmp_path / "rbac.yaml"
    path.write_text(
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: agent-reader
subjects:
  - kind: ServiceAccount
    name: runtime
    namespace: agents
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
""",
        encoding="utf-8",
    )

    bindings, unresolved = discover_kubernetes_bindings(path)

    assert unresolved == []
    assert bindings[0].scope_kind == "cluster"
    assert bindings[0].scope_name == "cluster"
    assert bindings[0].role == "k8s:ClusterRole/view"


def test_repository_bundle_contains_workload_and_matching_binding(tmp_path: Path) -> None:
    workload = tmp_path / "service.tf"
    workload.write_text(
        '''
resource "google_cloud_run_v2_service" "agent" {
  name = "support-agent"
  template {
    service_account = "agent@prod.iam.gserviceaccount.com"
  }
}
''',
        encoding="utf-8",
    )
    iam = tmp_path / "iam.tf"
    iam.write_text(
        '''
resource "google_project_iam_member" "agent" {
  project = "prod"
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:agent@prod.iam.gserviceaccount.com"
}
''',
        encoding="utf-8",
    )

    result = discover_deployment_evidence([workload, iam])

    assert len(result.bundles) == 1
    bundle = result.bundles[0]
    assert bundle.provider == "gcp"
    assert len(bundle.workloads) == 1
    assert len(bundle.iam_bindings) == 1
    assert bundle.workloads[0].identity == bundle.iam_bindings[0].principal
