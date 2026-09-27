from horustrace.deployed_authority import deployed_authority_report
from horustrace.deployment_evidence import (
    DeploymentEvidenceBundle,
    DeploymentWorkloadEvidence,
    IAMBindingEvidence,
)
from horustrace.models import Agent, Graph

IDENTITY = "support-agent@prod.iam.gserviceaccount.com"


def _graph() -> Graph:
    return Graph(agents=[Agent(name="support")])


def _workload() -> DeploymentWorkloadEvidence:
    return DeploymentWorkloadEvidence(
        workload_id="projects/prod/locations/europe-west1/services/support",
        kind="cloud_run",
        name="support",
        identity=IDENTITY,
        agent="support",
        project="prod",
    )


def test_deployed_authority_expands_inherited_gcp_role_permissions() -> None:
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=(_workload(),),
        iam_bindings=(
            IAMBindingEvidence(
                principal=f"serviceAccount:{IDENTITY}",
                role="roles/secretmanager.secretAccessor",
                scope_kind="project",
                scope_name="prod",
                inherited_from_kind="folder",
                inherited_from_name="12345",
            ),
        ),
        role_permissions={
            "roles/secretmanager.secretAccessor": (
                "secretmanager.versions.access",
                "secretmanager.versions.get",
            )
        },
    )

    relationship = deployed_authority_report(_graph(), bundle)["relationships"][0]

    assert relationship["roles"] == ["roles/secretmanager.secretAccessor"]
    assert relationship["permissions"] == [
        "secretmanager.versions.access",
        "secretmanager.versions.get",
    ]
    assert relationship["inherited_from"] == [{"kind": "folder", "name": "12345"}]
    assert relationship["resolution"] == "fully_resolved"


def test_inline_binding_permissions_are_retained_without_role_catalogue() -> None:
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=(_workload(),),
        iam_bindings=(
            IAMBindingEvidence(
                principal=IDENTITY,
                role="projects/prod/roles/customAgent",
                scope_kind="project",
                scope_name="prod",
                permissions=("tickets.read", "tickets.write"),
            ),
        ),
    )

    relationship = deployed_authority_report(_graph(), bundle)["relationships"][0]

    assert relationship["permissions"] == ["tickets.read", "tickets.write"]
    assert relationship["unresolved_roles"] == []
    assert "permissions" not in relationship["unresolved"]


def test_conditioned_binding_does_not_become_unconditional_authority() -> None:
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=(_workload(),),
        iam_bindings=(
            IAMBindingEvidence(
                principal=IDENTITY,
                role="roles/storage.objectAdmin",
                scope_kind="project",
                scope_name="prod",
                condition={"expression": "resource.name.startsWith('projects/_/buckets/support-')"},
            ),
        ),
        role_permissions={
            "roles/storage.objectAdmin": (
                "storage.objects.create",
                "storage.objects.delete",
            )
        },
    )

    relationship = deployed_authority_report(_graph(), bundle)["relationships"][0]

    assert relationship["roles"] == []
    assert relationship["conditional_roles"] == ["roles/storage.objectAdmin"]
    assert relationship["permissions"] == []
    assert relationship["conditional_permissions"] == [
        "storage.objects.create",
        "storage.objects.delete",
    ]
    assert relationship["resolution"] == "partially_resolved"
    assert "iam_condition_applicability" in relationship["unresolved"]


def test_unknown_role_permission_expansion_stays_unresolved() -> None:
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=(_workload(),),
        iam_bindings=(
            IAMBindingEvidence(
                principal=IDENTITY,
                role="roles/custom.unknown",
                scope_kind="project",
                scope_name="prod",
            ),
        ),
    )

    relationship = deployed_authority_report(_graph(), bundle)["relationships"][0]

    assert relationship["unresolved_roles"] == ["roles/custom.unknown"]
    assert "permissions" in relationship["unresolved"]


def test_unrelated_principal_is_not_attached_to_agent() -> None:
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=(_workload(),),
        iam_bindings=(
            IAMBindingEvidence(
                principal="other@prod.iam.gserviceaccount.com",
                role="roles/owner",
                scope_kind="project",
                scope_name="prod",
                permissions=("resourcemanager.projects.setIamPolicy",),
            ),
        ),
    )

    relationship = deployed_authority_report(_graph(), bundle)["relationships"][0]

    assert relationship["roles"] == []
    assert relationship["permissions"] == []
    assert "iam_bindings" in relationship["unresolved"]


def test_aws_role_binding_matches_workload_principal() -> None:
    arn = "arn:aws:iam::123456789012:role/Platform/AgentRuntime"
    graph = Graph(agents=[Agent(name="support")])
    workload = DeploymentWorkloadEvidence(
        workload_id="ecs/support",
        kind="ecs_service",
        name="support",
        identity=arn,
        agent="support",
    )
    bundle = DeploymentEvidenceBundle(
        provider="aws",
        source="fixture",
        workloads=(workload,),
        iam_bindings=(
            IAMBindingEvidence(
                principal=arn,
                role="inline-policy",
                scope_kind="account",
                scope_name="123456789012",
                permissions=("s3:GetObject",),
            ),
        ),
    )

    relationship = deployed_authority_report(graph, bundle)["relationships"][0]

    assert relationship["permissions"] == ["s3:GetObject"]
    assert relationship["resolution"] == "fully_resolved"


def test_azure_role_assignment_matches_principal_case_insensitively() -> None:
    object_id = "6F9619FF-8B86-D011-B42D-00C04FC964FF"
    graph = Graph(agents=[Agent(name="support")])
    workload = DeploymentWorkloadEvidence(
        workload_id="containerapps/support",
        kind="container_app",
        name="support",
        identity=object_id,
        agent="support",
    )
    bundle = DeploymentEvidenceBundle(
        provider="azure",
        source="fixture",
        workloads=(workload,),
        iam_bindings=(
            IAMBindingEvidence(
                principal=object_id.lower(),
                role="Storage Blob Data Reader",
                scope_kind="storage_account",
                scope_name="supportdata",
                permissions=("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",),
            ),
        ),
    )

    relationship = deployed_authority_report(graph, bundle)["relationships"][0]

    assert relationship["roles"] == ["Storage Blob Data Reader"]
    assert relationship["permissions"] == [
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    ]


def test_kubernetes_service_account_binding_matches_short_and_canonical_forms() -> None:
    graph = Graph(agents=[Agent(name="support")])
    workload = DeploymentWorkloadEvidence(
        workload_id="apps/v1/Deployment/agents/support",
        kind="deployment",
        name="support",
        identity="agents/runtime",
        agent="support",
    )
    bundle = DeploymentEvidenceBundle(
        provider="kubernetes",
        source="fixture",
        workloads=(workload,),
        iam_bindings=(
            IAMBindingEvidence(
                principal="system:serviceaccount:agents:runtime",
                role="k8s:Role/read-secrets",
                scope_kind="namespace",
                scope_name="agents",
                permissions=("get:secrets",),
            ),
        ),
    )

    relationship = deployed_authority_report(graph, bundle)["relationships"][0]

    assert relationship["roles"] == ["k8s:Role/read-secrets"]
    assert relationship["permissions"] == ["get:secrets"]
