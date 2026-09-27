from horustrace.deployed_identity import deployed_identity_report
from horustrace.deployment_evidence import (
    DeploymentEvidenceBundle,
    DeploymentWorkloadEvidence,
)
from horustrace.models import Agent, Graph


def _bundle(*workloads: DeploymentWorkloadEvidence) -> DeploymentEvidenceBundle:
    return DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=tuple(workloads),
    )


def test_explicit_agent_binding_resolves_gcp_workload_identity() -> None:
    graph = Graph(agents=[Agent(name="support")])
    bundle = _bundle(
        DeploymentWorkloadEvidence(
            workload_id="projects/prod/locations/europe-west1/services/support-api",
            kind="cloud_run",
            name="support-api",
            identity="SUPPORT@PROD.IAM.GSERVICEACCOUNT.COM",
            agent="support",
            project="prod",
            region="europe-west1",
        )
    )

    report = deployed_identity_report(graph, bundle)
    relationship = report["relationships"][0]

    assert relationship["agent"] == "support"
    assert relationship["identity"] == "support@prod.iam.gserviceaccount.com"
    assert relationship["binding_basis"] == "explicit_agent"
    assert relationship["resolution"] == "fully_resolved"
    assert relationship["runtime_effectiveness"] == "not_verified"


def test_exact_agent_deployment_hint_can_bind_without_evidence_agent_field() -> None:
    graph = Graph(
        agents=[
            Agent(
                name="support",
                metadata={"deployment_name": "support-api"},
            )
        ]
    )
    bundle = _bundle(
        DeploymentWorkloadEvidence(
            workload_id="projects/prod/locations/europe-west1/services/support-api",
            kind="cloud_run",
            name="support-api",
            identity="support@prod.iam.gserviceaccount.com",
        )
    )

    relationship = deployed_identity_report(graph, bundle)["relationships"][0]

    assert relationship["binding_basis"] == "agent_deployment_name"


def test_name_similarity_does_not_create_deployment_binding() -> None:
    graph = Graph(agents=[Agent(name="support")])
    bundle = _bundle(
        DeploymentWorkloadEvidence(
            workload_id="projects/prod/locations/europe-west1/services/support",
            kind="cloud_run",
            name="support",
            identity="support@prod.iam.gserviceaccount.com",
        )
    )

    report = deployed_identity_report(graph, bundle)

    assert report["relationships"] == []
    assert report["summary"]["agents_with_deployment"] == 0


def test_invalid_gcp_runtime_identity_remains_explicitly_unresolved() -> None:
    graph = Graph(agents=[Agent(name="support")])
    bundle = _bundle(
        DeploymentWorkloadEvidence(
            workload_id="workloads/support",
            kind="cloud_run",
            name="support",
            identity="runtime-derived",
            agent="support",
        )
    )

    relationship = deployed_identity_report(graph, bundle)["relationships"][0]

    assert relationship["identity"] == "runtime-derived"
    assert relationship["resolution"] == "partially_resolved"
    assert relationship["unresolved"] == ["identity"]


def test_aws_role_identity_is_canonicalized() -> None:
    graph = Graph(agents=[Agent(name="support")])
    arn = "arn:aws:iam::123456789012:role/Platform/AgentRuntime"
    bundle = DeploymentEvidenceBundle(
        provider="aws",
        source="fixture",
        workloads=(
            DeploymentWorkloadEvidence(
                workload_id="ecs/support",
                kind="ecs_service",
                name="support",
                identity=arn,
                agent="support",
            ),
        ),
    )

    relationship = deployed_identity_report(graph, bundle)["relationships"][0]

    assert relationship["identity"] == arn
    assert relationship["resolution"] == "fully_resolved"


def test_azure_managed_identity_object_id_is_canonicalized() -> None:
    graph = Graph(agents=[Agent(name="support")])
    bundle = DeploymentEvidenceBundle(
        provider="azure",
        source="fixture",
        workloads=(
            DeploymentWorkloadEvidence(
                workload_id="containerapps/support",
                kind="container_app",
                name="support",
                identity="6F9619FF-8B86-D011-B42D-00C04FC964FF",
                agent="support",
            ),
        ),
    )

    relationship = deployed_identity_report(graph, bundle)["relationships"][0]

    assert relationship["identity"] == "6f9619ff-8b86-d011-b42d-00c04fc964ff"
    assert relationship["resolution"] == "fully_resolved"


def test_kubernetes_service_account_short_form_is_canonicalized() -> None:
    graph = Graph(agents=[Agent(name="support")])
    bundle = DeploymentEvidenceBundle(
        provider="kubernetes",
        source="fixture",
        workloads=(
            DeploymentWorkloadEvidence(
                workload_id="apps/v1/Deployment/agents/support",
                kind="deployment",
                name="support",
                identity="agents/runtime",
                agent="support",
            ),
        ),
    )

    relationship = deployed_identity_report(graph, bundle)["relationships"][0]

    assert relationship["identity"] == "system:serviceaccount:agents:runtime"
    assert relationship["resolution"] == "fully_resolved"
