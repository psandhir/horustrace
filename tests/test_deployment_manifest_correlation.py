from pathlib import Path

import pytest

from horustrace.adapters.manifest import ManifestError, scan_manifest
from horustrace.deployed_identity import deployed_identity_report
from horustrace.deployment_evidence import (
    DeploymentEvidenceBundle,
    DeploymentWorkloadEvidence,
)


def test_manifest_workload_id_correlates_agent_to_deployment(tmp_path: Path) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        """
version: 1
agents:
  - name: support
    deployment:
      workload_id: terraform:google_cloud_run_v2_service.support
""",
        encoding="utf-8",
    )
    graph = scan_manifest(manifest)
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="repository_discovery",
        workloads=(
            DeploymentWorkloadEvidence(
                workload_id="terraform:google_cloud_run_v2_service.support",
                kind="cloud_run_v2",
                name="support-api",
                identity="support@prod.iam.gserviceaccount.com",
            ),
        ),
    )

    relationship = deployed_identity_report(graph, bundle)["relationships"][0]

    assert relationship["agent"] == "support"
    assert relationship["binding_basis"] == "agent_workload_id"
    assert graph.agents[0].metadata["deployment_binding"]["source"] == "manifest"


def test_manifest_deployment_name_uses_exact_name_only(tmp_path: Path) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        """
version: 1
agent:
  name: support
  deployment:
    name: support-api
""",
        encoding="utf-8",
    )
    graph = scan_manifest(manifest)
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="repository_discovery",
        workloads=(
            DeploymentWorkloadEvidence(
                workload_id="workloads/support",
                kind="cloud_run",
                name="support-api",
                identity="support@prod.iam.gserviceaccount.com",
            ),
        ),
    )

    relationship = deployed_identity_report(graph, bundle)["relationships"][0]

    assert relationship["binding_basis"] == "agent_deployment_name"


def test_manifest_deployment_hint_does_not_fuzzy_match(tmp_path: Path) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        """
version: 1
agent:
  name: support
  deployment:
    name: support
""",
        encoding="utf-8",
    )
    graph = scan_manifest(manifest)
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="repository_discovery",
        workloads=(
            DeploymentWorkloadEvidence(
                workload_id="workloads/support",
                kind="cloud_run",
                name="support-api",
                identity="support@prod.iam.gserviceaccount.com",
            ),
        ),
    )

    assert deployed_identity_report(graph, bundle)["relationships"] == []


def test_manifest_rejects_unknown_deployment_fields(tmp_path: Path) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        """
version: 1
agent:
  name: support
  deployment:
    service_account: support@prod.iam.gserviceaccount.com
""",
        encoding="utf-8",
    )

    with pytest.raises(ManifestError, match="deployment.service_account"):
        scan_manifest(manifest)
