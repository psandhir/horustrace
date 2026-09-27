import pytest

from horustrace.principals import (
    canonical_principal,
    normalize_aws_role,
    normalize_azure_principal,
    normalize_gcp_service_account,
    normalize_kubernetes_service_account,
)


def test_gcp_service_account_literal_forms_are_canonical() -> None:
    expected = "agent@prod.iam.gserviceaccount.com"
    assert normalize_gcp_service_account("SERVICEACCOUNT:Agent@Prod.iam.gserviceaccount.com") == expected
    assert canonical_principal("gcp", "Agent@Prod.iam.gserviceaccount.com") == expected


def test_aws_iam_role_arn_is_preserved_without_lowering_role_name() -> None:
    arn = "arn:aws:iam::123456789012:role/Platform/AgentRuntime"
    assert normalize_aws_role(arn) == arn
    assert canonical_principal("aws", arn) == arn


def test_azure_object_id_is_lowercased() -> None:
    value = "6F9619FF-8B86-D011-B42D-00C04FC964FF"
    assert normalize_azure_principal(value) == value.lower()
    assert canonical_principal("azure", value) == value.lower()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("system:serviceaccount:Agents:Runtime", "system:serviceaccount:agents:runtime"),
        ("agents/runtime", "system:serviceaccount:agents:runtime"),
    ],
)
def test_kubernetes_service_account_forms_are_canonical(
    value: str, expected: str
) -> None:
    assert normalize_kubernetes_service_account(value) == expected
    assert canonical_principal("k8s", value) == expected


@pytest.mark.parametrize(
    ("provider", "value"),
    [
        ("gcp", "runtime-derived"),
        ("aws", "aws_iam_role.agent.arn"),
        ("azure", "/subscriptions/x/resourceGroups/y/providers/Microsoft.ManagedIdentity/userAssignedIdentities/z"),
        ("kubernetes", "${var.namespace}/agent"),
    ],
)
def test_dynamic_or_noncanonical_provider_identity_stays_unresolved(
    provider: str, value: str
) -> None:
    assert canonical_principal(provider, value) is None
