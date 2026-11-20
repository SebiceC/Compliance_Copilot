"""Tests del modelo Finding: qué acepta, qué rechaza y por qué."""

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from compliance_copilot.models import Finding, Severity, Status


def valid_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "finding_uid": "prowler-aws-check-123456789001-us-east-1-res",
        "check_id": "s3_bucket_object_versioning",
        "check_title": "S3 bucket has versioning enabled",
        "status": "FAIL",
        "status_detail": "Bucket has versioning disabled.",
        "severity": "Medium",
        "observed_at": datetime(2026, 11, 17, 2, 56, 49, tzinfo=timezone.utc),
        "provider": "aws",
        "account_uid": "123456789001",
        "region": "us-east-1",
        "resource_uid": "arn:aws:s3:::example-bucket",
        "resource_name": "example-bucket",
        "resource_type": "AwsS3Bucket",
    }
    fields.update(overrides)
    return fields


def test_valid_finding_is_created() -> None:
    finding = Finding(**valid_fields())
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.MEDIUM


@pytest.mark.parametrize("raw", ["FAIL", "Fail", "fail", " fail "])
def test_status_is_normalized_whatever_the_case(raw: str) -> None:
    assert Finding(**valid_fields(status=raw)).status is Status.FAIL


def test_ocsf_lifecycle_status_is_rejected() -> None:
    """'New' es el campo status de OCSF (ciclo de vida), no el resultado del check."""
    with pytest.raises(ValidationError, match="status"):
        Finding(**valid_fields(status="New"))


def test_unknown_severity_is_rejected() -> None:
    with pytest.raises(ValidationError, match="severity"):
        Finding(**valid_fields(severity="urgent"))


def test_datetime_without_timezone_is_rejected() -> None:
    """Una hora sin zona horaria es ambigua: como evidencia, puede estar corrida varias horas."""
    with pytest.raises(ValidationError, match="observed_at"):
        Finding(**valid_fields(observed_at=datetime(2026, 11, 16, 21, 56, 49)))


def test_datetime_in_the_future_is_rejected() -> None:
    future = datetime.now(timezone.utc) + timedelta(days=1)
    with pytest.raises(ValidationError, match="futuro"):
        Finding(**valid_fields(observed_at=future))


@pytest.mark.parametrize("field", ["finding_uid", "check_id", "account_uid", "resource_uid", "provider"])
def test_empty_identifiers_are_rejected(field: str) -> None:
    """Un hallazgo sin identificadores no se puede rastrear."""
    with pytest.raises(ValidationError, match=field):
        Finding(**valid_fields(**{field: ""}))


def test_unknown_fields_are_rejected() -> None:
    """Minimización de datos: un campo no previsto (como el nombre de la cuenta) no entra en silencio."""
    with pytest.raises(ValidationError, match="account_name"):
        Finding(**valid_fields(account_name="someone"))


def test_finding_cannot_be_modified() -> None:
    """Un hallazgo es evidencia: no se modifica después de creado."""
    finding = Finding(**valid_fields())
    with pytest.raises(ValidationError):
        finding.status = Status.PASS  # type: ignore[misc]


def test_tags_and_compliance_are_optional_and_not_shared() -> None:
    """Un recurso sin tags es válido; y cada hallazgo tiene su propio diccionario."""
    first, second = Finding(**valid_fields()), Finding(**valid_fields())
    assert first.tags == {} and first.compliance == {}
    assert first.tags is not second.tags


def test_risk_and_remediation_default_to_empty() -> None:
    finding = Finding(**valid_fields())
    assert finding.risk == "" and finding.remediation == ""
