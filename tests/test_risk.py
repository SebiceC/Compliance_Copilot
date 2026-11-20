"""Tests del motor de riesgo. Cada ejemplo de docs/metodologia-riesgo.md (sección 4) es un caso aquí."""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from compliance_copilot.models import Finding
from compliance_copilot.parsers.prowler_ocsf import parse_ocsf_file
from compliance_copilot.risk import (
    ACCOUNT_RESOURCE_TYPES,
    ADMIN_CHECKS,
    DATA_RESOURCE_TYPES,
    METHODOLOGY_VERSION,
    ClassificationSource,
    ResourceGroup,
    RiskLevel,
    Treatment,
    assess,
    assess_all,
    level_for,
)

METHODOLOGY = Path(__file__).resolve().parent.parent / "docs" / "metodologia-riesgo.md"
USER_UID = "arn:aws:iam::123456789001:user/admin-user"


def finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "finding_uid": "uid-1",
        "check_id": "some_check",
        "check_title": "Some check",
        "status": "fail",
        "status_detail": "",
        "severity": "medium",
        "observed_at": datetime(2026, 11, 17, tzinfo=timezone.utc),
        "provider": "aws",
        "account_uid": "123456789001",
        "region": "us-east-1",
        "resource_uid": "arn:aws:s3:::bucket",
        "resource_name": "bucket",
        "resource_type": "AwsS3Bucket",
        "compliance": {"ISO27001-2022": ["A.8.13"]},
    }
    fields.update(overrides)
    return Finding(**fields)


def tags(classification: str | None = None, **extra: str) -> dict[str, str]:
    result = {"data-classification": classification} if classification else {}
    return {**result, **extra}


# --- Sección 4 de la metodología: cada fila es un caso -------------------------------------------------------

EXAMPLES = [
    # (descripción, campos del hallazgo, probabilidad, impacto, riesgo, nivel)
    ("SSH abierto, public",
     dict(severity="high", categories=["internet-exposed"], resource_type="AwsEc2SecurityGroup", tags=tags("public")),
     5, 1, 5, RiskLevel.MEDIUM),
    ("usuario sin MFA, internal",
     dict(severity="high", resource_type="AwsIamUser", tags=tags("internal")),
     4, 2, 8, RiskLevel.MEDIUM),
    ("bucket sin versionado, confidential",
     dict(severity="medium", tags=tags("confidential")),
     3, 3, 9, RiskLevel.MEDIUM),
    ("bucket de logs sin versionado, restricted",
     dict(severity="medium", tags=tags("restricted")),
     3, 4, 12, RiskLevel.HIGH),
    ("trail sin validación, restricted, grupo Cuenta",
     dict(severity="medium", resource_type="AwsCloudTrailTrail", tags=tags("restricted")),
     3, 5, 15, RiskLevel.HIGH),
    ("admin sin MFA, sin tag",
     dict(severity="high", check_id="iam_user_mfa_enabled_console_access",
          resource_type="AwsIamUser", resource_uid=USER_UID),
     4, 4, 16, RiskLevel.HIGH),
    ("AdministratorAccess, sin tag",
     dict(severity="critical", check_id="iam_user_administrator_access_policy",
          resource_type="AwsIamUser", resource_uid=USER_UID),
     5, 4, 20, RiskLevel.CRITICAL),
    ("bucket con datos sin tag",
     dict(severity="medium"),
     3, 3, 9, RiskLevel.MEDIUM),
    ("bucket restricted en producción",
     dict(severity="medium", tags=tags("restricted", environment="prod")),
     3, 5, 15, RiskLevel.HIGH),
]


@pytest.mark.parametrize(
    ("fields", "probability", "impact", "score", "level"),
    [example[1:] for example in EXAMPLES],
    ids=[example[0] for example in EXAMPLES],
)
def test_methodology_examples(fields: dict[str, Any], probability: int, impact: int, score: int, level: RiskLevel) -> None:
    admin = frozenset({USER_UID})  # en un escaneo real lo calcula admin_resource_uids
    result = assess(finding(**fields), admin)
    assert (result.probability, result.impact, result.score, result.level) == (probability, impact, score, level)


# --- Clasificación ---------------------------------------------------------------------------------------------


def test_untagged_data_resource_requires_classification() -> None:
    result = assess(finding(resource_type="AwsS3Bucket"))
    assert result.classification_source is ClassificationSource.MISSING
    assert result.impact_base == 3
    assert result.requires_classification
    assert "A.5.12" in result.rationale


@pytest.mark.parametrize("resource_type", ["Other", "AwsGuardDutyDetector", "AwsEc2SecurityGroup", "AwsIamPolicy"])
def test_untagged_non_data_resource_does_not_require_classification(resource_type: str) -> None:
    """Controles de cuenta e infraestructura sin tag: base 3, pero no es un incumplimiento (evita ruido)."""
    result = assess(finding(resource_type=resource_type))
    assert result.impact_base == 3
    assert not result.requires_classification


def test_account_control_without_tag_gets_modifier_a() -> None:
    result = assess(finding(resource_type="Other"))
    assert result.resource_group is ResourceGroup.ACCOUNT
    assert result.impact_modifiers == ("a",)
    assert result.impact == 4


@pytest.mark.parametrize("value", ["private", "secreto", ""])
def test_invalid_tag_is_treated_as_missing_and_flagged_in_any_group(value: str) -> None:
    """Alguien intentó clasificar y lo hizo mal: se usa el valor prudente y se reporta A.5.12."""
    result = assess(finding(resource_type="AwsEc2SecurityGroup", tags={"data-classification": value}))
    assert result.classification_source is ClassificationSource.INVALID
    assert result.impact_base == 3
    assert result.requires_classification
    assert "inválido" in result.rationale


@pytest.mark.parametrize("value", ["Confidential", " CONFIDENTIAL "])
def test_tag_case_and_spaces_are_ignored(value: str) -> None:
    result = assess(finding(tags={"data-classification": value}))
    assert result.classification == "confidential"
    assert result.classification_source is ClassificationSource.TAG


# --- Modificadores ---------------------------------------------------------------------------------------------


def test_impact_modifiers_do_not_accumulate() -> None:
    """Cuenta + producción + administrador suma +1, no +3."""
    uid = "arn:aws:cloudtrail:us-east-1:123456789001:trail/t"
    result = assess(
        finding(resource_type="AwsCloudTrailTrail", resource_uid=uid, tags=tags("internal", environment="prod")),
        frozenset({uid}),
    )
    assert result.impact_modifiers == ("a", "b", "c")
    assert result.impact == 3  # internal 2 + 1


def test_scores_are_capped_at_5() -> None:
    result = assess(finding(severity="critical", categories=["internet-exposed"], tags=tags("restricted", environment="prod")))
    assert (result.probability, result.impact, result.score) == (5, 5, 25)


def test_admin_modifier_comes_from_another_finding_on_the_same_resource() -> None:
    """(c) no lee políticas: reutiliza el FAIL del check de administrador sobre el mismo recurso."""
    admin_check = finding(finding_uid="a", check_id="iam_user_administrator_access_policy",
                          resource_type="AwsIamUser", resource_uid=USER_UID, severity="critical")
    mfa_check = finding(finding_uid="b", check_id="iam_user_mfa_enabled_console_access",
                        resource_type="AwsIamUser", resource_uid=USER_UID, severity="high")
    other_user = finding(finding_uid="c", check_id="iam_user_mfa_enabled_console_access",
                         resource_type="AwsIamUser", resource_uid="arn:aws:iam::123456789001:user/other",
                         severity="high")

    results = {r.finding_uid: r for r in assess_all([admin_check, mfa_check, other_user])}
    assert "c" in results["a"].impact_modifiers
    assert "c" in results["b"].impact_modifiers
    assert "c" not in results["c"].impact_modifiers


def test_passing_admin_check_does_not_trigger_modifier() -> None:
    admin_pass = finding(finding_uid="a", check_id="iam_user_administrator_access_policy", status="pass",
                         resource_type="AwsIamUser", resource_uid=USER_UID)
    mfa_fail = finding(finding_uid="b", resource_type="AwsIamUser", resource_uid=USER_UID)
    (result,) = assess_all([admin_pass, mfa_fail])
    assert result.impact_modifiers == ()


# --- Qué se evalúa ---------------------------------------------------------------------------------------------


def test_only_fail_findings_are_assessed() -> None:
    results = assess_all([finding(finding_uid="f"), finding(finding_uid="p", status="pass"),
                          finding(finding_uid="m", status="manual")])
    assert [r.finding_uid for r in results] == ["f"]


def test_assessing_a_pass_is_an_error() -> None:
    with pytest.raises(ValueError, match="FAIL"):
        assess(finding(status="pass"))


def test_unmapped_finding_is_assessed_and_flagged() -> None:
    result = assess(finding(compliance={}))
    assert not result.has_control_mapping
    assert "Sin control mapeado" in result.rationale


# --- Niveles y tratamiento -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "level", "treatment"),
    [
        (1, RiskLevel.LOW, Treatment.ACCEPT), (4, RiskLevel.LOW, Treatment.ACCEPT),
        (5, RiskLevel.MEDIUM, Treatment.MITIGATE_OR_ACCEPT), (9, RiskLevel.MEDIUM, Treatment.MITIGATE_OR_ACCEPT),
        (10, RiskLevel.HIGH, Treatment.MITIGATE), (16, RiskLevel.HIGH, Treatment.MITIGATE),
        (20, RiskLevel.CRITICAL, Treatment.MITIGATE_PRIORITY), (25, RiskLevel.CRITICAL, Treatment.MITIGATE_PRIORITY),
    ],
)
def test_level_thresholds(score: int, level: RiskLevel, treatment: Treatment) -> None:
    assert level_for(score) == (level, treatment)


def test_rationale_allows_recalculation() -> None:
    result = assess(finding(severity="high", categories=["internet-exposed"],
                            resource_type="AwsEc2SecurityGroup", tags=tags("public")))
    assert result.rationale == (
        "Probabilidad 5 = severidad high (4) + expuesto a internet (+1). "
        "Impacto 1 = clasificación public (1). Riesgo 5 (medium)."
    )


def test_assessment_cannot_be_modified() -> None:
    result = assess(finding())
    with pytest.raises(ValueError):
        result.score = 1  # type: ignore[misc]


# --- Laboratorio real (muestra anonimizada) --------------------------------------------------------------------


def test_lab_designed_weaknesses(lab_sample_path: Path) -> None:
    findings = parse_ocsf_file(lab_sample_path).findings
    by_check = {}
    for f, r in zip([f for f in findings if f.status.value == "fail"], assess_all(findings), strict=True):
        by_check.setdefault((r.check_id, f.resource_name), r)

    assert by_check[("iam_user_mfa_enabled_console_access", "lab-user-nomfa")].score == 8
    assert by_check[("s3_bucket_object_versioning", "cc-lab-data-7asda3")].score == 9
    assert by_check[("cloudtrail_log_file_validation_enabled", "lab-trail")].score == 15
    ssh = next(r for (check, _), r in by_check.items()
               if check == "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22")
    assert (ssh.probability, ssh.impact, ssh.score) == (5, 1, 5)


# --- Código y documento sincronizados ----------------------------------------------------------------------------


def test_code_and_methodology_document_agree() -> None:
    """Si alguien cambia una lista en el código, debe cambiarla también en la metodología (y viceversa)."""
    text = METHODOLOGY.read_text(encoding="utf-8")
    assert re.search(rf"\*\*Versión:\*\* {re.escape(METHODOLOGY_VERSION)}\b", text)
    for name in DATA_RESOURCE_TYPES | ACCOUNT_RESOURCE_TYPES | ADMIN_CHECKS:
        assert f"`{name}`" in text, name
