"""Motor de riesgo: convierte hallazgos FAIL en riesgos evaluados.

Implementa docs/metodologia-riesgo.md (v0.2). Las tablas de la metodología están como constantes al inicio del
archivo para que el código y el documento se puedan comparar línea por línea; si cambia una, cambia la otra.

Riesgo = Probabilidad (1-5) × Impacto (1-5)
  Impacto      = base por clasificación + 1 si (a) cuenta, (b) producción o (c) administrador   (máx. 5)
  Probabilidad = base por severidad     + 1 si el check es "internet-exposed"                 (máx. 5)
"""

from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from compliance_copilot.models import Finding, Severity, Status

METHODOLOGY_VERSION = "0.2"

# --- 1. Clasificación ------------------------------------------------------------------------------------

CLASSIFICATION_TAG = "data-classification"

IMPACT_BASE: dict[str, int] = {
    "public": 1,
    "internal": 2,
    "confidential": 3,
    "restricted": 4,
}
DEFAULT_IMPACT_BASE = IMPACT_BASE["confidential"]  # sin tag o con tag inválido: valor prudente

# 1.1 Grupos de recursos (resource_type de Prowler)
DATA_RESOURCE_TYPES: frozenset[str] = frozenset({
    "AwsS3Bucket", "AwsEc2Instance", "AwsEc2Volume", "AwsEc2Snapshot",
    "AwsRdsDbInstance", "AwsRdsDbCluster", "AwsRdsDbSnapshot", "AwsDynamoDbTable",
    "AwsEfsFileSystem", "AwsRedshiftCluster", "AwsBackupBackupVault", "AwsKmsKey",
    "AwsSecretsManagerSecret", "AwsLogsLogGroup", "AwsOpenSearchServiceDomain",
})
ACCOUNT_RESOURCE_TYPES: frozenset[str] = frozenset({
    "Other", "AwsCloudTrailTrail", "AwsCloudWatchAlarm",
    "AwsConfigConfigurationRecorder", "AwsConfigConfigurationAggregator",
    "AwsGuardDutyDetector", "AwsSecurityHubHub", "AwsS3AccountPublicAccessBlock", "AwsIamPasswordPolicy",
})

# --- 2. Impacto: modificador (c) ---------------------------------------------------------------------------

ADMIN_CHECKS: frozenset[str] = frozenset({
    "iam_user_administrator_access_policy",
    "iam_role_administratoraccess_policy",
    "iam_group_administrator_access_policy",
    "iam_aws_attached_policy_no_administrative_privileges",
    "iam_customer_attached_policy_no_administrative_privileges",
    "iam_inline_policy_no_administrative_privileges",
})

# --- 3. Probabilidad ---------------------------------------------------------------------------------------

PROBABILITY_BASE: dict[Severity, int] = {
    Severity.INFORMATIONAL: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
EXPOSURE_CATEGORY = "internet-exposed"

MAX_SCORE = 5


# --- Modelos -------------------------------------------------------------------------------------------------


class ResourceGroup(StrEnum):
    DATA = "data"
    ACCOUNT = "account"
    INFRASTRUCTURE = "infrastructure"


class ClassificationSource(StrEnum):
    TAG = "tag"  # tag presente y válido
    MISSING = "missing"  # sin tag: se usa el valor prudente
    INVALID = "invalid"  # tag con un valor que no está en la escala


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Treatment(StrEnum):
    ACCEPT = "accept"
    MITIGATE_OR_ACCEPT = "mitigate_or_accept_with_justification"
    MITIGATE = "mitigate"
    MITIGATE_PRIORITY = "mitigate_with_priority"


# Sección 5: (puntuación máxima del nivel, nivel, tratamiento sugerido)
LEVELS: tuple[tuple[int, RiskLevel, Treatment], ...] = (
    (4, RiskLevel.LOW, Treatment.ACCEPT),
    (9, RiskLevel.MEDIUM, Treatment.MITIGATE_OR_ACCEPT),
    (16, RiskLevel.HIGH, Treatment.MITIGATE),
    (25, RiskLevel.CRITICAL, Treatment.MITIGATE_PRIORITY),
)


class RiskAssessment(BaseModel):
    """La evaluación de un hallazgo. Es una opinión sobre la evidencia, no la evidencia: va aparte del Finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_uid: str
    check_id: str
    resource_uid: str
    methodology_version: str = METHODOLOGY_VERSION

    # Clasificación
    resource_group: ResourceGroup
    classification: str | None  # el valor válido del tag, o None
    classification_source: ClassificationSource
    requires_classification: bool  # genera el hallazgo A.5.12

    # Impacto
    impact_base: int = Field(ge=1, le=4)
    impact_modifiers: tuple[str, ...]  # condiciones cumplidas: "a", "b", "c"
    impact: int = Field(ge=1, le=MAX_SCORE)

    # Probabilidad
    probability_base: int = Field(ge=1, le=MAX_SCORE)
    probability_modifiers: tuple[str, ...]  # "internet-exposed"
    probability: int = Field(ge=1, le=MAX_SCORE)

    # Resultado
    score: int = Field(ge=1, le=MAX_SCORE * MAX_SCORE)
    level: RiskLevel
    treatment: Treatment
    has_control_mapping: bool
    rationale: str


# --- Motor ---------------------------------------------------------------------------------------------------


def assess_all(findings: Iterable[Finding]) -> list[RiskAssessment]:
    """Evalúa todos los FAIL de un escaneo. Los PASS y MANUAL no son riesgos y no se evalúan."""
    findings = list(findings)
    admin_resources = admin_resource_uids(findings)
    return [assess(f, admin_resources) for f in findings if f.status is Status.FAIL]


def admin_resource_uids(findings: Iterable[Finding]) -> frozenset[str]:
    """Recursos con un FAIL en un check de privilegios administrativos: activan el modificador (c)."""
    return frozenset(f.resource_uid for f in findings if f.status is Status.FAIL and f.check_id in ADMIN_CHECKS)


def assess(finding: Finding, admin_resources: frozenset[str] = frozenset()) -> RiskAssessment:
    """Evalúa un hallazgo FAIL. ``admin_resources`` viene de ``admin_resource_uids`` sobre el mismo escaneo."""
    if finding.status is not Status.FAIL:
        raise ValueError(f"solo se evalúan hallazgos FAIL; {finding.finding_uid} es {finding.status}")

    group = resource_group(finding.resource_type)
    classification, source = read_classification(finding.tags)

    impact_base = IMPACT_BASE[classification] if classification else DEFAULT_IMPACT_BASE
    impact_mods = impact_modifiers(finding, group, admin_resources)
    impact = min(impact_base + (1 if impact_mods else 0), MAX_SCORE)

    probability_base = PROBABILITY_BASE[finding.severity]
    probability_mods = (EXPOSURE_CATEGORY,) if EXPOSURE_CATEGORY in finding.categories else ()
    probability = min(probability_base + (1 if probability_mods else 0), MAX_SCORE)

    score = probability * impact
    level, treatment = level_for(score)
    requires_classification = source is ClassificationSource.INVALID or (
        source is ClassificationSource.MISSING and group is ResourceGroup.DATA
    )

    return RiskAssessment(
        finding_uid=finding.finding_uid,
        check_id=finding.check_id,
        resource_uid=finding.resource_uid,
        resource_group=group,
        classification=classification,
        classification_source=source,
        requires_classification=requires_classification,
        impact_base=impact_base,
        impact_modifiers=impact_mods,
        impact=impact,
        probability_base=probability_base,
        probability_modifiers=probability_mods,
        probability=probability,
        score=score,
        level=level,
        treatment=treatment,
        has_control_mapping=bool(finding.compliance),
        rationale=_rationale(finding, classification, source, impact_base, impact_mods, impact,
                             probability_base, probability_mods, probability, score, level, requires_classification),
    )


def resource_group(resource_type: str) -> ResourceGroup:
    if resource_type in DATA_RESOURCE_TYPES:
        return ResourceGroup.DATA
    if resource_type in ACCOUNT_RESOURCE_TYPES:
        return ResourceGroup.ACCOUNT
    return ResourceGroup.INFRASTRUCTURE


def read_classification(tags: dict[str, str]) -> tuple[str | None, ClassificationSource]:
    """Lee el tag ``data-classification``. Ignora mayúsculas y espacios; un valor fuera de la escala es inválido."""
    if CLASSIFICATION_TAG not in tags:
        return None, ClassificationSource.MISSING
    value = tags[CLASSIFICATION_TAG].strip().lower()
    if value in IMPACT_BASE:
        return value, ClassificationSource.TAG
    return None, ClassificationSource.INVALID


def impact_modifiers(finding: Finding, group: ResourceGroup, admin_resources: frozenset[str]) -> tuple[str, ...]:
    """Condiciones (a), (b) y (c) que cumple el recurso. Se devuelven todas, aunque solo sumen +1."""
    conditions = []
    if group is ResourceGroup.ACCOUNT:
        conditions.append("a")
    if finding.tags.get("environment", "").strip().lower() == "prod":
        conditions.append("b")
    if finding.resource_uid in admin_resources:
        conditions.append("c")
    return tuple(conditions)


def level_for(score: int) -> tuple[RiskLevel, Treatment]:
    for maximum, level, treatment in LEVELS:
        if score <= maximum:
            return level, treatment
    raise ValueError(f"puntuación fuera de rango: {score}")


_MODIFIER_TEXT = {"a": "alcance de toda la cuenta", "b": "producción", "c": "privilegios administrativos"}


def _rationale(
    finding: Finding, classification: str | None, source: ClassificationSource,
    impact_base: int, impact_mods: tuple[str, ...], impact: int,
    probability_base: int, probability_mods: tuple[str, ...], probability: int,
    score: int, level: RiskLevel, requires_classification: bool,
) -> str:
    """Texto que permite recalcular el riesgo a mano."""
    p = f"Probabilidad {probability} = severidad {finding.severity.value} ({probability_base})"
    if probability_mods:
        p += " + expuesto a internet (+1)"

    if source is ClassificationSource.TAG:
        i = f"Impacto {impact} = clasificación {classification} ({impact_base})"
    elif source is ClassificationSource.INVALID:
        i = f"Impacto {impact} = tag de clasificación inválido, se usa confidential ({impact_base})"
    else:
        i = f"Impacto {impact} = sin clasificación, se usa confidential ({impact_base})"
    if impact_mods:
        i += " + " + " y ".join(f"({m}) {_MODIFIER_TEXT[m]}" for m in impact_mods) + " (+1)"

    text = f"{p}. {i}. Riesgo {score} ({level.value})."
    if requires_classification:
        text += " Requiere clasificar el recurso (A.5.12)."
    if not finding.compliance:
        text += " Sin control mapeado en los marcos del proyecto."
    return text
