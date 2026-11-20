"""Lógica de los entregables: arma las filas de cada uno, sin ningún formato de salida.

Separar el contenido (aquí) de la presentación (markdown.py, excel.py) permite probar las reglas de negocio
con datos simples y agregar formatos nuevos sin tocar la lógica.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from compliance_copilot.catalogs import Catalog, Control, Theme, load_catalog
from compliance_copilot.drafting.schema import FindingDraft
from compliance_copilot.models import Finding, ScanMetadata, Severity, Status
from compliance_copilot.parsers.prowler_ocsf import ParseError, ParseResult
from compliance_copilot.risk import RiskAssessment, RiskLevel, Treatment, assess_all

SOA_FRAMEWORK = "ISO27001-2022"

# Etiquetas en español para los entregables (el código usa valores en inglés).
LEVEL_LABEL = {RiskLevel.LOW: "Bajo", RiskLevel.MEDIUM: "Medio", RiskLevel.HIGH: "Alto", RiskLevel.CRITICAL: "Crítico"}
TREATMENT_LABEL = {
    Treatment.ACCEPT: "Aceptar",
    Treatment.MITIGATE_OR_ACCEPT: "Mitigar, o aceptar con justificación",
    Treatment.MITIGATE: "Mitigar",
    Treatment.MITIGATE_PRIORITY: "Mitigar con prioridad",
}
THEME_LABEL = {
    Theme.ORGANIZATIONAL: "Organizacional", Theme.PEOPLE: "Personas",
    Theme.PHYSICAL: "Físico", Theme.TECHNOLOGICAL: "Tecnológico",
}
SEVERITY_LABEL = {
    Severity.INFORMATIONAL: "Informativa", Severity.LOW: "Baja", Severity.MEDIUM: "Media",
    Severity.HIGH: "Alta", Severity.CRITICAL: "Crítica",
}


class TechnicalStatus(StrEnum):
    """Estado técnico de un control en la SoA. No es una opinión de cumplimiento: lo decide una persona."""

    GAPS = "Con brechas"  # al menos un FAIL
    REVIEW = "Requiere revisión"  # algún MANUAL y ningún FAIL
    NO_GAPS = "Sin brechas detectadas"  # solo PASS
    MANUAL_EVIDENCE = "Evidencia manual requerida"  # ningún check lo cubre


@dataclass(frozen=True)
class RiskRow:
    """Una fila de la matriz de riesgos: el hallazgo y su evaluación."""

    finding: Finding
    assessment: RiskAssessment


@dataclass(frozen=True)
class SoARow:
    control: Control
    status: TechnicalStatus
    pass_count: int
    fail_count: int
    manual_count: int
    max_level: RiskLevel | None  # el nivel más alto entre los FAIL del control
    max_score: int | None
    check_ids: tuple[str, ...]
    # Decisiones humanas: la herramienta las deja vacías a propósito (ISO 27001, 6.1.3 d).
    applicable: str = ""
    justification: str = ""


@dataclass(frozen=True)
class RemediationAction:
    """Una acción por check: una misma corrección arregla todos los recursos afectados."""

    priority: int
    check_id: str
    check_title: str
    severity: Severity
    max_score: int
    max_level: RiskLevel
    resources: tuple[str, ...]
    remediation: str
    controls: tuple[str, ...]  # controles ISO 27001 relacionados
    # Decisiones humanas.
    owner: str = ""
    due_date: str = ""


AUDIT_STATE_LABEL = {
    "approved": "Aprobada",
    "approved_with_edits": "Aprobada con ediciones",
    "pending": "Pendiente de aprobación",
    "rejected": "Rechazada",
    "failed": "Falló la generación",
    "outdated": "Desactualizada (el escaneo cambió)",
    "not_generated": "Sin redacción",
}


@dataclass(frozen=True)
class AuditEntry:
    """Estado de la redacción con IA de una acción. ``text`` solo existe si una persona la aprobó."""

    state: str = "not_generated"
    text: FindingDraft | None = None
    model: str = ""
    reviewer: str = ""
    reviewed_at: str = ""

    @property
    def label(self) -> str:
        return AUDIT_STATE_LABEL.get(self.state, self.state)


@dataclass(frozen=True)
class Report:
    """Todo lo que necesitan los entregables, ya calculado."""

    source: Path
    scan: ScanMetadata
    total_in_file: int
    parse_errors: tuple[ParseError, ...]
    findings: tuple[Finding, ...]
    risks: tuple[RiskRow, ...]  # ordenados de mayor a menor riesgo
    soa: tuple[SoARow, ...]  # todos los controles del catálogo, en orden
    remediation: tuple[RemediationAction, ...]  # ordenadas por prioridad
    heatmap: dict[tuple[int, int], int] = field(default_factory=dict)  # (probabilidad, impacto) -> cantidad
    audit: dict[str, AuditEntry] = field(default_factory=dict)  # redacción con IA por check_id (si se pidió)

    @property
    def is_complete(self) -> bool:
        """False si algún hallazgo del archivo no se pudo leer (ADR 0003): los entregables deben decirlo."""
        return not self.parse_errors

    @property
    def status_counts(self) -> Counter[Status]:
        return Counter(f.status for f in self.findings)

    @property
    def level_counts(self) -> Counter[RiskLevel]:
        return Counter(r.assessment.level for r in self.risks)

    @property
    def classification_required(self) -> tuple[RiskRow, ...]:
        """Recursos que generan el hallazgo A.5.12 (sin clasificar o con clasificación inválida)."""
        return tuple(r for r in self.risks if r.assessment.requires_classification)

    @property
    def unmapped(self) -> tuple[RiskRow, ...]:
        return tuple(r for r in self.risks if not r.assessment.has_control_mapping)


def build_report(parsed: ParseResult, catalog: Catalog | None = None) -> Report:
    catalog = catalog or load_catalog(SOA_FRAMEWORK)
    findings = tuple(parsed.findings)
    by_uid = {f.finding_uid: f for f in findings}

    risks = tuple(sorted(
        (RiskRow(by_uid[a.finding_uid], a) for a in assess_all(findings)),
        key=lambda r: (-r.assessment.score, -r.assessment.probability, r.finding.check_id, r.finding.resource_name),
    ))

    return Report(
        source=parsed.source,
        scan=parsed.scan,
        total_in_file=parsed.total,
        parse_errors=tuple(parsed.errors),
        findings=findings,
        risks=risks,
        soa=build_soa(findings, risks, catalog),
        remediation=build_remediation(risks),
        heatmap=dict(Counter((r.assessment.probability, r.assessment.impact) for r in risks)),
    )


def build_soa(findings: tuple[Finding, ...], risks: tuple[RiskRow, ...], catalog: Catalog) -> tuple[SoARow, ...]:
    """Una fila por cada control del catálogo, tenga o no hallazgos."""
    by_control: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        for control_id in finding.compliance.get(catalog.framework, []):
            by_control[control_id].append(finding)

    score_of = {r.finding.finding_uid: r.assessment for r in risks}
    rows = []
    for control in catalog.controls:
        mapped = by_control.get(control.id, [])
        statuses = Counter(f.status for f in mapped)
        fails = [score_of[f.finding_uid] for f in mapped if f.finding_uid in score_of]
        worst = max(fails, key=lambda a: a.score, default=None)
        rows.append(SoARow(
            control=control,
            status=_technical_status(statuses),
            pass_count=statuses[Status.PASS],
            fail_count=statuses[Status.FAIL],
            manual_count=statuses[Status.MANUAL],
            max_level=worst.level if worst else None,
            max_score=worst.score if worst else None,
            check_ids=tuple(sorted({f.check_id for f in mapped})),
        ))
    return tuple(rows)


def _technical_status(statuses: Counter[Status]) -> TechnicalStatus:
    if statuses[Status.FAIL]:
        return TechnicalStatus.GAPS
    if statuses[Status.MANUAL]:
        return TechnicalStatus.REVIEW
    if statuses[Status.PASS]:
        return TechnicalStatus.NO_GAPS
    return TechnicalStatus.MANUAL_EVIDENCE


def build_remediation(risks: tuple[RiskRow, ...]) -> tuple[RemediationAction, ...]:
    """Agrupa los FAIL por check y ordena por el riesgo más alto de cada grupo."""
    groups: dict[str, list[RiskRow]] = defaultdict(list)
    for row in risks:
        groups[row.finding.check_id].append(row)

    ordered = sorted(
        groups.values(),
        key=lambda rows: (-max(r.assessment.score for r in rows), -len(rows), rows[0].finding.check_id),
    )
    actions = []
    for priority, rows in enumerate(ordered, start=1):
        worst = max(rows, key=lambda r: r.assessment.score)
        actions.append(RemediationAction(
            priority=priority,
            check_id=worst.finding.check_id,
            check_title=worst.finding.check_title,
            severity=worst.finding.severity,
            max_score=worst.assessment.score,
            max_level=worst.assessment.level,
            resources=tuple(sorted({r.finding.resource_name or r.finding.resource_uid for r in rows})),
            remediation=worst.finding.remediation,
            controls=tuple(sorted({c for r in rows for c in r.finding.compliance.get(SOA_FRAMEWORK, [])})),
        ))
    return tuple(actions)
