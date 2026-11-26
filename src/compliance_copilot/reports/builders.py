"""Lógica de los entregables: arma las filas de cada uno, sin ningún formato de salida.

Separar el contenido (aquí) de la presentación (markdown.py, excel.py) permite probar las reglas de negocio
con datos simples y agregar formatos nuevos sin tocar la lógica.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from compliance_copilot.catalogs import Catalog, Requirement, load_catalogs
from compliance_copilot.drafting.schema import FindingDraft
from compliance_copilot.models import Finding, ScanMetadata, Severity, Status
from compliance_copilot.parsers.prowler_ocsf import ParseError, ParseResult
from compliance_copilot.personal_data import ResourceRef, personal_data_scope
from compliance_copilot.risk import RiskAssessment, RiskLevel, Treatment, assess_all

# Marco de referencia del plan de remediación, la matriz de riesgos y la redacción con IA (ADR 0007, D5).
# Los demás marcos tienen su propia declaración.
PRIMARY_FRAMEWORK = "ISO27001-2022"

# Etiquetas en español para los entregables (el código usa valores en inglés).
LEVEL_LABEL = {RiskLevel.LOW: "Bajo", RiskLevel.MEDIUM: "Medio", RiskLevel.HIGH: "Alto", RiskLevel.CRITICAL: "Crítico"}
TREATMENT_LABEL = {
    Treatment.ACCEPT: "Aceptar",
    Treatment.MITIGATE_OR_ACCEPT: "Mitigar, o aceptar con justificación",
    Treatment.MITIGATE: "Mitigar",
    Treatment.MITIGATE_PRIORITY: "Mitigar con prioridad",
}
SEVERITY_LABEL = {
    Severity.INFORMATIONAL: "Informativa", Severity.LOW: "Baja", Severity.MEDIUM: "Media",
    Severity.HIGH: "Alta", Severity.CRITICAL: "Crítica",
}


class TechnicalStatus(StrEnum):
    """Estado técnico de un requisito en su declaración. No es una opinión de cumplimiento: lo decide una persona."""

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
class StatementRow:
    """Un requisito del marco en su declaración (en ISO 27001, una fila de la SoA)."""

    requirement: Requirement
    status: TechnicalStatus
    pass_count: int
    fail_count: int
    manual_count: int
    max_level: RiskLevel | None  # el nivel más alto entre los FAIL del requisito
    max_score: int | None
    check_ids: tuple[str, ...]
    # Decisiones humanas, una por cada columna de ``catalog.statement.human_columns``. La herramienta las deja
    # vacías a propósito (en ISO 27001, cláusula 6.1.3 d): decidirlas es de una persona. Un grupo del catálogo
    # puede traer una sugerencia (Ley 1581, arts. 17 y 18), marcada como tal para que se confirme o corrija.
    human: tuple[str, ...] = ()


@dataclass(frozen=True)
class UnmappedId:
    """Un ID que Prowler asigna a este marco sin correspondencia en el catálogo (ADR 0007, D3).

    No se descarta: se reporta, para que una persona decida si falta en el catálogo o si el mapeo está mal.
    """

    raw_id: str
    finding_count: int
    check_ids: tuple[str, ...]


@dataclass(frozen=True)
class Statement:
    """La declaración de un marco: SoA (ISO 27001), matriz de criterios (SOC 2), perfil (NIST CSF)..."""

    catalog: Catalog
    rows: tuple[StatementRow, ...]  # todos los requisitos del catálogo, en orden
    unmapped: tuple[UnmappedId, ...] = ()
    evidence: dict[str, tuple[Finding, ...]] = field(default_factory=dict)  # requisito -> sus hallazgos
    # Solo en los marcos con regla de datos personales (ADR 0008).
    unqualified: tuple[ResourceRef, ...] = ()  # recursos de datos sin calificar: requieren revisión
    outside: tuple[ResourceRef, ...] = ()  # recursos con datos personales fuera del país: se señalan

    @property
    def framework(self) -> str:
        return self.catalog.framework

    def outside_notes(self) -> tuple[str, ...]:
        """El texto del señalamiento por cada recurso fuera del país."""
        rule = self.catalog.personal_data
        if not rule:
            return ()
        return tuple(rule.outside_note.format(resource=r.name, region=r.region, country=r.country)
                     for r in self.outside)


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
    statements: tuple[Statement, ...]  # una declaración por marco, en el orden de catalogs.FRAMEWORKS
    remediation: tuple[RemediationAction, ...]  # ordenadas por prioridad
    heatmap: dict[tuple[int, int], int] = field(default_factory=dict)  # (probabilidad, impacto) -> cantidad
    resource_tags: Path | None = None  # archivo de tags aparte (Azure), si se usó
    findings_tagged: int = 0
    audit: dict[str, AuditEntry] = field(default_factory=dict)  # redacción con IA por check_id (si se pidió)

    @property
    def soa(self) -> tuple[StatementRow, ...]:
        """Las filas de la SoA de ISO 27001 (el marco de referencia)."""
        return self.statement(PRIMARY_FRAMEWORK).rows

    def statement(self, framework: str) -> Statement:
        return next(s for s in self.statements if s.framework == framework)

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


def build_report(parsed: ParseResult, catalogs: tuple[Catalog, ...] | None = None) -> Report:
    catalogs = catalogs or load_catalogs()
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
        statements=tuple(build_statement(findings, risks, catalog) for catalog in catalogs),
        remediation=build_remediation(risks),
        heatmap=dict(Counter((r.assessment.probability, r.assessment.impact) for r in risks)),
        resource_tags=parsed.resource_tags,
        findings_tagged=parsed.findings_tagged,
    )


def build_statement(findings: tuple[Finding, ...], risks: tuple[RiskRow, ...], catalog: Catalog) -> Statement:
    """Una fila por cada requisito del catálogo, tenga o no hallazgos.

    Los IDs de Prowler se traducen al formato del catálogo (``catalog.resolve``; un ID puede ir a varios
    requisitos). Los que no tienen correspondencia no se pierden: quedan en ``unmapped`` con sus hallazgos (ADR 0007, D3; el mismo principio del
    ADR 0003 para los hallazgos que no se pueden leer).
    """
    scope = None
    if catalog.personal_data:  # solo cuentan los hallazgos de recursos con datos personales (ADR 0008)
        rule = catalog.personal_data
        scope = personal_data_scope(findings, rule.tag, rule.local_regions)
        findings = scope.counted
    flagged = set(catalog.personal_data.outside_obligations) if scope and scope.outside else set()

    by_requirement: dict[str, list[Finding]] = defaultdict(list)
    unmapped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        # Un catálogo derivado lee los IDs del marco de origen (la Ley 1581, los de ISO 27001).
        for raw_id in finding.compliance.get(catalog.source_framework, []):
            targets = catalog.resolve(raw_id)
            if not targets and raw_id not in catalog.excluded:
                unmapped[raw_id].append(finding)
            for requirement_id in targets:
                if finding not in by_requirement[requirement_id]:  # varios IDs de Prowler pueden ir al mismo requisito
                    by_requirement[requirement_id].append(finding)

    score_of = {r.finding.finding_uid: r.assessment for r in risks}
    decisions = {g.id: tuple(g.suggested.get(c, "") for c in catalog.statement.human_columns)
                 for g in catalog.groups}  # vacías, salvo lo que el catálogo sugiere
    rows = []
    for requirement in catalog.requirements:
        mapped = by_requirement.get(requirement.id, [])
        statuses = Counter(f.status for f in mapped)
        fails = [score_of[f.finding_uid] for f in mapped if f.finding_uid in score_of]
        worst = max(fails, key=lambda a: a.score, default=None)
        status = _technical_status(statuses)
        if requirement.id in flagged and status is not TechnicalStatus.GAPS:
            status = TechnicalStatus.REVIEW  # datos personales fuera del país: lo verifica una persona
        rows.append(StatementRow(
            requirement=requirement,
            status=status,
            pass_count=statuses[Status.PASS],
            fail_count=statuses[Status.FAIL],
            manual_count=statuses[Status.MANUAL],
            max_level=worst.level if worst else None,
            max_score=worst.score if worst else None,
            check_ids=tuple(sorted({f.check_id for f in mapped})),
            human=decisions[requirement.group],
        ))
    return Statement(
        catalog=catalog,
        rows=tuple(rows),
        unmapped=tuple(
            UnmappedId(raw_id, len(found), tuple(sorted({f.check_id for f in found})))
            for raw_id, found in sorted(unmapped.items())
        ),
        evidence={rid: tuple(found) for rid, found in by_requirement.items()},
        unqualified=scope.unqualified if scope else (),
        outside=scope.outside if scope else (),
    )


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
            controls=tuple(sorted({c for r in rows for c in r.finding.compliance.get(PRIMARY_FRAMEWORK, [])})),
        ))
    return tuple(actions)
