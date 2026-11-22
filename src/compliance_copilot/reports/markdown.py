"""Entregables en Markdown: legibles en GitHub y comparables entre escaneos con un diff."""

from collections import Counter
from pathlib import Path

from compliance_copilot.reports.builders import (
    LEVEL_LABEL,
    PRIMARY_FRAMEWORK,
    SEVERITY_LABEL,
    TREATMENT_LABEL,
    AuditEntry,
    Report,
    Statement,
    TechnicalStatus,
)
from compliance_copilot.risk import METHODOLOGY_VERSION, RiskLevel

# Los archivos de las declaraciones (uno por marco) los define cada catálogo en ``statement.file``.
FILES = {
    "summary": "resumen.md",
    "risks": "matriz-riesgos.md",
    "remediation": "plan-remediacion.md",
    "audit": "hallazgos-auditoria.md",
}


def write_markdown(report: Report, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = {
        FILES["summary"]: render_summary(report),
        FILES["risks"]: render_risks(report),
        **{s.catalog.statement.file: render_statement(report, s) for s in report.statements},
        FILES["remediation"]: render_remediation(report),
        FILES["audit"]: render_audit(report),
    }
    paths = []
    for name, text in contents.items():
        path = out_dir / name
        path.write_text(text, encoding="utf-8", newline="\n")
        paths.append(path)
    return paths


# --- Partes comunes ------------------------------------------------------------------------------------------


def _cell(value: object) -> str:
    """Una celda de tabla: sin saltos de línea y con las barras escapadas."""
    return " ".join(str(value if value is not None else "").split()).replace("|", "\\|")


def _table(headers: list[str], rows: list[list[object]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(_cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)


def _header(title: str, report: Report) -> str:
    scan = report.scan
    when = scan.last_observed_at.strftime("%Y-%m-%d %H:%M UTC") if scan.last_observed_at else "sin hallazgos"
    lines = [
        f"# {title}",
        "",
        f"- **Escaneo:** {', '.join(scan.scan_ids) or 'desconocido'} · {scan.scanner} "
        f"{', '.join(scan.scanner_versions)} · {when}",
        f"- **Cuentas:** {', '.join(scan.account_uids) or '-'} · **Metodología de riesgo:** v{METHODOLOGY_VERSION}",
        "",
    ]
    if not report.is_complete:
        lines += [
            f"> ⚠️ **Entregable incompleto:** {len(report.parse_errors)} de {report.total_in_file} hallazgos del "
            "escaneo no se pudieron leer y no están incluidos. Ver `resumen.md`.",
            "",
        ]
    return "\n".join(lines)


def _level(level: RiskLevel | None) -> str:
    return LEVEL_LABEL[level] if level else "-"


# --- Entregables ---------------------------------------------------------------------------------------------


def render_summary(report: Report) -> str:
    counts = report.status_counts
    levels = report.level_counts
    parts = [_header("Resumen del escaneo", report)]

    parts.append("## Hallazgos\n")
    parts.append(_table(["Total en el archivo", "Leídos", "FAIL", "PASS", "MANUAL", "No leídos"], [[
        report.total_in_file, len(report.findings), counts["fail"], counts["pass"], counts["manual"],
        len(report.parse_errors),
    ]]))

    parts.append("\n\n## Riesgos (solo FAIL)\n")
    parts.append(_table([LEVEL_LABEL[lvl] for lvl in reversed(RiskLevel)],
                        [[levels[lvl] for lvl in reversed(RiskLevel)]]))

    parts.append("\n\n## Mapa de calor (cantidad de riesgos)\n")
    rows = [[f"**P{p}**", *[report.heatmap.get((p, i), "") for i in range(1, 6)]] for p in range(5, 0, -1)]
    parts.append(_table(["Probabilidad \\ Impacto", "I1", "I2", "I3", "I4", "I5"], rows))

    for statement in report.statements:
        counts_by_status = Counter(row.status for row in statement.rows)
        parts.append(f"\n\n## {statement.catalog.statement.summary_title}\n")
        parts.append(_table(["Estado técnico", _plural(statement.catalog.statement.id_label)],
                            [[status.value, counts_by_status[status]] for status in TechnicalStatus]))
        if statement.unmapped:
            parts.append(f"\n**IDs de Prowler sin correspondencia en el catálogo: {len(statement.unmapped)}** "
                         f"(ver `{statement.catalog.statement.file}`).")

    parts.append(f"\n\n## Clasificación faltante (A.5.12): {len(report.classification_required)} recursos\n")
    if report.classification_required:
        parts.append(_table(["Recurso", "Tipo", "Motivo"], sorted({
            (r.finding.resource_name, r.finding.resource_type,
             "tag inválido" if r.assessment.classification_source == "invalid" else "sin tag")
            for r in report.classification_required
        })))

    parts.append(f"\n\n## Riesgos sin control mapeado: {len(report.unmapped)}\n")
    parts.append("Se evalúan igual, pero no entran en la SoA (metodología, sección 6).")

    if report.parse_errors:
        parts.append("\n\n## Hallazgos no leídos (ADR 0003)\n")
        parts.append(_table(["Posición", "Hallazgo", "Check", "Motivo"],
                            [[e.index, e.finding_uid or "-", e.check_id or "-", e.reason] for e in report.parse_errors]))
    return "\n".join(parts) + "\n"


def render_risks(report: Report) -> str:
    rows = [[
        n, LEVEL_LABEL[a.level], a.score, a.probability, a.impact, f.check_title, f.resource_name, f.region,
        a.classification or "-", ", ".join(f.compliance.get(PRIMARY_FRAMEWORK, [])) or "sin mapeo",
        TREATMENT_LABEL[a.treatment], a.rationale,
    ] for n, (f, a) in enumerate(((r.finding, r.assessment) for r in report.risks), start=1)]
    return "\n".join([
        _header("Matriz de riesgos", report),
        f"{len(report.risks)} riesgos, de mayor a menor. Riesgo = probabilidad × impacto "
        "(docs/metodologia-riesgo.md). El tratamiento es una sugerencia: la decisión es de una persona.\n",
        _table(["#", "Nivel", "Riesgo", "P", "I", "Hallazgo", "Recurso", "Región", "Clasificación",
                "ISO 27001", "Tratamiento sugerido", "Justificación"], rows),
    ]) + "\n"


def _plural(label: str) -> str:
    return label + ("es" if label[-1] in "lnrd" else "s")


def render_statement(report: Report, statement: Statement) -> str:
    """La declaración de un marco (en ISO 27001, la SoA), agrupada como lo agrupa el marco."""
    catalog, config = statement.catalog, statement.catalog.statement
    parts = [_header(config.title, report), config.intro + "\n"]
    headers = [config.id_label, "Título", "Estado técnico", "PASS", "FAIL", "MANUAL", "Riesgo máximo",
               *config.human_columns]
    for group in catalog.groups:
        rows = [[
            r.requirement.id, r.requirement.title, r.status.value, r.pass_count, r.fail_count, r.manual_count,
            _level(r.max_level), *r.human,
        ] for r in statement.rows if r.requirement.group == group.id]
        parts.append(f"## {group.label} ({len(rows)})\n")
        parts.append(_table(headers, rows))
        parts.append("")
    if statement.unmapped:
        parts.append(f"## IDs de Prowler sin correspondencia ({len(statement.unmapped)})\n")
        parts.append("Prowler los asigna a este marco, pero no existen en el catálogo. No se descartan: una persona "
                     "decide si falta el requisito en el catálogo o si el mapeo de Prowler está mal (ADR 0007).\n")
        parts.append(_table(["ID de Prowler", "Hallazgos", "Checks"],
                            [[u.raw_id, u.finding_count, ", ".join(u.check_ids)] for u in statement.unmapped]))
        parts.append("")
    return "\n".join(parts)


def render_remediation(report: Report) -> str:
    rows = [[
        a.priority, LEVEL_LABEL[a.max_level], a.max_score, a.check_title, SEVERITY_LABEL[a.severity],
        len(a.resources), ", ".join(a.resources), ", ".join(a.controls) or "sin mapeo", a.remediation,
        a.owner, a.due_date,
    ] for a in report.remediation]
    return "\n".join([
        _header("Plan de remediación", report),
        f"{len(report.remediation)} acciones, una por check: una sola corrección cubre todos los recursos "
        "afectados. **Responsable** y **Fecha compromiso** los asigna la organización.\n",
        _table(["Prioridad", "Nivel", "Riesgo máx.", "Acción sobre", "Severidad", "Recursos", "Lista de recursos",
                "ISO 27001", "Cómo corregirlo", "Responsable", "Fecha compromiso"], rows),
    ]) + "\n"


def render_audit(report: Report) -> str:
    """Hallazgos en formato de auditoría (5 C). Solo se publica el texto que una persona aprobó."""
    parts = [
        _header("Hallazgos de auditoría", report),
        "Redacción asistida por IA. **Solo se muestra el texto aprobado por una persona**; el resto aparece con "
        "el texto técnico del escáner y su estado. Los niveles de riesgo y los controles los calcula la "
        "metodología, no la IA.\n",
    ]
    states = Counter(report.audit.get(a.check_id, AuditEntry()).label for a in report.remediation)
    parts.append(_table(["Estado de la redacción", "Hallazgos"], sorted(states.items())))
    parts.append("")

    for action in report.remediation:
        entry = report.audit.get(action.check_id, AuditEntry())
        text = entry.text
        title = text.title if text else action.check_title
        parts.append(f"## {action.priority}. {title}\n")
        parts.append(f"**Riesgo:** {LEVEL_LABEL[action.max_level]} ({action.max_score}) · **Recursos:** "
                     f"{', '.join(action.resources)} · **ISO 27001:** {', '.join(action.controls) or 'sin mapeo'}\n")
        if text:
            for label, value in [("Condición", text.condition), ("Criterio", text.criteria), ("Causa", text.cause),
                                 ("Efecto", text.effect), ("Recomendación", text.recommendation)]:
                parts.append(f"**{label}.** {value}\n")
            parts.append(f"*Redactado con asistencia de IA ({entry.model}); {entry.label.lower()} por "
                         f"{entry.reviewer} el {entry.reviewed_at}.*\n")
        else:
            parts.append(f"> Redacción: **{entry.label}**. Texto técnico del escáner: {action.check_title}.\n")
    return "\n".join(parts)
