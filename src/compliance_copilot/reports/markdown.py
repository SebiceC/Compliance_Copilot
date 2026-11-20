"""Entregables en Markdown: legibles en GitHub y comparables entre escaneos con un diff."""

from collections import Counter
from pathlib import Path

from compliance_copilot.reports.builders import (
    LEVEL_LABEL,
    SEVERITY_LABEL,
    THEME_LABEL,
    TREATMENT_LABEL,
    Report,
    TechnicalStatus,
)
from compliance_copilot.risk import METHODOLOGY_VERSION, RiskLevel

FILES = {
    "summary": "resumen.md",
    "risks": "matriz-riesgos.md",
    "soa": "soa-iso27001.md",
    "remediation": "plan-remediacion.md",
}


def write_markdown(report: Report, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    contents = {
        "summary": render_summary(report),
        "risks": render_risks(report),
        "soa": render_soa(report),
        "remediation": render_remediation(report),
    }
    paths = []
    for key, text in contents.items():
        path = out_dir / FILES[key]
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

    soa_counts = Counter(row.status for row in report.soa)
    parts.append("\n\n## SoA ISO 27001:2022\n")
    parts.append(_table(["Estado técnico", "Controles"], [[status.value, soa_counts[status]] for status in TechnicalStatus]))

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
        a.classification or "-", ", ".join(f.compliance.get("ISO27001-2022", [])) or "sin mapeo",
        TREATMENT_LABEL[a.treatment], a.rationale,
    ] for n, (f, a) in enumerate(((r.finding, r.assessment) for r in report.risks), start=1)]
    return "\n".join([
        _header("Matriz de riesgos", report),
        f"{len(report.risks)} riesgos, de mayor a menor. Riesgo = probabilidad × impacto "
        "(docs/metodologia-riesgo.md). El tratamiento es una sugerencia: la decisión es de una persona.\n",
        _table(["#", "Nivel", "Riesgo", "P", "I", "Hallazgo", "Recurso", "Región", "Clasificación",
                "ISO 27001", "Tratamiento sugerido", "Justificación"], rows),
    ]) + "\n"


def render_soa(report: Report) -> str:
    parts = [
        _header("Declaración de Aplicabilidad (SoA): ISO/IEC 27001:2022", report),
        "Borrador generado a partir del escaneo. **Aplicable** y **Justificación** los decide la organización "
        "(cláusula 6.1.3 d). \"Sin brechas detectadas\" no equivale a cumplimiento: solo indica que los checks "
        "automáticos no encontraron fallos.\n",
    ]
    for theme, label in THEME_LABEL.items():
        rows = [[
            r.control.id, r.control.title, r.status.value, r.pass_count, r.fail_count, r.manual_count,
            _level(r.max_level), r.applicable, r.justification,
        ] for r in report.soa if r.control.theme == theme]
        parts.append(f"## {label} ({len(rows)})\n")
        parts.append(_table(["Control", "Título", "Estado técnico", "PASS", "FAIL", "MANUAL", "Riesgo máximo",
                             "Aplicable", "Justificación"], rows))
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
