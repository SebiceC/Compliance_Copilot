"""Entregable en Excel: un libro con una hoja por entregable, filtros y colores por nivel de riesgo."""

from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from compliance_copilot.reports.builders import (
    LEVEL_LABEL,
    PRIMARY_FRAMEWORK,
    SEVERITY_LABEL,
    TREATMENT_LABEL,
    AuditEntry,
    Report,
    Statement,
)
from compliance_copilot.risk import METHODOLOGY_VERSION, RiskLevel, level_for

FILENAME = "compliance-copilot.xlsx"

LEVEL_FILL = {
    RiskLevel.LOW: PatternFill("solid", fgColor="C6EFCE"),
    RiskLevel.MEDIUM: PatternFill("solid", fgColor="FFEB9C"),
    RiskLevel.HIGH: PatternFill("solid", fgColor="F8CBAD"),
    RiskLevel.CRITICAL: PatternFill("solid", fgColor="FF7C80"),
}
HEADER_FILL = PatternFill("solid", fgColor="1F3864")
HEADER_FONT = Font(bold=True, color="FFFFFF")
HUMAN_FILL = PatternFill("solid", fgColor="DDEBF7")  # columnas que completa una persona
WRAP = Alignment(wrap_text=True, vertical="top")


def write_excel(report: Report, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    wb = Workbook()
    _summary(wb.active, report)
    _risks(wb.create_sheet("Matriz de riesgos"), report)
    _heatmap(wb.create_sheet("Mapa de calor"), report)
    for statement in report.statements:
        _statement(wb.create_sheet(statement.catalog.statement.sheet), statement)
    _remediation(wb.create_sheet("Plan de remediación"), report)
    _audit(wb.create_sheet("Hallazgos de auditoría"), report)
    if any(s.unmapped for s in report.statements):
        _unmapped(wb.create_sheet("Sin correspondencia"), report)
    if any(s.outside or s.unqualified for s in report.statements):
        _personal_data(wb.create_sheet("Revisión datos personales"), report)
    path = out_dir / FILENAME
    wb.save(path)
    return path


def _table(ws: Worksheet, headers: list[str], rows: list[list[object]], widths: list[int],
           human_columns: tuple[int, ...] = (), start_row: int = 1) -> None:
    """Escribe una tabla con encabezado fijo, filtro y columnas de decisión humana resaltadas."""
    for col, header in enumerate(headers, start=1):
        cell = ws.cell(row=start_row, column=col, value=header)
        cell.fill, cell.font, cell.alignment = HEADER_FILL, HEADER_FONT, WRAP
    for r, row in enumerate(rows, start=start_row + 1):
        for col, value in enumerate(row, start=1):
            cell = ws.cell(row=r, column=col, value=value)
            cell.alignment = WRAP
            if col in human_columns:
                cell.fill = HUMAN_FILL
    for col, width in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(col)].width = width
    ws.freeze_panes = ws.cell(row=start_row + 1, column=1)
    ws.auto_filter.ref = f"A{start_row}:{get_column_letter(len(headers))}{start_row + max(len(rows), 1)}"


def _paint_level(ws: Worksheet, column: int, levels: list[RiskLevel | None], start_row: int = 2) -> None:
    for offset, level in enumerate(levels):
        if level:
            ws.cell(row=start_row + offset, column=column).fill = LEVEL_FILL[level]


def _summary(ws: Worksheet, report: Report) -> None:
    ws.title = "Resumen"
    scan = report.scan
    counts, levels = report.status_counts, report.level_counts
    rows: list[tuple[str, object]] = [
        ("Escaneo", ", ".join(scan.scan_ids)),
        ("Escáner", f"{scan.scanner} {', '.join(scan.scanner_versions)}"),
        ("Cuentas", ", ".join(scan.account_uids)),
        ("Observado (UTC)", scan.last_observed_at.strftime("%Y-%m-%d %H:%M") if scan.last_observed_at else "-"),
        ("Metodología de riesgo", f"v{METHODOLOGY_VERSION}"),
        ("Completo", "Sí" if report.is_complete else f"NO: {len(report.parse_errors)} hallazgos no leídos"),
        ("", ""),
        ("Hallazgos en el archivo", report.total_in_file),
        ("FAIL / PASS / MANUAL", f"{counts['fail']} / {counts['pass']} / {counts['manual']}"),
        *[(f"Riesgos {LEVEL_LABEL[lvl]}", levels[lvl]) for lvl in reversed(RiskLevel)],
        ("Recursos sin clasificar (A.5.12)", len(report.classification_required)),
        ("Riesgos sin control mapeado", len(report.unmapped)),
    ]
    for r, (label, value) in enumerate(rows, start=1):
        ws.cell(row=r, column=1, value=label).font = Font(bold=True)
        ws.cell(row=r, column=2, value=value)
    ws.column_dimensions["A"].width = 34
    ws.column_dimensions["B"].width = 60
    if not report.is_complete:
        ws.cell(row=6, column=2).fill = LEVEL_FILL[RiskLevel.CRITICAL]


def _risks(ws: Worksheet, report: Report) -> None:
    rows = [[
        n, LEVEL_LABEL[a.level], a.score, a.probability, a.impact, f.check_id, f.check_title, f.resource_name,
        f.resource_type, f.region, a.classification or "-", ", ".join(f.compliance.get(PRIMARY_FRAMEWORK, [])),
        TREATMENT_LABEL[a.treatment], a.rationale, f.status_detail,
    ] for n, (f, a) in enumerate(((r.finding, r.assessment) for r in report.risks), start=1)]
    _table(ws, ["#", "Nivel", "Riesgo", "P", "I", "Check", "Hallazgo", "Recurso", "Tipo", "Región",
                "Clasificación", "ISO 27001", "Tratamiento sugerido", "Justificación", "Detalle del escáner"],
           rows, [5, 9, 7, 4, 4, 30, 40, 28, 20, 11, 13, 16, 22, 60, 50])
    _paint_level(ws, 2, [r.assessment.level for r in report.risks])


def _heatmap(ws: Worksheet, report: Report) -> None:
    ws.cell(row=1, column=1, value="Probabilidad \\ Impacto").font = Font(bold=True)
    for i in range(1, 6):
        ws.cell(row=1, column=i + 1, value=f"I{i}").font = Font(bold=True)
    for r, p in enumerate(range(5, 0, -1), start=2):
        ws.cell(row=r, column=1, value=f"P{p}").font = Font(bold=True)
        for i in range(1, 6):
            cell =ws.cell(row=r, column=i + 1, value=report.heatmap.get((p, i)) or None)
            cell.fill = LEVEL_FILL[level_for(p * i)[0]]
            cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[r].height = 30
    ws.column_dimensions["A"].width = 22
    ws.cell(row=8, column=1, value="Cada celda: cantidad de riesgos con esa probabilidad e impacto. "
                                   "El color es el nivel de la celda (P × I).")


def _statement(ws: Worksheet, statement: Statement) -> None:
    """La declaración de un marco. Las columnas de decisión humana van al final, resaltadas."""
    catalog, config = statement.catalog, statement.catalog.statement
    rows = [[
        r.requirement.id, catalog.group_label(r.requirement.group), r.requirement.title, r.status.value,
        r.pass_count, r.fail_count, r.manual_count, LEVEL_LABEL[r.max_level] if r.max_level else "-",
        ", ".join(r.check_ids), *r.human,
    ] for r in statement.rows]
    fixed = [config.id_label, config.group_label, "Título", "Estado técnico", "PASS", "FAIL", "MANUAL",
             "Riesgo máximo", "Checks"]
    human = tuple(range(len(fixed) + 1, len(fixed) + len(config.human_columns) + 1))
    widths = [9, 15, 42, 26, 7, 7, 9, 13, 50, *[12 if i == 0 else 50 for i in range(len(config.human_columns))]]
    _table(ws, [*fixed, *config.human_columns], rows, widths, human_columns=human)
    _paint_level(ws, 8, [r.max_level for r in statement.rows])


def _unmapped(ws: Worksheet, report: Report) -> None:
    """IDs de Prowler sin correspondencia en el catálogo de su marco (ADR 0007): se reportan, no se descartan."""
    rows = [[s.framework, u.raw_id, u.finding_count, ", ".join(u.check_ids)]
            for s in report.statements for u in s.unmapped]
    _table(ws, ["Marco", "ID de Prowler", "Hallazgos", "Checks"], rows, [16, 16, 10, 80])


def _personal_data(ws: Worksheet, report: Report) -> None:
    """Las revisiones de la regla de datos personales (ADR 0008). La evidencia la anota una persona."""
    rows = []
    for s in report.statements:
        rows += [[s.framework, "Fuera del país", r.name, r.type, r.region, r.country, note, ""]
                 for r, note in zip(s.outside, s.outside_notes(), strict=True)]
        rows += [[s.framework, "Sin calificar", r.name, r.type, r.region, r.country,
                  f"Decidir si trata datos personales y etiquetarlo ({s.catalog.personal_data.tag}=yes|no).", ""]
                 for r in s.unqualified if s.catalog.personal_data]
    _table(ws, ["Marco", "Revisión", "Recurso", "Tipo", "Región", "País", "Qué verificar", "Evidencia manual"],
           rows, [12, 15, 30, 20, 12, 18, 80, 50], human_columns=(8,))


def _remediation(ws: Worksheet, report: Report) -> None:
    rows = [[
        a.priority, LEVEL_LABEL[a.max_level], a.max_score, a.check_id, a.check_title, SEVERITY_LABEL[a.severity],
        len(a.resources), ", ".join(a.resources), ", ".join(a.controls), a.remediation, a.owner, a.due_date,
    ] for a in report.remediation]
    _table(ws, ["Prioridad", "Nivel", "Riesgo máx.", "Check", "Acción sobre", "Severidad", "Recursos",
                "Lista de recursos", "ISO 27001", "Cómo corregirlo", "Responsable", "Fecha compromiso"],
           rows, [9, 9, 9, 30, 40, 10, 9, 40, 16, 60, 18, 15], human_columns=(11, 12))
    _paint_level(ws, 2, [a.max_level for a in report.remediation])


def _audit(ws: Worksheet, report: Report) -> None:
    """Hallazgos en formato de auditoría. Las columnas de texto solo se llenan con redacciones aprobadas."""
    rows = []
    for a in report.remediation:
        entry = report.audit.get(a.check_id, AuditEntry())
        t = entry.text
        rows.append([
            a.priority, LEVEL_LABEL[a.max_level], a.max_score, a.check_id, entry.label,
            t.title if t else a.check_title, t.condition if t else "", t.criteria if t else "",
            t.cause if t else "", t.effect if t else "", t.recommendation if t else "",
            entry.reviewer, entry.reviewed_at, entry.model,
        ])
    _table(ws, ["Prioridad", "Nivel", "Riesgo", "Check", "Estado de la redacción", "Título", "Condición",
                "Criterio", "Causa", "Efecto", "Recomendación", "Aprobado por", "Fecha de aprobación", "Modelo"],
           rows, [9, 9, 7, 30, 22, 40, 50, 50, 45, 50, 60, 18, 20, 18])
    _paint_level(ws, 2, [a.max_level for a in report.remediation])
