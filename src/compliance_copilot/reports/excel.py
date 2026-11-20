"""Entregable en Excel: un libro con una hoja por entregable, filtros y colores por nivel de riesgo."""

from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from compliance_copilot.reports.builders import (
    LEVEL_LABEL,
    SEVERITY_LABEL,
    THEME_LABEL,
    TREATMENT_LABEL,
    Report,
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
    _soa(wb.create_sheet("SoA ISO 27001"), report)
    _remediation(wb.create_sheet("Plan de remediación"), report)
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
        f.resource_type, f.region, a.classification or "-", ", ".join(f.compliance.get("ISO27001-2022", [])),
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


def _soa(ws: Worksheet, report: Report) -> None:
    rows = [[
        r.control.id, THEME_LABEL[r.control.theme], r.control.title, r.status.value, r.pass_count, r.fail_count,
        r.manual_count, LEVEL_LABEL[r.max_level] if r.max_level else "-", ", ".join(r.check_ids),
        r.applicable, r.justification,
    ] for r in report.soa]
    _table(ws, ["Control", "Tema", "Título", "Estado técnico", "PASS", "FAIL", "MANUAL", "Riesgo máximo",
                "Checks", "Aplicable", "Justificación"],
           rows, [9, 15, 42, 26, 7, 7, 9, 13, 50, 12, 50], human_columns=(10, 11))
    _paint_level(ws, 8, [r.max_level for r in report.soa])


def _remediation(ws: Worksheet, report: Report) -> None:
    rows = [[
        a.priority, LEVEL_LABEL[a.max_level], a.max_score, a.check_id, a.check_title, SEVERITY_LABEL[a.severity],
        len(a.resources), ", ".join(a.resources), ", ".join(a.controls), a.remediation, a.owner, a.due_date,
    ] for a in report.remediation]
    _table(ws, ["Prioridad", "Nivel", "Riesgo máx.", "Check", "Acción sobre", "Severidad", "Recursos",
                "Lista de recursos", "ISO 27001", "Cómo corregirlo", "Responsable", "Fecha compromiso"],
           rows, [9, 9, 9, 30, 40, 10, 9, 40, 16, 60, 18, 15], human_columns=(11, 12))
    _paint_level(ws, 2, [a.max_level for a in report.remediation])
