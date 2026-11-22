"""Test de regresión de los entregables (ADR 0007, decisión D4).

Compara la salida completa de ``report`` sobre la muestra anonimizada del laboratorio con una referencia
guardada en ``tests/golden/``: los Markdown, las evidencias y el contenido del Excel (valores, colores, filtros y
paneles fijos). Un refactor no debe cambiar ningún entregable; si cambia, el test muestra exactamente qué.

Cuando un cambio **debe** alterar la salida (p. ej. una metodología nueva), se regenera la referencia a propósito
y el diff del PR muestra el cambio en los entregables:

    $env:UPDATE_GOLDEN = "1"; pytest tests/test_golden.py; Remove-Item Env:UPDATE_GOLDEN

La referencia sale de la muestra anonimizada (ya versionada): nunca de un escaneo real.
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest
from openpyxl import load_workbook

from compliance_copilot.__main__ import EXIT_OK, main

from conftest import LAB_SAMPLE

GOLDEN = Path(__file__).resolve().parent / "golden"
UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"
# El manifest tiene la fecha de generación y los hashes cambian con ella: se compara su estructura aparte.
EXCLUDED = {"manifest.json", "compliance-copilot.xlsx"}


def excel_snapshot(path: Path) -> dict[str, Any]:
    """El contenido del libro sin los metadatos que cambian en cada guardado."""
    wb = load_workbook(path)
    sheets = {}
    for ws in wb.worksheets:
        sheets[ws.title] = {
            "freeze_panes": ws.freeze_panes,
            "auto_filter": ws.auto_filter.ref,
            "widths": {k: v.width for k, v in sorted(ws.column_dimensions.items()) if v.width},
            "rows": [
                [{"v": c.value, "fill": c.fill.fgColor.rgb if c.fill.fill_type else None} for c in row]
                for row in ws.iter_rows()
            ],
        }
    return {"sheets": list(sheets), "content": sheets}


def snapshot(out: Path) -> dict[str, str]:
    """Archivo relativo -> contenido de texto (el Excel como JSON)."""
    files = {
        p.relative_to(out).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(out.rglob("*")) if p.is_file() and p.name not in EXCLUDED
    }
    files["compliance-copilot.xlsx.json"] = json.dumps(
        excel_snapshot(out / "compliance-copilot.xlsx"), ensure_ascii=False, indent=1, default=str) + "\n"
    return files


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("golden") / "reporte"
    assert main(["report", str(LAB_SAMPLE), "-o", str(out)]) == EXIT_OK
    return out


def test_deliverables_match_golden(generated: Path) -> None:
    current = snapshot(generated)
    if UPDATE:
        for old in GOLDEN.rglob("*"):
            if old.is_file():
                old.unlink()
        for rel, text in current.items():
            target = GOLDEN / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
        pytest.skip("referencia regenerada: revisa el diff antes de hacer commit")

    expected = {p.relative_to(GOLDEN).as_posix(): p.read_text(encoding="utf-8")
                for p in sorted(GOLDEN.rglob("*")) if p.is_file()}
    assert expected, "no hay referencia: genérala con UPDATE_GOLDEN=1"
    assert sorted(current) == sorted(expected), "cambió la lista de archivos generados"
    for rel in expected:
        assert current[rel] == expected[rel], f"cambió {rel}"


def test_manifest_structure_matches_golden(generated: Path) -> None:
    """El manifest cambia en cada ejecución (fecha y hashes), pero no su lista de archivos ni su origen."""
    manifest = json.loads((generated / "manifest.json").read_text(encoding="utf-8"))
    paths = sorted(f["path"] for f in manifest["files"])
    golden_paths = sorted([*(rel for rel in (p.relative_to(GOLDEN).as_posix() for p in GOLDEN.rglob("*") if p.is_file())
                             if rel != "compliance-copilot.xlsx.json"), "compliance-copilot.xlsx"])
    assert paths == golden_paths
    assert manifest["source"]["complete"] is True
