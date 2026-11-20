"""Tests de los entregables: reglas de la SoA y del plan, salidas Markdown/Excel, evidencias y CLI."""

import copy
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from openpyxl import load_workbook

from compliance_copilot.__main__ import EXIT_INCOMPLETE, EXIT_OK, EXIT_VERIFY_FAILED, main
from compliance_copilot.catalogs import Catalog
from compliance_copilot.models import Finding
from compliance_copilot.parsers.prowler_ocsf import parse_ocsf_file
from compliance_copilot.reports.builders import (
    Report,
    TechnicalStatus,
    _technical_status,
    build_remediation,
    build_report,
)
from compliance_copilot.reports.evidence import MANIFEST, verify_manifest
from compliance_copilot.risk import RiskLevel, assess_all

from conftest import write_json


@pytest.fixture(scope="module")
def report() -> Report:
    from conftest import LAB_SAMPLE

    return build_report(parse_ocsf_file(LAB_SAMPLE))


def finding(uid: str, check: str, status: str, resource: str, controls: list[str], severity: str = "medium") -> Finding:
    return Finding(
        finding_uid=uid, check_id=check, check_title=check, status=status, status_detail="", severity=severity,
        observed_at=datetime(2026, 11, 17, tzinfo=timezone.utc), provider="aws", account_uid="123456789001",
        region="us-east-1", resource_uid=f"arn:{resource}", resource_name=resource, resource_type="AwsS3Bucket",
        tags={"data-classification": "internal"}, compliance={"ISO27001-2022": controls},
    )


# --- SoA -------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ({"fail": 1, "pass": 40}, TechnicalStatus.GAPS),  # un solo FAIL basta para "con brechas"
        ({"manual": 1, "pass": 3}, TechnicalStatus.REVIEW),  # un MANUAL sin FAIL no se puede dar por bueno
        ({"pass": 2}, TechnicalStatus.NO_GAPS),
        ({}, TechnicalStatus.MANUAL_EVIDENCE),
    ],
)
def test_technical_status_rules(statuses: dict[str, int], expected: TechnicalStatus) -> None:
    assert _technical_status(Counter(statuses)) is expected


def test_soa_lists_every_catalog_control(report: Report) -> None:
    """Los 93 controles, en orden, aunque el escaneo solo toque algunos (ISO 27001, 6.1.3 d)."""
    assert len(report.soa) == 93
    assert [r.control.id for r in report.soa][:3] == ["A.5.1", "A.5.2", "A.5.3"]


def test_people_and_physical_controls_require_manual_evidence(report: Report) -> None:
    for row in report.soa:
        if row.control.id.startswith(("A.6.", "A.7.")):
            assert row.status is TechnicalStatus.MANUAL_EVIDENCE, row.control.id


def test_soa_leaves_human_decisions_empty(report: Report) -> None:
    """Aplicabilidad y justificación las decide la organización, nunca la herramienta."""
    assert all(r.applicable == "" and r.justification == "" for r in report.soa)


def test_soa_counts_and_max_risk(report: Report) -> None:
    logging_control = next(r for r in report.soa if r.control.id == "A.8.15")
    assert logging_control.status is TechnicalStatus.GAPS
    assert logging_control.fail_count >= 1
    assert logging_control.max_level is RiskLevel.HIGH  # lab-trail: 15
    assert "cloudtrail_log_file_validation_enabled" in logging_control.check_ids


# --- Matriz y plan ------------------------------------------------------------------------------------------------


def test_risks_are_sorted_by_score(report: Report) -> None:
    scores = [r.assessment.score for r in report.risks]
    assert scores == sorted(scores, reverse=True)
    assert len(report.risks) == 29  # solo los FAIL de la muestra


def test_heatmap_adds_up_to_number_of_risks(report: Report) -> None:
    assert sum(report.heatmap.values()) == len(report.risks)


def test_remediation_groups_by_check() -> None:
    """Un mismo check en dos recursos es una sola acción, con el riesgo más alto del grupo."""
    findings = [
        finding("1", "s3_bucket_object_versioning", "fail", "bucket-a", ["A.8.13"]),
        finding("2", "s3_bucket_object_versioning", "fail", "bucket-b", ["A.8.13"], severity="high"),
        finding("3", "other_check", "fail", "bucket-a", ["A.8.15"], severity="low"),
    ]
    by_uid = {f.finding_uid: f for f in findings}
    from compliance_copilot.reports.builders import RiskRow

    risks = tuple(sorted((RiskRow(by_uid[a.finding_uid], a) for a in assess_all(findings)),
                         key=lambda r: -r.assessment.score))
    actions = build_remediation(risks)

    assert [a.check_id for a in actions] == ["s3_bucket_object_versioning", "other_check"]
    assert actions[0].resources == ("bucket-a", "bucket-b")
    assert actions[0].max_score == 8  # high (4) × internal (2)
    assert [a.priority for a in actions] == [1, 2]
    assert actions[0].owner == "" and actions[0].due_date == ""


# --- Salidas ------------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from conftest import LAB_SAMPLE

    out = tmp_path_factory.mktemp("reports")
    assert main(["report", str(LAB_SAMPLE), "-o", str(out)]) == EXIT_OK
    return out


def test_all_deliverables_are_generated(generated: Path) -> None:
    for name in ["resumen.md", "matriz-riesgos.md", "soa-iso27001.md", "plan-remediacion.md",
                 "compliance-copilot.xlsx", MANIFEST, "evidencias/hallazgos.json"]:
        assert (generated / name).exists(), name


def test_markdown_tables_are_well_formed(generated: Path) -> None:
    """Cada fila de tabla tiene tantas columnas como el encabezado (un '|' sin escapar las rompería)."""
    for path in generated.glob("*.md"):
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if line.startswith("|---"):
                expected = lines[i - 1].replace("\\|", "").count("|")
                for row in lines[i + 1:]:
                    if not row.startswith("|"):
                        break
                    assert row.replace("\\|", "").count("|") == expected, (path.name, row[:60])


def test_excel_has_one_sheet_per_deliverable(generated: Path) -> None:
    wb = load_workbook(generated / "compliance-copilot.xlsx")
    assert wb.sheetnames == ["Resumen", "Matriz de riesgos", "Mapa de calor", "SoA ISO 27001", "Plan de remediación"]
    assert wb["SoA ISO 27001"].max_row == 94  # encabezado + 93 controles
    assert wb["Matriz de riesgos"].max_row == 30  # encabezado + 29 riesgos
    assert wb["Matriz de riesgos"].auto_filter.ref


def test_evidence_per_control(generated: Path) -> None:
    evidence = json.loads((generated / "evidencias/controles/ISO27001-2022/A.8.15.json").read_text(encoding="utf-8"))
    assert evidence["control"] == "A.8.15"
    assert evidence["counts"]["fail"] == sum(e["status"] == "fail" for e in evidence["evidence"])
    assert all(e["observed_at"].endswith("+00:00") for e in evidence["evidence"])


def test_manifest_hashes_every_file(generated: Path) -> None:
    manifest = json.loads((generated / MANIFEST).read_text(encoding="utf-8"))
    listed = {f["path"] for f in manifest["files"]}
    on_disk = {p.relative_to(generated).as_posix() for p in generated.rglob("*") if p.is_file()} - {MANIFEST}
    assert listed == on_disk
    assert manifest["methodology_version"] == "0.2"
    assert manifest["source"]["complete"] is True


def test_verify_detects_tampering(tmp_path: Path, lab_sample_path: Path) -> None:
    """Cadena de custodia: si alguien edita un entregable, la verificación falla."""
    out = tmp_path / "out"
    main(["report", str(lab_sample_path), "-o", str(out)])
    assert verify_manifest(out / MANIFEST, lab_sample_path) == []

    soa = out / "soa-iso27001.md"
    soa.write_text(soa.read_text(encoding="utf-8").replace("Con brechas", "Sin brechas detectadas"), encoding="utf-8")
    assert verify_manifest(out / MANIFEST) == ["modificado soa-iso27001.md"]
    assert main(["verify", str(out / MANIFEST)]) == EXIT_VERIFY_FAILED


def test_verify_detects_a_different_source(tmp_path: Path, lab_sample_path: Path, lab_sample_raw: list[Any]) -> None:
    out = tmp_path / "out"
    main(["report", str(lab_sample_path), "-o", str(out)])
    other = write_json(tmp_path / "other.ocsf.json", lab_sample_raw[:10])
    assert any("origen" in p for p in verify_manifest(out / MANIFEST, other))


def test_incomplete_scan_is_flagged_everywhere(tmp_path: Path, raw_finding: dict[str, Any]) -> None:
    """ADR 0003: si se perdió un hallazgo, los entregables lo dicen y el comando no termina en 0."""
    broken = copy.deepcopy(raw_finding)
    broken["status_code"] = "WEIRD"
    scan = write_json(tmp_path / "scan.ocsf.json", [raw_finding, broken])
    out = tmp_path / "out"

    assert main(["report", str(scan), "-o", str(out)]) == EXIT_INCOMPLETE
    assert "Entregable incompleto" in (out / "soa-iso27001.md").read_text(encoding="utf-8")
    manifest = json.loads((out / MANIFEST).read_text(encoding="utf-8"))
    assert manifest["source"]["complete"] is False
    assert manifest["source"]["parse_errors"][0]["index"] == 1


def test_custom_catalog_is_used(lab_sample_path: Path) -> None:
    tiny = Catalog(framework="ISO27001-2022", name="x", source="x",
                   controls=[{"id": "A.8.15", "theme": "technological", "title": "Registro de eventos"}])
    result = build_report(parse_ocsf_file(lab_sample_path), tiny)
    assert [r.control.id for r in result.soa] == ["A.8.15"]


def test_sanitize_is_available_from_main_cli(tmp_path: Path, lab_sample_path: Path) -> None:
    out = tmp_path / "s.ocsf.json"
    assert main(["sanitize", str(lab_sample_path), str(out)]) == 0
    assert out.exists()
