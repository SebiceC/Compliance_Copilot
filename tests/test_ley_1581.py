"""Ley 1581: catálogo derivado de ISO 27001 y regla de datos personales (ADR 0008)."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from openpyxl import load_workbook
from pydantic import ValidationError

from compliance_copilot.__main__ import EXIT_OK, main
from compliance_copilot.catalogs import Catalog, load_catalog
from compliance_copilot.models import Finding, ScanMetadata
from compliance_copilot.parsers.prowler_ocsf import ParseResult, parse_ocsf_file
from compliance_copilot.personal_data import PersonalData, personal_data_scope, read_personal_data
from compliance_copilot.reports.builders import Report, Statement, StatementRow, TechnicalStatus, build_report
from compliance_copilot.reports.markdown import render_statement

from conftest import write_json

DOC = Path(__file__).resolve().parent.parent / "docs" / "correspondencia-ley-1581.md"
ACCOUNT = "123456789001"


@pytest.fixture(scope="module")
def ley() -> Catalog:
    return load_catalog("LEY-1581")


def finding(uid: str, *, rtype: str = "AwsS3Bucket", pd: str | None = None, status: str = "fail",
            controls: tuple[str, ...] = ("A.8.24",), region: str = "us-east-1", account: str = ACCOUNT,
            name: str | None = None, arn: str | None = None) -> Finding:
    tags = {"data-classification": "confidential"}
    if pd is not None:
        tags["personal-data"] = pd
    return Finding(
        finding_uid=uid, check_id=f"check_{uid}", check_title=uid, status=status, status_detail="",
        severity="high", observed_at=datetime(2026, 11, 17, tzinfo=timezone.utc), provider="aws",
        account_uid=account, region=region, resource_uid=arn or f"arn:{name or uid}", resource_name=name or uid,
        resource_type=rtype, tags=tags, compliance={"ISO27001-2022": list(controls)},
    )


def statement_for(findings: list[Finding]) -> Statement:
    return build_report_from(findings).statement("LEY-1581")


def build_report_from(findings: list[Finding]) -> Report:
    scan = ScanMetadata(scanner="prowler", scanner_versions=("5.48.0",), scan_ids=("s",), providers=("aws",),
                        account_uids=(ACCOUNT,), first_observed_at=None, last_observed_at=None)
    return build_report(ParseResult(source=Path("x.json"), scan=scan, total=len(findings), findings=findings,
                                    errors=[]))


def row(statement: Statement, obligation: str) -> StatementRow:
    return next(r for r in statement.rows if r.requirement.id == obligation)


# --- Catálogo ------------------------------------------------------------------------------------------------


def test_catalog_has_50_obligations_derived_from_iso(ley: Catalog) -> None:
    assert len(ley.requirements) == 50
    assert ley.derived_from == "ISO27001-2022"
    assert ley.source_framework == "ISO27001-2022"
    assert ley.statement.human_columns == ("Aplica", "Evidencia manual")


def test_twelve_obligations_are_technical(ley: Catalog) -> None:
    assert ley.personal_data is not None
    technical = {t for targets in ley.aliases.values() for t in targets} | set(ley.personal_data.outside_obligations)
    assert len(technical) == 12
    assert {"L1581-4f", "L1581-4g", "L1581-4h", "L1581-17d", "L1581-18b", "L1581-26"} <= technical


def test_security_duties_of_controller_and_processor_always_go_together(ley: Catalog) -> None:
    """Los arts. 17 d y 18 b tienen el mismo texto: la matriz no sabe si la organización es responsable o encargada."""
    for iso, targets in ley.aliases.items():
        assert ("L1581-17d" in targets) == ("L1581-18b" in targets), iso


def test_every_iso_control_in_the_sample_is_mapped_or_excluded(ley: Catalog, lab_sample_path: Path) -> None:
    iso = {c for f in parse_ocsf_file(lab_sample_path).findings for c in f.compliance.get("ISO27001-2022", [])}
    assert iso
    assert iso <= set(ley.aliases) | set(ley.excluded), sorted(iso - set(ley.aliases) - set(ley.excluded))


def test_document_matches_the_catalog(ley: Catalog) -> None:
    """El documento que revisó el responsable jurídico y lo que usa el código no pueden divergir."""
    text = DOC.read_text(encoding="utf-8")
    obligations, mapping, excluded = set(), {}, set()
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and re.fullmatch(r"`[^`]+`", cells[0]):
            obligations.add(cells[0].strip("`"))
        elif len(cells) == 4 and re.match(r"A\.\d", cells[0]):
            mapping[cells[0].split()[0]] = tuple(re.findall(r"`([^`]+)`", cells[1]))
        elif len(cells) == 2 and re.match(r"A\.\d", cells[0]):
            excluded.add(cells[0].split()[0])
    assert obligations == {r.id for r in ley.requirements}
    assert mapping == dict(ley.aliases)
    assert excluded == set(ley.excluded)


def test_flag_text_is_in_the_document(ley: Catalog) -> None:
    assert ley.personal_data is not None
    note = ley.personal_data.outside_note.format(resource="<recurso>", region="<región>", country="<país>")
    assert note in DOC.read_text(encoding="utf-8")


def catalog_data(**changes: Any) -> dict[str, Any]:
    data = json.loads(json.dumps(load_catalog("LEY-1581").model_dump(mode="json")))
    data.update(changes)
    return data


def test_excluded_and_mapped_at_the_same_time_is_rejected() -> None:
    with pytest.raises(ValidationError, match="excluidos que también"):
        Catalog.model_validate(catalog_data(excluded=["A.8.24"]))


def test_flag_must_point_to_existing_obligations() -> None:
    data = catalog_data()
    data["personal_data"]["outside_obligations"] = ["L1581-99"]
    with pytest.raises(ValidationError, match="señalamiento"):
        Catalog.model_validate(data)


def test_flag_text_only_accepts_known_fields() -> None:
    data = catalog_data()
    data["personal_data"]["outside_note"] = "Recurso {bucket}"
    with pytest.raises(ValidationError, match="outside_note"):
        Catalog.model_validate(data)


# --- Regla de datos personales (L4) ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        ({"personal-data": "yes"}, PersonalData.YES),
        ({"personal-data": " Yes "}, PersonalData.YES),
        ({"personal-data": "no"}, PersonalData.NO),
        ({"personal-data": "tal vez"}, PersonalData.INVALID),
        ({}, PersonalData.MISSING),
    ],
)
def test_read_personal_data(tags: dict[str, str], expected: PersonalData) -> None:
    assert read_personal_data(tags, "personal-data") is expected


def test_three_group_rule() -> None:
    findings = [
        finding("clientes", pd="yes"),
        finding("catalogo", pd="no"),
        finding("sin-tag"),
        finding("root", rtype="Other"),
        finding("ssh", rtype="AwsEc2SecurityGroup"),
    ]
    scope = personal_data_scope(findings, "personal-data")
    assert [f.finding_uid for f in scope.counted] == ["clientes", "root", "ssh"]
    assert [r.name for r in scope.unqualified] == ["sin-tag"]


@pytest.mark.parametrize(
    ("rtype", "name", "arn"),
    [  # configuraciones de la cuenta que Prowler 5.48 reporta con un tipo de datos (escaneo en CI, 2026-11-25)
        ("AwsEc2Volume", ACCOUNT, f"arn:aws:ec2:us-east-1:{ACCOUNT}:volume"),  # ec2_ebs_default_encryption
        ("AwsEc2Instance", ACCOUNT, f"arn:aws:ec2:us-east-1:{ACCOUNT}:account"),  # ec2_instance_account_imdsv2_enabled
        ("AwsBackupBackupVault", ACCOUNT, f"arn:aws:backup:us-east-1:{ACCOUNT}:backup-vault"),  # backup_vaults_exist
        ("AwsKmsKey", "enclave-debug-attestation", f"arn:aws:kms:us-east-1:{ACCOUNT}:enclave-debug-attestation"),
    ],
)
def test_account_settings_with_a_data_type_count_as_account(rtype: str, name: str, arn: str) -> None:
    findings = [finding("clientes", pd="yes"), finding("ajuste", rtype=rtype, name=name, arn=arn)]
    scope = personal_data_scope(findings, "personal-data")
    assert [f.finding_uid for f in scope.counted] == ["clientes", "ajuste"]
    assert scope.unqualified == ()


@pytest.mark.parametrize(
    ("rtype", "arn"),
    [  # recursos de datos reales: el ARN tiene ID de recurso, o es de S3 (sin cuenta)
        ("AwsEc2Volume", f"arn:aws:ec2:us-east-1:{ACCOUNT}:volume/vol-0abc"),
        ("AwsKmsKey", f"arn:aws:kms:us-east-1:{ACCOUNT}:key/1234abcd"),
        ("AwsRdsDbInstance", f"arn:aws:rds:us-east-1:{ACCOUNT}:db:clientes"),
        ("AwsS3Bucket", "arn:aws:s3:::clientes"),
    ],
)
def test_real_data_resources_without_tag_stay_unqualified(rtype: str, arn: str) -> None:
    scope = personal_data_scope([finding("r", rtype=rtype, name="r", arn=arn)], "personal-data")
    assert [r.uid for r in scope.unqualified] == [arn]


def test_account_findings_do_not_count_without_personal_data() -> None:
    """Sin ningún recurso con personal-data=yes en la cuenta, la ley no aplica a sus controles."""
    scope = personal_data_scope([finding("catalogo", pd="no"), finding("root", rtype="Other")], "personal-data")
    assert scope.counted == ()


def test_personal_data_in_another_account_does_not_count() -> None:
    findings = [finding("clientes", pd="yes"), finding("root", rtype="Other", account="999999999999")]
    assert [f.finding_uid for f in personal_data_scope(findings, "personal-data").counted] == ["clientes"]


def test_findings_from_iso_reach_the_obligations() -> None:
    s = statement_for([finding("clientes", pd="yes", controls=("A.8.24",))])
    for obligation in ("L1581-4g", "L1581-4h", "L1581-17d", "L1581-18b"):
        assert row(s, obligation).status is TechnicalStatus.GAPS
    assert row(s, "L1581-9").status is TechnicalStatus.MANUAL_EVIDENCE  # documental


def test_uncounted_findings_do_not_reach_the_matrix() -> None:
    s = statement_for([finding("catalogo", pd="no"), finding("sin-tag")])
    assert all(r.fail_count == 0 for r in s.rows)
    assert [r.name for r in s.unqualified] == ["sin-tag"]


def test_excluded_iso_controls_are_not_reported_as_unmapped() -> None:
    s = statement_for([finding("clientes", pd="yes", controls=("A.8.1", "A.5.7"))])
    assert [u.raw_id for u in s.unmapped] == ["A.5.7"]  # A.8.1 está excluido a propósito; A.5.7 no está decidido


# --- Circulación internacional (L5) ----------------------------------------------------------------------


def test_personal_data_outside_the_country_is_flagged(ley: Catalog) -> None:
    s = statement_for([finding("a", pd="yes", name="cc-lab-data-7asda3"),
                       finding("b", pd="yes", name="cc-lab-data-7asda3", status="pass")])
    assert [r.name for r in s.outside] == ["cc-lab-data-7asda3"]  # un señalamiento por recurso, no por hallazgo
    assert s.outside_notes() == (
        "Recurso con datos personales fuera de Colombia: `cc-lab-data-7asda3` · región `us-east-1` (EE. UU.). "
        "Verificar: si el proveedor actúa como encargado, que exista un contrato de transmisión conforme al art. 25 "
        "del Decreto 1377 de 2013; si se trata de una transferencia, el fundamento del art. 26 de la Ley 1581.",
    )
    assert ley.personal_data is not None
    for obligation in ley.personal_data.outside_obligations:
        assert row(s, obligation).status is TechnicalStatus.REVIEW


def test_a_resource_reported_with_two_types_is_flagged_once() -> None:
    """Prowler 5.48 reporta lab-trail como AwsCloudTrailTrail y, en un check, como AwsS3Bucket (mismo ARN)."""
    arn = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/lab-trail"
    findings = [finding("a", pd="yes", rtype="AwsCloudTrailTrail", name="lab-trail", arn=arn),
                finding("b", pd="yes", rtype="AwsS3Bucket", name="lab-trail", arn=arn)]
    assert [r.uid for r in personal_data_scope(findings, "personal-data").outside] == [arn]


def test_local_regions_are_not_flagged() -> None:
    scope = personal_data_scope([finding("a", pd="yes", region="co-bogota-1")], "personal-data", ["co-bogota-1"])
    assert scope.outside == ()


def test_no_flag_without_personal_data() -> None:
    s = statement_for([finding("catalogo", pd="no")])
    assert s.outside == ()
    assert row(s, "L1581-26").status is TechnicalStatus.MANUAL_EVIDENCE


def test_unknown_region_has_no_country() -> None:
    scope = personal_data_scope([finding("a", pd="yes", region="xx-nowhere-1")], "personal-data")
    assert scope.outside[0].country == "país por confirmar"


# --- Entregables -------------------------------------------------------------------------------------------


def test_matrix_shows_both_reviews() -> None:
    report = build_report_from([finding("clientes", pd="yes"), finding("sin-tag")])
    text = render_statement(report, report.statement("LEY-1581"))
    assert "## Datos personales fuera del país (1)" in text
    assert "## Requiere revisión: recursos de datos sin calificar (1)" in text
    assert "fuera de Colombia: `clientes`" in text


def test_report_writes_the_review_sheet_and_evidence(tmp_path: Path, lab_sample_raw: list[Any]) -> None:
    raw = json.loads(json.dumps(lab_sample_raw))
    for x in raw:  # etiquetar un bucket de la muestra como un recurso con datos personales
        for resource in x["resources"]:
            if resource.get("name") == "cc-lab-data-7asda3":
                resource.setdefault("labels", [])
                resource["labels"].append("personal-data:yes")
    source = write_json(tmp_path / "scan.json", raw)
    out = tmp_path / "out"
    assert main(["report", str(source), "-o", str(out)]) == EXIT_OK

    evidence = json.loads((out / "evidencias/controles/LEY-1581/_datos-personales.json").read_text(encoding="utf-8"))
    assert [r["resource_name"] for r in evidence["outside"]] == ["cc-lab-data-7asda3"]
    assert "cc-lab-data-7asda3" not in {r["resource_name"] for r in evidence["unqualified"]}
    sheet = load_workbook(out / "compliance-copilot.xlsx")["Revisión datos personales"]
    assert [c.value for c in sheet[1]][-1] == "Evidencia manual"
