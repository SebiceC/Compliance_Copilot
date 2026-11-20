"""Tests del parser OCSF de Prowler, con la muestra anonimizada del laboratorio."""

import copy
import logging
from datetime import timezone
from pathlib import Path
from typing import Any

import pytest

from compliance_copilot.models import Status
from compliance_copilot.parsers.prowler_ocsf import FRAMEWORKS, _parse_labels, parse_ocsf_file

from conftest import write_json

# Las cuatro debilidades diseñadas del laboratorio (docs/laboratorio.md) y su clasificación.
DESIGNED_FAILS = {
    ("iam_user_mfa_enabled_console_access", "lab-user-nomfa", "internal"),
    ("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "lab-sg-ssh-open", "public"),
    ("s3_bucket_object_versioning", "cc-lab-data-7asda3", "confidential"),
    ("cloudtrail_log_file_validation_enabled", "lab-trail", "restricted"),
}


# --- La muestra del laboratorio ------------------------------------------------------------------------


def test_sample_is_read_completely(lab_sample_path: Path) -> None:
    """Ningún hallazgo se pierde: los 76 de la muestra se convierten."""
    result = parse_ocsf_file(lab_sample_path)
    assert result.total == 76
    assert len(result.findings) == 76
    assert result.is_complete


def test_status_counts_match_the_scan(lab_sample_path: Path) -> None:
    """El parser no inventa ni cambia resultados: 29 FAIL y 47 PASS, como en la salida de Prowler."""
    findings = parse_ocsf_file(lab_sample_path).findings
    assert sum(f.status is Status.FAIL for f in findings) == 29
    assert sum(f.status is Status.PASS for f in findings) == 47


@pytest.mark.parametrize(("check_id", "resource", "classification"), sorted(DESIGNED_FAILS))
def test_designed_weaknesses_are_detected(
    lab_sample_path: Path, check_id: str, resource: str, classification: str
) -> None:
    """Las cuatro debilidades del laboratorio llegan como FAIL y con su data-classification."""
    findings = parse_ocsf_file(lab_sample_path).findings
    matches = [
        f for f in findings
        if f.check_id == check_id and f.status is Status.FAIL
        # En los security groups, Prowler usa el ID como nombre; el nombre legible está en el detalle.
        and resource in (f.resource_name + f.status_detail)
    ]
    assert matches, f"no se encontró el FAIL de {check_id} sobre {resource}"
    assert matches[0].tags["data-classification"] == classification


def test_observed_at_is_utc(lab_sample_path: Path) -> None:
    """Se usa el epoch, no created_time_dt (hora local sin zona)."""
    finding = parse_ocsf_file(lab_sample_path).findings[0]
    assert finding.observed_at.tzinfo is not None
    assert finding.observed_at.utcoffset() == timezone.utc.utcoffset(None)


def test_compliance_keeps_only_project_frameworks(lab_sample_path: Path) -> None:
    findings = parse_ocsf_file(lab_sample_path).findings
    used = {framework for f in findings for framework in f.compliance}
    assert used <= set(FRAMEWORKS)
    assert "ISO27001-2022" in used


def test_lab_trail_maps_to_logging_controls(lab_sample_path: Path) -> None:
    """La validación de logs de CloudTrail corresponde a los controles de registro de ISO 27001:2022."""
    finding = next(
        f for f in parse_ocsf_file(lab_sample_path).findings
        if f.check_id == "cloudtrail_log_file_validation_enabled"
    )
    assert "A.8.15" in finding.compliance["ISO27001-2022"]


# --- Labels ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("labels", "expected"),
    [
        (["data-classification:restricted"], {"data-classification": "restricted"}),
        (["url:https://example.com:8443"], {"url": "https://example.com:8443"}),  # corta solo en el primer ':'
        (["sin-valor"], {"sin-valor": ""}),  # un tag sin valor se conserva
        ([":huérfano", "  "], {}),  # sin clave no hay tag
        ([], {}),
    ],
)
def test_parse_labels(labels: list[str], expected: dict[str, str]) -> None:
    assert _parse_labels(labels) == expected


# --- Hallazgos rotos: se reportan, no se pierden (ADR 0003) ------------------------------------------------


def test_broken_findings_are_reported_not_dropped(
    tmp_path: Path, raw_finding: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    bad_status = copy.deepcopy(raw_finding)
    bad_status["status_code"] = "WEIRD"
    no_uid = copy.deepcopy(raw_finding)
    del no_uid["finding_info"]["uid"]
    no_resource = copy.deepcopy(raw_finding)
    no_resource["resources"] = []

    path = write_json(tmp_path / "broken.ocsf.json", [raw_finding, bad_status, no_uid, no_resource])
    with caplog.at_level(logging.WARNING):
        result = parse_ocsf_file(path)

    assert result.total == 4
    assert len(result.findings) == 1
    assert not result.is_complete
    assert [e.index for e in result.errors] == [1, 2, 3]

    by_index = {e.index: e for e in result.errors}
    assert "status" in by_index[1].reason
    assert by_index[2].finding_uid is None and "uid" in by_index[2].reason
    assert by_index[2].check_id == raw_finding["metadata"]["event_code"]  # aún se puede ubicar
    assert "1 recurso" in by_index[3].reason

    assert "3 de 4 hallazgos con errores" in caplog.text


def test_finding_with_two_resources_is_reported(tmp_path: Path, raw_finding: dict[str, Any]) -> None:
    two = copy.deepcopy(raw_finding)
    two["resources"] = two["resources"] * 2
    result = parse_ocsf_file(write_json(tmp_path / "two.ocsf.json", [two]))
    assert "llegaron 2" in result.errors[0].reason


def test_non_dict_item_is_reported(tmp_path: Path) -> None:
    result = parse_ocsf_file(write_json(tmp_path / "weird.ocsf.json", ["no soy un hallazgo"]))
    assert len(result.errors) == 1
    assert result.errors[0].finding_uid is None


def test_file_that_is_not_a_list_fails(tmp_path: Path) -> None:
    """Si el archivo entero está mal, no hay evidencia parcial que rescatar: se lanza un error."""
    with pytest.raises(ValueError, match="lista"):
        parse_ocsf_file(write_json(tmp_path / "dict.ocsf.json", {"findings": []}))


def test_empty_file_is_complete(tmp_path: Path) -> None:
    result = parse_ocsf_file(write_json(tmp_path / "empty.ocsf.json", []))
    assert result.total == 0 and result.is_complete
