"""Tests del anonimizador.

Usan valores inventados que tienen la forma de datos reales (no los de ninguna cuenta real), para poder
comprobar que desaparecen.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest

from compliance_copilot.parsers.prowler_ocsf import parse_ocsf_file
from compliance_copilot.sanitize import ACCOUNT_NAME_PSEUDONYM, main, sanitize_findings

from conftest import write_json

ACCOUNT = "111122223333"
OTHER_ACCOUNT = "444455556666"
ORG = "o-abcdefghij"
CANONICAL = "ab" * 32
SSO_ROLE = "AWSReservedSSO_LabAdmin_0123456789abcdef"


def fake_finding(**overrides: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "cloud": {"account": {"name": "AcmeCorp", "uid": ACCOUNT}, "org": {"uid": ORG}},
        "resources": [
            {
                "uid": f"arn:aws:s3:::aws-cloudtrail-logs-{ACCOUNT}-abc",
                "labels": ["project:compliance-copilot"],
                "data": {
                    "owner": CANONICAL,
                    "principal": f"arn:aws:iam::{ACCOUNT}:role/{SSO_ROLE}",
                    "user": "acmecorp-admin",
                    "contact": "ana@acme.example",
                    "public_ip": "8.8.8.8",
                    "private_cidr": "172.31.0.0/16",
                    "open_cidr": "0.0.0.0/0",
                },
            }
        ],
        "unmapped": {"compliance": {"CIS-2.0": ["3.5.1.2"]}},
        "message": f"Trail in account {ACCOUNT} of AcmeCorp",
    }
    finding.update(overrides)
    return finding


def test_real_values_disappear() -> None:
    sanitized, sanitizer = sanitize_findings([fake_finding()])
    text = json.dumps(sanitized)
    for real in (ACCOUNT, ORG, CANONICAL, "0123456789abcdef", "acmecorp", "ana@acme.example", "8.8.8.8"):
        assert real not in text.lower(), real
    assert sanitizer.leaks(text) == set()


def test_pseudonyms_are_consistent() -> None:
    """El mismo valor real recibe el mismo seudónimo: se conservan las relaciones entre hallazgos."""
    sanitized, _ = sanitize_findings([fake_finding(), fake_finding()])
    first, second = sanitized
    assert first["cloud"]["account"]["uid"] == second["cloud"]["account"]["uid"]
    assert first["cloud"]["account"]["uid"] in first["resources"][0]["uid"]


def test_different_accounts_get_different_pseudonyms() -> None:
    other = fake_finding()
    other["cloud"]["account"]["uid"] = OTHER_ACCOUNT
    sanitized, _ = sanitize_findings([fake_finding(), other])
    assert sanitized[0]["cloud"]["account"]["uid"] != sanitized[1]["cloud"]["account"]["uid"]


def test_pseudonyms_keep_a_realistic_format() -> None:
    sanitized, _ = sanitize_findings([fake_finding()])
    assert re.fullmatch(r"\d{12}", sanitized[0]["cloud"]["account"]["uid"])
    assert re.fullmatch(r"o-[a-z0-9]{10,32}", sanitized[0]["cloud"]["org"]["uid"])
    assert re.fullmatch(r"[0-9a-f]{64}", sanitized[0]["resources"][0]["data"]["owner"])


def test_account_name_is_replaced_in_any_case() -> None:
    """El nombre de la cuenta también aparece como nombre de usuario, con otras mayúsculas."""
    sanitized, _ = sanitize_findings([fake_finding()])
    assert sanitized[0]["cloud"]["account"]["name"] == ACCOUNT_NAME_PSEUDONYM
    assert sanitized[0]["resources"][0]["data"]["user"] == f"{ACCOUNT_NAME_PSEUDONYM}-admin"


def test_sso_role_keeps_permission_set_name() -> None:
    """El nombre del permission set es diseño, no dato de la cuenta: se conserva."""
    sanitized, _ = sanitize_findings([fake_finding()])
    assert "AWSReservedSSO_LabAdmin_" in sanitized[0]["resources"][0]["data"]["principal"]


def test_evidence_and_control_ids_are_not_touched() -> None:
    """0.0.0.0/0 es la evidencia del hallazgo; 3.5.1.2 es un control de CIS, no una IP."""
    data = sanitize_findings([fake_finding()])[0][0]
    assert data["resources"][0]["data"]["open_cidr"] == "0.0.0.0/0"
    assert data["resources"][0]["data"]["private_cidr"] == "172.31.0.0/16"
    assert data["unmapped"]["compliance"]["CIS-2.0"] == ["3.5.1.2"]


def test_public_ip_uses_documentation_range() -> None:
    data = sanitize_findings([fake_finding()])[0][0]
    assert data["resources"][0]["data"]["public_ip"].startswith("203.0.113.")


def test_original_is_not_modified() -> None:
    original = fake_finding()
    sanitize_findings([original])
    assert original["cloud"]["account"]["uid"] == ACCOUNT


# --- CLI ------------------------------------------------------------------------------------------------


def test_cli_writes_sanitized_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = write_json(tmp_path / "in.ocsf.json", [fake_finding(), fake_finding(resources=[{"labels": []}])])
    target = tmp_path / "out" / "sample.ocsf.json"

    assert main([str(source), str(target), "--only-label", "project:compliance-copilot"]) == 0
    written = target.read_text(encoding="utf-8")
    assert ACCOUNT not in written
    assert len(json.loads(written)) == 1  # el filtro dejó solo el hallazgo con el label
    assert "1 hallazgos anonimizados" in capsys.readouterr().out


def test_cli_rejects_file_that_is_not_a_list(tmp_path: Path) -> None:
    source = write_json(tmp_path / "in.ocsf.json", {"findings": []})
    assert main([str(source), str(tmp_path / "out.json")]) == 2
    assert not (tmp_path / "out.json").exists()


# --- La muestra versionada -------------------------------------------------------------------------------


def test_committed_sample_has_only_pseudonymous_accounts(lab_sample_path: Path) -> None:
    """Protección contra subir una muestra sin anonimizar: solo puede haber IDs de cuenta seudónimos."""
    text = lab_sample_path.read_text(encoding="utf-8")
    accounts = set(re.findall(r"(?<!\d)\d{12}(?!\d)", text))
    assert accounts and all(a.startswith("123456789") for a in accounts), accounts


def test_sanitized_sample_is_still_parseable(lab_sample_path: Path) -> None:
    """Anonimizar no rompe el formato: el parser lee la muestra completa."""
    assert parse_ocsf_file(lab_sample_path).is_complete
