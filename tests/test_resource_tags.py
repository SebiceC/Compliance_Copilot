"""Tags de recursos desde un archivo aparte: Prowler 5.48 no exporta los de Azure (parsers/resource_tags.py)."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from compliance_copilot.__main__ import EXIT_OK, main
from compliance_copilot.parsers.prowler_ocsf import parse_ocsf_file
from compliance_copilot.parsers.resource_tags import apply_resource_tags, load_resource_tags

from conftest import write_json

SUB = "00000000-0000-0000-0000-000000000001"
BOM = "\N{BYTE ORDER MARK}"  # lo escribe Out-File -Encoding utf8 de Windows PowerShell
STORAGE = f"/subscriptions/{SUB}/resourceGroups/rg-cc-lab/providers/Microsoft.Storage/storageAccounts/cclabdata"
VAULT = f"/subscriptions/{SUB}/resourceGroups/rg-cc-lab/providers/Microsoft.KeyVault/vaults/cc-lab-kv"


def azure_finding(raw_finding: dict[str, Any], uid: str, resource_uid: str, labels: list[str]) -> dict[str, Any]:
    raw = copy.deepcopy(raw_finding)
    raw["finding_info"]["uid"] = uid
    raw["cloud"]["provider"] = "azure"
    raw["cloud"]["account"]["uid"] = SUB
    raw["resources"][0].update(uid=resource_uid, name=resource_uid.rsplit("/", 1)[-1], region="eastus",
                               type="microsoft.storage/storageaccounts", labels=labels)
    return raw


@pytest.fixture
def scan(tmp_path: Path, raw_finding: dict[str, Any]) -> Path:
    return write_json(tmp_path / "azure.ocsf.json", [
        azure_finding(raw_finding, "sin-tags", STORAGE, []),
        azure_finding(raw_finding, "con-tags", VAULT, ["data-classification:internal"]),
    ])


@pytest.fixture
def tags_file(tmp_path: Path) -> Path:
    # Como lo escribe az: IDs con otras mayúsculas, null para un recurso sin tags, y el BOM de Out-File.
    data = [
        {"id": STORAGE.replace("resourceGroups", "resourcegroups"),
         "tags": {"data-classification": "confidential", "personal-data": "yes"}},
        {"id": VAULT, "tags": {"data-classification": "restricted"}},
        {"id": f"/subscriptions/{SUB}/resourceGroups/rg-cc-lab/providers/Microsoft.Network/networkSecurityGroups/n",
         "tags": None},
    ]
    path = tmp_path / "azure-tags.json"
    path.write_text(BOM + json.dumps(data), encoding="utf-8")
    return path


def test_tags_complete_findings_without_tags(scan: Path, tags_file: Path) -> None:
    parsed = apply_resource_tags(parse_ocsf_file(scan), load_resource_tags(tags_file))
    tags = {f.finding_uid: f.tags for f in parsed.findings}
    # El ID del archivo trae otras mayúsculas: en Azure es el mismo recurso.
    assert tags["sin-tags"] == {"data-classification": "confidential", "personal-data": "yes"}
    assert parsed.findings_tagged == 1
    assert parsed.resource_tags == tags_file


def test_scan_tags_win_over_the_file(scan: Path, tags_file: Path) -> None:
    """Cuando Prowler exporte los tags de Azure, el archivo deja de tener efecto."""
    parsed = apply_resource_tags(parse_ocsf_file(scan), load_resource_tags(tags_file))
    assert {f.finding_uid: f.tags for f in parsed.findings}["con-tags"] == {"data-classification": "internal"}


@pytest.mark.parametrize("data", [{"id": "x"}, [{"tags": {}}], [{"id": " "}], [{"id": "x", "tags": ["a"]}]])
def test_malformed_tags_file_stops_everything(tmp_path: Path, data: Any) -> None:
    with pytest.raises(ValueError):
        load_resource_tags(write_json(tmp_path / "tags.json", data))


def test_manifest_records_the_tags_file(scan: Path, tags_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "reporte"
    assert main(["report", str(scan), "-o", str(out), "--resource-tags", str(tags_file)]) == EXIT_OK
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["resource_tags"]["file"] == "azure-tags.json"
    assert manifest["resource_tags"]["findings_tagged"] == 1
    assert len(manifest["resource_tags"]["sha256"]) == 64


def test_without_tags_file_the_manifest_has_no_entry(scan: Path, tmp_path: Path) -> None:
    out = tmp_path / "reporte"
    assert main(["report", str(scan), "-o", str(out)]) == EXIT_OK
    assert "resource_tags" not in json.loads((out / "manifest.json").read_text(encoding="utf-8"))
