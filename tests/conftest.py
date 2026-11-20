"""Datos compartidos por los tests."""

import json
from pathlib import Path
from typing import Any

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
LAB_SAMPLE = SAMPLES / "prowler-aws-lab.ocsf.json"


@pytest.fixture
def lab_sample_path() -> Path:
    """Muestra anonimizada del laboratorio: 76 hallazgos reales de Prowler (29 FAIL, 47 PASS)."""
    return LAB_SAMPLE


@pytest.fixture
def lab_sample_raw() -> list[dict[str, Any]]:
    with LAB_SAMPLE.open(encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def raw_finding(lab_sample_raw: list[dict[str, Any]]) -> dict[str, Any]:
    """Un hallazgo OCSF válido (FAIL de lab-trail) para modificarlo en cada test."""
    return next(
        x for x in lab_sample_raw
        if x["metadata"]["event_code"] == "cloudtrail_log_file_validation_enabled"
        and x["status_code"] == "FAIL"
    )


def write_json(path: Path, data: Any) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path
