"""Paquete de evidencias: qué sustenta cada control y un manifest con hashes para la cadena de custodia.

El manifest registra el SHA-256 del archivo de origen y de cada archivo generado. Si alguien modifica un
entregable o una evidencia después de generarlos, ``verify_manifest`` lo detecta.
"""

import hashlib
import json
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from compliance_copilot.reports.builders import SOA_FRAMEWORK, Report
from compliance_copilot.risk import METHODOLOGY_VERSION

EVIDENCE_DIR = "evidencias"
MANIFEST = "manifest.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def write_evidence(report: Report, out_dir: Path, deliverables: list[Path]) -> Path:
    """Escribe las evidencias y el manifest. ``deliverables`` son los archivos ya generados (se incluyen sus hashes)."""
    evidence_dir = out_dir / EVIDENCE_DIR
    controls_dir = evidence_dir / "controles" / SOA_FRAMEWORK
    controls_dir.mkdir(parents=True, exist_ok=True)

    written = [_write_json(evidence_dir / "hallazgos.json",
                           [f.model_dump(mode="json") for f in report.findings])]

    findings_by_control: dict[str, list[dict[str, Any]]] = {}
    for f in report.findings:
        for control_id in f.compliance.get(SOA_FRAMEWORK, []):
            findings_by_control.setdefault(control_id, []).append({
                "finding_uid": f.finding_uid,
                "check_id": f.check_id,
                "status": f.status.value,
                "severity": f.severity.value,
                "resource_uid": f.resource_uid,
                "resource_name": f.resource_name,
                "region": f.region,
                "status_detail": f.status_detail,
                "observed_at": f.observed_at.isoformat(),
            })

    for row in report.soa:
        if row.control.id not in findings_by_control:
            continue  # sin hallazgos: la evidencia de ese control es manual
        written.append(_write_json(controls_dir / f"{row.control.id}.json", {
            "framework": SOA_FRAMEWORK,
            "control": row.control.id,
            "title": row.control.title,
            "technical_status": row.status.value,
            "counts": {"pass": row.pass_count, "fail": row.fail_count, "manual": row.manual_count},
            "evidence": sorted(findings_by_control[row.control.id], key=lambda e: (e["status"], e["check_id"])),
        }))

    manifest = {
        "generator": {"name": "compliance-copilot", "version": _own_version()},
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "methodology_version": METHODOLOGY_VERSION,
        "scan": report.scan.model_dump(mode="json"),
        "source": {
            "file": report.source.name,
            "sha256": sha256(report.source),
            "findings_in_file": report.total_in_file,
            "findings_read": len(report.findings),
            "complete": report.is_complete,
            "parse_errors": [
                {"index": e.index, "finding_uid": e.finding_uid, "check_id": e.check_id, "reason": e.reason}
                for e in report.parse_errors
            ],
        },
        "files": [
            {"path": p.relative_to(out_dir).as_posix(), "sha256": sha256(p), "bytes": p.stat().st_size}
            for p in sorted([*deliverables, *written])
        ],
    }
    return _write_json(out_dir / MANIFEST, manifest)


def verify_manifest(manifest_path: Path, source: Path | None = None) -> list[str]:
    """Recalcula los hashes del manifest. Devuelve los problemas encontrados; vacío si todo coincide."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    base = manifest_path.parent
    problems = []
    for entry in manifest["files"]:
        path = base / entry["path"]
        if not path.exists():
            problems.append(f"falta {entry['path']}")
        elif sha256(path) != entry["sha256"]:
            problems.append(f"modificado {entry['path']}")
    if source is not None and sha256(source) != manifest["source"]["sha256"]:
        problems.append(f"el archivo de origen {source.name} no es el que se usó")
    return problems


def _write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def _own_version() -> str:
    try:
        return version("compliance-copilot")
    except PackageNotFoundError:
        return "desconocida"
