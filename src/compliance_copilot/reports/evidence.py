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

from compliance_copilot.drafting.schema import DraftStore
from compliance_copilot.models import Finding
from compliance_copilot.personal_data import group_by_location
from compliance_copilot.reports.builders import Report, Statement
from compliance_copilot.risk import METHODOLOGY_VERSION

EVIDENCE_DIR = "evidencias"
MANIFEST = "manifest.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def write_evidence(report: Report, out_dir: Path, deliverables: list[Path], drafts: DraftStore | None = None) -> Path:
    """Escribe las evidencias y el manifest. ``deliverables`` son los archivos ya generados (se incluyen sus hashes)."""
    evidence_dir = out_dir / EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)

    written = [_write_json(evidence_dir / "hallazgos.json",
                           [f.model_dump(mode="json") for f in report.findings])]

    if drafts is not None:
        # Trazabilidad de la IA: qué datos vio el modelo (hash), qué escribió, quién lo revisó y qué quedó.
        # Incluye los rechazados y fallidos: también son parte del registro.
        written.append(_write_json(evidence_dir / "redaccion-ia.json", drafts.model_dump(mode="json")))

    for statement in report.statements:
        written += _statement_evidence(statement, evidence_dir / "controles" / statement.framework)

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


def _evidence_entry(f: Finding) -> dict[str, Any]:
    return {
        "finding_uid": f.finding_uid,
        "check_id": f.check_id,
        "status": f.status.value,
        "severity": f.severity.value,
        "resource_uid": f.resource_uid,
        "resource_name": f.resource_name,
        "region": f.region,
        "status_detail": f.status_detail,
        "observed_at": f.observed_at.isoformat(),
    }


def _statement_evidence(statement: Statement, directory: Path) -> list[Path]:
    """Un JSON por requisito con hallazgos, y uno con los IDs sin correspondencia si los hay."""
    written = []
    for row in statement.rows:
        found = statement.evidence.get(row.requirement.id)
        if not found:
            continue  # sin hallazgos: la evidencia de ese requisito es manual
        written.append(_write_json(directory / f"{row.requirement.id}.json", {
            "framework": statement.framework,
            "control": row.requirement.id,
            "title": row.requirement.title,
            **({"technical_scope": row.requirement.technical_scope} if row.requirement.technical_scope else {}),
            "technical_status": row.status.value,
            "counts": {"pass": row.pass_count, "fail": row.fail_count, "manual": row.manual_count},
            "evidence": sorted((_evidence_entry(f) for f in found), key=lambda e: (e["status"], e["check_id"])),
        }))
    if statement.unmapped:
        written.append(_write_json(directory / "_sin-correspondencia.json", {
            "framework": statement.framework,
            "note": "IDs que Prowler asigna a este marco sin correspondencia en el catálogo (ADR 0007).",
            "unmapped": [
                {"raw_id": u.raw_id, "finding_count": u.finding_count, "check_ids": list(u.check_ids)}
                for u in statement.unmapped
            ],
        }))
    rule = statement.catalog.personal_data
    if rule:
        written.append(_write_json(directory / "_datos-personales.json", {
            "framework": statement.framework,
            "note": "Regla de datos personales (ADR 0008): qué recursos están fuera del país y cuáles sin calificar.",
            "tag": rule.tag,
            "local_regions": list(rule.local_regions),
            "outside": [
                {"resource_uid": r.uid, "resource_name": r.name, "resource_type": r.type, "region": r.region,
                 "country": r.country, "obligations": list(rule.outside_obligations), "note": note}
                for r, note in zip(statement.outside, statement.outside_notes(), strict=True)
            ],
            "outside_by_location": [
                {"provider": g.provider, "region": g.region, "country": g.country, "resources": g.count}
                for g in group_by_location(statement.outside)
            ],
            "unqualified": [
                {"resource_uid": r.uid, "resource_name": r.name, "resource_type": r.type, "region": r.region}
                for r in statement.unqualified
            ],
        }))
    return written


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
