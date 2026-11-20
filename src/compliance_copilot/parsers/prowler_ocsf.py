"""Parser de la salida JSON OCSF de Prowler.

Es el único módulo que conoce el formato de Prowler. Convierte cada hallazgo OCSF en un ``Finding``.

Política de errores (ver docs/adr/0003-hallazgos-invalidos-se-reportan.md):

- Si el **archivo** no se puede leer o no es una lista de hallazgos, se lanza una excepción: no hay nada que
  procesar.
- Si **un hallazgo** viene mal formado, no se descarta en silencio ni se detiene todo el lote: se registra en
  ``ParseResult.errors`` con su posición, su identificador y el motivo, y se sigue con los demás.
"""

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from compliance_copilot.models import Finding, ScanMetadata

logger = logging.getLogger(__name__)

# Marcos que usa el proyecto, con el nombre exacto de la clave en ``unmapped.compliance`` de Prowler.
FRAMEWORKS: tuple[str, ...] = ("ISO27001-2022", "SOC2", "NIST-CSF-2.0")


@dataclass(frozen=True)
class ParseError:
    """Un hallazgo que no se pudo convertir en ``Finding``."""

    index: int  # posición en el archivo (desde 0), para encontrarlo a mano
    finding_uid: str | None  # puede faltar: a veces es justamente lo que está roto
    check_id: str | None
    reason: str


@dataclass(frozen=True)
class ParseResult:
    """Resultado de leer un archivo: los hallazgos válidos y los que fallaron."""

    source: Path
    total: int  # hallazgos que traía el archivo
    scan: ScanMetadata
    findings: list[Finding] = field(default_factory=list)
    errors: list[ParseError] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """True si todos los hallazgos del archivo se convirtieron. Ningún hallazgo se perdió."""
        return not self.errors


def parse_ocsf_file(path: Path) -> ParseResult:
    """Lee un archivo ``.ocsf.json`` de Prowler y devuelve sus hallazgos y sus errores."""
    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"{path}: se esperaba una lista de hallazgos OCSF, llegó {type(data).__name__}")

    findings: list[Finding] = []
    errors: list[ParseError] = []

    for index, raw in enumerate(data):
        try:
            findings.append(_to_finding(raw))
        except (KeyError, TypeError, ValueError) as exc:  # ValidationError hereda de ValueError
            error = ParseError(
                index=index,
                finding_uid=_dig(raw, "finding_info", "uid"),
                check_id=_dig(raw, "metadata", "event_code"),
                reason=_describe(exc),
            )
            errors.append(error)
            logger.warning(
                "Hallazgo %d no se pudo leer (uid=%s, check=%s): %s",
                error.index, error.finding_uid, error.check_id, error.reason,
            )

    if errors:
        logger.warning("%s: %d de %d hallazgos con errores", path.name, len(errors), len(data))

    return ParseResult(
        source=path, total=len(data), scan=_scan_metadata(data, findings), findings=findings, errors=errors,
    )


def _scan_metadata(data: list[Any], findings: list[Finding]) -> ScanMetadata:
    """Datos del escaneo. Se leen de todos los elementos (incluso los que fallaron) y se deduplican."""

    def distinct(*keys: str) -> tuple[str, ...]:
        return tuple(sorted({str(v) for raw in data if (v := _dig(raw, *keys))}))

    observed = sorted(f.observed_at for f in findings)
    return ScanMetadata(
        scanner="prowler",
        scanner_versions=distinct("metadata", "product", "version"),
        scan_ids=distinct("unmapped", "scan_id"),
        providers=tuple(sorted({f.provider for f in findings})),
        account_uids=tuple(sorted({f.account_uid for f in findings})),
        first_observed_at=observed[0] if observed else None,
        last_observed_at=observed[-1] if observed else None,
    )


def _to_finding(raw: dict[str, Any]) -> Finding:
    """Traduce un hallazgo OCSF de Prowler a ``Finding``.

    Los campos obligatorios se leen con ``[...]`` para que su ausencia falle de inmediato; los opcionales,
    con ``.get()``.
    """
    resources = raw["resources"]
    if len(resources) != 1:
        raise ValueError(f"se esperaba exactamente 1 recurso, llegaron {len(resources)}")
    resource = resources[0]

    return Finding(
        finding_uid=raw["finding_info"]["uid"],
        check_id=raw["metadata"]["event_code"],
        check_title=raw["finding_info"]["title"],
        status=raw["status_code"],  # no raw["status"]: ese es el ciclo de vida OCSF ("New")
        status_detail=raw.get("status_detail", ""),
        severity=raw["severity"],
        # El epoch es UTC sin ambigüedad; created_time_dt viene en hora local y sin zona horaria.
        observed_at=datetime.fromtimestamp(raw["finding_info"]["created_time"], tz=timezone.utc),
        provider=raw["cloud"]["provider"],
        account_uid=raw["cloud"]["account"]["uid"],
        region=resource.get("region", ""),
        resource_uid=resource["uid"],
        resource_name=resource.get("name", ""),
        resource_type=resource.get("type", ""),
        tags=_parse_labels(resource.get("labels") or []),
        categories=[str(c) for c in _dig(raw, "unmapped", "categories") or []],
        compliance=_filter_compliance(_dig(raw, "unmapped", "compliance") or {}),
        risk=raw.get("risk_details") or "",
        remediation=_dig(raw, "remediation", "desc") or "",
    )


def _parse_labels(labels: Iterable[str]) -> dict[str, str]:
    """``["data-classification:restricted"]`` → ``{"data-classification": "restricted"}``.

    Corta solo en el primer ``:`` porque el valor puede contener otros. Un label sin ``:`` se conserva con
    valor vacío: es un tag sin valor, y descartarlo sería perder información.
    """
    tags: dict[str, str] = {}
    for label in labels:
        key, _, value = label.partition(":")
        if key.strip():
            tags[key.strip()] = value.strip()
    return tags


def _filter_compliance(compliance: dict[str, Any]) -> dict[str, list[str]]:
    """Se queda solo con los marcos del proyecto. Un marco sin controles no se incluye."""
    return {
        framework: [str(control) for control in compliance[framework]]
        for framework in FRAMEWORKS
        if compliance.get(framework)
    }


def _dig(data: Any, *keys: str) -> Any:
    """Lee una ruta anidada sin lanzar excepciones; devuelve None si algún nivel falta."""
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _describe(exc: Exception) -> str:
    """Convierte la excepción en un motivo legible para el reporte."""
    if isinstance(exc, ValidationError):
        return "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
    if isinstance(exc, KeyError):
        return f"falta el campo {exc}"
    return f"{type(exc).__name__}: {exc}"
