"""Tags de recursos leídos de un archivo aparte, para los proveedores en que Prowler no los exporta.

Prowler 5.48 no incluye los tags de Azure en su salida OCSF (``resources[].labels`` llega vacío): sus servicios
de Azure no leen el atributo ``tags``. Sin tags, el motor de riesgo no ve ``data-classification`` y la Ley 1581
no ve ``personal-data``. Este módulo lee la exportación de solo lectura del proveedor y completa los hallazgos.

Formato del archivo (la salida de ``az resource list --query "[].{id:id, tags:tags}" -o json``)::

    [{"id": "/subscriptions/…/providers/Microsoft.Storage/storageAccounts/x", "tags": {"project": "…"}}, …]

Reglas:

- **El escaneo manda.** Un hallazgo que ya trae tags los conserva; el archivo solo completa los que llegan sin
  ninguno. Cuando Prowler exporte los tags de Azure, el archivo deja de tener efecto sin cambiar nada.
- **Los IDs de Azure no distinguen mayúsculas** (``resourceGroups`` y ``resourcegroups`` son el mismo recurso):
  se comparan en minúscula.
- **Un archivo mal formado detiene todo**, como un escaneo ilegible (ADR 0003): unos tags a medias cambiarían
  la clasificación sin que nadie lo note.
"""

import dataclasses
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from compliance_copilot.parsers.prowler_ocsf import ParseResult


@dataclass(frozen=True)
class ResourceTags:
    source: Path
    by_id: dict[str, dict[str, str]]  # ID del recurso en minúscula -> tags


def load_resource_tags(path: Path) -> ResourceTags:
    # utf-8-sig: ``Out-File -Encoding utf8`` de Windows PowerShell escribe el BOM.
    data: Any = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        raise ValueError(f"{path}: se esperaba una lista de recursos con 'id' y 'tags', llegó {type(data).__name__}")
    by_id: dict[str, dict[str, str]] = {}
    for index, item in enumerate(data):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"].strip():
            raise ValueError(f"{path}: el elemento {index} no tiene un 'id' de recurso")
        tags = item.get("tags") or {}  # az devuelve null para un recurso sin tags
        if not isinstance(tags, dict):
            raise ValueError(f"{path}: los tags del elemento {index} no son un objeto clave-valor")
        by_id[item["id"].strip().lower()] = {str(k).strip(): str(v).strip() for k, v in tags.items() if str(k).strip()}
    return ResourceTags(source=path, by_id=by_id)


def apply_resource_tags(parsed: ParseResult, tags: ResourceTags) -> ParseResult:
    """Completa los tags de los hallazgos que llegaron sin ninguno. Devuelve un resultado nuevo."""
    findings, completed = [], 0
    for finding in parsed.findings:
        found = tags.by_id.get(finding.resource_uid.lower())
        if found and not finding.tags:
            findings.append(finding.model_copy(update={"tags": dict(found)}))
            completed += 1
        else:
            findings.append(finding)
    return dataclasses.replace(parsed, findings=findings, resource_tags=tags.source, findings_tagged=completed)
