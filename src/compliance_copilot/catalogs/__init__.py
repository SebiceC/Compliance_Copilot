"""Catálogos de requisitos de los marcos normativos (ADR 0007).

Cada catálogo es un JSON en esta carpeta con la lista **completa** de requisitos de un marco: identificador,
grupo y un título redactado para este proyecto (nunca el texto de la norma). La declaración de cada marco
recorre el catálogo, no los hallazgos, para que aparezcan también los requisitos que ningún escáner evidencia.

Todo lo propio de un marco vive en su JSON, no en el código:

- el patrón de sus identificadores (``id_pattern``), que valida el catálogo al cargarlo;
- sus grupos (temas en ISO 27001, funciones en NIST CSF, categorías en SOC 2) con su etiqueta;
- cómo se llama su entregable y qué columnas decide una persona (``statement``);
- cómo se traducen los identificadores de Prowler al formato oficial (``normalization`` y ``aliases``).

Los JSON viajan dentro del paquete (``importlib.resources``) para que funcionen igual con ``pip install -e .``,
con una instalación normal y en CI.
"""

import json
import re
from collections.abc import Callable
from importlib import resources

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Group(BaseModel):
    """Agrupación de requisitos: tema (ISO 27001), función (NIST CSF), categoría (SOC 2)..."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    label: str = Field(min_length=1)


class Requirement(BaseModel):
    """Un control, criterio, subcategoría u obligación del marco."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    group: str
    title: str = Field(min_length=3, max_length=80)  # breve a propósito: un título, no una descripción


class Statement(BaseModel):
    """El entregable del marco y las decisiones que toma una persona (la herramienta las deja vacías)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str  # encabezado del documento
    summary_title: str  # título de su sección en el resumen
    file: str  # nombre del Markdown
    sheet: str = Field(max_length=31)  # nombre de la hoja de Excel (límite de Excel: 31 caracteres)
    id_label: str  # cómo se llama un requisito: "Control", "Criterio", "Subcategoría", "Obligación"
    group_label: str  # cómo se llama un grupo: "Tema", "Categoría", "Función"
    intro: str  # nota al inicio del documento: qué decide la persona y qué no significa el estado técnico
    human_columns: tuple[str, ...] = Field(min_length=1)


_PROWLER_SOC2 = re.compile(r"(?:cc_(?=(?:a|c|pi|p)_))?(cc|a|c|pi|p)_(\d+)_(\d+)")


def _prowler_soc2(raw: str) -> str:
    """``cc_6_1`` -> ``CC6.1``; ``cc_a_1_1`` -> ``A1.1``; ``cc_c_1_2`` -> ``C1.2``; ``pi_1_2`` -> ``PI1.2``.

    Prowler antepone ``cc_`` a algunos criterios que no son comunes (Disponibilidad, Confidencialidad): se quita.
    Un formato que no reconoce se devuelve tal cual y queda como "sin correspondencia".
    """
    match = _PROWLER_SOC2.fullmatch(raw.strip().lower())
    if not match:
        return raw
    prefix, series, number = match.groups()
    return f"{prefix.upper()}{series}.{number}"


# Traducciones de los IDs de Prowler al formato oficial. Cada catálogo elige la suya en ``normalization``; los
# casos que no siguen una regla se listan en ``aliases`` (una tabla de correspondencia).
NORMALIZERS: dict[str, Callable[[str], str]] = {
    "identity": lambda raw: raw,
    "prowler_soc2": _prowler_soc2,
}


class Catalog(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    framework: str  # misma clave que usa Finding.compliance (p. ej. "ISO27001-2022")
    name: str
    source: str
    id_pattern: str
    normalization: str = "identity"
    aliases: dict[str, str] = Field(default_factory=dict)  # ID de Prowler -> ID oficial, cuando no hay regla
    groups: tuple[Group, ...] = Field(min_length=1)
    statement: Statement
    requirements: tuple[Requirement, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _consistent(self) -> "Catalog":
        ids = [r.id for r in self.requirements]
        duplicated = sorted({i for i in ids if ids.count(i) > 1})
        if duplicated:
            raise ValueError(f"requisitos duplicados: {duplicated}")
        pattern = re.compile(self.id_pattern)
        malformed = [i for i in ids if not pattern.fullmatch(i)]
        if malformed:
            raise ValueError(f"IDs que no cumplen el patrón {self.id_pattern}: {malformed}")
        group_ids = {g.id for g in self.groups}
        orphans = sorted({r.group for r in self.requirements} - group_ids)
        if orphans:
            raise ValueError(f"grupos no declarados: {orphans}")
        if self.normalization not in NORMALIZERS:
            raise ValueError(f"normalización desconocida: {self.normalization}; disponibles: {sorted(NORMALIZERS)}")
        bad_aliases = sorted(v for v in self.aliases.values() if v not in ids)
        if bad_aliases:
            raise ValueError(f"alias hacia IDs que no están en el catálogo: {bad_aliases}")
        return self

    def get(self, requirement_id: str) -> Requirement | None:
        return next((r for r in self.requirements if r.id == requirement_id), None)

    def group_label(self, group_id: str) -> str:
        return next(g.label for g in self.groups if g.id == group_id)

    def normalize(self, raw_id: str) -> str | None:
        """ID de Prowler -> ID del catálogo, o ``None`` si no tiene correspondencia (se reporta, no se descarta)."""
        candidate = self.aliases.get(raw_id) or NORMALIZERS[self.normalization](raw_id)
        return candidate if self.get(candidate) else None


CATALOG_FILES = {"ISO27001-2022": "iso27001-2022.json", "SOC2": "soc2-tsc.json"}
# Orden de las declaraciones en los entregables.
FRAMEWORKS: tuple[str, ...] = tuple(CATALOG_FILES)


def load_catalog(framework: str) -> Catalog:
    """Carga y valida el catálogo de un marco."""
    if framework not in CATALOG_FILES:
        raise KeyError(f"no hay catálogo para {framework}; disponibles: {sorted(CATALOG_FILES)}")
    text = resources.files(__name__).joinpath(CATALOG_FILES[framework]).read_text(encoding="utf-8")
    return Catalog.model_validate(json.loads(text))


def load_catalogs() -> tuple[Catalog, ...]:
    """Todos los catálogos disponibles, en el orden de ``FRAMEWORKS``."""
    return tuple(load_catalog(f) for f in FRAMEWORKS)
