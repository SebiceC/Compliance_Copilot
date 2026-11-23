"""Catálogos de requisitos de los marcos normativos (ADR 0007).

Cada catálogo es un JSON en esta carpeta con la lista **completa** de requisitos de un marco: identificador,
grupo y un título redactado para este proyecto (nunca el texto de la norma). La declaración de cada marco
recorre el catálogo, no los hallazgos, para que aparezcan también los requisitos que ningún escáner evidencia.

Todo lo propio de un marco vive en su JSON, no en el código:

- el patrón de sus identificadores (``id_pattern``), que valida el catálogo al cargarlo;
- sus grupos (temas en ISO 27001, funciones en NIST CSF, categorías en SOC 2) con su etiqueta;
- cómo se llama su entregable y qué columnas decide una persona (``statement``);
- cómo se traducen los identificadores de Prowler al formato oficial (``normalization`` y ``aliases``);
- si el marco se deriva de otro (``derived_from``): Prowler no lo mapea y sus requisitos se obtienen de los
  controles de otro marco (la Ley 1581 desde ISO 27001, ADR 0008);
- si solo cuentan los recursos con datos personales (``personal_data``).

Los JSON viajan dentro del paquete (``importlib.resources``) para que funcionen igual con ``pip install -e .``,
con una instalación normal y en CI.
"""

import json
import re
from collections.abc import Callable
from importlib import resources

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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


class PersonalDataRule(BaseModel):
    """Regla de un marco de protección de datos (ADR 0008): qué hallazgos cuentan y qué datos salen del país."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tag: str = "personal-data"  # yes/no: lo decide una persona, como data-classification
    # Regiones que están en el país. Un recurso con datos personales fuera de ellas se señala para revisión.
    local_regions: tuple[str, ...] = ()
    outside_obligations: tuple[str, ...] = Field(min_length=1)  # obligaciones que recibe el señalamiento
    outside_note: str = Field(min_length=1)  # texto del señalamiento; admite {resource}, {region} y {country}


class Catalog(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    framework: str  # misma clave que usa Finding.compliance (p. ej. "ISO27001-2022")
    name: str
    source: str
    id_pattern: str
    normalization: str = "identity"
    # ID de Prowler -> uno o varios IDs oficiales, cuando no hay regla. Varios destinos: la correspondencia oficial
    # reparte un requisito antiguo entre varios nuevos (p. ej. NIST CSF 1.1 -> 2.0); el hallazgo cuenta en todos.
    aliases: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    groups: tuple[Group, ...] = Field(min_length=1)
    statement: Statement
    requirements: tuple[Requirement, ...] = Field(min_length=1)
    # Marco del que se deriva: sus IDs (no los de Prowler) se traducen con ``aliases``. Los IDs de ese marco que
    # se decidió no llevar a este van en ``excluded``, para no reportarlos como "sin correspondencia".
    derived_from: str | None = None
    excluded: tuple[str, ...] = ()
    personal_data: PersonalDataRule | None = None

    @field_validator("aliases", mode="before")
    @classmethod
    def _aliases_as_tuples(cls, value: object) -> object:
        if isinstance(value, dict):
            return {k: (v,) if isinstance(v, str) else v for k, v in value.items()}
        return value

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
        bad_aliases = sorted({t for targets in self.aliases.values() for t in targets} - set(ids))
        empty = sorted(k for k, targets in self.aliases.items() if not targets)
        if empty:
            raise ValueError(f"alias sin destino: {empty}")
        if bad_aliases:
            raise ValueError(f"alias hacia IDs que no están en el catálogo: {bad_aliases}")
        both = sorted(set(self.excluded) & set(self.aliases))
        if both:
            raise ValueError(f"IDs excluidos que también tienen correspondencia: {both}")
        if self.excluded and not self.derived_from:
            raise ValueError("excluded solo aplica a un catálogo derivado (derived_from)")
        if self.personal_data:
            unknown = sorted(set(self.personal_data.outside_obligations) - set(ids))
            if unknown:
                raise ValueError(f"obligaciones del señalamiento que no están en el catálogo: {unknown}")
            try:
                self.personal_data.outside_note.format(resource="r", region="r", country="c")
            except (KeyError, IndexError) as exc:
                raise ValueError(f"outside_note admite solo {{resource}}, {{region}} y {{country}}: {exc}") from exc
        return self

    @property
    def source_framework(self) -> str:
        """La clave de ``Finding.compliance`` de donde salen los IDs: la propia o la del marco de origen."""
        return self.derived_from or self.framework

    def get(self, requirement_id: str) -> Requirement | None:
        return next((r for r in self.requirements if r.id == requirement_id), None)

    def group_label(self, group_id: str) -> str:
        return next(g.label for g in self.groups if g.id == group_id)

    def resolve(self, raw_id: str) -> tuple[str, ...]:
        """ID de Prowler -> IDs del catálogo; vacío si no tiene correspondencia (se reporta, no se descarta)."""
        if raw_id in self.aliases:
            return self.aliases[raw_id]
        candidate = NORMALIZERS[self.normalization](raw_id)
        return (candidate,) if self.get(candidate) else ()

    def normalize(self, raw_id: str) -> str | None:
        """Como ``resolve``, para marcos de correspondencia uno a uno: el primer destino o ``None``."""
        targets = self.resolve(raw_id)
        return targets[0] if targets else None


CATALOG_FILES = {
    "ISO27001-2022": "iso27001-2022.json",
    "SOC2": "soc2-tsc.json",
    "NIST-CSF-2.0": "nist-csf-2.0.json",
    "LEY-1581": "ley-1581.json",
}
# Orden de las declaraciones en los entregables.
FRAMEWORKS: tuple[str, ...] = tuple(CATALOG_FILES)


def load_catalog(framework: str) -> Catalog:
    """Carga y valida el catálogo de un marco."""
    if framework not in CATALOG_FILES:
        raise KeyError(f"no hay catálogo para {framework}; disponibles: {sorted(CATALOG_FILES)}")
    text = resources.files(__name__).joinpath(CATALOG_FILES[framework]).read_text(encoding="utf-8")
    catalog = Catalog.model_validate(json.loads(text))
    if catalog.derived_from:
        _check_derivation(catalog, load_catalog(catalog.derived_from))
    return catalog


def _check_derivation(catalog: Catalog, source: Catalog) -> None:
    """Las correspondencias y exclusiones de un catálogo derivado deben ser IDs reales del marco de origen."""
    if source.derived_from:
        raise ValueError(f"{catalog.framework}: no se puede derivar de otro catálogo derivado ({source.framework})")
    unknown = sorted((set(catalog.aliases) | set(catalog.excluded)) - {r.id for r in source.requirements})
    if unknown:
        raise ValueError(f"{catalog.framework}: IDs que no existen en {source.framework}: {unknown}")


def load_catalogs() -> tuple[Catalog, ...]:
    """Todos los catálogos disponibles, en el orden de ``FRAMEWORKS``."""
    return tuple(load_catalog(f) for f in FRAMEWORKS)
