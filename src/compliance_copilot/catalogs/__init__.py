"""Catálogos de controles de los marcos normativos.

Cada catálogo es un JSON en esta carpeta con la lista **completa** de controles de un marco: identificador, tema
y un título redactado para este proyecto (nunca el texto de la norma). La SoA recorre el catálogo, no los
hallazgos, para que aparezcan también los controles que ningún escáner puede evidenciar.

Los JSON viajan dentro del paquete (``importlib.resources``) para que funcionen igual con ``pip install -e .``,
con una instalación normal y en CI.
"""

import json
from enum import StrEnum
from importlib import resources

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Theme(StrEnum):
    """Temas del Anexo A de ISO 27001:2022."""

    ORGANIZATIONAL = "organizational"  # A.5
    PEOPLE = "people"  # A.6
    PHYSICAL = "physical"  # A.7
    TECHNOLOGICAL = "technological"  # A.8


class Control(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^A\.[5-8]\.\d{1,2}$")
    theme: Theme
    title: str = Field(min_length=3, max_length=80)  # breve a propósito: un título, no una descripción


class Catalog(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    framework: str  # misma clave que usa Finding.compliance (p. ej. "ISO27001-2022")
    name: str
    source: str
    controls: tuple[Control, ...]

    @field_validator("controls")
    @classmethod
    def _unique_ids(cls, controls: tuple[Control, ...]) -> tuple[Control, ...]:
        ids = [c.id for c in controls]
        duplicated = sorted({i for i in ids if ids.count(i) > 1})
        if duplicated:
            raise ValueError(f"controles duplicados: {duplicated}")
        return controls

    def get(self, control_id: str) -> Control | None:
        return next((c for c in self.controls if c.id == control_id), None)


CATALOG_FILES = {"ISO27001-2022": "iso27001-2022.json"}


def load_catalog(framework: str) -> Catalog:
    """Carga y valida el catálogo de un marco (por ahora solo ``ISO27001-2022``)."""
    if framework not in CATALOG_FILES:
        raise KeyError(f"no hay catálogo para {framework}; disponibles: {sorted(CATALOG_FILES)}")
    text = resources.files(__name__).joinpath(CATALOG_FILES[framework]).read_text(encoding="utf-8")
    return Catalog.model_validate(json.loads(text))
