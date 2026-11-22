"""Tests de los catálogos: el modelo común (ADR 0007) y el catálogo de ISO 27001:2022."""

from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from compliance_copilot.catalogs import FRAMEWORKS, Catalog, load_catalog, load_catalogs
from compliance_copilot.parsers.prowler_ocsf import parse_ocsf_file


@pytest.fixture(scope="module")
def iso() -> Catalog:
    return load_catalog("ISO27001-2022")


def catalog_data(**changes: Any) -> dict[str, Any]:
    """Un catálogo mínimo válido, para probar las validaciones cambiando una sola cosa."""
    data: dict[str, Any] = {
        "framework": "X", "name": "x", "source": "x", "id_pattern": r"X\d",
        "groups": [{"id": "g", "label": "Grupo"}],
        "statement": {"title": "t", "summary_title": "t", "file": "x.md", "sheet": "X", "id_label": "Requisito",
                      "group_label": "Grupo", "intro": "i", "human_columns": ["Decisión"]},
        "requirements": [{"id": "X1", "group": "g", "title": "Uno"}, {"id": "X2", "group": "g", "title": "Dos"}],
    }
    data.update(changes)
    return data


# --- Catálogo de ISO 27001:2022 -----------------------------------------------------------------------------


def test_annex_a_has_93_controls(iso: Catalog) -> None:
    assert len(iso.requirements) == 93


def test_controls_per_theme(iso: Catalog) -> None:
    """A.5 organizacionales 37, A.6 personas 8, A.7 físicos 14, A.8 tecnológicos 34."""
    assert Counter(r.group for r in iso.requirements) == {
        "organizational": 37, "people": 8, "physical": 14, "technological": 34,
    }


def test_theme_matches_control_number(iso: Catalog) -> None:
    expected = {"5": "organizational", "6": "people", "7": "physical", "8": "technological"}
    for requirement in iso.requirements:
        assert requirement.group == expected[requirement.id.split(".")[1]], requirement.id


def test_numbering_is_continuous(iso: Catalog) -> None:
    """Sin saltos ni huecos: A.5.1 a A.5.37, A.6.1 a A.6.8, etc."""
    by_theme: dict[str, list[int]] = {}
    for requirement in iso.requirements:
        _, theme, number = requirement.id.split(".")
        by_theme.setdefault(theme, []).append(int(number))
    for numbers in by_theme.values():
        assert numbers == list(range(1, len(numbers) + 1))


def test_framework_key_matches_finding_compliance(iso: Catalog) -> None:
    assert iso.framework == "ISO27001-2022"


def test_iso_statement_is_the_soa(iso: Catalog) -> None:
    """El vocabulario de ISO: SoA, con Aplicable y Justificación (cláusula 6.1.3 d)."""
    assert iso.statement.file == "soa-iso27001.md"
    assert iso.statement.human_columns == ("Aplicable", "Justificación")
    assert iso.group_label("technological") == "Tecnológico"


def test_every_prowler_mapped_control_exists_in_catalog(iso: Catalog, lab_sample_path: Path) -> None:
    """Si Prowler mapea un ID que no existe (p. ej. uno de la versión 2013), se detecta aquí."""
    mapped = {c for f in parse_ocsf_file(lab_sample_path).findings for c in f.compliance.get("ISO27001-2022", [])}
    assert mapped
    assert all(iso.normalize(c) for c in mapped), [c for c in mapped if not iso.normalize(c)]


def test_get_control(iso: Catalog) -> None:
    assert iso.get("A.5.12").title == "Clasificación de la información"
    assert iso.get("A.12.4.1") is None


def test_iso_normalization_is_identity(iso: Catalog) -> None:
    assert iso.normalize("A.8.15") == "A.8.15"
    assert iso.normalize("A.12.4.1") is None  # ID de la versión 2013: sin correspondencia


# --- Modelo común (ADR 0007, D1) -------------------------------------------------------------------------------


def test_minimal_catalog_is_valid() -> None:
    assert Catalog.model_validate(catalog_data()).get("X1").title == "Uno"


def test_duplicated_ids_are_rejected() -> None:
    requirement = {"id": "X1", "group": "g", "title": "Uno"}
    with pytest.raises(ValidationError, match="duplicados"):
        Catalog.model_validate(catalog_data(requirements=[requirement, requirement]))


@pytest.mark.parametrize("bad_id", ["5.1", "A.9.1", "A.12.4.1", "A.5", "A.5.1 "])
def test_iso_pattern_rejects_malformed_ids(iso: Catalog, bad_id: str) -> None:
    """El patrón vive en el JSON del marco, pero se sigue validando al cargar."""
    data = iso.model_dump()
    data["requirements"] = [{"id": bad_id, "group": "organizational", "title": "Algo"}]
    with pytest.raises(ValidationError, match="patrón"):
        Catalog.model_validate(data)


def test_requirement_in_undeclared_group_is_rejected() -> None:
    with pytest.raises(ValidationError, match="grupos no declarados"):
        Catalog.model_validate(catalog_data(requirements=[{"id": "X1", "group": "otro", "title": "Uno"}]))


def test_unknown_normalization_is_rejected() -> None:
    with pytest.raises(ValidationError, match="normalización desconocida"):
        Catalog.model_validate(catalog_data(normalization="magia"))


def test_alias_to_missing_requirement_is_rejected() -> None:
    with pytest.raises(ValidationError, match="alias"):
        Catalog.model_validate(catalog_data(aliases={"x_1": "X9"}))


def test_aliases_translate_and_unknown_ids_have_no_correspondence() -> None:
    """La tabla de correspondencia traduce; lo que no se puede traducir devuelve None (se reportará)."""
    catalog = Catalog.model_validate(catalog_data(aliases={"legacy_1": "X2"}))
    assert catalog.normalize("legacy_1") == "X2"
    assert catalog.normalize("X1") == "X1"
    assert catalog.normalize("legacy_9") is None


def test_sheet_name_respects_excel_limit() -> None:
    statement = catalog_data()["statement"] | {"sheet": "x" * 32}
    with pytest.raises(ValidationError):
        Catalog.model_validate(catalog_data(statement=statement))


def test_unknown_framework_fails() -> None:
    with pytest.raises(KeyError, match="NO-EXISTE"):
        load_catalog("NO-EXISTE")


def test_load_catalogs_follows_framework_order() -> None:
    assert tuple(c.framework for c in load_catalogs()) == FRAMEWORKS
