"""Tests del catálogo de ISO 27001:2022."""

from collections import Counter
from pathlib import Path

import pytest
from pydantic import ValidationError

from compliance_copilot.catalogs import Catalog, Theme, load_catalog
from compliance_copilot.parsers.prowler_ocsf import parse_ocsf_file


@pytest.fixture(scope="module")
def iso() -> Catalog:
    return load_catalog("ISO27001-2022")


def test_annex_a_has_93_controls(iso: Catalog) -> None:
    assert len(iso.controls) == 93


def test_controls_per_theme(iso: Catalog) -> None:
    """A.5 organizacionales 37, A.6 personas 8, A.7 físicos 14, A.8 tecnológicos 34."""
    assert Counter(c.theme for c in iso.controls) == {
        Theme.ORGANIZATIONAL: 37, Theme.PEOPLE: 8, Theme.PHYSICAL: 14, Theme.TECHNOLOGICAL: 34,
    }


def test_theme_matches_control_number(iso: Catalog) -> None:
    expected = {"5": Theme.ORGANIZATIONAL, "6": Theme.PEOPLE, "7": Theme.PHYSICAL, "8": Theme.TECHNOLOGICAL}
    for control in iso.controls:
        assert control.theme is expected[control.id.split(".")[1]], control.id


def test_numbering_is_continuous(iso: Catalog) -> None:
    """Sin saltos ni huecos: A.5.1 a A.5.37, A.6.1 a A.6.8, etc."""
    by_theme: dict[str, list[int]] = {}
    for control in iso.controls:
        _, theme, number = control.id.split(".")
        by_theme.setdefault(theme, []).append(int(number))
    for numbers in by_theme.values():
        assert numbers == list(range(1, len(numbers) + 1))


def test_framework_key_matches_finding_compliance(iso: Catalog) -> None:
    assert iso.framework == "ISO27001-2022"


def test_every_prowler_mapped_control_exists_in_catalog(iso: Catalog, lab_sample_path: Path) -> None:
    """Si Prowler mapea un ID que no existe (p. ej. uno de la versión 2013), se detecta aquí y no se pierde en la SoA."""
    mapped = {c for f in parse_ocsf_file(lab_sample_path).findings for c in f.compliance.get("ISO27001-2022", [])}
    assert mapped
    assert mapped <= {c.id for c in iso.controls}, mapped - {c.id for c in iso.controls}


def test_get_control(iso: Catalog) -> None:
    assert iso.get("A.5.12").title == "Clasificación de la información"
    assert iso.get("A.12.4.1") is None


def test_duplicated_ids_are_rejected() -> None:
    control = {"id": "A.5.1", "theme": "organizational", "title": "Políticas"}
    with pytest.raises(ValidationError, match="duplicados"):
        Catalog(framework="x", name="x", source="x", controls=[control, control])


@pytest.mark.parametrize("bad_id", ["5.1", "A.9.1", "A.12.4.1", "A.5"])
def test_malformed_ids_are_rejected(bad_id: str) -> None:
    with pytest.raises(ValidationError):
        Catalog(framework="x", name="x", source="x",
                controls=[{"id": bad_id, "theme": "organizational", "title": "Algo"}])


def test_unknown_framework_fails() -> None:
    with pytest.raises(KeyError, match="SOC2"):
        load_catalog("SOC2")
