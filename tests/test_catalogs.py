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


# --- Catálogo de SOC 2 (Fase 7) ------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def soc2() -> Catalog:
    return load_catalog("SOC2")


def test_soc2_has_61_criteria(soc2: Catalog) -> None:
    """33 comunes, 3 de Disponibilidad, 2 de Confidencialidad, 5 de Integridad y 18 de Privacidad."""
    assert len(soc2.requirements) == 61
    assert Counter(r.group for r in soc2.requirements) == {
        "cc1": 5, "cc2": 3, "cc3": 4, "cc4": 2, "cc5": 3, "cc6": 8, "cc7": 5, "cc8": 1, "cc9": 2,
        "a": 3, "c": 2, "pi": 5, "p": 18,
    }


def test_soc2_numbering_is_continuous(soc2: Catalog) -> None:
    by_series: dict[str, list[int]] = {}
    for requirement in soc2.requirements:
        series, number = requirement.id.split(".")
        by_series.setdefault(series, []).append(int(number))
    for series, numbers in by_series.items():
        assert numbers == list(range(1, len(numbers) + 1)), series


def test_soc2_statement_uses_scope_not_applicability(soc2: Catalog) -> None:
    """En SOC 2 la organización decide el alcance, no la aplicabilidad (ADR 0007, D2)."""
    assert soc2.statement.human_columns == ("En alcance", "Justificación")
    assert soc2.statement.file == "matriz-soc2.md"
    assert "Tipo I" in soc2.statement.intro and "Tipo II" in soc2.statement.intro


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("cc_6_1", "CC6.1"),
        ("cc_1_3", "CC1.3"),
        ("cc_a_1_1", "A1.1"),  # Prowler antepone cc_ a Disponibilidad y Confidencialidad
        ("cc_c_1_2", "C1.2"),
        ("pi_1_2", "PI1.2"),
        ("p_6_7", "P6.7"),
        ("CC_6_1", "CC6.1"),
        ("cc_10_1", None),  # no existe la serie CC10
        ("cc_6_9", None),  # no existe CC6.9
        ("formato-raro", None),
    ],
)
def test_soc2_normalizes_prowler_ids(soc2: Catalog, raw: str, expected: str | None) -> None:
    assert soc2.normalize(raw) == expected


def test_every_prowler_soc2_id_in_the_sample_has_correspondence(soc2: Catalog, lab_sample_path: Path) -> None:
    raw = {c for f in parse_ocsf_file(lab_sample_path).findings for c in f.compliance.get("SOC2", [])}
    assert raw
    assert all(soc2.normalize(c) for c in raw), [c for c in raw if not soc2.normalize(c)]


# --- Catálogo de NIST CSF 2.0 (Fase 8) -----------------------------------------------------------------------


@pytest.fixture(scope="module")
def nist() -> Catalog:
    return load_catalog("NIST-CSF-2.0")


def test_nist_has_106_subcategories_in_22_categories(nist: Catalog) -> None:
    """Según el Apéndice A de NIST CSWP 29."""
    assert len(nist.requirements) == 106
    assert len(nist.groups) == 22
    by_function = Counter(r.id.split(".")[0] for r in nist.requirements)
    assert by_function == {"GV": 31, "ID": 21, "PR": 22, "DE": 11, "RS": 13, "RC": 8}


def test_nist_group_is_the_category(nist: Catalog) -> None:
    assert all(r.group == r.id.split("-")[0] for r in nist.requirements)
    assert nist.group_label("PR.DS") == "PR.DS · Seguridad de los datos"


def test_nist_statement_is_a_profile(nist: Catalog) -> None:
    """NIST no se "cumple": perfil actual frente a perfil objetivo (ADR 0007, D2)."""
    assert nist.statement.human_columns == ("Perfil objetivo", "Prioridad")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ac_1", ("PR.AA-01", "PR.AA-05")),  # PR.AC-01 retirado, incorporado en dos subcategorías
        ("ds_1", ("PR.DS-01",)),  # conservado en la 2.0
        ("ds_4", ("PR.IR-04",)),  # PR.DS-04 se movió a PR.IR-04
        ("po_3", ("GV.OC-03",)),  # rotulado GV.PO, pero su texto es el de ID.GV-03
        ("PR.DS-01", ("PR.DS-01",)),  # un ID oficial de la 2.0 pasa tal cual
        ("co_1", ()),  # ambiguo (RS.CO o RC.CO) y no está en la tabla: sin correspondencia
        ("ds_9", ()),
    ],
)
def test_nist_resolves_prowler_ids(nist: Catalog, raw: str, expected: tuple[str, ...]) -> None:
    assert nist.resolve(raw) == expected


def test_every_prowler_nist_id_in_the_sample_has_correspondence(nist: Catalog, lab_sample_path: Path) -> None:
    raw = {c for f in parse_ocsf_file(lab_sample_path).findings for c in f.compliance.get("NIST-CSF-2.0", [])}
    assert raw
    assert all(nist.resolve(c) for c in raw), [c for c in raw if not nist.resolve(c)]


def test_crosswalk_document_matches_the_catalog(nist: Catalog) -> None:
    """La tabla legible (docs/correspondencia-nist-csf.md) y la que usa el código no pueden divergir."""
    doc = (Path(__file__).resolve().parent.parent / "docs" / "correspondencia-nist-csf.md").read_text(encoding="utf-8")
    rows = {}
    for line in doc.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 5 and cells[0].startswith("`"):
            rows[cells[0].strip("`")] = tuple(t.strip() for t in cells[2].split(","))
    assert rows == dict(nist.aliases)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("rp_1", ("RS.MA-01",)),  # RS.RP-01 retirado, incorporado en RS.MA-01
        ("cm_4", ("DE.CM-01", "DE.CM-09")),
        ("sc_1", ("GV.RM-05", "GV.SC-01", "GV.SC-06", "GV.SC-09", "GV.SC-10")),  # texto de ID.SC-01
        ("po_5", ("GV.SC-05",)),
    ],
)
def test_nist_covers_ids_added_after_prowler_548(nist: Catalog, raw: str, expected: tuple[str, ...]) -> None:
    """Los 10 IDs que Prowler agregó después de 5.48: una actualización no debe dejarlos sin correspondencia."""
    assert nist.resolve(raw) == expected


def test_nist_crosswalk_covers_all_78_prowler_ids(nist: Catalog) -> None:
    assert len(nist.aliases) == 78
