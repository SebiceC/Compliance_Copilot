"""Reglas de datos personales para los marcos de protección de datos (ADR 0008; docs/metodologia-ley-1581.md).

Una ley de protección de datos solo aplica a los recursos que tratan datos personales. Lo decide una persona con
el tag ``personal-data=yes|no`` (independiente de ``data-classification``: la clasificación mide el impacto de la
divulgación; este tag dice si aplica la ley). Con él:

- **Qué hallazgos cuentan** (decisión L4). Un hallazgo sobre un recurso de datos cuenta si el recurso tiene
  ``yes``. Un hallazgo de la cuenta o de infraestructura cuenta si la cuenta tiene al menos un recurso con ``yes``:
  un control de la cuenta protege todos sus datos, y una red expuesta es una vía de entrada hacia ellos. Un
  recurso de datos sin el tag (o con un valor inválido) no se cuenta ni se descarta: queda para revisión.
- **Qué datos salen del país** (decisión L5). Cada recurso con ``yes`` en una región que no está en el país se
  señala para revisión. La herramienta solo ve la región: si hay un contrato de transmisión o el fundamento de una
  transferencia lo verifica una persona.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from compliance_copilot.models import Finding
from compliance_copilot.risk import ResourceGroup, finding_group

YES, NO = "yes", "no"

# País de cada región, para el texto del señalamiento. Una región que no esté aquí se muestra sin país.
REGION_COUNTRY: dict[str, str] = {
    "us-east-1": "EE. UU.", "us-east-2": "EE. UU.", "us-west-1": "EE. UU.", "us-west-2": "EE. UU.",
    "ca-central-1": "Canadá", "ca-west-1": "Canadá", "mx-central-1": "México", "sa-east-1": "Brasil",
    "eu-west-1": "Irlanda", "eu-west-2": "Reino Unido", "eu-west-3": "Francia", "eu-central-1": "Alemania",
    "eu-central-2": "Suiza", "eu-north-1": "Suecia", "eu-south-1": "Italia", "eu-south-2": "España",
}
UNKNOWN_COUNTRY = "país por confirmar"


class PersonalData(StrEnum):
    YES = "yes"
    NO = "no"
    MISSING = "missing"  # sin tag
    INVALID = "invalid"  # un valor distinto de yes/no


@dataclass(frozen=True, order=True)
class ResourceRef:
    """Un recurso, sin el detalle de sus hallazgos: lo que necesita una persona para revisarlo."""

    name: str
    uid: str
    type: str
    region: str

    @property
    def country(self) -> str:
        return REGION_COUNTRY.get(self.region, UNKNOWN_COUNTRY)


@dataclass(frozen=True)
class PersonalDataScope:
    counted: tuple[Finding, ...]  # los hallazgos que cuentan para el marco
    unqualified: tuple[ResourceRef, ...]  # recursos de datos sin calificar (sin tag o con un valor inválido)
    outside: tuple[ResourceRef, ...]  # recursos con datos personales fuera del país


def read_personal_data(tags: dict[str, str], tag: str) -> PersonalData:
    """Lee el tag. Ignora mayúsculas y espacios, como ``data-classification``; la Tag Policy exige minúsculas."""
    if tag not in tags:
        return PersonalData.MISSING
    value = tags[tag].strip().lower()
    return PersonalData(value) if value in (YES, NO) else PersonalData.INVALID


def _ref(finding: Finding) -> ResourceRef:
    return ResourceRef(finding.resource_name or finding.resource_uid, finding.resource_uid, finding.resource_type,
                       finding.region)


def personal_data_scope(findings: Iterable[Finding], tag: str, local_regions: Iterable[str] = ()) -> PersonalDataScope:
    findings = tuple(findings)
    local = frozenset(local_regions)
    value = {f.finding_uid: read_personal_data(f.tags, tag) for f in findings}
    accounts = {f.account_uid for f in findings if value[f.finding_uid] is PersonalData.YES}

    # Por UID: Prowler puede reportar el mismo recurso con dos tipos (lab-trail como trail y como bucket).
    counted: list[Finding] = []
    unqualified: dict[str, ResourceRef] = {}
    outside: dict[str, ResourceRef] = {}
    for f in findings:
        pd = value[f.finding_uid]
        if pd is PersonalData.YES:
            counted.append(f)
            if f.region not in local:
                outside.setdefault(f.resource_uid, _ref(f))
        elif finding_group(f) is ResourceGroup.DATA:  # una configuración de cuenta no es un recurso de datos
            if pd is not PersonalData.NO:
                unqualified.setdefault(f.resource_uid, _ref(f))
        elif f.account_uid in accounts:
            counted.append(f)  # cuenta o infraestructura de una cuenta con datos personales
    return PersonalDataScope(tuple(counted), tuple(sorted(unqualified.values())), tuple(sorted(outside.values())))
