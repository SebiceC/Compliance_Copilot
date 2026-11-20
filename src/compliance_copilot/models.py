"""Modelo de datos interno de Compliance Copilot.

Un ``Finding`` es el resultado (PASS/FAIL/MANUAL) de evaluar un check de seguridad sobre un recurso cloud,
con su gravedad, su contexto y los controles normativos a los que corresponde.

Este modelo no depende de Prowler: el parser traduce la salida del escáner a ``Finding``, y el resto de la
herramienta (motor de riesgo, reportes, agente) solo lee ``Finding``.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class Status(StrEnum):
    """Resultado del check sobre el recurso."""

    PASS = "pass"
    FAIL = "fail"
    MANUAL = "manual"  # el check no puede decidirlo solo; requiere revisión humana


class Severity(StrEnum):
    """Gravedad que el escáner asigna al check. Es la base de la probabilidad (Fase 2)."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """Un hallazgo normalizado, independiente del escáner que lo produjo."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    # Identificación y trazabilidad
    finding_uid: str = Field(min_length=1)
    check_id: str = Field(min_length=1)
    check_title: str

    # Resultado
    status: Status
    status_detail: str
    severity: Severity
    observed_at: AwareDatetime

    # Dónde
    provider: str = Field(min_length=1)
    account_uid: str = Field(min_length=1)
    region: str

    # Recurso afectado
    resource_uid: str = Field(min_length=1)
    resource_name: str
    resource_type: str
    tags: dict[str, str] = Field(default_factory=dict)

    # Marcos normativos: {"ISO27001-2022": ["A.8.15"], "SOC2": ["cc_7_2"], ...}
    compliance: dict[str, list[str]] = Field(default_factory=dict)

    # Contexto para remediación y redacción
    risk: str = ""
    remediation: str = ""

    @field_validator("status", "severity", "provider", mode="before")
    @classmethod
    def _to_lowercase(cls, value: object) -> object:
        """Acepta 'FAIL', 'Fail' o 'fail': cada escáner escribe distinto, el modelo guarda una sola forma."""
        # strip() aquí: str_strip_whitespace no se aplica a los enums, solo a los campos de tipo str.
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("observed_at")
    @classmethod
    def _not_in_future(cls, value: datetime) -> datetime:
        """Una evidencia no puede haberse observado en el futuro: suele indicar una zona horaria mal leída."""
        if value > datetime.now(value.tzinfo):
            raise ValueError("observed_at está en el futuro")
        return value
