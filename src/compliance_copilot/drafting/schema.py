"""Modelos de la redacción asistida por IA: el borrador que devuelve el modelo y su registro de revisión."""

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class FindingDraft(BaseModel):
    """Hallazgo de auditoría en formato de las 5 C. Es lo que el modelo devuelve (structured outputs).

    Sin restricciones de longitud en el esquema: las valida ``guards.py`` después, para poder explicar el
    motivo del rechazo en lugar de recibir un error genérico de la API.
    """

    model_config = ConfigDict(extra="forbid")

    title: str  # título breve del hallazgo
    condition: str  # qué se encontró
    criteria: str  # qué debería ser (control y requisito)
    cause: str  # por qué ocurre
    effect: str  # qué riesgo genera
    recommendation: str  # qué hacer
    cited_controls: list[str]  # controles que el texto menciona; deben ser los del hallazgo
    cited_risk_level: str  # nivel de riesgo que el texto menciona; debe ser el del motor

    def sha256(self) -> str:
        return sha256_of(self.model_dump(mode="json"))


class DraftStatus(StrEnum):
    PENDING = "pending"  # generado y validado, espera revisión humana
    APPROVED = "approved"
    APPROVED_WITH_EDITS = "approved_with_edits"
    REJECTED = "rejected"
    FAILED = "failed"  # el modelo no respondió, se negó o el borrador no pasó la validación


APPROVED_STATUSES = frozenset({DraftStatus.APPROVED, DraftStatus.APPROVED_WITH_EDITS})


class Review(BaseModel):
    """La decisión humana sobre un borrador: quién, cuándo, qué decidió y qué texto quedó."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reviewer: str = Field(min_length=1)
    reviewed_at: AwareDatetime
    decision: DraftStatus
    final: FindingDraft | None = None  # texto aprobado (igual al borrador o editado)
    final_sha256: str | None = None
    comment: str = ""


class DraftRecord(BaseModel):
    """Trazabilidad completa de un borrador: qué vio el modelo, qué escribió y qué decidió la persona."""

    model_config = ConfigDict(extra="forbid")

    check_id: str
    status: DraftStatus
    input_sha256: str  # hash de los datos enviados al modelo: detecta si el escaneo cambió después
    generated_at: AwareDatetime
    model: str = ""  # el modelo que respondió (puede ser el de respaldo)
    draft: FindingDraft | None = None
    draft_sha256: str | None = None
    problems: list[str] = Field(default_factory=list)  # motivos de FAILED
    usage: dict[str, int] = Field(default_factory=dict)
    review: Review | None = None

    @property
    def approved_text(self) -> FindingDraft | None:
        return self.review.final if self.review and self.status in APPROVED_STATUSES else None


class DraftStore(BaseModel):
    """Archivo con todos los borradores de un escaneo. Contiene datos de la cuenta: no se versiona."""

    model_config = ConfigDict(extra="forbid")

    scan_ids: list[str] = Field(default_factory=list)
    methodology_version: str = ""
    records: dict[str, DraftRecord] = Field(default_factory=dict)  # por check_id

    @classmethod
    def load(cls, path: Path) -> "DraftStore":
        if not path.exists():
            return cls()
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n")


def sha256_of(data: object) -> str:
    """Hash estable de un objeto JSON (claves ordenadas): el mismo contenido da siempre el mismo hash."""
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def now_utc() -> datetime:
    return datetime.now(UTC)
