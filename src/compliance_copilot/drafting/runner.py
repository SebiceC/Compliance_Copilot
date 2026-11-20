"""Orquestación: qué hallazgos se redactan, con qué datos, y cómo se registra cada resultado."""

import re
from collections import Counter
from collections.abc import Callable, Iterable
from typing import Any

from compliance_copilot.catalogs import Catalog
from compliance_copilot.drafting.client import Drafter
from compliance_copilot.drafting.guards import TEXT_FIELDS, check_draft
from compliance_copilot.drafting.prompt import aliases_for, payloads_for, restore_aliases, user_message
from compliance_copilot.drafting.schema import (
    APPROVED_STATUSES,
    DraftRecord,
    DraftStatus,
    DraftStore,
    FindingDraft,
    now_utc,
    sha256_of,
)
from compliance_copilot.reports.builders import AuditEntry, Report
from compliance_copilot.risk import METHODOLOGY_VERSION, RiskLevel

_PSEUDONYM_ACCOUNT = re.compile(r"^1234567890\d{2}$")
_TWELVE_DIGITS = re.compile(r"(?<!\d)\d{12}(?!\d)")


def report_payloads(report: Report, catalog: Catalog) -> dict[str, dict[str, Any]]:
    return payloads_for(report.remediation, report.risks, catalog, aliases_for(report.findings))


def run_drafting(
    report: Report,
    store: DraftStore,
    drafter: Drafter,
    catalog: Catalog,
    levels: Iterable[RiskLevel] = tuple(RiskLevel),
    limit: int | None = None,
    on_record: Callable[[DraftRecord], None] = lambda record: None,
) -> Counter[str]:
    """Redacta las acciones del plan (en orden de prioridad) que aún no tienen un borrador vigente.

    Es idempotente: si un hallazgo ya tiene un borrador para exactamente los mismos datos, no se vuelve a
    pagar. ``on_record`` se llama tras cada hallazgo (el CLI guarda el archivo para no perder progreso).
    """
    wanted = set(levels)
    payloads = report_payloads(report, catalog)
    store.scan_ids = list(report.scan.scan_ids)
    store.methodology_version = METHODOLOGY_VERSION
    summary: Counter[str] = Counter()

    for action in report.remediation:
        if action.max_level not in wanted:
            continue
        if limit is not None and summary["requested"] >= limit:
            break
        payload = payloads[action.check_id]
        input_hash = sha256_of(payload)
        existing = store.records.get(action.check_id)
        if existing and existing.input_sha256 == input_hash and existing.status is not DraftStatus.FAILED:
            summary["skipped_current"] += 1
            continue

        leaked = [n for n in _TWELVE_DIGITS.findall(str(payload)) if not _PSEUDONYM_ACCOUNT.match(n)]
        if leaked:  # defensa en profundidad: el anonimizador ya debió reemplazarlos
            record = _failed(action.check_id, input_hash, [f"datos sin anonimizar en el payload: {len(leaked)}"])
        else:
            summary["requested"] += 1
            response = drafter.draft(user_message(payload))
            problems = response.problems or check_draft(response.draft, payload)
            record = DraftRecord(
                check_id=action.check_id,
                status=DraftStatus.FAILED if problems else DraftStatus.PENDING,
                input_sha256=input_hash,
                generated_at=now_utc(),
                model=response.model,
                draft=response.draft,
                draft_sha256=response.draft.sha256() if response.draft else None,
                problems=problems,
                usage=response.usage,
            )
            for name, value in response.usage.items():
                summary[name] += value

        store.records[action.check_id] = record
        summary[record.status.value] += 1
        on_record(record)
    return summary


def audit_entries(report: Report, store: DraftStore, catalog: Catalog) -> dict[str, AuditEntry]:
    """Estado de la redacción de cada acción del plan, para los entregables.

    Un texto aprobado solo se usa si se redactó con los mismos datos del escaneo actual: si el escaneo cambió,
    el texto queda "desactualizado" y no se publica.
    """
    payloads = report_payloads(report, catalog)
    aliases = aliases_for(report.findings)
    entries = {}
    for action in report.remediation:
        record = store.records.get(action.check_id)
        if record is None:
            entries[action.check_id] = AuditEntry(state="not_generated")
            continue
        current = record.input_sha256 == sha256_of(payloads[action.check_id])
        approved = record.status in APPROVED_STATUSES
        entries[action.check_id] = AuditEntry(
            state=record.status.value if current else "outdated",
            text=restore_draft(record.approved_text, aliases) if (approved and current) else None,
            model=record.model,
            reviewer=record.review.reviewer if record.review else "",
            reviewed_at=record.review.reviewed_at.isoformat(timespec="seconds") if record.review else "",
        )
    return entries


def restore_draft(draft: FindingDraft | None, aliases: dict[str, str]) -> FindingDraft | None:
    """El borrador con los nombres reales de las personas (el modelo solo vio seudónimos)."""
    if draft is None or not aliases:
        return draft
    return draft.model_copy(update={f: restore_aliases(getattr(draft, f), aliases) for f in TEXT_FIELDS})


def _failed(check_id: str, input_hash: str, problems: list[str]) -> DraftRecord:
    return DraftRecord(check_id=check_id, status=DraftStatus.FAILED, input_sha256=input_hash,
                       generated_at=now_utc(), problems=problems)
