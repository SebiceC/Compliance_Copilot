"""Revisión humana de los borradores: aprobar, editar o rechazar, con registro de quién y cuándo.

Es interactiva a propósito: no existe un "aprobar todo". ``ask`` y ``say`` se inyectan para poder probarla.
"""

import json
from collections import Counter
from collections.abc import Callable
from typing import Any

from compliance_copilot.drafting.prompt import restore_aliases
from compliance_copilot.drafting.schema import DraftStatus, DraftStore, FindingDraft, Review, now_utc, sha256_of

FIELDS = {
    "title": "Título",
    "condition": "Condición",
    "criteria": "Criterio",
    "cause": "Causa",
    "effect": "Efecto",
    "recommendation": "Recomendación",
}


def review_pending(
    store: DraftStore,
    payloads: dict[str, dict[str, Any]],
    reviewer: str,
    ask: Callable[[str], str] = input,
    say: Callable[[str], None] = print,
    on_change: Callable[[], None] = lambda: None,
    aliases: dict[str, str] | None = None,
) -> Counter[str]:
    """Recorre los borradores pendientes en el orden del plan. ``on_change`` se llama tras cada decisión."""
    summary: Counter[str] = Counter()
    pending = [check for check in payloads if (r := store.records.get(check)) and r.status is DraftStatus.PENDING]
    say(f"{len(pending)} borradores pendientes de revisión.\n")

    for number, check_id in enumerate(pending, start=1):
        record = store.records[check_id]
        payload = payloads[check_id]
        if record.input_sha256 != sha256_of(payload):
            say(f"[{number}/{len(pending)}] {check_id}: el escaneo cambió desde que se redactó. Vuelve a generarlo.")
            summary["outdated"] += 1
            continue

        names = aliases or {}
        say(_render(number, len(pending), payload, record.draft, names))
        choice = _ask_choice(ask)
        if choice == "q":
            break
        if choice == "s":
            summary["skipped"] += 1
            continue

        if choice == "a":
            final, decision, comment = record.draft, DraftStatus.APPROVED, ""
        elif choice == "e":
            final = _edit(record.draft, ask, say)
            decision = DraftStatus.APPROVED_WITH_EDITS if final != record.draft else DraftStatus.APPROVED
            comment = ask("Comentario (opcional): ").strip()
        else:  # "r"
            final, decision = None, DraftStatus.REJECTED
            comment = ""
            while not comment:
                comment = ask("Motivo del rechazo (obligatorio): ").strip()

        record.review = Review(
            reviewer=reviewer,
            reviewed_at=now_utc(),
            decision=decision,
            final=final,
            final_sha256=final.sha256() if final else None,
            comment=comment,
        )
        record.status = decision
        summary[decision.value] += 1
        on_change()
    return summary


def _render(number: int, total: int, payload: dict[str, Any], draft: FindingDraft, names: dict[str, str]) -> str:
    """Muestra el borrador con los nombres reales: el modelo vio seudónimos, quien revisa ve la realidad."""
    risk = payload["riesgo"]
    controls = ", ".join(c["id"] for c in payload["controles_iso27001"]) or "sin mapeo"
    lines = [
        "=" * 100,
        f"[{number}/{total}] {payload['check_id']}",
        f"Datos: riesgo {risk['nivel']} ({risk['puntuacion']}) · {payload['recursos_total']} recursos · "
        f"controles {controls}",
        f"Recursos: {restore_aliases(', '.join(r['nombre'] for r in payload['recursos']), names)}",
        "-" * 100,
    ]
    for field, label in FIELDS.items():
        lines += [f"{label}:", f"  {restore_aliases(getattr(draft, field), names)}", ""]
    lines.append(f"Controles citados: {', '.join(draft.cited_controls)} · Nivel citado: {draft.cited_risk_level}")
    return "\n".join(lines)


def _ask_choice(ask: Callable[[str], str]) -> str:
    while True:
        choice = ask("[a]probar  [e]ditar  [r]echazar  [s]altar  [q]salir: ").strip().lower()[:1]
        if choice in {"a", "e", "r", "s", "q"}:
            return choice


def _edit(draft: FindingDraft, ask: Callable[[str], str], say: Callable[[str], None]) -> FindingDraft:
    """Edición campo por campo. Enter deja el texto como está."""
    values = draft.model_dump()
    for field, label in FIELDS.items():
        new = ask(f"{label} (Enter para mantener): ").strip()
        if new:
            values[field] = new
    edited = FindingDraft.model_validate(values)
    say("Cambios: " + json.dumps(
        {f: True for f in FIELDS if getattr(edited, f) != getattr(draft, f)}, ensure_ascii=False))
    return edited
