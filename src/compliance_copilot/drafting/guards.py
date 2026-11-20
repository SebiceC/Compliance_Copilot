"""Validación de los borradores: el modelo redacta, pero no puede contradecir los datos.

Un borrador que falla aquí no llega a la persona que revisa: se marca FAILED con los motivos.
"""

import re
from typing import Any

from compliance_copilot.drafting.schema import FindingDraft

MAX_FIELD_CHARS = 1500
CONTROL_ID = re.compile(r"\bA\.\d{1,2}\.\d{1,2}\b")
TWELVE_DIGITS = re.compile(r"(?<!\d)\d{12}(?!\d)")
TEXT_FIELDS = ("title", "condition", "criteria", "cause", "effect", "recommendation")


def check_draft(draft: FindingDraft, payload: dict[str, Any]) -> list[str]:
    """Devuelve los problemas del borrador frente a los datos que se le dieron. Vacío si es aceptable."""
    problems: list[str] = []
    allowed_controls = {c["id"] for c in payload.get("controles_iso27001", [])}
    expected_level = payload["riesgo"]["nivel"]
    payload_text = str(payload)

    for field in TEXT_FIELDS:
        value = getattr(draft, field).strip()
        if not value:
            problems.append(f"{field} está vacío")
        elif len(value) > MAX_FIELD_CHARS:
            problems.append(f"{field} supera {MAX_FIELD_CHARS} caracteres")

    # 1. Controles: ni los declarados ni los que aparecen en el texto pueden salir de la lista del hallazgo.
    invented = set(draft.cited_controls) - allowed_controls
    if invented:
        problems.append(f"cita controles que no son del hallazgo: {sorted(invented)}")
    in_text = {m for field in TEXT_FIELDS for m in CONTROL_ID.findall(getattr(draft, field))}
    if in_text - allowed_controls:
        problems.append(f"el texto menciona controles que no son del hallazgo: {sorted(in_text - allowed_controls)}")
    if allowed_controls and not set(draft.cited_controls) & allowed_controls:
        problems.append("no cita ninguno de los controles del hallazgo")

    # 2. Nivel de riesgo: lo calcula el motor, no el modelo.
    if draft.cited_risk_level.strip().lower() != expected_level.lower():
        problems.append(f"cambia el nivel de riesgo: dice '{draft.cited_risk_level}', el motor dice '{expected_level}'")
    if expected_level.lower() not in draft.effect.lower():
        problems.append(f"effect no menciona el nivel de riesgo '{expected_level}'")

    # 3. Identificadores: no puede aparecer un ID de cuenta que no estaba en los datos.
    for field in TEXT_FIELDS:
        for number in TWELVE_DIGITS.findall(getattr(draft, field)):
            if number not in payload_text:
                problems.append(f"{field} contiene un identificador que no está en los datos: {number}")

    return problems
