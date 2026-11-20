"""La llamada a Claude. Es el único módulo que habla con la API.

- Modelo Claude Sonnet 5.5 (ADR 0005) con effort ``medium``: redactar con todos los datos dados no requiere
  razonamiento profundo (effort controla cuánto piensa el modelo).
- Structured outputs (``output_format=FindingDraft``): la respuesta llega validada contra el esquema.
- Fallback del servidor (``fallbacks="default"``): si el modelo se niega por un falso positivo de sus
  clasificadores (p. ej. por términos de seguridad), la API reintenta con otro modelo en la misma llamada.
- Prompt caching sobre las instrucciones fijas: cada hallazgo solo paga sus propios datos.

La credencial se lee del entorno (``ANTHROPIC_API_KEY`` o un perfil de ``ant auth login``); nunca va en el repo.
"""

from dataclasses import dataclass, field
from typing import Protocol

import anthropic
from pydantic import ValidationError

from compliance_copilot.drafting.prompt import SYSTEM_PROMPT
from compliance_copilot.drafting.schema import FindingDraft

# Modelos que se pueden elegir con ``draft --model`` (ver docs/redaccion-ia.md).
MODELS = {"opus": "claude-opus-5-5", "sonnet": "claude-sonnet-5-5", "haiku": "claude-haiku-5-5"}
DEFAULT_MODEL = "sonnet"  # elegido comparando los tres sobre los mismos hallazgos (ADR 0005)
MODEL = MODELS[DEFAULT_MODEL]
# Haiku 5.5 no tiene fallback del servidor: enviar el parámetro no sirve (o da 400). Sus negativas quedan fallidas.
WITHOUT_FALLBACK = {"claude-haiku-5-5"}
EFFORT = "medium"
MAX_TOKENS = 16000
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class DrafterUnavailable(RuntimeError):
    """Error que impide redactar cualquier hallazgo (credencial inválida, sin saldo): se detiene todo."""


# Errores de la cuenta, no del hallazgo: reintentar con el siguiente hallazgo daría el mismo error.
ACCOUNT_ERRORS: tuple[type[anthropic.APIStatusError], ...] = (
    anthropic.PaymentRequiredError,            # 402: sin método de pago o facturación no disponible
    anthropic.EnforcedSpendLimitReachedError,  # 429: se alcanzó el límite de gasto configurado
    anthropic.ContractSpendLimitReachedError,
    anthropic.OrganizationOnHoldError,
)
# Hoy la API responde "sin saldo" como 400 genérico; solo el mensaje lo distingue.
NO_CREDIT_MESSAGE = "credit balance is too low"


def _is_account_problem(exc: anthropic.APIStatusError) -> bool:
    return isinstance(exc, ACCOUNT_ERRORS) or NO_CREDIT_MESSAGE in str(exc.message).lower()


@dataclass(frozen=True)
class DraftResponse:
    draft: FindingDraft | None
    model: str
    problems: list[str] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)


class Drafter(Protocol):
    """Lo que necesita el resto del código. Los tests usan una implementación falsa: no gastan dinero."""

    def draft(self, user_message: str) -> DraftResponse: ...


class ClaudeDrafter:
    def __init__(self, client: anthropic.Anthropic | None = None, model: str = MODEL, effort: str = EFFORT) -> None:
        self._client = client or anthropic.Anthropic()
        self.model = model
        self.effort = effort

    def draft(self, user_message: str) -> DraftResponse:
        fallback = {} if self.model in WITHOUT_FALLBACK else {"betas": [FALLBACK_BETA], "fallbacks": "default"}
        try:
            response = self._client.beta.messages.parse(
                model=self.model,
                max_tokens=MAX_TOKENS,
                **fallback,
                system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
                output_config={"effort": self.effort},
                output_format=FindingDraft,
                messages=[{"role": "user", "content": user_message}],
            )
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            raise DrafterUnavailable(f"credencial de Anthropic inválida o sin permisos: {exc.message}") from exc
        except anthropic.APIStatusError as exc:  # 400, 404, 429 tras reintentos, 5xx tras reintentos
            if _is_account_problem(exc):
                raise DrafterUnavailable(f"la cuenta de Anthropic no puede facturar: {exc.message}") from exc
            return DraftResponse(None, self.model, [f"error de la API ({exc.status_code}): {exc.message}"])
        except anthropic.APIConnectionError as exc:
            return DraftResponse(None, self.model, [f"sin conexión con la API: {exc}"])
        except ValidationError as exc:  # la respuesta no encajó en FindingDraft
            return DraftResponse(None, self.model, [f"respuesta con formato inválido: {exc.error_count()} errores"])

        usage = {
            name: getattr(response.usage, name) or 0
            for name in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
        }
        if response.stop_reason == "refusal":
            category = response.stop_details.category if response.stop_details else None
            return DraftResponse(None, response.model, [f"el modelo se negó a responder (categoría: {category})"], usage)
        if response.stop_reason == "max_tokens":
            return DraftResponse(None, response.model, ["respuesta cortada por max_tokens"], usage)
        if response.parsed_output is None:
            return DraftResponse(None, response.model, ["respuesta sin contenido estructurado"], usage)
        return DraftResponse(response.parsed_output, response.model, [], usage)
