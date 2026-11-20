"""Anonimizador de la salida OCSF de Prowler.

Reemplaza los identificadores de la cuenta real por seudónimos **consistentes** (el mismo valor real siempre
recibe el mismo seudónimo dentro de un archivo), para poder guardar muestras en ``data/samples/``, compartir
ejemplos o enviar hallazgos a un modelo de IA sin exponer la cuenta.

Trabaja sobre el JSON crudo, no sobre ``Finding``: la muestra anonimizada sigue teniendo el formato de Prowler
y sirve para probar el parser.

Uso::

    python -m compliance_copilot.sanitize ENTRADA.ocsf.json SALIDA.ocsf.json [--only-label project:compliance-copilot]
"""

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

# Seudónimo de un nombre de cuenta (``cloud.account.name``), que suele ser el nombre de una persona o empresa.
ACCOUNT_NAME_PSEUDONYM = "example-account"

# Claves cuyo contenido no se revisa con la regla de IP: los identificadores de control (``3.5.1.2`` en CIS)
# tienen forma de dirección IPv4 y no son datos de la cuenta.
_SKIP_IP_RULE_UNDER = frozenset({"compliance"})

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


class Sanitizer:
    """Reemplaza identificadores por seudónimos y recuerda cada reemplazo para poder verificarlo."""

    def __init__(self, account_names: set[str] | None = None) -> None:
        self._maps: dict[str, dict[str, str]] = {}
        self.originals: set[str] = set()  # valores reales encontrados, para la verificación final
        self.counts: Counter[str] = Counter()  # reemplazos por categoría, para el reporte

        # (categoría, patrón, generador del seudónimo n-ésimo). El orden importa: lo más específico primero.
        self._rules: list[tuple[str, re.Pattern[str], Callable[[int], str]]] = [
            # Llaves de acceso: no deberían aparecer nunca, pero si aparecen no pueden salir.
            ("access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), lambda n: f"AKIAEXAMPLE{n:09d}"),
            # IDs únicos de IAM (usuarios, roles, grupos, políticas): identifican a un principal concreto.
            ("iam_unique_id", re.compile(r"\b(?:AIDA|AROA|AGPA|ANPA|AIPA)[A-Z0-9]{13,21}\b"),
             lambda n: f"AIDAEXAMPLE{n:010d}"),
            # Sufijo aleatorio de los roles que crea Identity Center.
            ("sso_role_suffix", re.compile(r"(?<=AWSReservedSSO_)([A-Za-z0-9+=,.@-]+?)_[0-9a-f]{16}\b"),
             None),  # caso especial, ver _replace_sso_role
            ("organization_id", re.compile(r"\bo-[a-z0-9]{10,32}\b"), lambda n: f"o-example{n:05d}"),
            ("ou_id", re.compile(r"\bou-[a-z0-9]{4,32}-[a-z0-9]{8,32}\b"), lambda n: f"ou-exam-example{n:03d}"),
            # ID canónico de S3: 64 hexadecimales que identifican al dueño de la cuenta.
            ("s3_canonical_id", re.compile(r"\b[0-9a-f]{64}\b"), lambda n: f"{n:064x}"),
            # ID de cuenta AWS: 12 dígitos, también dentro de ARN y nombres de bucket.
            ("aws_account_id", re.compile(r"(?<!\d)\d{12}(?!\d)"), lambda n: f"{123456789000 + n:012d}"),
            ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), lambda n: f"user{n}@example.com"),
        ]
        self._names = {name for name in (account_names or set()) if name}
        if self._names:
            alternatives = "|".join(re.escape(name) for name in sorted(self._names, key=len, reverse=True))
            self._name_pattern: re.Pattern[str] | None = re.compile(alternatives, re.IGNORECASE)
        else:
            self._name_pattern = None

    def sanitize(self, data: Any, *, ip_rule: bool = True) -> Any:
        """Devuelve una copia anonimizada de ``data`` (dict, list o valores sueltos)."""
        if isinstance(data, dict):
            return {
                self._text(key, ip_rule=False): self.sanitize(value, ip_rule=ip_rule and key not in _SKIP_IP_RULE_UNDER)
                for key, value in data.items()
            }
        if isinstance(data, list):
            return [self.sanitize(item, ip_rule=ip_rule) for item in data]
        if isinstance(data, str):
            return self._text(data, ip_rule=ip_rule)
        return data  # números, booleanos y None no llevan identificadores

    def leaks(self, text: str) -> set[str]:
        """Valores reales que siguen apareciendo en ``text``. Debe devolver un conjunto vacío."""
        lowered = text.lower()
        # Un valor que ya era un seudónimo (al anonimizar un archivo ya anonimizado) no es un dato real.
        pseudonyms = {p.lower() for mapping in self._maps.values() for p in mapping.values()}
        return {
            original for original in self.originals
            if original.lower() not in pseudonyms and original.lower() in lowered
        }

    # --- internos ---------------------------------------------------------------------------------------

    def _pseudonym(self, category: str, original: str, make: Callable[[int], str]) -> str:
        mapping = self._maps.setdefault(category, {})
        if original not in mapping:
            mapping[original] = make(len(mapping) + 1)
            self.originals.add(original)
        self.counts[category] += 1
        return mapping[original]

    def _text(self, text: str, *, ip_rule: bool) -> str:
        for category, pattern, make in self._rules:
            if category == "sso_role_suffix":
                text = pattern.sub(self._replace_sso_role, text)
            else:
                text = pattern.sub(lambda m, c=category, f=make: self._pseudonym(c, m.group(0), f), text)
        if self._name_pattern is not None:
            text = self._name_pattern.sub(
                lambda m: self._pseudonym("account_name", m.group(0).lower(), lambda _: ACCOUNT_NAME_PSEUDONYM),
                text,
            )
        if ip_rule:
            text = _IPV4.sub(self._replace_ip, text)
        return text

    def _replace_sso_role(self, match: re.Match[str]) -> str:
        # Conserva el nombre del permission set (LabAdmin, ProwlerAudit): es información de diseño, no de la cuenta.
        suffix = match.group(0)[len(match.group(1)) + 1:]
        return f"{match.group(1)}_{self._pseudonym('sso_role_suffix', suffix, lambda n: f'{n:016x}')}"

    def _replace_ip(self, match: re.Match[str]) -> str:
        """Solo las IP públicas identifican algo; 0.0.0.0, 10.x o 172.31.x son iguales en cualquier cuenta."""
        raw = match.group(0)
        try:
            address = ipaddress.IPv4Address(raw)
        except ValueError:
            return raw  # no es una IP válida (p. ej. 999.1.1.1)
        if not address.is_global:
            return raw
        # 203.0.113.0/24 (TEST-NET-3) está reservado para documentación (RFC 5737).
        return self._pseudonym("public_ip", raw, lambda n: f"203.0.113.{n % 254 + 1}")


def sanitize_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], Sanitizer]:
    """Anonimiza una lista de hallazgos OCSF. Devuelve la copia y el ``Sanitizer`` (con reporte y verificación)."""
    names = {
        str(name)
        for finding in findings
        if isinstance(finding, dict) and (name := (finding.get("cloud") or {}).get("account", {}).get("name"))
    }
    sanitizer = Sanitizer(account_names=names)
    return sanitizer.sanitize(findings), sanitizer


def _has_label(finding: dict[str, Any], label: str) -> bool:
    return any(label in (resource.get("labels") or []) for resource in finding.get("resources") or [])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m compliance_copilot.sanitize",
        description="Anonimiza un archivo OCSF de Prowler.",
    )
    parser.add_argument("input", type=Path, help="archivo .ocsf.json de Prowler")
    parser.add_argument("output", type=Path, help="archivo anonimizado a escribir")
    parser.add_argument(
        "--only-label",
        metavar="CLAVE:VALOR",
        help="conservar solo los hallazgos cuyo recurso tenga este label (p. ej. project:compliance-copilot)",
    )
    args = parser.parse_args(argv)

    with args.input.open(encoding="utf-8") as f:
        findings = json.load(f)
    if not isinstance(findings, list):
        print(f"error: {args.input} no es una lista de hallazgos OCSF", file=sys.stderr)
        return 2

    if args.only_label:
        findings = [finding for finding in findings if isinstance(finding, dict) and _has_label(finding, args.only_label)]

    sanitized, sanitizer = sanitize_findings(findings)
    text = json.dumps(sanitized, indent=2, ensure_ascii=False) + "\n"

    # Verificación antes de escribir: si queda algún valor real, no se genera el archivo.
    leaked = sanitizer.leaks(text)
    if leaked:
        print(f"error: quedaron {len(leaked)} valores sin anonimizar; no se escribió {args.output}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8", newline="\n")

    print(f"{len(sanitized)} hallazgos anonimizados → {args.output}")
    for category, count in sorted(sanitizer.counts.items()):
        print(f"  {category}: {count} reemplazos de {len(sanitizer._maps[category])} valores distintos")
    return 0


if __name__ == "__main__":
    sys.exit(main())
