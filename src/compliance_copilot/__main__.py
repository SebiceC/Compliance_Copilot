"""Línea de comandos: ``python -m compliance_copilot <comando>``.

- ``report``: genera los entregables (Markdown, Excel) y el paquete de evidencias a partir de un escaneo.
- ``draft``: redacta borradores de hallazgos de auditoría con Claude (requiere credencial de Anthropic).
- ``review``: revisión humana de los borradores (aprobar, editar o rechazar).
- ``verify``: comprueba que los entregables no se modificaron desde que se generaron.
- ``sanitize``: anonimiza un escaneo (ver docs/anonimizacion.md).
"""

import argparse
import dataclasses
import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path

from compliance_copilot import sanitize
from compliance_copilot.catalogs import load_catalog
from compliance_copilot.drafting.client import DEFAULT_MODEL, MODELS, ClaudeDrafter, Drafter, DrafterUnavailable
from compliance_copilot.drafting.prompt import aliases_for, user_message
from compliance_copilot.drafting.review import review_pending
from compliance_copilot.drafting.runner import audit_entries, report_payloads, run_drafting
from compliance_copilot.drafting.schema import DraftStore
from compliance_copilot.parsers.prowler_ocsf import parse_ocsf_file
from compliance_copilot.reports.builders import LEVEL_LABEL, SOA_FRAMEWORK, Report, build_report
from compliance_copilot.reports.evidence import MANIFEST, verify_manifest, write_evidence
from compliance_copilot.reports.excel import write_excel
from compliance_copilot.reports.markdown import write_markdown
from compliance_copilot.risk import RiskLevel

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INCOMPLETE = 3  # se generaron entregables, pero faltan hallazgos (ADR 0003)
EXIT_VERIFY_FAILED = 4

LEVEL_NAMES = {level.value: level for level in RiskLevel}


def main(argv: list[str] | None = None, drafter_factory: Callable[..., Drafter] = ClaudeDrafter) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(prog="python -m compliance_copilot")
    commands = parser.add_subparsers(dest="command", required=True)

    report = commands.add_parser("report", help="genera los entregables a partir de un escaneo OCSF de Prowler")
    report.add_argument("scan", type=Path, help="archivo .ocsf.json de Prowler")
    report.add_argument("-o", "--output", type=Path, help="carpeta de salida (por defecto reports/<fecha>)")
    report.add_argument("--drafts", type=Path, help="borradores revisados: incluye los textos aprobados")

    draft = commands.add_parser("draft", help="redacta hallazgos de auditoría con Claude (cuesta dinero)")
    draft.add_argument("scan", type=Path)
    draft.add_argument("--drafts", type=Path, help="archivo de borradores (por defecto drafts/<fecha>.json)")
    draft.add_argument("--levels", default="critical,high,medium,low",
                       help="niveles de riesgo a redactar, separados por coma (p. ej. critical,high)")
    draft.add_argument("--limit", type=int, help="máximo de llamadas a la API en esta ejecución")
    draft.add_argument("--model", choices=MODELS, default=DEFAULT_MODEL,
                       help=f"modelo que redacta (por defecto {DEFAULT_MODEL}); cada modelo usa su propio archivo")
    draft.add_argument("--dry-run", action="store_true",
                       help="no llama a la API: muestra cuántos hallazgos se redactarían y qué datos saldrían")

    review = commands.add_parser("review", help="revisión humana de los borradores")
    review.add_argument("scan", type=Path)
    review.add_argument("--drafts", type=Path, help="archivo de borradores (por defecto el del modelo de --model)")
    review.add_argument("--model", choices=MODELS, default=DEFAULT_MODEL, help="elige el archivo por defecto")
    review.add_argument("--reviewer", required=True, help="nombre de quien revisa (queda en el registro)")

    verify = commands.add_parser("verify", help="verifica los hashes de un paquete generado")
    verify.add_argument("manifest", type=Path, help=f"ruta del {MANIFEST}")
    verify.add_argument("--source", type=Path, help="archivo de escaneo original, para verificarlo también")

    commands.add_parser("sanitize", help="anonimiza un escaneo", add_help=False)

    args, rest = parser.parse_known_args(argv)
    if args.command == "sanitize":
        return sanitize.main(rest)
    if rest:
        parser.error(f"argumentos no reconocidos: {' '.join(rest)}")
    if args.command == "verify":
        return _verify(args.manifest, args.source)
    if args.command == "draft":
        return _draft(args, drafter_factory)
    if args.command == "review":
        return _review(args)
    return _report(args.scan, args.output, args.drafts)


def _scan_stamp(report: Report) -> str:
    when = report.scan.last_observed_at
    return when.strftime("%Y%m%d-%H%M%S") if when else "sin-fecha"


def _drafts_path(report: Report, model: str) -> Path:
    """Un archivo por modelo: si compartieran archivo, la idempotencia omitiría lo que ya redactó otro modelo."""
    return Path("drafts") / f"{_scan_stamp(report)}-{model}.json"


def _report(scan: Path, output: Path | None, drafts_path: Path | None) -> int:
    report = build_report(parse_ocsf_file(scan))
    output = output or Path("reports") / _scan_stamp(report)
    drafts = None
    if drafts_path is not None:
        drafts = DraftStore.load(drafts_path)
        report = dataclasses.replace(report, audit=audit_entries(report, drafts, load_catalog(SOA_FRAMEWORK)))

    deliverables = [*write_markdown(report, output), write_excel(report, output)]
    manifest = write_evidence(report, output, deliverables, drafts)

    levels = report.level_counts
    print(f"Entregables en {output}")
    print(f"  {len(report.findings)} hallazgos · {len(report.risks)} riesgos: "
          + ", ".join(f"{levels[lvl]} {LEVEL_LABEL[lvl].lower()}" for lvl in reversed(RiskLevel)))
    print(f"  SoA: {len(report.soa)} controles · plan: {len(report.remediation)} acciones · manifest: {manifest.name}")
    if report.audit:
        approved = sum(1 for e in report.audit.values() if e.text is not None)
        print(f"  Hallazgos de auditoría: {approved} de {len(report.remediation)} con redacción aprobada")
    if not report.is_complete:
        print(f"ATENCIÓN: {len(report.parse_errors)} hallazgos no se pudieron leer; los entregables lo indican.",
              file=sys.stderr)
        return EXIT_INCOMPLETE
    return EXIT_OK


def _draft(args: argparse.Namespace, drafter_factory: Callable[..., Drafter]) -> int:
    try:
        levels = [LEVEL_NAMES[name.strip()] for name in args.levels.split(",") if name.strip()]
    except KeyError as exc:
        print(f"nivel desconocido: {exc}; usa {', '.join(LEVEL_NAMES)}", file=sys.stderr)
        return EXIT_ERROR

    report = build_report(parse_ocsf_file(args.scan))
    catalog = load_catalog(SOA_FRAMEWORK)
    path = args.drafts or _drafts_path(report, args.model)
    store = DraftStore.load(path)

    if args.dry_run:
        selected = [a for a in report.remediation if a.max_level in levels]
        payloads = report_payloads(report, catalog)
        print(f"Se redactarían hasta {len(selected)} hallazgos (los que ya tengan borrador vigente se omiten).")
        if selected:
            print("Datos que saldrían hacia la API para el primero (anonimizados):\n")
            print(user_message(payloads[selected[0].check_id]))
        return EXIT_OK

    try:
        summary = run_drafting(report, store, drafter_factory(model=MODELS[args.model]), catalog, levels, args.limit,
                               on_record=lambda record: store.save(path))
    except DrafterUnavailable as exc:
        store.save(path)
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    store.save(path)

    print(f"Borradores en {path}")
    print("  " + json.dumps(dict(summary), ensure_ascii=False))
    if summary["failed"]:
        print(f"  {summary['failed']} fallaron: revisa 'problems' en el archivo; se reintentan en la próxima ejecución.")
    return EXIT_OK


def _review(args: argparse.Namespace) -> int:
    report = build_report(parse_ocsf_file(args.scan))
    path = args.drafts or _drafts_path(report, args.model)
    if not path.exists():
        print(f"no existe {path}: genera los borradores con 'draft'", file=sys.stderr)
        return EXIT_ERROR
    store = DraftStore.load(path)
    summary = review_pending(store, report_payloads(report, load_catalog(SOA_FRAMEWORK)), args.reviewer,
                             on_change=lambda: store.save(path),
                             aliases=aliases_for(report.findings))
    store.save(path)
    print("\nRevisión: " + json.dumps(dict(summary), ensure_ascii=False))
    return EXIT_OK


def _verify(manifest: Path, source: Path | None) -> int:
    problems = verify_manifest(manifest, source)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return EXIT_VERIFY_FAILED
    print("Todos los archivos coinciden con el manifest.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
