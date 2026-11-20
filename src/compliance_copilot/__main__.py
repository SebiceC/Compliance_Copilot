"""Línea de comandos: ``python -m compliance_copilot <comando>``.

- ``report``: genera los entregables (Markdown, Excel) y el paquete de evidencias a partir de un escaneo.
- ``verify``: comprueba que los entregables no se modificaron desde que se generaron.
- ``sanitize``: anonimiza un escaneo (ver docs/anonimizacion.md).
"""

import argparse
import logging
import sys
from pathlib import Path

from compliance_copilot import sanitize
from compliance_copilot.parsers.prowler_ocsf import parse_ocsf_file
from compliance_copilot.reports.builders import LEVEL_LABEL, build_report
from compliance_copilot.reports.evidence import MANIFEST, verify_manifest, write_evidence
from compliance_copilot.reports.excel import write_excel
from compliance_copilot.reports.markdown import write_markdown
from compliance_copilot.risk import RiskLevel

EXIT_OK = 0
EXIT_INCOMPLETE = 3  # se generaron entregables, pero faltan hallazgos (ADR 0003)
EXIT_VERIFY_FAILED = 4


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(prog="python -m compliance_copilot")
    commands = parser.add_subparsers(dest="command", required=True)

    report = commands.add_parser("report", help="genera los entregables a partir de un escaneo OCSF de Prowler")
    report.add_argument("scan", type=Path, help="archivo .ocsf.json de Prowler")
    report.add_argument("-o", "--output", type=Path,
                        help="carpeta de salida (por defecto reports/<fecha del escaneo>)")

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
    return _report(args.scan, args.output)


def _report(scan: Path, output: Path | None) -> int:
    parsed = parse_ocsf_file(scan)
    report = build_report(parsed)
    if output is None:
        when = report.scan.last_observed_at
        output = Path("reports") / (when.strftime("%Y%m%d-%H%M%S") if when else "sin-fecha")

    deliverables = [*write_markdown(report, output), write_excel(report, output)]
    manifest = write_evidence(report, output, deliverables)

    levels = report.level_counts
    print(f"Entregables en {output}")
    print(f"  {len(report.findings)} hallazgos · {len(report.risks)} riesgos: "
          + ", ".join(f"{levels[lvl]} {LEVEL_LABEL[lvl].lower()}" for lvl in reversed(RiskLevel)))
    print(f"  SoA: {len(report.soa)} controles · plan: {len(report.remediation)} acciones · manifest: {manifest.name}")
    if not report.is_complete:
        print(f"ATENCIÓN: {len(report.parse_errors)} hallazgos no se pudieron leer; los entregables lo indican.",
              file=sys.stderr)
        return EXIT_INCOMPLETE
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
