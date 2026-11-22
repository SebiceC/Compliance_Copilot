# Compliance Copilot

> 🚧 **En construcción.** Este README describe el objetivo del proyecto; las secciones marcadas como
> *pendiente* todavía no están implementadas.

Pipeline en Python que convierte los hallazgos técnicos de [Prowler](https://github.com/prowler-cloud/prowler)
(AWS y Azure) en entregables de auditoría: matriz de riesgos, borrador de Declaración de Aplicabilidad (SoA),
paquete de evidencias por control y plan de remediación. Una IA redacta; una persona aprueba.

## El problema

Las herramientas de postura cloud entregan cientos de hallazgos técnicos. Un auditor de ISO 27001 o SOC 2 no
pide hallazgos: pide riesgos evaluados, una SoA, evidencias por control y un plan de tratamiento. Hoy ese
puente se construye a mano, en hojas de cálculo.

## Qué hace (y qué no)

Prowler ya mapea sus checks a marcos como ISO 27001 y SOC 2. **Este proyecto no reinventa ese mapeo: lo usa
como insumo.** Lo que agrega es lo que Prowler no hace:

| Capacidad | Estado |
|---|---|
| Ingesta de la salida de Prowler (JSON OCSF) con anonimización | listo para AWS (Azure pendiente) |
| Agrupación por control: ISO 27001:2022, SOC 2, NIST CSF 2.0 y Ley 1581 de 2012 (Colombia) | ISO 27001:2022 y SOC 2 listos; NIST CSF 2.0 y Ley 1581 pendientes |
| Evaluación de riesgo (probabilidad × impacto, matriz 5×5) con [metodología documentada](docs/metodologia-riesgo.md) | listo (metodología v0.2) |
| Entregables: matriz de riesgos y SoA (.xlsx / .md), paquete de evidencias, plan de remediación ([detalle](docs/entregables.md)) | listo (SoA de ISO 27001:2022) |
| Redacción de hallazgos en formato de auditoría con Claude, **solo publicados tras aprobación humana** ([detalle](docs/redaccion-ia.md)) | listo |
| Ejecución como compliance-as-code en GitHub Actions con OIDC, sin llaves de larga duración ([detalle](docs/ci.md)) | listo (tests, escaneo de AWS con aprobación manual y evidencia firmada) |

## Principios

- **La IA propone, la persona decide.** El estado de un control lo determinan el motor y la aprobación humana,
  nunca el modelo.
- **Solo lectura.** El escaneo usa permisos de auditoría (`SecurityAudit` + `ViewOnlyAccess` en AWS, `Reader`
  en Azure); la herramienta que mide no puede modificar lo que mide.
- **Sin datos reales en el repo.** Los ejemplos de `data/samples/` son sintéticos o anonimizados.
- **Sin texto de las normas.** Solo identificadores de control (ej. `A.8.24`) y títulos redactados para este
  proyecto.

## Límites

La herramienta solo puede evidenciar **controles técnicos**. Los controles organizacionales, de personas y
físicos de ISO 27001 aparecen en la SoA como *evidencia manual requerida*. No reemplaza a un auditor ni emite
una opinión de cumplimiento.

## Cómo correrlo

*En construcción.* Por ahora, con Python 3.13:

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows (PowerShell)
pip install -e .
pip install --group dev             # pytest, solo para desarrollo

# Tests (usan la muestra anonimizada de data/samples/)
pytest

# Generar los entregables y el paquete de evidencias (ver docs/entregables.md)
python -m compliance_copilot report output/<escaneo>.ocsf.json -o reports/<carpeta>

# Redactar hallazgos con Claude y revisarlos (ver docs/redaccion-ia.md); luego: report ... --drafts drafts/<fecha>-sonnet.json
python -m compliance_copilot draft output/<escaneo>.ocsf.json --levels critical,high --dry-run
python -m compliance_copilot draft output/<escaneo>.ocsf.json --levels critical,high
python -m compliance_copilot draft output/<escaneo>.ocsf.json --levels critical --limit 5 --model haiku  # comparar modelos
python -m compliance_copilot review output/<escaneo>.ocsf.json --reviewer "Nombre Apellido"

# Verificar que el paquete no se modificó
python -m compliance_copilot verify reports/<carpeta>/manifest.json

# Anonimizar un escaneo de Prowler antes de compartirlo (ver docs/anonimizacion.md)
python -m compliance_copilot sanitize output/<escaneo>.ocsf.json data/samples/<muestra>.ocsf.json
```

## Licencia

MIT, ver [LICENSE](LICENSE).
