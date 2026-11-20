# Entregables

Un solo comando convierte un escaneo de Prowler en los entregables que pide una auditoría:

```bash
python -m compliance_copilot report output/<escaneo>.ocsf.json -o reports/<carpeta>
```

Sin `-o`, la salida va a `reports/<fecha y hora del escaneo>`. La carpeta `reports/` está en `.gitignore`: los
entregables reales contienen datos de la cuenta.

| Archivo | Contenido |
|---|---|
| `resumen.md` | Totales, riesgos por nivel, mapa de calor, estado de la SoA, recursos sin clasificar, hallazgos no leídos |
| `matriz-riesgos.md` | Un riesgo por hallazgo FAIL, de mayor a menor, con su justificación |
| `soa-iso27001.md` | Los 93 controles del Anexo A con su estado técnico |
| `plan-remediacion.md` | Una acción por check, ordenada por riesgo |
| `compliance-copilot.xlsx` | Lo mismo en un libro de Excel (una hoja por entregable, más el mapa de calor) |
| `evidencias/` | Hallazgos normalizados y una evidencia por control |
| `manifest.json` | Datos del escaneo y SHA-256 de cada archivo |

**Código de salida:** `0` si todo salió bien; `3` si se generaron los entregables pero algún hallazgo no se pudo
leer (ADR 0003). En ese caso todos los entregables lo indican.

Los entregables se generan **sin IA**: todo número y estado sale de reglas documentadas y verificadas con tests.

---

## Matriz de riesgos

Una fila por hallazgo FAIL, evaluada con `docs/metodologia-riesgo.md`. Columnas: nivel, riesgo, probabilidad,
impacto, hallazgo, recurso, clasificación, controles ISO 27001, tratamiento sugerido y **justificación** (el
texto que permite recalcular el riesgo a mano). El tratamiento es una sugerencia: lo decide una persona.

## SoA ISO/IEC 27001:2022

Recorre el **catálogo completo** (93 controles, `src/compliance_copilot/catalogs/iso27001-2022.json`), no solo los
controles que toca el escaneo: la cláusula 6.1.3 d exige que la SoA incluya todos.

| Estado técnico | Regla |
|---|---|
| Con brechas | Al menos un FAIL |
| Requiere revisión | Algún MANUAL y ningún FAIL: un check que no puede decidir solo no se da por bueno |
| Sin brechas detectadas | Solo PASS |
| Evidencia manual requerida | Ningún check lo cubre (todos los controles de personas y físicos, y la mayoría de los organizacionales) |

Además: conteos de PASS, FAIL y MANUAL, el **riesgo máximo** entre sus FAIL y los checks relacionados. Así un
control con 40 PASS y 1 FAIL bajo no se ve igual que uno con fallos críticos.

**"Sin brechas detectadas" no es "cumple":** solo dice que los checks automáticos no encontraron fallos.

**Columnas que decide la organización** (vacías a propósito, resaltadas en azul en el Excel): *Aplicable* y
*Justificación*. Ni la herramienta ni la IA deciden la aplicabilidad de un control.

## Plan de remediación

Una acción por check: una misma corrección (por ejemplo, una configuración de S3) arregla todos los recursos
afectados. Se ordena por el riesgo más alto del grupo y luego por cantidad de recursos. Incluye la lista de
recursos, los controles ISO 27001 relacionados y cómo corregirlo (texto del escáner). *Responsable* y *Fecha
compromiso* las asigna la organización.

## Paquete de evidencias y cadena de custodia

- `evidencias/hallazgos.json`: todos los hallazgos normalizados (PASS, FAIL y MANUAL). Los PASS son evidencia de
  que un control funciona.
- `evidencias/controles/ISO27001-2022/<control>.json`: para cada control con hallazgos, qué checks lo
  sustentan, sobre qué recurso, con qué resultado y **cuándo** se observaron (UTC).
- `manifest.json`: versión de la herramienta y de la metodología, datos del escaneo (escáner, versión,
  `scan_id`, cuentas, fechas), **SHA-256 del archivo de origen** y de **cada archivo generado**, y los hallazgos
  que no se pudieron leer.

Verificación (por ejemplo, la hace el auditor al recibir el paquete):

```bash
python -m compliance_copilot verify reports/<carpeta>/manifest.json --source output/<escaneo>.ocsf.json
```

Si un entregable o una evidencia cambió, o si el archivo de origen no es el que se usó, la verificación falla
(código de salida `4`) y dice qué archivo no coincide.

**Límite:** el hash prueba que nada cambió *después* de generar el paquete, no quién lo generó. Para eso haría
falta firmar el manifest (pendiente para la fase de CI).

## Pendiente

- SoA y cobertura para SOC 2 y NIST CSF 2.0 (los hallazgos ya traen el mapeo).
- Ley 1581 de 2012: requiere un mapeo propio; Prowler no la cubre.
- Redacción de hallazgos en formato de auditoría con IA, con aprobación humana.
