# Entregables

Un solo comando convierte un escaneo de Prowler en los entregables que pide una auditoría:

```bash
python -m compliance_copilot report output/<escaneo>.ocsf.json -o reports/<carpeta>
```

Sin `-o`, la salida va a `reports/<fecha y hora del escaneo>`. La carpeta `reports/` está en `.gitignore`: los
entregables reales contienen datos de la cuenta.

| Archivo | Contenido |
|---|---|
| `resumen.md` | Totales, riesgos por nivel, mapa de calor, estado de cada declaración, recursos sin clasificar, hallazgos no leídos |
| `matriz-riesgos.md` | Un riesgo por hallazgo FAIL, de mayor a menor, con su justificación |
| `soa-iso27001.md` | Los 93 controles del Anexo A con su estado técnico (la declaración de ISO 27001; ver abajo) |
| `matriz-soc2.md` | Los 61 Trust Services Criteria de SOC 2 con su estado técnico |
| `perfil-nist-csf.md` | Las 106 subcategorías de NIST CSF 2.0 con su estado técnico (perfil actual) |
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

## Declaraciones por marco

Cada marco tiene su declaración, con el vocabulario que espera su auditor (ADR 0007). La lógica del estado
técnico es la misma para todos; cambian el nombre del entregable y las columnas que decide una persona, que se
definen en el catálogo del marco (`src/compliance_copilot/catalogs/`):

| Marco | Entregable | Columnas que decide una persona | Estado |
|---|---|---|---|
| ISO 27001:2022 | SoA (`soa-iso27001.md`) | Aplicable, Justificación | listo |
| SOC 2 | Matriz de criterios (`matriz-soc2.md`) | En alcance, Justificación | listo |
| NIST CSF 2.0 | Perfil actual (`perfil-nist-csf.md`) | Perfil objetivo, Prioridad | listo |
| Ley 1581 de 2012 | Matriz técnica | Aplica, Evidencia manual | Fase 9 |

**IDs sin correspondencia.** Los IDs que Prowler asigna a un marco se traducen al formato oficial del catálogo.
Los que no tienen correspondencia no se descartan: aparecen en el resumen, en una sección de la declaración, en
la hoja *Sin correspondencia* del Excel y en `evidencias/controles/<marco>/_sin-correspondencia.json`. Una persona
decide si falta el requisito en el catálogo o si el mapeo de Prowler está mal.

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

## Matriz de criterios SOC 2

Los **61 Trust Services Criteria** de AICPA (`catalogs/soc2-tsc.json`), agrupados por serie: los criterios comunes
CC1 a CC9 y las categorías Disponibilidad (A), Confidencialidad (C), Integridad del procesamiento (PI) y
Privacidad (P). Identificadores oficiales con títulos propios (el texto de los criterios tiene derechos de AICPA).

- **En alcance** en vez de *Aplicable*: los criterios comunes siempre están en un informe SOC 2; las otras
  categorías solo si la organización las incluye.
- **Tipo I y Tipo II:** un escaneo es evidencia de un momento, útil para un informe Tipo I (diseño de los
  controles en una fecha). Un Tipo II exige evidencia de que funcionaron durante un período (de 3 a 12 meses):
  la darían escaneos periódicos (hoja de ruta, Fase 12).
- **IDs de Prowler:** se traducen a su formato oficial (`cc_6_1` → `CC6.1`, `cc_a_1_1` → `A1.1`). En el escaneo 5,
  los 23 IDs tuvieron correspondencia.
- **El mapeo de Prowler es insumo, no verdad.** Prowler asigna checks técnicos a criterios organizacionales (por
  ejemplo, checks de IAM a CC1.3, *estructuras y autoridades*, o a CC3.x, *evaluación de riesgos*). Un hallazgo
  así es evidencia parcial: el criterio exige además evidencia de gobierno que ningún escáner ve.

## Perfil actual NIST CSF 2.0

Las **106 subcategorías** de NIST CSF 2.0 (`catalogs/nist-csf-2.0.json`, según el Apéndice A de NIST CSWP 29),
agrupadas por sus 22 categorías. El CSF no se "cumple": se compara el perfil actual con un **perfil objetivo** y
se prioriza la brecha; esas dos columnas las decide la organización.

**El mapeo "NIST CSF 2.0" de Prowler usa IDs de la versión 1.1.** Se traduce a la 2.0 con la tabla de
[docs/correspondencia-nist-csf.md](correspondencia-nist-csf.md), basada en el documento oficial de NIST de
elementos retirados. Un ID de la 1.1 puede corresponder a varias subcategorías de la 2.0: el hallazgo cuenta en
todas, así que la suma de PASS y FAIL del perfil puede superar la cantidad de hallazgos. Once filas de la tabla no
tienen equivalencia oficial y se asignaron por significado: están marcadas para revisión.

## Plan de remediación

Una acción por check: una misma corrección (por ejemplo, una configuración de S3) arregla todos los recursos
afectados. Se ordena por el riesgo más alto del grupo y luego por cantidad de recursos. Incluye la lista de
recursos, los controles ISO 27001 relacionados y cómo corregirlo (texto del escáner). *Responsable* y *Fecha
compromiso* las asigna la organización.

## Paquete de evidencias y cadena de custodia

- `evidencias/hallazgos.json`: todos los hallazgos normalizados (PASS, FAIL y MANUAL). Los PASS son evidencia de
  que un control funciona.
- `evidencias/controles/<marco>/<requisito>.json`: para cada requisito con hallazgos, qué checks lo
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

**Límite:** el hash prueba que nada cambió *después* de generar el paquete, no quién lo generó. Los escaneos
desde CI firman el manifest para probar su origen (ver `docs/ci.md`).

**Regresión:** `tests/test_golden.py` compara la salida completa sobre la muestra del laboratorio con una
referencia en `tests/golden/`. Un cambio en cualquier entregable aparece en el diff del PR.

## Pendiente

- Declaración de la Ley 1581 (Fase 9 de `docs/hoja-de-ruta-v1.md`).
