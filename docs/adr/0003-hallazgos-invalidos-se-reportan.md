# 3. Los hallazgos inválidos se reportan, no se descartan en silencio

- **Fecha:** 2026-11-19
- **Estado:** Aceptada

## Contexto

El parser convierte cada hallazgo de Prowler en un `Finding` validado. Un hallazgo puede no pasar la
validación: un campo obligatorio ausente, un valor fuera de lo esperado o un cambio de formato en una versión
nueva de Prowler. En una herramienta de auditoría, cada hallazgo es evidencia de un control; perder uno sin
aviso hace que un control parezca cubierto (o sin fallos) cuando no lo está.

## Opciones consideradas

- **Fallar todo el lote**
  - A favor: imposible ignorar el problema.
  - En contra: un solo hallazgo roto bloquea los demás; en un pipeline programado no se produce ningún
    entregable.
- **Saltar el hallazgo en silencio**
  - A favor: el pipeline siempre termina.
  - En contra: pérdida de evidencia no detectable; el reporte afirma más de lo que se puede sostener.
- **Saltar el hallazgo y reportarlo**
  - A favor: se procesan los válidos y se sabe exactamente qué falta, dónde está y por qué.
  - En contra: quien consume el resultado debe revisar los errores; el parser no puede obligarlo.

## Decisión

**Saltar y reportar.** `parse_ocsf_file` devuelve un `ParseResult` con los hallazgos válidos (`findings`), los
que fallaron (`errors`, cada uno con posición, `finding_uid`, `check_id` y motivo) y el total del archivo.
`ParseResult.is_complete` indica si no se perdió ninguno. Cada error se registra además con `logging` como
advertencia.

Si el **archivo** no se puede leer o no es una lista, el parser sí lanza una excepción: en ese caso no hay
evidencia parcial que rescatar.

## Consecuencias

- **Ganamos:** el escaneo nunca se pierde por un hallazgo; los errores son trazables hasta su posición en el
  archivo original.
- **Aceptamos:** la responsabilidad de actuar sobre los errores pasa a quien consume el resultado.
- **Nos obliga a futuro:**
  - Los entregables (SoA, paquete de evidencias) deben indicar cuántos hallazgos no se pudieron leer, y no
    presentarse como completos si `is_complete` es falso.
  - En CI (Fase 5), un `ParseResult` incompleto debe hacer visible el problema (advertencia o fallo del
    job, a definir).

## Revisión

Reevaluar si los errores se vuelven frecuentes (por ejemplo, tras una actualización de Prowler) o si un uso
regulado exige que el lote completo se rechace ante cualquier error.
