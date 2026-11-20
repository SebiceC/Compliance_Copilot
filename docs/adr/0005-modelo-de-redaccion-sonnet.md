# 5. Claude Sonnet 5.5 como modelo de redacción

- **Fecha:** 2026-11-20
- **Estado:** Aceptada
- **Reemplaza:** la elección de Claude Opus 5.5 en `docs/redaccion-ia.md` (ADR 0004 no fijaba modelo)

## Contexto

La redacción empezó con Claude Opus 5.5, el modelo más capaz, sin haber medido si la tarea lo necesitaba. La
tarea es acotada: el motor ya calculó el riesgo, el nivel y los controles, y los guards rechazan cualquier
cambio. El modelo solo redacta las 5 C a partir de datos dados. Un modelo más barato podría bastar.

## Prueba

Los mismos 5 hallazgos del escaneo 2 del laboratorio (niveles crítico y alto: políticas IAM con privilegios de
administrador, bloqueo de acceso público de S3, MFA) se redactaron con los tres modelos, con el mismo prompt y
effort `medium`. Una persona revisó los 15 borradores con el criterio "¿se lo entregaría así a un auditor?".

| | Haiku 5.5 | Sonnet 5.5 | Opus 5.5 |
|---|---|---|---|
| Pasaron las validaciones automáticas | 5/5 | 5/5 | 5/5 |
| Aprobados sin ediciones | 5/5 | 5/5 | 5/5 |
| Tokens de salida (promedio) | ~737 | ~746 | ~928 |
| Costo por hallazgo, caché caliente (USD, lista 2026-11) | ~0,0005 | ~0,009 | ~0,022 |
| Costo de un escaneo (96 acciones del plan) | ~0,04 | ~0,90 | ~2,10 |
| Fallback del servidor ante negativas | No | Sí | Sí |
| Preferido por quien revisó | | **Sí** | |

La tasa de aprobación no distinguió a los modelos. La preferencia por Sonnet se explica por la calidad del texto:

- recomendaciones más accionables, estructuradas de forma que se convierten directamente en **criterios de
  aceptación** de la remediación;
- tono más propio de un informe de auditoría;
- el **efecto** explica con más claridad la puntuación de riesgo del motor.

## Opciones consideradas

- **Opus 5.5:** igual de aceptable, más del doble de costo que Sonnet y sin ventaja observada en la redacción.
- **Haiku 5.5:** el más barato (unas 20 veces menos que Sonnet), aceptable, pero sin fallback del servidor: los
  checks de seguridad usan términos que pueden provocar una negativa falsa, y en Haiku esa negativa deja el
  hallazgo fallido.
- **Sonnet 5.5.**

## Decisión

Sonnet 5.5 (`claude-sonnet-5-5`) es el modelo por defecto de `draft`, con effort `medium` (el usado en la
prueba). `--model opus|haiku` sigue disponible para comparar.

## Consecuencias

- **Ganamos:** el texto que prefirió quien revisa, a menos de la mitad del costo de Opus, con fallback.
- **Aceptamos:** pagar unas 20 veces más que Haiku por una diferencia de calidad que no mide la tasa de
  aprobación, sino el juicio de una persona.
- **Límites de la prueba:** 5 hallazgos, todos de IAM y S3, una sola persona que sabía qué modelo revisaba. Es
  evidencia suficiente para elegir el valor por defecto, no para afirmar que Sonnet es mejor en general.

## Revisión

Reevaluar cuando exista el conjunto de evaluación (ADR 0004), con revisión a ciegas y hallazgos de más tipos;
cuando el volumen crezca (varias cuentas o ejecución diaria en CI), donde Haiku pesa más; o cuando cambien los
modelos o sus precios.
