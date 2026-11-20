# 4. La IA redacta, una persona aprueba

- **Fecha:** 2026-11-19
- **Estado:** Aceptada

## Contexto

Los entregables necesitan hallazgos redactados en formato de auditoría. Un modelo de lenguaje puede redactarlos
bien, pero también puede inventar datos, cambiar conclusiones o ser manipulado por el texto que procesa (los
nombres de recursos los escribe cualquiera con acceso a la cuenta). Además, enviar datos a un proveedor externo
es una transferencia internacional de datos (Ley 1581).

## Opciones consideradas

- **Agente autónomo con herramientas** (consulta la cuenta, decide qué revisar): más flexible, pero amplía lo que
  el modelo puede hacer y lo que puede salir mal; la tarea no lo necesita.
- **Llamada única por hallazgo, publicación directa:** simple, pero el texto del modelo llegaría al auditor sin
  supervisión.
- **Llamada única por hallazgo, sin herramientas, con validación y aprobación humana.**

## Decisión

La tercera. El modelo solo redacta, a partir de datos de una lista blanca, anonimizados y con los nombres de
personas reemplazados por seudónimos. Los números (riesgo, nivel, controles) los calcula el motor; el modelo no
puede cambiarlos (validación automática). Ningún texto llega a los entregables sin la aprobación de una persona,
registrada con nombre, fecha y hash.

## Consecuencias

- **Ganamos:** el alcance de un error del modelo se limita a un borrador que una persona revisa; trazabilidad
  completa de qué escribió la IA y qué decidió la persona; minimización de los datos que salen.
- **Aceptamos:** la revisión humana toma tiempo; un escaneo grande requiere revisar decenas de borradores.
- **Nos obliga a futuro:** cualquier capacidad nueva del modelo (herramientas, más datos) requiere un ADR nuevo;
  en CI, la redacción puede ejecutarse, pero la aprobación sigue siendo manual.

## Revisión

Reevaluar si se agrega un conjunto de evaluación que demuestre una calidad estable, o si cambia el marco
regulatorio aplicable a sistemas de IA (por ejemplo, la adopción de ISO/IEC 42001).
