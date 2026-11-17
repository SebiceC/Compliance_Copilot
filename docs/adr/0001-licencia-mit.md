# 1. Usar licencia MIT

- **Fecha:** 2026-11-08
- **Estado:** Aceptada

## Contexto

Proyecto personal open source en fase temprana, con un único autor y sin contribuyentes externos. El
repositorio publicará código reutilizable y debe tener una licencia antes de hacerse público. No hay, por
ahora, usuarios empresariales ni requisitos de patentes.

## Opciones consideradas

- **MIT**
  - A favor: muy corta y fácil de entender; es la licencia más común en proyectos de portafolio; permite
    reutilizar el código con la única condición de conservar el aviso de copyright.
  - En contra: no incluye una concesión explícita de patentes.
- **Apache-2.0**
  - A favor: concesión explícita de patentes y protección frente a litigios de patentes; mecanismo de
    `NOTICE` para atribuciones; preferida por varias empresas para adoptar código.
  - En contra: texto más largo y obligaciones adicionales para quien redistribuye (indicar cambios,
    conservar `NOTICE`).

## Decisión

Usar **MIT** mientras el proyecto está en desarrollo, por simplicidad y máxima reutilización. Apache-2.0
queda como alternativa a evaluar si aparece adopción empresarial.

## Consecuencias

- **Ganamos:** cualquier persona u organización puede usar, modificar y redistribuir el proyecto con
  requisitos mínimos, lo que facilita su adopción y revisión.
- **Aceptamos:** no hay concesión explícita de patentes.
- **Nos obliga a futuro:**
  - Un cambio de licencia **no es retroactivo**: las versiones ya publicadas con MIT siguen siendo MIT para
    quien las obtuvo.
  - Mientras haya un único autor, el cambio se puede hacer sin permisos de terceros. Con contribuciones
    externas, haría falta el consentimiento de cada contribuyente (o un acuerdo de contribución).
  - Pasar de MIT a Apache-2.0 es compatible: el código MIT puede incorporarse en un proyecto Apache-2.0.

## Revisión

Reevaluar esta decisión ante el primero de estos eventos:

1. Antes de hacer público el repositorio, al terminar la fase de desarrollo.
2. Antes de aceptar el primer pull request externo.
3. Si una organización manifiesta interés en adoptar la herramienta.

Si la licencia cambia, se crea un nuevo ADR y este pasa a estado *Reemplazada por ADR-XXXX*.
