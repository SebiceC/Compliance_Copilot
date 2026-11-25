# 8. Ley 1581 derivada de ISO 27001, con regla de datos personales

- **Fecha:** 2026-11-23
- **Estado:** Aceptada

## Contexto

La v1.0 incluye la Ley 1581 de 2012 (`docs/hoja-de-ruta-v1.md`, Fase 9). Es distinta de los otros tres marcos:

- **Prowler no la mapea.** No hay IDs de Prowler que traducir, como en SOC 2 o NIST CSF.
- **Es una ley, no un marco de controles.** La mayoría de sus obligaciones son documentales (autorización,
  política de tratamiento, aviso de privacidad, registro en el RNBD) y ningún escáner las ve.
- **Solo aplica a datos personales.** Un bucket público con un catálogo de productos es una brecha de seguridad,
  pero no un incumplimiento de la ley.
- **Los datos salen del país.** El proveedor de nube no tiene región en Colombia, y la ley regula la circulación
  internacional (art. 26; Decreto 1377 de 2013, arts. 24 y 25).

Las decisiones jurídicas (L1 a L6) las tomó el responsable del análisis de privacidad del proyecto; la tabla de
correspondencia la revisó fila por fila el 2026-11-23. La herramienta codifica ese criterio: no es asesoría
jurídica.

## Decisiones

| # | Decisión | Por qué |
|---|---|---|
| L1 | **Alcance normativo:** Ley 1581 de 2012; Decreto 1377 de 2013 (compilado en el Decreto 1074 de 2015); Circular Externa 005 de 2017 de la SIC; Guía de Responsabilidad Demostrada de la SIC | Son las normas que un auditor de la SIC esperaría ver |
| L2 | **Todas las obligaciones en el catálogo** (50), no solo las técnicas (12). Las documentales salen como *Evidencia manual requerida* | El mismo principio de la SoA: un requisito sin evidencia automática no desaparece, se muestra |
| L3 | **Mapeo indirecto:** hallazgo → control ISO 27001 → obligación (`derived_from` y `aliases` en `catalogs/ley-1581.json`; tabla legible en `docs/correspondencia-ley-1581.md`). Los controles ISO que se decidió no llevar a la ley van en `excluded`; uno que no esté en ninguna de las dos listas se reporta como *sin correspondencia* | Reutiliza un mapeo ya revisado. Un mapeo directo check → artículo serían cientos de filas sin un marco de referencia que lo respalde. Nada se pierde en silencio (ADR 0003, 0007) |
| L4 | **Solo cuentan los recursos con datos personales**, marcados con el tag `personal-data=yes\|no` que decide una persona y controla la Tag Policy. Regla de los tres grupos del motor de riesgo: un recurso de datos cuenta si tiene `yes`; los hallazgos de la cuenta y de infraestructura cuentan si la cuenta tiene al menos un recurso con `yes`. Un recurso de datos sin calificar queda en *Requiere revisión* | Contar todos los hallazgos sobrerreporta y contradice el principio de finalidad. La clasificación (`data-classification`) mide el impacto; no dice si aplica la ley |
| L5 | **Circulación internacional como transmisión por defecto**: el proveedor de nube actúa como encargado. Cada recurso con `personal-data=yes` fuera de las regiones del país (configurables, hoy ninguna) pone en *Requiere revisión* las obligaciones `L1581-26`, `D1377-25` y `SIC-C005`, con un texto que pide verificar el contrato de transmisión o el fundamento de la transferencia | La herramienta solo ve la región. Calificar la figura y revisar el contrato es trabajo de una persona |
| L6 | **Entregable:** *Matriz técnica: Ley 1581 de 2012* (`matriz-ley-1581.md` y su hoja), con las columnas **Aplica** y **Evidencia manual**, las secciones de datos fuera del país y de recursos sin calificar, y la hoja *Revisión datos personales* | La matriz no sabe si la organización es responsable o encargada (por eso los arts. 17 d y 18 b van siempre juntos): lo decide la columna *Aplica* |

## Consecuencias

- **La regla de datos personales vive en el catálogo** (`personal_data`: tag, regiones locales, obligaciones
  señaladas y texto). Otra ley de protección de datos podría reutilizarla con su propio JSON.
- **La matriz depende de que el tag esté bien puesto.** Un recurso con `personal-data=no` por error desaparece
  de la matriz. Mitigación: la Tag Policy impide valores inválidos, y el tag lo pone el dueño del activo, como la
  clasificación. Un recurso de datos sin tag no se pierde: queda para revisión.
- **Configuraciones de cuenta con tipo de datos** (agregado el 2026-11-25, tras el primer escaneo en CI).
  Prowler reporta algunos ajustes de la cuenta con un tipo de recurso de datos (`AwsEc2Volume`, `AwsKmsKey`…)
  y sin recurso concreto. La regla los trata como hallazgos de cuenta (`risk.finding_group`); si no, salían
  como recursos sin calificar y sus FAIL desaparecían de la matriz. El motor de riesgo adopta la misma regla en
  la v0.3, porque allí cambia la puntuación.
- **Aplica sugerida** (agregado el 2026-11-25, en la revisión de la matriz). Un grupo del catálogo puede traer
  una sugerencia para una columna de decisión humana (`suggested`). La Ley 1581 la usa en *Aplica*: *Sí* en el
  art. 17 y *Por definir* en el art. 18, con *(sugerido)* en el valor. Ahorra trabajo sin decidir por la persona:
  la herramienta sigue sin saber si la organización es responsable o encargada.
- **Un solo nivel de derivación.** Un catálogo no puede derivarse de otro derivado (se valida al cargar).
- **Límites que se declaran en la matriz:** el estado técnico evidencia solo la parte técnica de una obligación;
  *Sin brechas detectadas* no significa cumplimiento; ninguna fila reemplaza el análisis jurídico.
- **Azure (Fase 10):** el país de cada región está en `personal_data.REGION_COUNTRY`; habrá que agregar las
  regiones de Azure.

## Revisión

Revisar si el proveedor abre una región en Colombia (se agrega a `local_regions`), si la SIC actualiza la lista
de países con nivel adecuado, o si Prowler publica un mapeo propio de la Ley 1581.
